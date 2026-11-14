"""Serve proof on 8080 and process/worker health on 8081.

Readiness confirms worker initialization, not remote JWKS availability.
"""

import heapq
import json
import os
import queue
import re
import secrets
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

NAME = re.compile(r'^[A-Za-z0-9._:-]{1,128}$')
TOKEN = re.compile(r'^[A-Za-z0-9_.-]{1,16384}$')
TIMEOUT = 5


class HeaderLimit(Exception):
    pass


class LimitedReader:
    def __init__(self, reader):
        self.reader = reader
        self.remaining = 16384

    def readline(self, limit=-1):
        limit = self.remaining + 1 if limit < 0 else min(limit, self.remaining + 1)
        data = self.reader.readline(limit)
        if len(data) > self.remaining:
            raise HeaderLimit()
        self.remaining -= len(data)
        return data

    def close(self):
        self.reader.close()


class HeaderWatchdog:
    def __init__(self):
        self.lock = threading.Condition()
        self.active = {}
        self.heap = []
        self.serial = 0
        self.stopped = False
        threading.Thread(target=self.run, daemon=True).start()

    def arm(self, connection):
        with self.lock:
            self.serial += 1
            token = self.serial
            deadline = time.monotonic() + TIMEOUT
            self.active[connection] = (token, deadline)
            if len(self.heap) >= 160:
                self.heap = [(item[1], item[0], conn) for conn, item in self.active.items()]
                heapq.heapify(self.heap)
            heapq.heappush(self.heap, (deadline, token, connection))
            self.lock.notify()

    def cancel(self, connection):
        with self.lock:
            self.active.pop(connection, None)
            self.lock.notify()

    def run(self):
        while True:
            with self.lock:
                if self.stopped:
                    return
                if not self.heap:
                    self.lock.wait()
                    continue
                deadline, token, connection = self.heap[0]
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    self.lock.wait(remaining)
                    continue
                heapq.heappop(self.heap)
                if self.active.get(connection) != (token, deadline):
                    continue
                del self.active[connection]
                # Keep the socket object alive until shutdown; never act on a reused fd.
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        with self.lock:
            self.stopped = True
            self.lock.notify_all()


class Worker:
    def __init__(self):
        self.calls = threading.Lock()
        self.pending = queue.Queue(maxsize=1)
        self.stopped = threading.Event()
        self.quarantined = threading.Event()
        self.initialized = threading.Event()
        self.process = None
        self.retry_after = 0.0
        threading.Thread(target=self.run, daemon=True).start()

    def ready(self):
        proc = self.process
        return (not self.stopped.is_set() and not self.quarantined.is_set() and self.initialized.is_set()
                and proc is not None and proc.poll() is None)

    def call(self, token):
        deadline = time.monotonic() + TIMEOUT
        if not self.calls.acquire(timeout=TIMEOUT):
            return 503
        try:
            if not self.ready():
                return 503
            done = threading.Event()
            result = {'status': 503}
            item = (deadline, token, done, result)
            try:
                self.pending.put_nowait(item)
            except queue.Full:
                return 503
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not done.wait(remaining) or time.monotonic() >= deadline:
                self.quarantined.set()
                return 503
            return result['status']
        finally:
            self.calls.release()

    def start(self, deadline):
        self.initialized.clear()
        proc = subprocess.Popen([sys.executable, '-I', '-B', '/app/worker.py'], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
        self.process = proc
        os.set_blocking(proc.stdin.fileno(), False)
        os.set_blocking(proc.stdout.fileno(), False)
        nonce = secrets.token_hex(16)
        request = (json.dumps({'init': nonce}, separators=(',', ':')) + '\n').encode('ascii')
        expected = ('READY:' + nonce + '\n').encode('ascii')
        self.exchange_frame(request, (expected,), deadline)
        if self.stopped.is_set() or self.quarantined.is_set() or proc.poll() is not None:
            raise OSError('worker unavailable')
        self.initialized.set()

    def terminate(self):
        self.initialized.clear()
        self.quarantined.set()
        proc = self.process
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        self.retry_after = time.monotonic() + 5

    def exchange(self, token, deadline):
        data = (json.dumps({'token': token}, separators=(',', ':')) + '\n').encode('ascii')
        if len(data) > 32768:
            raise ValueError('frame too large')
        response = self.exchange_frame(data, (b'200\n', b'401\n', b'403\n', b'503\n'), deadline)
        return int(response[:3])

    def exchange_frame(self, data, allowed, deadline):
        proc = self.process
        written = 0
        response = bytearray()
        limit = max(map(len, allowed))
        while time.monotonic() < deadline:
            if self.stopped.is_set() or proc.poll() is not None:
                raise OSError('worker exited')
            ready_r, ready_w, _ = select.select([proc.stdout], [proc.stdin] if written < len(data) else [], [],
                                                max(0, deadline - time.monotonic()))
            if time.monotonic() >= deadline:
                raise TimeoutError('worker deadline')
            if ready_w:
                written += os.write(proc.stdin.fileno(), data[written:])
            if ready_r:
                chunk = os.read(proc.stdout.fileno(), limit + 1 - len(response))
                if not chunk:
                    raise OSError('worker closed')
                response.extend(chunk)
                if b'\n' in response:
                    if written != len(data) or bytes(response) not in allowed:
                        raise ValueError('invalid worker response')
                    return bytes(response)
                if len(response) > limit:
                    raise ValueError('worker response too large')
        raise TimeoutError('worker deadline')

    def run(self):
        while not self.stopped.is_set():
            proc = self.process
            if proc is not None and proc.poll() is not None:
                self.initialized.clear()
                proc.stdin.close()
                proc.stdout.close()
                self.process = None
                self.quarantined.clear()
                self.retry_after = max(self.retry_after, time.monotonic() + 5)
            if self.process is None and time.monotonic() >= self.retry_after:
                self.quarantined.clear()
                try:
                    self.start(time.monotonic() + TIMEOUT)
                except (OSError, ValueError, TimeoutError):
                    self.terminate()
            if self.quarantined.is_set() and self.process is not None:
                self.terminate()
                self.stopped.wait(.1)
                continue
            try:
                deadline, token, done, result = self.pending.get(timeout=.1)
            except queue.Empty:
                continue
            try:
                if self.process is not None and not self.quarantined.is_set() and time.monotonic() < deadline:
                    result['status'] = self.exchange(token, deadline)
                    if result['status'] == 503:
                        self.retry_after = time.monotonic() + 5
            except (OSError, ValueError, TimeoutError):
                self.terminate()
            finally:
                done.set()
        self.terminate()
        if self.process is not None:
            self.process.poll()

    def close(self):
        self.stopped.set()
        self.terminate()
        deadline = time.monotonic() + 1
        proc = self.process
        while proc is not None and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, limit, watchdog, worker):
        super().__init__(address, handler)
        self.slots = threading.BoundedSemaphore(limit)
        self.watchdog, self.worker = watchdog, worker

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        self.watchdog.arm(request)
        try:
            super().process_request(request, address)
        except BaseException:
            self.watchdog.cancel(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.watchdog.cancel(request)
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.rfile = LimitedReader(self.rfile)

    def parse_request(self):
        try:
            return super().parse_request()
        except HeaderLimit:
            return False
        finally:
            self.server.watchdog.cancel(self.request)

    def log_message(self, _format, *_args):
        pass

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        self.send_response(code)
        self.send_header('Connection', 'close')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        if self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Content-Length') not in (None, ['0']):
            status = 400
        elif self.server.server_port == 8081:
            status = (200 if self.path == '/live' or (self.path == '/ready' and self.server.worker.ready())
                      else 503 if self.path == '/ready' else 404)
        elif self.path == '/proof':
            headers = self.headers.get_all('Authorization', [])
            if len(headers) != 1 or not headers[0].startswith('Bearer ') or not TOKEN.fullmatch(headers[0][7:]):
                status = 401
            else:
                status = self.server.worker.call(headers[0][7:])
        else:
            status = 404
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()


def main():
    issuer, audience, role, ca_file = (os.environ[name] for name in
                                       ('OIDC_ISSUER', 'OIDC_AUDIENCE', 'OIDC_ROLE', 'OIDC_CA_FILE'))
    parsed = urlsplit(issuer)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or issuer.endswith('/') or len(issuer) > 2048
            or parsed.geturl() != issuer or '\\' in issuer or any(c.isspace() or ord(c) < 32 for c in issuer)
            or not NAME.fullmatch(audience) or not NAME.fullmatch(role)):
        raise ValueError('invalid OIDC configuration')
    _ = parsed.port
    ssl.create_default_context(cafile=ca_file)
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_args: stopped.set())
    signal.signal(signal.SIGINT, lambda *_args: stopped.set())
    watchdog, worker = HeaderWatchdog(), Worker()
    proof = BoundedServer(('0.0.0.0', 8080), Handler, 32, watchdog, worker)
    health = BoundedServer(('0.0.0.0', 8081), Handler, 8, watchdog, worker)
    for server in (proof, health):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    stopped.wait()
    for server in (proof, health):
        server.shutdown()
        server.server_close()
    watchdog.close()
    worker.close()


if __name__ == '__main__':
    main()
