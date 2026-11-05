"""Isolated TLS SMTP sink and authenticated notification receiver."""
import base64
import hmac
import json
from pathlib import Path
import socketserver
import ssl
import threading
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURE = Path('/fixture')
SECRET = FIXTURE / 'secrets/alertmanager-notification-fixture'
LOCK = threading.Lock()
EVENTS = []
REJECTED = 0
FAIL = True
REDIRECTS = {307: 0, 308: 0}
OFF_PATH_CALLBACKS = 0
FAILED_REQUESTS = 0


def tls_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(FIXTURE / 'server.crt', FIXTURE / 'server.key')
    return context


class Webhook(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def reply(self, code, value):
        raw = json.dumps(value).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self):
        global REJECTED
        expected = 'Bearer ' + (SECRET / 'token').read_text()
        valid = hmac.compare_digest(self.headers.get('Authorization', '').encode(), expected.encode())
        if not valid:
            with LOCK: REJECTED += 1
            self.reply(401, {'accepted': False})
        return valid

    def do_GET(self):
        if self.path == '/health': return self.reply(200, {'ready': True})
        if not self.authorized(): return
        if self.path != '/events': return self.reply(404, {})
        with LOCK:
            self.reply(200, {'events': list(EVENTS), 'rejected': REJECTED,
                            'redirects': dict(REDIRECTS), 'off_path_callbacks': OFF_PATH_CALLBACKS,
                            'failed_requests': FAILED_REQUESTS})

    def do_POST(self):
        global FAIL, OFF_PATH_CALLBACKS, FAILED_REQUESTS
        if self.path == '/off-path':
            with LOCK: OFF_PATH_CALLBACKS += 1
            return self.reply(200, {'accepted': True})
        if not self.authorized(): return
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.reply(400, {})
        if not 0 < size <= 65536: return self.reply(400, {})
        try:
            value = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeDecodeError):
            return self.reply(400, {})
        if self.path in ('/redirect307', '/redirect308'):
            code = int(self.path[-3:])
            with LOCK: REDIRECTS[code] += 1
            self.send_response(code)
            self.send_header('Location', 'https://incident-receiver.cloudlab-app-incident-receiver.svc:9443/off-path')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if self.path == '/control':
            if set(value) != {'fail'} or not isinstance(value['fail'], bool): return self.reply(400, {})
            with LOCK: FAIL = value['fail']
            return self.reply(200, {'accepted': True})
        if self.path not in ('/alerts/primary', '/alerts/secondary', '/alerts/failing'):
            return self.reply(404, {})
        with LOCK:
            if self.path == '/alerts/failing' and FAIL:
                FAILED_REQUESTS += 1
                return self.reply(503, {'accepted': False})
            alerts = value.get('alerts')
            if not isinstance(alerts, list) or len(alerts) > 16: return self.reply(400, {})
            for alert in alerts:
                if not isinstance(alert, dict) or not isinstance(alert.get('labels'), dict): return self.reply(400, {})
                name = alert.get('labels', {}).get('alertname', '')
                status = alert.get('status')
                if isinstance(name, str) and name.startswith('Fixture') and len(name) <= 64 and status in ('firing', 'resolved'):
                    if len(EVENTS) >= 128: return self.reply(429, {})
                    EVENTS.append({'channel': self.path, 'name': name, 'status': status})
        self.reply(200, {'accepted': True})


class SMTP(socketserver.BaseRequestHandler):
    def handle(self):
        connection = self.request
        connection.settimeout(10)
        stream = connection.makefile('rb')
        secure = authenticated = False
        def send(raw): connection.sendall(raw)
        send(b'220 smtp.fixture.invalid fixture\r\n')
        try:
            for _ in range(32):
                line = stream.readline(4097)
                if not line or len(line) > 4096: return
                command, _, argument = line.strip().partition(b' ')
                command = command.upper()
                if command in (b'EHLO', b'HELO'):
                    send(b'250-fixture\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n')
                elif command == b'STARTTLS' and not secure:
                    send(b'220 Ready to start TLS\r\n')
                    connection = tls_server().wrap_socket(connection, server_side=True)
                    stream.close()
                    stream = connection.makefile('rb')
                    secure = True
                elif command == b'AUTH' and secure:
                    mechanism, _, encoded = argument.partition(b' ')
                    try:
                        decoded = base64.b64decode(encoded, validate=True).split(b'\0')
                    except ValueError:
                        decoded = []
                    authenticated = (mechanism == b'PLAIN' and len(decoded) == 3 and decoded[1] == b'fixture'
                        and hmac.compare_digest(decoded[2], (SECRET / 'password').read_bytes()))
                    send(b'235 Authenticated\r\n' if authenticated else b'535 Authentication failed\r\n')
                elif command in (b'MAIL', b'RCPT') and secure and authenticated:
                    send(b'250 Accepted\r\n')
                elif command == b'DATA' and secure and authenticated:
                    send(b'354 End with dot\r\n')
                    data = bytearray()
                    while True:
                        part = stream.readline(65537)
                        if not part or len(data) + len(part) > 65536: return
                        if part == b'.\r\n': break
                        data.extend(part)
                    subject = str(BytesParser().parsebytes(data)['Subject'] or '')[:1024]
                    status = 'firing' if '[FIRING:' in subject else 'resolved' if '[RESOLVED]' in subject else ''
                    with LOCK:
                        if len(EVENTS) >= 128: return
                        EVENTS.append({'channel': 'email', 'subject': subject, 'status': status})
                    send(b'250 Queued\r\n')
                elif command == b'QUIT':
                    send(b'221 Bye\r\n')
                    return
                else:
                    send(b'530 TLS and authentication required\r\n')
        except (OSError, ssl.SSLError):
            return
        finally:
            stream.close()
            connection.close()


def run():
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 2525), SMTP)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    webhook = ThreadingHTTPServer(('0.0.0.0', 9443), Webhook)
    webhook.socket = tls_server().wrap_socket(webhook.socket, server_side=True)
    webhook.serve_forever()


if __name__ == '__main__':
    run()
