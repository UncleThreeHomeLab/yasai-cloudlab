"""Local TLS registry reads and native-provider transport through trusted SSH."""
import base64
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time


def hostname(value):
    if not isinstance(value, str) or not re.fullmatch(r'harbor[.]internal[.][a-z0-9]+(?:[-.][a-z0-9]+)*', value):
        raise ValueError('Harbor transport requires its canonical private hostname')
    return value


class Reader:
    def __init__(self, host, port, username, password):
        self.host, self.port = hostname(host), port
        self.authorization = 'Basic ' + base64.b64encode((username + ':' + password).encode()).decode()

    def get(self, path, missing=False):
        if (not path.startswith('/api/v2.0/') or '..' in path or
                not re.fullmatch(r'/[a-zA-Z0-9_./?=&%+,-]+', path)):
            raise ValueError('Harbor reader accepts only bounded API paths')
        connection = http.client.HTTPSConnection(self.host, timeout=30)
        try:
            connection.sock = ssl.create_default_context().wrap_socket(
                socket.create_connection(('127.0.0.1', self.port), timeout=15), server_hostname=self.host)
            connection.request('GET', path, headers={'Authorization': self.authorization, 'Accept': 'application/json'})
            response = connection.getresponse()
            if response.status == 404 and missing:
                return None
            if response.status != 200:
                raise RuntimeError('Harbor API read failed; private response withheld')
            raw = response.read(8 * 1024**2 + 1)
            if len(raw) > 8 * 1024**2:
                raise RuntimeError('Harbor API inventory exceeds its bounded size')
            if not raw and path == '/api/v2.0/system/gc/schedule':
                return None
            return json.loads(raw)
        finally:
            connection.close()


def _ports():
    with socket.socket() as first, socket.socket() as second:
        first.bind(('127.0.0.1', 0))
        second.bind(('127.0.0.1', 0))
        return first.getsockname()[1], second.getsockname()[1]


@contextmanager
def forward(values, host):
    host = hostname(host)
    if (not re.fullmatch(r'[a-z_][a-z0-9_-]*', values.get('VM_USER') or '') or
            not re.fullmatch(r'[a-zA-Z0-9.:\[\]-]+', values.get('VM_HOST') or '') or
            not values.get('VM_PASSWORD') or not Path('/state/known_hosts').is_file()):
        raise ValueError('Harbor requires existing VM credentials and verified SSH host identity')
    vm_port = values.get('VM_PORT') or '22'
    if not vm_port.isdecimal() or not 1 <= int(vm_port) <= 65535:
        raise ValueError('Invalid SSH port')
    socks, tls = _ports()
    environment = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    environment['SSHPASS'] = values['VM_PASSWORD']
    arguments = ['sshpass', '-e', 'ssh', '-F', '/dev/null', '-N', '-p', vm_port,
        '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1', '-o', 'PreferredAuthentications=password',
        '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/state/known_hosts',
        '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
        '-D', '127.0.0.1:' + str(socks), '-L', '127.0.0.1:' + str(tls) + ':' + host + ':443',
        values['VM_USER'] + '@' + values['VM_HOST']]
    with tempfile.TemporaryFile() as diagnostics:
        process = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=diagnostics)
        try:
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Harbor SSH transport unavailable; private diagnostics withheld')
                try:
                    with socket.create_connection(('127.0.0.1', socks), timeout=1), \
                            socket.create_connection(('127.0.0.1', tls), timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            yield tls, {'HTTPS_PROXY': 'socks5://127.0.0.1:' + str(socks),
                        'NO_PROXY': 'gitlab.com,localhost,127.0.0.1'}
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
