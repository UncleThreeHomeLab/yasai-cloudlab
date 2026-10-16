"""Exercise the pinned native provider against an isolated TLS protocol fixture.

This qualifies secret handling and interruption behavior, not Harbor behavior.
No production credential, state backend, VM, vault or registry is consulted.
"""
import base64
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SOURCE = Path(__file__).parent / 'provider-fixture'


class Registry(ThreadingHTTPServer):
    """Only the robot API subset used by the real provider; never deployment CRUD."""
    daemon_threads = True

    def __init__(self, credential):
        super().__init__(('127.0.0.1', 0), Handler)
        self.authorization = 'Basic ' + base64.b64encode(('fixture:' + credential).encode()).decode()
        self.robot = None
        self.password = None
        self.creations = 0
        self.patches = 0
        self.failure = None
        self.calls = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, status, value, location=None):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        if location:
            self.send_header('Location', location)
        self.end_headers()
        self.wfile.write(data)

    def execute(self):
        server = self.server
        if self.headers.get('Authorization') != server.authorization:
            return self.respond(401, {})
        server.calls.append((self.command, self.path))
        length = int(self.headers.get('Content-Length', 0))
        if length > 16384:
            return self.respond(413, {})
        body = json.loads(self.rfile.read(length)) if length else None
        if self.command == 'POST' and self.path == '/api/v2.0/robots':
            if server.robot is not None:
                return self.respond(409, {})
            server.creations += 1
            server.password = secrets.token_urlsafe(48)
            server.robot = dict(body, id=71, name='robot$custody-fixture+custody')
            if server.failure == 'lost-create':
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            return self.respond(201, dict(server.robot, secret=server.password), '/api/v2.0/robots/71')
        if self.path != '/api/v2.0/robots/71' or server.robot is None:
            return self.respond(404, {})
        if self.command == 'GET':
            return self.respond(200, server.robot)
        if self.command == 'PATCH':
            if server.failure == 'before-password':
                return self.respond(503, {})
            server.patches += 1
            server.password = body['secret']
            if server.failure == 'lost-password':
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            return self.respond(200, {})
        if self.command == 'PUT':
            server.robot.update(body)
            return self.respond(200, {})
        return self.respond(405, {})

    do_POST = execute
    do_GET = execute
    do_PATCH = execute
    do_PUT = execute


def certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    private = directory / 'key.pem'
    public = directory / 'ca.pem'
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    public.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return public, private


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def clean_state(directory, secret):
    for path in directory.glob('terraform.tfstate*'):
        require(secret.encode() not in path.read_bytes(), 'Robot password leaked into provider state')
    state = json.loads((directory / 'terraform.tfstate').read_text())
    resources = [item for item in state.get('resources', []) if item['type'] == 'harbor_robot_account']
    if resources:
        require(len(resources) == 1 and resources[0]['instances'][0]['attributes'].get('secret') in (None, ''),
                'Provider persisted a generated password')


def run(directory):
    directory.mkdir(mode=0o700)
    for source in SOURCE.iterdir():
        if source.is_file():
            shutil.copy(source, directory / source.name)
    public, private = certificate(directory)
    secret, credential = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    # Deliberate allowlist: no OP token, GitHub token, inherited TF logging or production backend.
    environment = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    environment.update(TF_IN_AUTOMATION='true', TF_INPUT='false', TF_VAR_robot_secret=secret,
                       HARBOR_USERNAME='fixture', HARBOR_PASSWORD=credential, SSL_CERT_FILE=str(public),
                       TF_CLI_CONFIG_FILE='/opt/runner/providers.tfrc')
    def tofu(*arguments, expected=0):
        result = subprocess.run(['tofu', '-chdir=' + str(directory), *arguments, '-no-color'],
                                capture_output=True, text=True, timeout=180, env=environment)
        require(secret not in result.stdout + result.stderr and credential not in result.stdout + result.stderr,
                'Provider emitted a credential')
        if result.returncode != expected:
            # Errors remain in disposable tmpfs; stdout contains no provider response.
            (directory / 'failure.txt').write_text(result.stderr)
            raise RuntimeError('Native Harbor provider fixture failed: ' + arguments[0])
        return result

    server = Registry(credential)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(public, private)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    environment['HARBOR_URL'] = 'https://localhost:' + str(server.server_port)
    try:
        tofu('init', '-backend=false', '-lockfile=readonly', '-input=false')
        tofu('apply', '-auto-approve', '-input=false')
        require(server.creations == 1 and server.patches == 1 and server.password == secret,
                'Provider did not set the durable vault-owned password')
        clean_state(directory, secret)
        tofu('plan', '-detailed-exitcode', '-input=false')
        tofu('apply', '-auto-approve', '-input=false')
        require(server.patches == 1, 'Repeat apply rotated a robot password')

        # Every interrupted creation resumes only after exact read-only identity/permission
        # inspection and native import. Never retry create or adopt by title alone.
        for failure in ('lost-create', 'before-password', 'lost-password'):
            tofu('state', 'rm', 'harbor_robot_account.fixture')
            server.robot = None
            server.failure = failure
            tofu('apply', '-auto-approve', '-input=false', expected=1)
            require(server.robot['name'] == 'robot$custody-fixture+custody' and
                    server.robot['level'] == 'project' and
                    server.robot['permissions'] == [{'access': [{'action': 'pull', 'effect': 'allow',
                      'resource': 'repository'}], 'kind': 'project', 'namespace': 'custody-fixture'}],
                    'Interrupted robot cannot be safely imported')
            creations = server.creations
            server.failure = None
            tofu('import', '-input=false', 'harbor_robot_account.fixture', '/robots/71')
            tofu('apply', '-auto-approve', '-input=false')
            require(server.creations == creations and server.password == secret,
                    'Native import recovery duplicated a robot or lost vault custody')
            clean_state(directory, secret)
            patches = server.patches
            tofu('plan', '-detailed-exitcode', '-input=false')
            tofu('apply', '-auto-approve', '-input=false')
            require(server.patches == patches, 'Recovered robot rotated on repeat apply')
        return {'provider': 'cloudlab/harbor@3.12.5-cloudlab.1', 'tls_verified': True, 'write_only': True,
                'repeat_rotations': 0, 'interruption_cases': 3, 'production_mutations': 0,
                'harbor_behavior_proven': False}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        print(json.dumps(run(Path('/fixture/candidate')), sort_keys=True))
    except Exception:
        raise SystemExit('Harbor custody fixture failed; private diagnostics withheld') from None
