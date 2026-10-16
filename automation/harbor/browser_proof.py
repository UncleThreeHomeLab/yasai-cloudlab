"""Prove absolute browser-cookie expiry with the pinned native OAuth2 Proxy binary."""
import base64
import hashlib
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from automation.harbor.chart import render
from automation.harbor.provider_proof import certificate, require

ISSUER = 'https://localhost:4443/realms/platform'
ORIGIN = 'https://localhost:4180'


def encode(value):
    raw = value if isinstance(value, bytes) else json.dumps(value, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b'=')


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, status, document, location=None):
        raw = json.dumps(document).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        if location:
            self.send_header('Location', location)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path.endswith('/.well-known/openid-configuration'):
            return self.respond(200, {'issuer': ISSUER, 'authorization_endpoint': ISSUER + '/authorize',
                'token_endpoint': ISSUER + '/token', 'jwks_uri': ISSUER + '/jwks',
                'userinfo_endpoint': ISSUER + '/userinfo', 'response_types_supported': ['code'],
                'subject_types_supported': ['public'], 'id_token_signing_alg_values_supported': ['RS256'],
                'code_challenge_methods_supported': ['S256']})
        if parsed.path.endswith('/jwks'):
            public = self.server.key.public_key().public_numbers()
            return self.respond(200, {'keys': [{'kty': 'RSA', 'kid': 'fixture', 'use': 'sig', 'alg': 'RS256',
                'n': encode(public.n.to_bytes((public.n.bit_length() + 7) // 8, 'big')).decode(),
                'e': encode(public.e.to_bytes((public.e.bit_length() + 7) // 8, 'big')).decode()}]})
        if parsed.path.endswith('/authorize'):
            query = {key: values[0] for key, values in urllib.parse.parse_qs(parsed.query).items()}
            if (query.get('client_id') != 'harbor' or query.get('redirect_uri') != ORIGIN + '/oauth2/callback' or
                    query.get('code_challenge_method') != 'S256' or not query.get('code_challenge')):
                return self.respond(400, {})
            code = secrets.token_hex(16)
            self.server.codes[code] = query
            return self.respond(302, {}, ORIGIN + '/oauth2/callback?' + urllib.parse.urlencode(
                {'code': code, 'state': query['state']}))
        if parsed.path.endswith('/userinfo'):
            return self.respond(200, self.server.claims)
        return self.respond(404, {})

    def do_POST(self):
        body = {key: values[0] for key, values in urllib.parse.parse_qs(
            self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()).items()}
        code = self.server.codes.pop(body.get('code'), None)
        authorization = 'Basic ' + base64.b64encode(('harbor:' + self.server.secret).encode()).decode()
        if (not code or self.headers.get('Authorization') != authorization and
                (body.get('client_id') != 'harbor' or body.get('client_secret') != self.server.secret)):
            return self.respond(400, {})
        if encode(hashlib.sha256(body.get('code_verifier', '').encode()).digest()).decode() != code['code_challenge']:
            return self.respond(400, {})
        self.server.pkce_verified += 1
        now = int(time.time())
        claims = dict(self.server.claims, iss=ISSUER, aud='harbor', iat=now, exp=now + 60,
                      nonce=code.get('nonce', ''))
        message = encode({'alg': 'RS256', 'typ': 'JWT', 'kid': 'fixture'}) + b'.' + encode(claims)
        token = (message + b'.' + encode(self.server.key.sign(message, padding.PKCS1v15(), hashes.SHA256()))).decode()
        return self.respond(200, {'token_type': 'Bearer', 'access_token': token, 'id_token': token,
                                  'expires_in': 60, 'scope': 'openid profile email'})


class Backend(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'synthetic-Harbor-protected-resource')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def binary(directory):
    lock = json.loads((Path(__file__).parent / 'browser-proof.lock.json').read_text())
    with urllib.request.urlopen(lock['url'], timeout=60) as response:
        raw = response.read(64 * 1024**2)
    require(hashlib.sha256(raw).hexdigest() == lock['sha256'], 'Browser fixture binary checksum mismatch')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        matches = [member for member in archive if member.isfile() and Path(member.name).name == 'oauth2-proxy']
        require(len(matches) == 1, 'Browser fixture archive inventory changed')
        executable = directory / 'oauth2-proxy'
        executable.write_bytes(archive.extractfile(matches[0]).read())
        executable.chmod(0o700)
    return executable


def run():
    directory = Path('/fixture/browser')
    directory.mkdir(mode=0o700)
    executable = binary(directory)
    cert, private = certificate(directory)
    provider = ThreadingHTTPServer(('127.0.0.1', 4443), Provider)
    provider.key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    provider.secret, provider.codes, provider.pkce_verified = secrets.token_urlsafe(48), {}, 0
    provider.claims = {'sub': 'synthetic-browser', 'email': 'proof@example.invalid',
                       'email_verified': True, 'preferred_username': 'proof', 'groups': ['/viewer']}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, private)
    provider.socket = context.wrap_socket(provider.socket, server_side=True)
    backend = ThreadingHTTPServer(('127.0.0.1', 8081), Backend)
    backend.requests = 0
    servers = (provider, backend)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    deployment = next(obj for obj in render('', {'enabled': True}) if obj['kind'] == 'Deployment')
    production_args = deployment['spec']['template']['spec']['containers'][0]['args']
    replacements = {'--oidc-issuer-url': ISSUER, '--redirect-url': ORIGIN + '/oauth2/callback',
                    '--upstream': 'http://127.0.0.1:8081', '--http-address': '', '--cookie-expire': '4s'}
    arguments = [argument.split('=', 1)[0] + '=' + replacements[argument.split('=', 1)[0]]
                 if argument.split('=', 1)[0] in replacements else argument for argument in production_args]
    arguments += ['--https-address=127.0.0.1:4180', '--tls-cert-file=' + str(cert),
                  '--tls-key-file=' + str(private), '--provider-ca-file=' + str(cert)]
    environment = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    environment.update(OAUTH2_PROXY_CLIENT_SECRET=provider.secret,
                       OAUTH2_PROXY_COOKIE_SECRET=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    client_context = ssl.create_default_context(cafile=str(cert))
    plain = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=client_context))
    proxy = subprocess.Popen([str(executable), *arguments], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, env=environment)
    def request(path, cookie=None):
        try:
            with plain.open(urllib.request.Request(ORIGIN + path,
                    headers={'Cookie': cookie} if cookie else {}), timeout=10) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(proxy.poll() is None, 'Browser gate startup failed')
            try:
                if request('/ready') == 200:
                    break
            except urllib.error.URLError:
                pass
            time.sleep(0.2)
        require(request('/protected') in (302, 401, 403) and backend.requests == 0,
                'Anonymous browser reached Harbor')
        jar = CookieJar()
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=client_context))
        with browser.open(ORIGIN + '/protected', timeout=20) as response:
            require(response.status == 200, 'Native OIDC browser login failed')
        require(provider.pkce_verified == 1, 'Browser gate did not verify PKCE')
        # Replay the old cookie explicitly after expiry; client-side cookie deletion is insufficient.
        replay = '; '.join(cookie.name + '=' + cookie.value for cookie in jar) + '; sid=synthetic-Harbor-session'
        require('__Host-harbor_oidc=' in replay, 'Native browser session cookie absent')
        started, accepted = time.monotonic(), 0
        while time.monotonic() - started < 3:
            require(request('/protected', replay) == 200, 'Browser session expired before the fixture bound')
            accepted += 1
            time.sleep(0.25)
        time.sleep(3)
        before = backend.requests
        require(request('/protected', replay) in (302, 401, 403), 'Active browser session exceeded its absolute bound')
        require(backend.requests == before, 'Expired replay reached Harbor despite the browser gate')
        return {'tls_verified': True, 'pkce_verified': True, 'active_requests_before_expiry': accepted,
                'expired_cookie_replay_denied': True, 'production_mutations': 0,
                'live_keycloak_offboarding_proven': False}
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.wait(timeout=5)
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        print(json.dumps(run(), sort_keys=True))
    except Exception:
        raise SystemExit('Browser session proof failed; private diagnostics withheld') from None
