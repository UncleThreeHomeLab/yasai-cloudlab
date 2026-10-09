"""Disposable reference BFF and bearer API; no deployment or personal accounts."""
import base64
import hashlib
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import ssl
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from automation.identity.tokens import access_token, identity_token

ISSUER = 'https://localhost:8443/realms/platform'
CLIENT = 'reference-ui'
CALLBACK = 'https://localhost/callback'
COOKIE = '__Host-cloudlab-fixture'
CONTEXT = ssl.create_default_context(cafile='/fixture/ca.crt')
SESSIONS = {}
KEYS = {'expires': 0}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


OPENER = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=CONTEXT))


def fetch(path, form=None):
    req = urllib.request.Request(ISSUER + path,
        data=urllib.parse.urlencode(form).encode() if form is not None else None)
    with OPENER.open(req, timeout=15) as response:
        raw = response.read(131073)
        if len(raw) > 131072:
            raise ValueError('Identity response exceeds fixture limit')
        return json.loads(raw)


def signing_keys():
    if KEYS['expires'] <= time.time():
        KEYS.update(document=fetch('/protocol/openid-connect/certs'), expires=time.time() + 300)
    return KEYS['document']


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log codes, tokens, cookies or usernames.

    def response(self, status, text, headers=None):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(text.encode())

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        cookie = SimpleCookie(self.headers.get('Cookie', ''))
        identifier = cookie[COOKIE].value if COOKIE in cookie else None
        now = time.time()
        for key in list(SESSIONS):
            if SESSIONS[key]['expires'] <= now:
                del SESSIONS[key]
        current = SESSIONS.get(identifier)
        try:
            if parsed.path == '/health':
                self.response(200, 'Reference fixture ready')
            elif parsed.path == '/login':
                if len(SESSIONS) >= 100:
                    self.response(503, 'Fixture capacity reached')
                    return
                # New login must reach the IdP. Do not accept a cached discovery
                # document as proof that a failed IdP can authenticate anyone.
                discovery = fetch('/.well-known/openid-configuration')
                if discovery['issuer'] != ISSUER or discovery['authorization_endpoint'] != ISSUER + '/protocol/openid-connect/auth':
                    raise ValueError('Unexpected issuer')
                identifier = secrets.token_urlsafe(32)
                verifier, state, nonce = [secrets.token_urlsafe(48) for _ in range(3)]
                SESSIONS[identifier] = {'state': state, 'nonce': nonce, 'verifier': verifier, 'expires': now + 120}
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
                query = urllib.parse.urlencode({'client_id': CLIENT, 'redirect_uri': CALLBACK,
                    'response_type': 'code', 'scope': 'openid profile', 'state': state, 'nonce': nonce,
                    'code_challenge': challenge, 'code_challenge_method': 'S256'})
                self.response(302, '', {'Location': discovery['authorization_endpoint'] + '?' + query,
                    'Set-Cookie': COOKIE + '=' + identifier + '; Path=/; Secure; HttpOnly; SameSite=Lax'})
            elif parsed.path == '/callback':
                query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
                if (not current or 'state' not in current or query.get('state') != [current['state']]
                        or len(query.get('code', [])) != 1 or set(query) - {'state', 'code', 'session_state', 'iss'}
                        or ('iss' in query and query['iss'] != [ISSUER])):
                    self.response(400, 'Authorization response rejected')
                    return
                # Consume state before exchange: failed or replayed callbacks fail closed.
                current.pop('state')
                tokens = fetch('/protocol/openid-connect/token', {'client_id': CLIENT,
                    'grant_type': 'authorization_code', 'redirect_uri': CALLBACK, 'code': query['code'][0],
                    'code_verifier': current.pop('verifier')})
                jwks = signing_keys()
                identity_token(tokens['id_token'], jwks, ISSUER, CLIENT, current.pop('nonce'))
                access_token(tokens['access_token'], jwks, ISSUER, 'reference-api', 'reader')
                # Keep the fixture cookie long enough to observe JWT rejection itself.
                # Every API request still validates the token's own 300-second expiry.
                current.update(token=tokens['access_token'], expires=now + 360)
                self.response(302, '', {'Location': '/'})
            elif parsed.path in ('/api', '/api-session'):
                raw = self.headers.get('Authorization', '')
                token = current.get('token') if parsed.path == '/api-session' and current else (
                    raw[7:] if raw.startswith('Bearer ') else None)
                if not token:
                    self.response(401, 'Access token required')
                    return
                access_token(token, signing_keys(), ISSUER, 'reference-api', 'reader')
                self.response(200, 'API permitted')
            elif parsed.path == '/':
                self.response(200, '<p>MFA session active</p><a href="/api-session">Check API permission</a>'
                              if current and current.get('token') else '<a href="/login">Sign in</a>')
            else:
                self.response(404, 'Not found')
        except ValueError:
            self.response(403, 'Identity or permission rejected')
        except Exception:
            self.response(503, 'Identity unavailable; access denied')


def main():
    server = HTTPServer(('127.0.0.1', 443), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain('/fixture/tls.crt', '/fixture/tls.key')
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
