"""Bounded, read-only access-token proof endpoint."""

import base64
import json
import math
import os
import re
import ssl
import sys
import threading
import time
from urllib.error import URLError
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

sys.path.insert(0, '/dependencies')
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

MAX_TOKEN = 16384
MAX_JWKS = 131072
MAX_KEYS = 32
NAME = re.compile(r'^[A-Za-z0-9._:-]{1,128}$')
SEGMENT = re.compile(r'^[A-Za-z0-9_-]+$')


class InvalidToken(Exception):
    pass


class KeysUnavailable(Exception):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError('nonfinite JSON number')


def parse_json(data):
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    depth = 0
    quoted = escaped = False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > 64:
                raise ValueError('JSON nesting exceeds limit')
        elif char in ']}':
            depth -= 1
    try:
        return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except RecursionError as exc:
        raise ValueError('JSON nesting exceeds parser limit') from exc


def decode_segment(segment):
    if not SEGMENT.fullmatch(segment):
        raise InvalidToken()
    try:
        raw = base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))
        if base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii') != segment:
            raise InvalidToken()
        return raw
    except (ValueError, UnicodeError) as exc:
        raise InvalidToken() from exc


def parse_token(token):
    if len(token) > MAX_TOKEN:
        raise InvalidToken()
    parts = token.split('.')
    if len(parts) != 3:
        raise InvalidToken()
    try:
        header = parse_json(decode_segment(parts[0]))
        claims = parse_json(decode_segment(parts[1]))
        decode_segment(parts[2])
    except (ValueError, UnicodeError, TypeError) as exc:
        raise InvalidToken() from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise InvalidToken()
    if (header.get('alg') != 'RS256' or header.get('typ') != 'JWT'
            or not isinstance(header.get('kid'), str) or not NAME.fullmatch(header['kid'])
            or any(name in header for name in ('crit', 'jku', 'x5u', 'jwk', 'x5c'))):
        raise InvalidToken()
    return header, claims


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class KeyCache:
    def __init__(self, issuer, ca_file):
        self.url = issuer + '/protocol/openid-connect/certs'
        self.opener = build_opener(ProxyHandler({}), NoRedirect(),
                                   HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
        self.lock = threading.Lock()
        self.expires = 0
        self.retry_after = 0
        self.keys = {}

    def get(self, kid):
        with self.lock:
            if time.monotonic() >= self.expires:
                if time.monotonic() < self.retry_after:
                    raise KeysUnavailable()
                self._refresh()
            return self.keys.get(kid)

    def _refresh(self):
        try:
            with self.opener.open(Request(self.url, headers={'Accept': 'application/json'}), timeout=5) as response:
                if response.status != 200:
                    raise ValueError('invalid JWKS status')
                body = response.read(MAX_JWKS + 1)
                if len(body) > MAX_JWKS:
                    raise ValueError('JWKS too large')
                document = parse_json(body)
            entries = document['keys']
            if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_KEYS:
                raise ValueError('invalid JWKS keys')
            keys = {}
            seen = set()
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get('kid'), str):
                    raise ValueError('invalid JWKS key')
                kid = entry['kid']
                if not NAME.fullmatch(kid) or kid in seen:
                    raise ValueError('invalid JWKS key identifier')
                seen.add(kid)
                if entry.get('kty') != 'RSA' or entry.get('use', 'sig') != 'sig' or entry.get('alg', 'RS256') != 'RS256':
                    continue
                # Bound modulus and exponent before any large integer conversion.
                if (not isinstance(entry.get('n'), str) or not 342 <= len(entry['n']) <= 1366
                        or not isinstance(entry.get('e'), str) or not 1 <= len(entry['e']) <= 8
                        or not SEGMENT.fullmatch(entry['n']) or not SEGMENT.fullmatch(entry['e'])):
                    raise ValueError('invalid RSA encoding')
                key = jwt.algorithms.RSAAlgorithm.from_jwk(entry)
                if not isinstance(key, rsa.RSAPublicKey):
                    raise ValueError('invalid RSA key')
                numbers = key.public_numbers()
                if not 2048 <= key.key_size <= 8192 or numbers.e < 3 or numbers.e % 2 == 0:
                    raise ValueError('invalid RSA key')
                keys[kid] = key
            if not keys:
                raise ValueError('no signing keys')
            self.keys, self.expires, self.retry_after = keys, time.monotonic() + 60, 0
        except (URLError, OSError, ValueError, KeyError, TypeError, RecursionError, jwt.PyJWTError) as exc:
            self.keys, self.expires = {}, 0
            self.retry_after = time.monotonic() + 5
            raise KeysUnavailable() from exc


def finite_number(value):
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def verify(token, issuer, audience, role, cache):
    header, claims = parse_token(token)
    for name in ('exp', 'iat'):
        value = claims.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not finite_number(value):
            raise InvalidToken()
    if 'nbf' in claims:
        value = claims['nbf']
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not finite_number(value):
            raise InvalidToken()
    if claims['iat'] > claims['exp'] or ('nbf' in claims and claims['nbf'] > claims['exp']):
        raise InvalidToken()
    if not isinstance(claims.get('sub'), str) or not claims['sub'] or claims.get('typ') != 'Bearer':
        raise InvalidToken()
    aud = claims.get('aud')
    if not (isinstance(aud, str) and aud or isinstance(aud, list) and aud and all(isinstance(v, str) and v for v in aud)):
        raise InvalidToken()
    key = cache.get(header['kid'])
    if key is None:
        raise InvalidToken()
    try:
        jwt.decode(token, key=key, algorithms=['RS256'], issuer=issuer, audience=audience,
                   options={'require': ['iss', 'aud', 'exp', 'iat', 'sub']})
    except (jwt.PyJWTError, RecursionError) as exc:
        raise InvalidToken() from exc
    roles = claims.get('roles', [])
    if not isinstance(roles, list) or any(not isinstance(item, str) for item in roles):
        raise InvalidToken()
    return role in roles


def main():
    issuer, audience, role = (os.environ[name] for name in ('OIDC_ISSUER', 'OIDC_AUDIENCE', 'OIDC_ROLE'))
    cache = KeyCache(issuer, os.environ['OIDC_CA_FILE'])
    line = sys.stdin.buffer.readline(257)
    try:
        request = parse_json(line)
        nonce = request['init']
        if (not line.endswith(b'\n') or len(line) > 256 or set(request) != {'init'}
                or not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{32}', nonce)):
            return
    except (ValueError, TypeError, KeyError, UnicodeError):
        return
    sys.stdout.buffer.write(('READY:' + nonce + '\n').encode('ascii'))
    sys.stdout.buffer.flush()
    while True:
        line = sys.stdin.buffer.readline(32769)
        if not line:
            return
        if len(line) > 32768 or not line.endswith(b'\n'):
            return
        try:
            request = parse_json(line)
            if not isinstance(request, dict) or set(request) != {'token'} or not isinstance(request['token'], str):
                return
            result = 200 if verify(request['token'], issuer, audience, role, cache) else 403
        except InvalidToken:
            result = 401
        except KeysUnavailable:
            result = 503
        except (ValueError, TypeError, KeyError, UnicodeError):
            return
        sys.stdout.buffer.write(('%d\n' % result).encode('ascii'))
        sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
