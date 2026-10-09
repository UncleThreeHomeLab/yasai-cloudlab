"""Reference API: verify signed access JWTs, never accept ID tokens as API grants."""
import base64
import json
import math
import secrets
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def decode(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def validated_claims(token, jwks, issuer, audience, kind, now=None):
    stage = 'format'
    try:
        if not isinstance(token, str) or len(token) > 16384:
            raise ValueError
        header_part, payload_part, signature = token.split('.')
        header, claims = json.loads(decode(header_part)), json.loads(decode(payload_part))
        stage = 'header'
        if (header.get('alg') != 'RS256' or header.get('typ') != 'JWT' or header.get('crit')
                or not isinstance(header.get('kid'), str) or not header['kid']):
            raise ValueError
        keys = [k for k in jwks['keys'] if k.get('kid') == header.get('kid')
                and k.get('kty') == 'RSA' and k.get('use') == 'sig' and k.get('alg') == 'RS256']
        stage = 'signing-key'
        if len(keys) != 1:
            raise ValueError
        key = keys[0]
        public = rsa.RSAPublicNumbers(int.from_bytes(decode(key['e']), 'big'),
                                     int.from_bytes(decode(key['n']), 'big')).public_key()
        stage = 'signature'
        public.verify(decode(signature), (header_part + '.' + payload_part).encode(), padding.PKCS1v15(), hashes.SHA256())
        current = time.time() if now is None else now
        audiences = claims.get('aud', [])
        audiences = [audiences] if isinstance(audiences, str) else audiences
        stage = 'issuer-audience-token-kind'
        if (not isinstance(audiences, list) or not audiences or any(not isinstance(a, str) for a in audiences)
                or claims.get('iss') != issuer or audience not in audiences or claims.get('typ') != kind
                or (kind == 'ID' and len(audiences) > 1 and claims.get('azp') != audience)):
            raise ValueError
        stage = 'lifetime-subject'
        dates = [claims.get('exp'), claims.get('iat'), claims.get('nbf', 0)]
        if (any(type(value) not in (int, float) or not math.isfinite(value) for value in dates)
                or claims['exp'] <= current or claims.get('nbf', 0) > current
                or claims['iat'] > current or not isinstance(claims.get('sub'), str) or not claims['sub']):
            raise ValueError
        return claims
    except Exception:
        raise ValueError('Token rejected: ' + stage) from None


def access_token(token, jwks, issuer, audience, role, now=None):
    claims = validated_claims(token, jwks, issuer, audience, 'Bearer', now)
    roles = claims.get('roles', [])
    if not isinstance(roles, list) or any(not isinstance(r, str) for r in roles) or role not in roles:
        raise ValueError('Access token rejected')
    return claims


def identity_token(token, jwks, issuer, client_id, nonce, now=None):
    claims = validated_claims(token, jwks, issuer, client_id, 'ID', now)
    if not isinstance(claims.get('nonce'), str) or not secrets.compare_digest(claims['nonce'], nonce):
        raise ValueError('ID token nonce rejected')
    return claims
