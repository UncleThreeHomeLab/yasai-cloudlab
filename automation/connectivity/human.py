"""Verify human Access JWT and backend response; retain evidence, never the session."""
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import time
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from automation.credentials.vault import fields
from automation.connectivity.cloudflare import API, access_application
from automation.connectivity.contract import host_rules
from automation.connectivity.provider_http import open_request
from automation.connectivity.reconcile import matches
from automation.connectivity.traffic import denied, https, success
from automation.connectivity.checkpoint import transaction
from automation.connectivity.cluster_fixture import PROOF_PATH

RECEIPT = Path('/state/connectivity/human-proof.json')


def selected():
    from automation.identity.access_cutover import approved_email, selection
    with transaction() as receipts:
        state = receipts.load('external') or {}
    identity_provider, identity_group = selection(state, os.environ['CLOUDFLARE_IDP_ID'])
    admin_values = fields('cloudflare-management', ('API_TOKEN', 'ACCOUNT_ID', 'ZONE_ID'))
    dns_values = fields('cloudlab-dns01', ('API_TOKEN', 'ZONE_ID'))
    admin, dns = API(admin_values['API_TOKEN']), API(dns_values['API_TOKEN'])
    if identity_group:
        from automation.identity.access_provider import public_provider
        provider = admin.request('GET', 'accounts/' + admin_values['ACCOUNT_ID'] + '/access/identity_providers/' + identity_provider)
        if not matches(public_provider(provider), state['identity_provider']['intent']):
            raise RuntimeError('Central Access provider differs from the verified OIDC contract')
    zone = dns.request('GET', 'zones/' + dns_values['ZONE_ID'])['name']
    rules = host_rules(json.loads(os.environ['CLOUDFLARE_ACCESS_HOSTS']), zone)
    organization = admin.request('GET', 'accounts/' + admin_values['ACCOUNT_ID'] + '/access/organizations')['auth_domain']
    if not organization.endswith('.cloudflareaccess.com') or '/' in organization:
        raise RuntimeError('Access organization identity is invalid')
    applications = admin.collection('accounts/' + admin_values['ACCOUNT_ID'] + '/access/apps')
    selected_apps = []
    for rule in rules:
        if rule['access'] != 'human': continue
        found = [a for a in applications if a.get('domain') == rule['hostname']]
        if len(found) != 1:
            raise RuntimeError('Human Access application identity is ambiguous')
        app = admin.request('GET', 'accounts/' + admin_values['ACCOUNT_ID'] + '/access/apps/' + found[0]['id'])
        desired = access_application(rule, human_email=approved_email(state, os.environ['CLOUDFLARE_HUMAN_EMAIL']),
                                     identity_provider=identity_provider, identity_group=identity_group)
        if not matches(app, desired):
            raise RuntimeError('Human Access policy differs from its declared identity rule')
        selected_apps.append({'hostname': rule['hostname'], 'aud': app['aud'], 'id': app['id'], 'policy': desired})
    evidence = {'applications': selected_apps, 'organization': organization}
    if identity_group:
        evidence['identity_credential'] = state['identity_provider']['credential_hash']
        evidence['identity_ready_at'] = state['identity_provider']['credential_ready_at']
    binding = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
    return selected_apps, rules, organization, binding


def decode(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def read_token(stream):
    """Accept bounded JSON or a CLI token pipe without printing or saving sessions."""
    raw = stream.read(131073)
    if len(raw) > 131072:
        raise ValueError('Access proof input exceeds its bound')
    token = raw.strip()
    if token.startswith('{'):
        document = json.loads(token)
        if not isinstance(document, dict) or set(document) != {'token'}:
            raise ValueError('Access proof requires one token field')
        token = document['token']
    if (not isinstance(token, str) or len(token) > 65536 or
            not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token)):
        raise ValueError('Access proof requires one bounded JWT')
    return token


def verify_token(token, expected_audience, organization, email, *, issued_after=None):
    """Verify a signed Access token without retaining its session or personal data."""
    if not isinstance(token, str) or len(token) > 65536 or token.count('.') != 2:
        raise ValueError('Access proof requires one bounded signed JWT')
    header, body, signature = token.split('.')
    metadata, claims = json.loads(decode(header)), json.loads(decode(body))
    if metadata.get('alg') != 'RS256' or not metadata.get('kid'):
        raise RuntimeError('Human Access JWT uses an unexpected signature algorithm')
    with open_request(urllib.request.Request('https://' + organization + '/cdn-cgi/access/certs')) as response:
        keys = json.load(response)['keys']
    key = next(k for k in keys if k.get('kid') == metadata['kid'] and k.get('kty') == 'RSA')
    public = rsa.RSAPublicNumbers(int.from_bytes(decode(key['e']), 'big'), int.from_bytes(decode(key['n']), 'big')).public_key()
    public.verify(decode(signature), (header + '.' + body).encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
    now = time.time()
    audience = claims.get('aud', [])
    if isinstance(audience, str): audience = [audience]
    if (claims.get('iss') != 'https://' + organization or expected_audience not in audience
            or claims.get('email', '').lower() != email.lower()
            or claims.get('exp', 0) <= now or claims.get('nbf', 0) > now):
        raise RuntimeError('Human Access JWT identity, audience or validity did not match')
    if issued_after is not None and (type(issued_after) is not int or type(claims.get('iat')) is not int
                                    or not issued_after < claims['iat'] <= now):
        raise RuntimeError('Access proof requires a newly issued token after provider configuration')
    return int(now)


def record(token):
    with transaction() as receipts:
        captured = receipts.load('external') or {}
    applications, rules, organization, binding = selected()
    if len(applications) != 1:
        raise RuntimeError('Human proof currently requires one selected human application')
    since = None
    if captured.get('identity_cutover'):
        since = captured['identity_provider']['credential_ready_at']
        from automation.identity.access_cutover import browser_gate
        browser_gate(organization.removesuffix('.cloudflareaccess.com'), since)
    from automation.identity.access_cutover import approved_email
    now = verify_token(token, applications[0]['aud'], organization,
                       approved_email(captured, os.environ['CLOUDFLARE_HUMAN_EMAIL']), issued_after=since)
    headers = {'Cookie': 'CF_Authorization=' + token}
    if not success(https(applications[0]['hostname'], headers=headers, path=PROOF_PATH)):
        raise RuntimeError('Verified human session did not reach the protected backend')
    for rule in rules:
        if rule['access'] == 'machine' and not denied(https(rule['hostname'], headers=headers, path=PROOF_PATH)):
            raise RuntimeError('Human session crossed the machine-only Access boundary')
    RECEIPT.parent.mkdir(mode=0o700, exist_ok=True)
    temporary = RECEIPT.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump({'binding': binding, 'verified_at': int(now), 'signed_identity_verified': True,
                   'human_backend_passed': True, 'machine_boundary_denied': True}, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(RECEIPT)
    with transaction() as receipts:
        current = receipts.load('external') or {}
        if current.get('identity_cutover'):
            if (current.get('identity_provider') != captured.get('identity_provider') or
                    current.get('identity_cutover') != captured.get('identity_cutover')):
                raise RuntimeError('Central Access inputs changed during browser proof; repeat verification')
            current['identity_cutover']['phase'] = 'accepted'
            current['identity_provider']['phase'] = 'accepted'
            receipts.save('external', current)
        receipts.save('human-proof', json.loads(RECEIPT.read_text()))
    return {'human_authenticated': True, 'human_cannot_use_machine_route': True, 'session_persisted': False}


def retained():
    _, _, _, binding = selected()
    with transaction() as receipts:
        evidence = receipts.load('human-proof') or {}
    if (evidence.get('binding') != binding or not evidence.get('signed_identity_verified')
            or not evidence.get('human_backend_passed') or not evidence.get('machine_boundary_denied')):
        raise RuntimeError('Human sign-in proof is missing or its selected policy changed')
    return {'human_policy_matches_signed_proof': True, 'human_verified_at': evidence['verified_at']}


if __name__ == '__main__':
    try:
        print(json.dumps(record(read_token(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Human Access proof failed; session and private diagnostics withheld.') from None
