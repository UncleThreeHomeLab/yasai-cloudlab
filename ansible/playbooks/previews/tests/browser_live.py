"""Explicit two-preview browser proof; private protocol and tokens remain in memory."""
import base64
import copy
import hmac
import ipaddress
import json
import re
import secrets
import socket
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

from playbooks.previews.files import contract

BUDGET = 240
FRAME = 32768


def refused():
    raise ValueError('Preview browser proof refused; diagnostics withheld')


def remaining(rows):
    now = int(time.time())
    if any(not row['createdAt'] <= now or row['expiresAt'] < now + BUDGET + 60 for row in rows):
        refused()


def bindings(state, settings, observed, runtime, *, now=None):
    """Validate explicit ownership before reading disposable viewer credentials."""
    now = int(time.time()) if now is None else now
    contract.catalog(settings)
    nonce = state['viewer']['nonce']
    if (state['viewer'] != {'nonce': nonce, 'realm': 'applications'} or not re.fullmatch('[a-f0-9]{32}', nonce) or
            not state.get('enrolled') or state.get('offboarded') or 'offboarding' in state or
            observed != state.get('identity') or observed.get('enabled') is not True or
            observed.get('realm') != 'applications' or observed.get('username') != 'proof-' + nonce or
            not isinstance(observed.get('email'), str) or not isinstance(observed.get('user_id'), str) or
            not re.fullmatch('[a-f0-9-]{36}', observed['user_id'])):
        refused()
    owned = state.get('browserApprovals')
    if not isinstance(owned, dict) or set(owned) != {'a', 'b'} or len(set(state.get('instances', []))) != 2:
        refused()
    rows = []
    for slot in ('a', 'b'):
        receipt = owned[slot]
        if not isinstance(receipt, dict) or set(receipt) != {'instance', 'approvalDigest'}:
            refused()
        found = [row for row in settings['approvals'] if row['instance'] == receipt['instance']]
        if len(found) != 1 or receipt['instance'] not in state['instances']:
            refused()
        row = found[0]
        contract.approval(row)
        pull = state.get('pulls', {}).get(slot, {})
        fingerprint = contract.digest(contract.canonical(row))
        if (receipt['approvalDigest'] != fingerprint or
                settings['ownership'].get(contract.names(row)['namespace']) != row['instance'] + ':' + fingerprint or
                any(row[key] != pull.get(other) for key, other in (
                    ('repository', 'repository'), ('repositoryId', 'repositoryId'), ('pullRequest', 'number'), ('sourceSha', 'head'))) or
                pull.get('closed') or pull.get('deleted') or pull.get('pending') is not None or
                row['definition']['profile'] != 'synthetic' or row['createdAt'] > now or row['expiresAt'] < now + BUDGET + 60 or
                row['platformRevision'] != state.get('executionPlatform') or
                row['sourceDigest'] != contract.digest(contract.canonical(row['definition']))):
            refused()
        rows.append(copy.deepcopy(row))
    if rows[0]['instance'] == rows[1]['instance']:
        refused()
    zone = runtime.get('zone')
    private = runtime.get('private', {})
    gateway = private.get('tailnet_gateway')
    try:
        address = ipaddress.ip_address(gateway)
        if address not in ipaddress.ip_network('100.64.0.0/10'):
            refused()
    except (ValueError, TypeError):
        refused()
    if (not isinstance(zone, str) or private.get('zone') != 'internal.' + zone or
            private.get('identity_host') != 'login.' + zone or
            settings['issuer'] != 'https://login.' + zone + '/realms/applications' or
            not settings['hostname'].endswith('.internal.' + zone)):
        refused()
    return rows, gateway


def callback(value, redirect, state, issuer):
    if (not isinstance(value, str) or not 1 <= len(value) <= 8192 or '#' in value or
            any(ord(char) <= 32 or ord(char) == 127 for char in value)):
        refused()
    url = urlsplit(value)
    target = urlsplit(redirect)
    if (url.scheme != 'https' or url.username or url.password or url.port or url.fragment or
            (url.scheme, url.netloc, url.path) != (target.scheme, target.netloc, target.path)):
        refused()
    pairs = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
    result = dict(pairs)
    if (len(pairs) != len(result) or not {'code', 'state'} <= set(result) or
            set(result) - {'code', 'state', 'iss', 'session_state'} or
            any(not 1 <= len(value) <= 4096 for value in result.values()) or
            not hmac.compare_digest(result['state'], state) or
            ('iss' in result and result['iss'] != issuer)):
        refused()
    return result['code']


def active(rows, cluster, now):
    for name, owner in ((contract.STATE, contract.OWNER), (contract.IDENTITY_STATE, 'cloudlab-preview-identity')):
        obj = cluster.get('states', {}).get(name) or {}
        if obj.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != owner:
            refused()
        records = json.loads(obj.get('data', {}).get('state.json', '{}')).get('entries', {})
        for row in rows:
            record = records.get(row['instance'], {})
            if (record.get('approval') != row or record.get('phase') != 'active' or
                    record.get('originVersion') != contract.ORIGIN_VERSION or
                    record.get('approvalDigest') != contract.digest(contract.canonical(row)) or
                    (name == contract.IDENTITY_STATE and (type(record.get('verifiedAt')) is not int or
                        not 0 <= now - record['verifiedAt'] <= 600))):
                refused()


def claims(response, jwks, issuer, client, nonce, subject, *, now=None):
    from playbooks.keycloak.files.tokens import identity_token, validated_claims
    now = int(time.time()) if now is None else now
    identity = identity_token(response['id_token'], jwks, issuer, client, nonce, now=now)
    access = validated_claims(response['access_token'], jwks, issuer, client, kind='Bearer', now=now)
    for value in (identity, access):
        if (value['sub'] != subject or value.get('azp') != client or
                value.get('aud') not in (client, [client]) or value['exp'] - value['iat'] > 300 or
                value['exp'] > now + 300 or value['iat'] < now - 300):
            refused()
    return response['access_token']


def protected(rows, settings, gateway, tokens, *, request=None):
    from playbooks.access.files.traffic import https
    request = request or https
    for index, row in enumerate(rows):
        host, path = contract.hostname(row, settings), contract.names(row)['path']
        for bearer, allowed in ((tokens[index], True), (None, False), (tokens[1-index], False)):
            response = request(host, address=gateway, path=path,
                               headers={'Authorization': 'Bearer ' + bearer} if bearer else {})
            if allowed:
                if response['status'] != 200 or json.loads(response['body']) != {
                        'message': row['definition']['message'], 'source': row['sourceSha']}:
                    refused()
            elif response['status'] not in (401, 403):
                refused()


class Channel:
    def __init__(self, connection):
        self.connection = connection
        self.buffer = b''
        self.deadline = time.monotonic() + BUDGET

    def send(self, value):
        raw = contract.canonical(value)
        if len(raw) > FRAME or time.monotonic() > self.deadline:
            refused()
        self.connection.sendall(raw + b'\n')

    def read(self, keys):
        while b'\n' not in self.buffer:
            self.connection.settimeout(max(0.01, min(35, self.deadline - time.monotonic())))
            chunk = self.connection.recv(min(4096, FRAME + 1 - len(self.buffer)))
            if not chunk or len(self.buffer) + len(chunk) > FRAME or time.monotonic() > self.deadline:
                refused()
            self.buffer += chunk
        raw, self.buffer = self.buffer.split(b'\n', 1)
        def unique(pairs):
            value = dict(pairs)
            if len(value) != len(pairs):
                refused()
            return value
        value = json.loads(raw, object_pairs_hook=unique)
        if self.buffer or not isinstance(value, dict) or set(value) != set(keys):
            refused()
        return value


def authorization(issuer, client, redirect, state, nonce, verifier):
    challenge = base64.urlsafe_b64encode(__import__('hashlib').sha256(verifier.encode()).digest()).decode().rstrip('=')
    return issuer + '/protocol/openid-connect/auth?' + urlencode({'client_id': client, 'response_type': 'code',
        'response_mode': 'query', 'scope': 'openid', 'redirect_uri': redirect, 'state': state, 'nonce': nonce,
        'code_challenge': challenge, 'code_challenge_method': 'S256'})


def run(values, state, observe, begin_enrollment):
    from playbooks.argocd.files.github_setup import repository
    from playbooks.previews.tests import catalog_fixture as fixture
    from playbooks.keycloak.tests import scoped_session as session
    from playbooks.access.files.verify import remote
    from playbooks.secrets.files.vault import fields
    from playbooks.keycloak.files.health import json_get
    request = state['viewer']
    observed = observe(values, dict(request, action='observe'))
    runtime = remote('runtime')
    with session.private_context(values) as api:
        snapshot = fixture.inspect(api, repository(values['PRIVATE_CONFIG_REPOSITORY']))
        rows, gateway = bindings(state, snapshot['catalog'], observed, runtime)
        active(rows, observe(values, dict(request, action='baseline', instances=state['instances'])), int(time.time()))
        settings = snapshot['catalog']
        for slot, row in zip(('a', 'b'), rows):
            pull = fixture.verified_pull(api, state['pulls'][slot], request['nonce'], slot)
            contract.validate_pull(row, pull)
            from playbooks.previews.files.github import GitHub
            from types import SimpleNamespace
            reader = SimpleNamespace(request=lambda path: api.request('GET', path))
            contract.verify_blob(row, GitHub.blob(reader, row))
        # Recheck both mutable source boundaries before any disposable credential read.
        if fixture.inspect(api, repository(values['PRIVATE_CONFIG_REPOSITORY'])) != snapshot:
            refused()
        for slot, row in zip(('a', 'b'), rows):
            contract.validate_pull(row, fixture.verified_pull(api, state['pulls'][slot], request['nonce'], slot))
    remaining(rows)
    from playbooks.previews.tests.probe_transport import handoff
    probe = handoff(state, rows, [])
    proof = fields('keycloak-proof-' + request['nonce'], ['username', 'password', 'email', 'ownership_id'])
    if (proof['ownership_id'] != request['nonce'] or proof['username'] != observed['username'] or
            proof['email'] != observed['email'] or not isinstance(proof['password'], str) or not 1 <= len(proof['password']) <= 4096):
        refused()
    issuer = settings['issuer']
    callbacks = [contract.client(row, settings)['callbacks'][0] for row in rows]
    clients = [contract.names(row)['client'] for row in rows]
    jwks = json_get(issuer + '/protocol/openid-connect/certs', address=gateway)
    with socket.create_connection(('browser', 5056), timeout=30) as connection:
        wire = Channel(connection)
        remaining(rows)
        begin_enrollment()
        wire.send({'action': 'enroll', 'issuer': issuer, 'gateway': gateway,
                   'hosts': [contract.hostname(row, settings) for row in rows],
                   'viewer': {key: proof[key] for key in ('username', 'password', 'email')}})
        if wire.read({'ready'}) != {'ready': True}:
            refused()
        tokens = []
        for client, redirect in zip(clients, callbacks):
            state_value, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
            wire.send({'action': 'authorize', 'authorization': authorization(issuer, client, redirect, state_value, nonce, verifier),
                       'redirect': redirect, 'state': state_value, 'issuer': issuer})
            code = callback(wire.read({'callback'})['callback'], redirect, state_value, issuer)
            response = json_get(issuer + '/protocol/openid-connect/token', address=gateway, form={
                'grant_type': 'authorization_code', 'client_id': client, 'redirect_uri': redirect,
                'code': code, 'code_verifier': verifier})
            tokens.append(claims(response, jwks, issuer, client, nonce, observed['user_id']))
        protected(rows, settings, gateway, tokens)
        dataplane = handoff(state, rows, tokens, probe, browser_deadline=wire.deadline)
        for bad in (callbacks[1], callbacks[0] + '/changed'):
            state_value, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
            wire.send({'action': 'reject', 'authorization': authorization(issuer, clients[0], bad, state_value, nonce, verifier),
                       'redirect': bad, 'state': state_value, 'issuer': issuer})
            if wire.read({'rejected'}) != {'rejected': True}:
                refused()
        wire.send({'action': 'origins', 'callbacks': callbacks})
        if wire.read({'origins', 'storage', 'dom', 'cors'}) != dict.fromkeys(('origins', 'storage', 'dom', 'cors'), True):
            refused()
    return {'authentication': True, 'audiences': True, 'callbacks': True, 'origins': True, 'dataplane': dataplane,
            'platform': state['executionPlatform'], 'approvals': copy.deepcopy(state['browserApprovals'])}
