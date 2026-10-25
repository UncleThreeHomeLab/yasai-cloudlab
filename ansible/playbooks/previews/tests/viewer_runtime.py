"""Explicit Ansible fixture operations; installed identity owners perform mutations."""
import hashlib
import json
import re
import sys

sys.path.insert(0, '/opt/cloudlab')


def validate(request):
    from playbooks.keycloak.files.session_fixture import scope
    if not isinstance(request, dict) or set(request) - {'action', 'nonce', 'realm', 'revision', 'identity', 'instances'}:
        raise ValueError('Invalid viewer operation')
    identity = {key: request[key] for key in ('nonce', 'realm')}
    scope(identity)
    if identity['realm'] != 'applications' or request.get('action') not in {'baseline', 'stage', 'enroll', 'observe', 'wait', 'offboard'}:
        raise ValueError('Viewer operation requires its applications fixture')
    extra = {'wait': {'revision'}, 'offboard': {'identity'}, 'baseline': {'instances'}}.get(request['action'], set())
    if set(request) != {'action', 'nonce', 'realm'} | extra:
        raise ValueError('Viewer operation fields differ')
    if request['action'] == 'wait' and not re.fullmatch('[a-f0-9]{40}', request.get('revision') or ''):
        raise ValueError('Viewer convergence requires an immutable source')
    if request['action'] == 'offboard':
        from playbooks.keycloak.files.lifecycle import offboard_scope
        offboard_scope(request['identity'])
        if request['identity']['realm'] != 'applications' or request['identity']['username'] != 'proof-' + identity['nonce']:
            raise ValueError('Viewer offboarding differs from its nonce')
    if request['action'] == 'baseline' and (not isinstance(request['instances'], list) or
            len(request['instances']) > 4 or any(not isinstance(item, str) or not re.fullmatch('[a-f0-9]{32}', item) for item in request['instances'])):
        raise ValueError('Preview baseline requires bounded journal-owned instances')
    return identity


def observe(request):
    from playbooks.keycloak.files.maintenance import BASE, APP, OWNER
    from playbooks.keycloak.files.configuration import private_request
    from playbooks.keycloak.files.emergency import vault_secret
    from playbooks.istio.files.kube import get, application_ready
    from urllib.parse import urlencode
    owner = json.loads((BASE / 'ownership.json').read_text())
    app = get('application.argoproj.io', APP, 'argocd') or {}
    values = app.get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {})
    checkpoint = json.loads((BASE / ('proof-' + request['nonce'] + '.json')).read_text())
    if (owner.get('phase') != 'scoped' or app.get('metadata', {}).get('uid') != owner.get('uid') or
            app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER or
            values.get('operation') or values.get('maintenance') or not application_ready(APP, owner['revision']) or
            checkpoint.get('nonce') != request['nonce'] or checkpoint.get('realm') != 'applications' or
            checkpoint.get('application_uid') != owner['uid'] or checkpoint.get('phase') != 'enrolled'):
        raise RuntimeError('Viewer observation requires its converged enrolled owner')
    origin = 'https://' + values['adminHost']
    token = private_request(origin + '/realms/applications/protocol/openid-connect/token', form={
        'grant_type': 'client_credentials', 'client_id': 'realm-writer',
        'client_secret': vault_secret('keycloak-realm-writers')['applications_client_secret']})['access_token']
    rows = private_request(origin + '/admin/realms/applications/users?' + urlencode({
        'username': 'proof-' + request['nonce'], 'exact': 'true', 'max': 2}), token=token)
    if (len(rows) != 1 or rows[0].get('id') != checkpoint.get('user_id') or
            rows[0].get('username') != 'proof-' + request['nonce'] or
            rows[0].get('attributes', {}).get('cloudlab-primary-owner') != [request['nonce']]):
        raise RuntimeError('Viewer observed identity changed')
    return {'realm': 'applications', 'username': rows[0]['username'], 'user_id': rows[0]['id'],
            'email': rows[0]['email'], 'enabled': rows[0]['enabled']}


def baseline(request):
    from playbooks.istio.files.kube import get, kube
    from playbooks.previews.files.contract import OWNER, STATE, IDENTITY_STATE
    states = {}
    for namespace, name, owner in [('argocd', STATE, OWNER), ('cloudlab-identity', IDENTITY_STATE, 'cloudlab-preview-identity')]:
        obj = get('configmap', name, namespace)
        if obj is not None:
            if obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != owner:
                raise ValueError('Preview baseline state has foreign ownership')
            state = json.loads(obj['data']['state.json'])
            if state.get('format') != 1 or set(state.get('entries', {})) - set(request['instances']):
                raise ValueError('Preview baseline contains unrelated instances')
        states[name] = obj
    inventory = {}
    for kind in ('namespaces', 'persistentvolumeclaims', 'applications.argoproj.io'):
        objects = json.loads(kube('get', kind, '-A', '-o', 'json'))
        if objects.get('metadata', {}).get('continue'):
            raise RuntimeError('Preview baseline inventory incomplete')
        items = objects['items']
        if kind == 'namespaces' and any(row['metadata']['name'].startswith('cloudlab-preview-') and
                row['metadata']['name'].removeprefix('cloudlab-preview-') not in request['instances'] for row in items):
            raise ValueError('Unrelated preview namespace blocks activation')
        ids = sorted((row['metadata'].get('namespace', ''), row['metadata']['name'], row['metadata']['uid']) for row in items
                     if row['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER)
        inventory[kind] = {'count': len(ids), 'uidHash': hashlib.sha256(json.dumps(ids).encode()).hexdigest(),
                           'identities': {namespace + '/' + name: uid for namespace, name, uid in ids}}
    # Trusted kubectl receives API objects; only these metadata columns enter fixture Python.
    expression = r'{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.uid}{"\t"}{.metadata.labels.cloudlab\.io/owner}{"\n"}{end}'
    raw = kube('get', 'secrets', '-A', '-o=jsonpath=' + expression)
    if len(raw) > 1048576:
        raise RuntimeError('Secret metadata inventory exceeds its bound')
    rows = [line.split('\t') for line in raw.splitlines()]
    if len(rows) > 10000 or any(len(row) != 4 or not all(row[:3]) for row in rows):
        raise RuntimeError('Secret metadata inventory is incomplete')
    owned_namespaces = {'cloudlab-preview-' + instance for instance in request['instances']}
    ids = sorted(tuple(row[:3]) for row in rows if not (row[0] in owned_namespaces and row[3] == OWNER))
    if len(ids) != len(set(ids)):
        raise RuntimeError('Secret metadata identity is ambiguous')
    inventory['secrets'] = {'count': len(ids), 'uidHash': hashlib.sha256(json.dumps(ids).encode()).hexdigest(),
                            'identities': {namespace + '/' + name: uid for namespace, name, uid in ids}}
    return {'states': states, 'persistent': inventory, 'clients': client_baseline(request)}


def client_baseline(request):
    from playbooks.keycloak.files.maintenance import APP, OWNER, BASE
    from playbooks.keycloak.files.configuration import private_request
    from playbooks.keycloak.files.emergency import vault_secret
    from playbooks.istio.files.kube import get, application_ready
    owner = json.loads((BASE / 'ownership.json').read_text())
    app = get('application.argoproj.io', APP, 'argocd') or {}
    values = app.get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {})
    if (owner.get('phase') != 'scoped' or app.get('metadata', {}).get('uid') != owner.get('uid') or
            app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER or
            values.get('operation') or values.get('maintenance') or not application_ready(APP, owner['revision'])):
        raise RuntimeError('Client baseline requires the existing scoped identity owner')
    origin = 'https://' + values['adminHost']
    writers = vault_secret('keycloak-realm-writers')
    result = {}
    for realm in ('platform', 'applications'):
        token = private_request(origin + '/realms/' + realm + '/protocol/openid-connect/token', form={
            'grant_type': 'client_credentials', 'client_id': 'realm-writer', 'client_secret': writers[realm + '_client_secret']})['access_token']
        identities = []
        for first in range(0, 10000, 100):
            page = private_request(origin + '/admin/realms/' + realm + '/clients?first=' + str(first) + '&max=100', token=token)
            if (not isinstance(page, list) or len(page) > 100 or
                    any(not isinstance(row.get('id'), str) or not row['id'] or not isinstance(row.get('clientId'), str) or not row['clientId'] for row in page)):
                raise RuntimeError('Client baseline identity inventory differs')
            identities.extend((row['clientId'], row['id']) for row in page
                if not (realm == 'applications' and row['clientId'] in {'preview-' + instance for instance in request['instances']}))
            if len(page) < 100:
                break
        else:
            raise RuntimeError('Client baseline exceeds its bound')
        if len({row[0] for row in identities}) != len(identities):
            raise RuntimeError('Client baseline identity is ambiguous')
        result[realm] = {'count': len(identities), 'identityHash': hashlib.sha256(json.dumps(sorted(identities)).encode()).hexdigest(),
                         'identities': dict(identities)}
    return result


def run(request):
    identity = validate(request)
    action = request['action']
    if action in ('stage', 'enroll'):
        from playbooks.keycloak.files.session_fixture import enroll
        return enroll(identity, stage=action == 'stage')
    if action == 'baseline':
        return baseline(request)
    if action == 'observe':
        return observe(identity)
    if action == 'wait':
        from playbooks.istio.files.kube import application_ready, wait
        wait(lambda: application_ready('cloudlab-identity-private', request['revision']), 'private viewer source', timeout=600)
        return {'private_source_ready': True}
    from playbooks.keycloak.files.lifecycle import offboard
    observed = observe(identity)
    if {key: observed[key] for key in request['identity']} != request['identity'] or observed['enabled'] is not False:
        raise ValueError('Offboarding requires the exact observed disabled viewer')
    return offboard(request['identity'])


if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise ValueError('Viewer request exceeds its bound')
        print(json.dumps(run(json.loads(raw))))
    except Exception:
        raise SystemExit('Preview viewer operation failed; private diagnostics withheld') from None
