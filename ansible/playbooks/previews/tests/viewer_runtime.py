"""Explicit Ansible fixture operations; installed identity owners perform mutations."""
import hashlib
import json
import re
import sys

sys.path.insert(0, '/opt/cloudlab')


def validate(request):
    if isinstance(request, dict) and request.get('action') == 'lifecycle':
        from playbooks.previews.tests.evidence_runtime import validate as evidence_validate
        evidence_validate(request)
        return {key: request[key] for key in ('nonce', 'realm')}
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


def retained_entries(records, instances):
    from playbooks.previews.files.contract import STATE, IDENTITY_STATE
    runtime, identity = records[STATE] or {}, records[IDENTITY_STATE]
    retained = set(runtime) - set(instances)
    if set(identity or {}) - set(instances) - retained or (retained and identity is None):
        raise ValueError('Preview baseline terminal history is incomplete')
    for instance in retained:
        row, client = runtime[instance], identity.get(instance)
        if (not re.fullmatch('[a-f0-9]{32}', instance) or not isinstance(row, dict) or
                set(row) != {'phase', 'approvalDigest', 'expiresAt'} or row['phase'] != 'retired' or
                not isinstance(row['approvalDigest'], str) or not re.fullmatch('[a-f0-9]{64}', row['approvalDigest']) or
                type(row['expiresAt']) is not int or row['expiresAt'] <= 0 or
                (instance in identity and (not isinstance(client, dict) or set(client) != {'phase', 'approvalDigest'} or
                    client['phase'] != 'retired' or client['approvalDigest'] != row['approvalDigest']))):
            raise ValueError('Preview baseline contains unrelated nonterminal or malformed history')
    return retained


def baseline_items(raw, kind, *, namespace=None):
    limit = 8388608 if kind == 'applications.argoproj.io' else 1048576
    if not isinstance(raw, str) or not raw or len(raw.encode()) > limit:
        raise RuntimeError('Preview baseline inventory unavailable or exceeds its bound')
    try:
        value = json.loads(raw)
    except ValueError:
        raise RuntimeError('Preview baseline inventory malformed') from None
    kinds = {'namespaces': 'NamespaceList', 'applications.argoproj.io': 'ApplicationList',
             'applicationsets.argoproj.io': 'ApplicationSetList', 'appprojects.argoproj.io': 'AppProjectList'}
    if (not isinstance(value, dict) or value.get('kind') not in ('List', kinds[kind]) or
            value.get('apiVersion') != ('v1' if kind == 'namespaces' or value.get('kind') == 'List' else 'argoproj.io/v1alpha1') or
            not isinstance(value.get('metadata'), dict) or
            not isinstance(value.get('items'), list) or len(value['items']) > 10000):
        raise RuntimeError('Preview baseline inventory malformed')
    metadata = value.get('metadata', {})
    if (not isinstance(metadata.get('continue', ''), str) or metadata.get('continue') or
            type(metadata.get('remainingItemCount', 0)) is not int or metadata.get('remainingItemCount', 0) != 0):
        raise RuntimeError('Preview baseline inventory incomplete')
    coordinates = set()
    for row in value['items']:
        meta = row.get('metadata') if isinstance(row, dict) else None
        if (not isinstance(meta, dict) or any(not isinstance(meta.get(field), str) or not meta[field] for field in ('name', 'uid')) or
                (kind != 'namespaces' and (not isinstance(meta.get('namespace'), str) or not meta['namespace'])) or
                (kind == 'namespaces' and meta.get('namespace', '') != '') or
                (namespace is not None and meta.get('namespace') != namespace)):
            raise RuntimeError('Preview baseline inventory coordinates unavailable')
        coordinate = (meta.get('namespace', ''), meta['name'])
        if coordinate in coordinates:
            raise RuntimeError('Preview baseline inventory identity is ambiguous')
        coordinates.add(coordinate)
    return value['items']


def baseline(request):
    from playbooks.istio.files.kube import get, kube
    from playbooks.previews.files.contract import OWNER, STATE, IDENTITY_STATE
    states, records = {}, {}
    for namespace, name, owner in [('argocd', STATE, OWNER), ('cloudlab-identity', IDENTITY_STATE, 'cloudlab-preview-identity')]:
        obj = get('configmap', name, namespace)
        if obj is not None:
            if obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != owner:
                raise ValueError('Preview baseline state has foreign ownership')
            state = json.loads(obj['data']['state.json'])
            allowed = {'format', 'entries', 'settings', 'checks', 'providerCheckAt'} if name == STATE else {'format', 'entries'}
            if (not isinstance(state, dict) or set(state) - allowed or not {'format', 'entries'} <= set(state) or
                    type(state['format']) is not int or state['format'] != 1 or
                    not isinstance(state['entries'], dict) or len(state['entries']) > 256):
                raise ValueError('Preview baseline state is malformed')
            records[name] = state['entries']
        else:
            records[name] = None
        states[name] = obj
    retained = retained_entries(records, request['instances'])
    retired_names = {'preview-' + instance for instance in retained}
    inventory = {}
    for kind in ('namespaces', 'persistentvolumeclaims', 'applications.argoproj.io'):
        raw = kube('get', kind, '-A', '-o', 'json')
        if retained and kind != 'persistentvolumeclaims':
            items = baseline_items(raw, kind)
        else:
            objects = json.loads(raw)
            if objects.get('metadata', {}).get('continue'):
                raise RuntimeError('Preview baseline inventory incomplete')
            items = objects['items']
        if kind == 'applications.argoproj.io' and any(row['metadata'].get('namespace') == 'argocd' and
                row['metadata']['name'] in retired_names for row in items):
            raise ValueError('Retired preview control still exists')
        if kind == 'namespaces' and any(row['metadata']['name'].startswith('cloudlab-preview-') and
                row['metadata']['name'].removeprefix('cloudlab-preview-') not in request['instances'] for row in items):
            raise ValueError('Unrelated preview namespace blocks activation')
        ids = sorted((row['metadata'].get('namespace', ''), row['metadata']['name'], row['metadata']['uid']) for row in items
                     if row['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER)
        inventory[kind] = {'count': len(ids), 'uidHash': hashlib.sha256(json.dumps(ids).encode()).hexdigest(),
                           'identities': {namespace + '/' + name: uid for namespace, name, uid in ids}}
    if retained:
        for kind in ('applicationsets.argoproj.io', 'appprojects.argoproj.io'):
            items = baseline_items(kube('get', kind, '-n', 'argocd', '-o', 'json'), kind, namespace='argocd')
            if any(row['metadata']['name'] in retired_names for row in items):
                raise ValueError('Retired preview control still exists')
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
    clients = client_baseline(request)
    if retained:
        if not isinstance(clients, dict) or set(clients) != {'platform', 'applications'}:
            raise RuntimeError('Preview baseline client inventory unavailable')
        for record in clients.values():
            if (not isinstance(record, dict) or set(record) != {'count', 'identityHash', 'identities'} or
                    not isinstance(record['identities'], dict) or len(record['identities']) > 10000 or
                    any(not isinstance(key, str) or not key or not isinstance(value, str) or not value
                        for key, value in record['identities'].items()) or
                    type(record['count']) is not int or record['count'] != len(record['identities']) or
                    record['identityHash'] != hashlib.sha256(json.dumps(sorted(record['identities'].items())).encode()).hexdigest()):
                raise RuntimeError('Preview baseline client inventory incomplete')
        if retired_names & set(clients['applications']['identities']):
            raise ValueError('Retired preview client still exists')
    return {'states': states, 'persistent': inventory, 'clients': clients}


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
    if action == 'lifecycle':
        from playbooks.previews.tests.evidence_runtime import run as evidence
        return evidence(request)
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
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError('Viewer request exceeds its bound')
        print(json.dumps(run(json.loads(raw))))
    except Exception:
        raise SystemExit('Preview viewer operation failed; private diagnostics withheld') from None
