"""Resumable vault rotation; ESO and the serialized CLI remain configuration writers."""
import copy
import fcntl
import json
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.identity.configuration import REALMS, client, name, private_request

TITLE = 'keycloak-client-secrets'


def request_scope(request):
    if (set(request) not in ({'action', 'realm', 'client_id'}, {'action', 'realm', 'client_id', 'client'}) or
            request['action'] not in ('provision', 'rotate') or request['realm'] not in REALMS):
        raise ValueError('Credential operation requires provision/rotate, realm and client_id')
    name(request['client_id'])
    if 'client' in request:
        proposed = request['client']
        if (request['action'] != 'provision' or not isinstance(proposed, dict) or
                proposed.get('id') != request['client_id'] or proposed.get('public') is not False or
                proposed.get('enabled', True) is not True):
            raise ValueError('Initial credential provisioning requires its active confidential client contract')
        client(proposed, {request['client_id']: 'validation-only-' + 'x' * 48})
    return request


def replacement(document, request, value):
    request_scope(request)
    if (document.get('title') != TITLE or document.get('category') != 'SECURE_NOTE' or
            'cloudlab-managed' not in document.get('tags', [])):
        raise ValueError('Credential operation requires its provisioner-owned vault item')
    matches = [field for field in document['fields'] if field.get('label') == 'client_secrets']
    if len(matches) != 1 or matches[0].get('type') != 'CONCEALED':
        raise ValueError('Client credential item has incompatible fields')
    current = json.loads(matches[0]['value'])
    if set(current) != set(REALMS) or any(not isinstance(current[realm], dict) for realm in REALMS):
        raise ValueError('Client credential inventory has an invalid realm scope')
    realm, identifier = request['realm'], request['client_id']
    old = current[realm].get(identifier)
    if old is not None and (not isinstance(old, str) or len(old) < 32):
        raise ValueError('Existing client credential is incompatible')
    if request['action'] == 'rotate' and old is None:
        raise ValueError('Only an existing credential can be rotated')
    result = copy.deepcopy(document)
    if old is not None and request['action'] == 'provision':
        return result, old, old
    if not isinstance(value, str) or len(value) < 32:
        raise ValueError('Client credential must contain at least 32 characters')
    current[realm][identifier] = value
    next(field for field in result['fields'] if field.get('label') == 'client_secrets')['value'] = json.dumps(current, sort_keys=True)
    return result, old, value


def inventory(request):
    from automation.identity.maintenance import APP, NAMESPACE, OWNER
    from automation.mesh.kube import get
    from automation.identity.bootstrap import private_inputs
    request_scope(request)
    app = get('application.argoproj.io', APP, 'argocd') or {}
    if app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER:
        raise RuntimeError('Credential operation requires the designated identity owner')
    values = app['spec']['source']['helm']['valuesObject']
    if values.get('maintenance'):
        raise RuntimeError('Resume identity maintenance before credential operations')
    private_app = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd') or {}
    source, revoked, _ = private_inputs({'values': values,
        'private_repository': private_app.get('spec', {}).get('source', {}).get('repoURL')})
    realm, identifier = request['realm'], request['client_id']
    matches = [row for row in source['realms'].get(realm, {}).get('clients', []) if row.get('id') == identifier]
    if 'client' in request:
        if matches and matches != [request['client']]:
            raise ValueError('Initial credential contract differs from existing private inventory')
        if not matches:
            matches = [request['client']]
    if (len(matches) != 1 or matches[0].get('public') is not False or
            matches[0].get('enabled', True) is not True or
            identifier in revoked['realms'].get(realm, {}).get('clients', []) or
            identifier in revoked['realms'].get(realm, {}).get('removed_clients', [])):
        raise ValueError('Credential operation requires one active private confidential client')
    client(matches[0], {identifier: 'validation-only-' + 'x' * 48})
    return {'admin_host': values['adminHost'], 'callback': matches[0]['callbacks'][0]}


def probe(settings, request, secret):
    # Invalid code proves client authentication without creating a session/token.
    result = private_request('https://' + settings['admin_host'] + '/realms/' + request['realm'] +
        '/protocol/openid-connect/token', form={'grant_type': 'authorization_code',
        'client_id': request['client_id'], 'client_secret': secret, 'code': 'cloudlab-invalid-rotation-proof',
        'redirect_uri': settings['callback'], 'code_verifier': 'x' * 64}, accepted_statuses=(400, 401))
    return result.get('error')


def verify(payload):
    from automation.mesh.kube import get, kube, condition
    from automation.identity.maintenance import NAMESPACE
    request, old, new = payload['request'], payload['old'], payload['new']
    settings = inventory(request)
    if len(new) < 32 or (old is not None and len(old) < 32):
        raise ValueError('Invalid rotation checkpoint')
    kube('annotate', 'externalsecret', 'keycloak-client-secrets', '-n', NAMESPACE,
         'force-sync=' + str(time.time_ns()), '--overwrite')
    started, deadline = time.time(), time.monotonic() + 660
    while time.monotonic() < deadline:
        external = get('externalsecret.external-secrets.io', 'keycloak-client-secrets', NAMESPACE)
        if condition(external, 'Ready') and probe(settings, request, new) == 'invalid_grant':
            if old is None or old == new or probe(settings, request, old) == 'invalid_client':
                return {'credential_accepted': True, 'old_credential_denied': old is not None and old != new,
                        'unchanged_existing_credential': old == new, 'elapsed_seconds': round(time.time() - started, 1),
                        'sessions_created': 0}
        time.sleep(5)
    raise RuntimeError('Credential convergence deadline exceeded; retain checkpoint and resume')


def local(request):
    from dotenv import dotenv_values
    from automation.credentials.provision import command
    from automation.connectivity.preflight import ssh
    from automation.data.control import atomic
    request_scope(request)
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    token = environment.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    if not token:
        raise RuntimeError('Credential operation requires the separate local vault writer')
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        os.environ[key] = environment[key]
    os.environ['VM_PORT'] = environment.get('VM_PORT') or '22'
    os.umask(0o077)
    pending = Path('/state/identity-client-credential-pending.json')
    with Path('/state/identity-vault-provision.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Public clients, retired clients and missing private input fail before vault mutation.
        ssh('VM', os.environ['VM_HOST'], 'python3 /opt/cloudlab/automation/identity/rotation.py inventory',
            input=json.dumps(request), timeout=60)
        rows = command(['item', 'list', '--vault', 'CloudLab'], token)
        matches = [row for row in rows if row['title'] == TITLE]
        if len(matches) != 1:
            raise RuntimeError('Client credential item is missing or ambiguous')
        current = command(['item', 'get', matches[0]['id'], '--vault', 'CloudLab'], token)
        if pending.exists():
            state = json.loads(pending.read_text())
            if state['request'] != request or state['id'] != current['id']:
                raise RuntimeError('Another credential operation requires completion first')
        else:
            updated, old, new = replacement(current, request, secrets.token_urlsafe(48))
            state = {'request': request, 'id': current['id'], 'before': current,
                     'after': updated, 'old': old, 'new': new}
            atomic(pending, state)
        # Compare the complete aggregate to avoid overwriting unrelated client rotations.
        field_value = lambda document: next(field['value'] for field in document['fields'] if field.get('label') == 'client_secrets')
        replacement(current, dict(request, action='provision'), state['new'])
        actual, before, after = [field_value(document) for document in (current, state['before'], state['after'])]
        if actual != after:
            if actual != before:
                raise RuntimeError('Vault credentials changed externally; rotation refused')
            next(field for field in current['fields'] if field.get('label') == 'client_secrets')['value'] = after
            command(['item', 'edit', current['id'], '--vault', 'CloudLab'], token, current)
        if request['action'] == 'provision':
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = environment.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
            from automation.credentials.vault import fields
            delivered = json.loads(fields(TITLE, ['client_secrets'])['client_secrets'])
            if delivered[request['realm']].get(request['client_id']) != state['new']:
                raise RuntimeError('Read-only vault reader cannot retrieve the provisioned credential')
            pending.unlink()
            return {'vault_credential_ready': True, 'existing_credential_preserved': state['old'] == state['new'],
                    'realm_credential_verified': False, 'sessions_created': 0}
        result = json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 /opt/cloudlab/automation/identity/rotation.py verify',
            input=json.dumps({key: state[key] for key in ('request', 'old', 'new')}), timeout=750))
        if not result.get('credential_accepted'):
            raise RuntimeError('Credential proof failed; retain checkpoint')
        pending.unlink()
        return result


if __name__ == '__main__':
    try:
        payload = json.load(sys.stdin)
        mode = sys.argv[1:] or ['local']
        print(json.dumps({'inventoried': bool(inventory(payload))} if mode == ['inventory'] else
                         verify(payload) if mode == ['verify'] else local(payload)))
    except Exception:
        raise SystemExit('Identity credential operation incomplete; preserve checkpoint. Private diagnostics withheld.') from None
