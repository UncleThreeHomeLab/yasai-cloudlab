"""Disposable viewer enrollment through ESO and the sole serialized Argo writer."""
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import sys
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def scope(request):
    if (not isinstance(request, dict) or set(request) != {'nonce'} or
            not isinstance(request['nonce'], str) or not re.fullmatch('[a-f0-9]{32}', request['nonce'])):
        raise ValueError('Session fixture requires one exact disposable ownership nonce')
    return request['nonce']


def provision(request):
    from dotenv import dotenv_values
    from automation.credentials.provision import ensure_items
    from automation.credentials.vault import fields
    nonce = scope(request)
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    writer = environment.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = environment.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    primary = fields('keycloak-primary-admin', ['email'])['email']
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', primary):
        raise ValueError('Disposable email requires the existing owned recovery address')
    local, domain = primary.rsplit('@', 1)
    # No invitations are sent. The alias is retained only in the private vault/source.
    email = local.split('+', 1)[0] + '+identity-proof-' + nonce[:12] + '@' + domain
    title = 'keycloak-proof-' + nonce
    os.umask(0o077)
    with Path('/state/identity-vault-provision.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = ensure_items(writer, {title: {
            'username': ('STRING', lambda: 'proof-' + nonce),
            'password': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
            'ownership_id': ('STRING', lambda: nonce), 'email': ('STRING', lambda: email)}})
        values = fields(title, ['username', 'password', 'ownership_id', 'email'])
        if values['username'] != 'proof-' + nonce or values['ownership_id'] != nonce or values['email'] != email:
            raise RuntimeError('Disposable vault identity changed; no overwrite permitted')
    return {'disposable_credentials_ready': True, 'created': bool(result['created']), 'messages_sent': 0}


def enroll(request):
    from automation.identity.bootstrap import private_inputs, writer_idle
    from automation.identity.configuration import compile_state, private_request
    from automation.identity.emergency import phase_sync_patches, vault_secret
    from automation.identity.maintenance import APP, BASE, NAMESPACE, OWNER
    from automation.data.control import atomic
    from automation.mesh.kube import application_ready, condition, contains, get, kube, wait
    nonce = scope(request)
    operation = {'action': 'initialize-proof', 'realm': 'platform', 'nonce': nonce}
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        owner = json.loads((BASE / 'ownership.json').read_text())
        app = get('application.argoproj.io', APP, 'argocd') or {}
        values = app.get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {})
        if (owner.get('phase') != 'scoped' or app.get('metadata', {}).get('uid') != owner.get('uid') or
                app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER or
                values.get('bootstrapAdminEnabled') is not False or values.get('bootstrapMode') or values.get('maintenance') or
                values.get('operation') not in (None, {}, operation) or
                (values.get('operation') != operation and not application_ready(APP, owner['revision'])) or
                not condition(get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE), 'Ready')):
            raise RuntimeError('Disposable enrollment requires the current retired scoped identity owner')
        private = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd')
        source, revoked, _ = private_inputs({'values': values,
            'private_repository': private['spec']['source']['repoURL']})
        credentials = json.loads(vault_secret('keycloak-client-secrets')['client_secrets'])
        state = compile_state('platform', values['loginHost'], source, credentials, revoked)
        members = [row for row in state.get('users', []) if row.get('username') == 'proof-' + nonce]
        if len(members) != 1 or members[0].get('enabled') is False:
            raise RuntimeError('Publish the exact active private disposable membership first')
        checkpoint = BASE / ('proof-' + nonce + '.json')
        record = json.loads(checkpoint.read_text()) if checkpoint.exists() else {
            'nonce': nonce, 'application_uid': owner['uid'], 'phase': 'prepared'}
        if (record.get('nonce') != nonce or record.get('application_uid') != owner['uid'] or
                record.get('phase') not in ('prepared', 'created', 'enrolled')):
            raise RuntimeError('Disposable enrollment checkpoint changed')
        atomic(checkpoint, record)
        origin = 'https://' + values['adminHost']
        endpoint = origin + '/admin/realms/platform/users?' + urlencode({'username': 'proof-' + nonce, 'exact': 'true', 'max': 2})
        def current():
            bearer = private_request(origin + '/realms/platform/protocol/openid-connect/token', form={
                'grant_type': 'client_credentials', 'client_id': 'realm-writer',
                'client_secret': vault_secret('keycloak-realm-writers')['platform_client_secret']})['access_token']
            return private_request(endpoint, token=bearer)
        before = current()
        if before and (len(before) != 1 or before[0].get('attributes', {}).get('cloudlab-primary-owner') != [nonce]):
            raise RuntimeError('Disposable enrollment refuses an existing unowned account')
        if record.get('user_id') and (not before or before[0]['id'] != record['user_id']):
            raise RuntimeError('Disposable user identity changed')
        def set_operation(value, revision):
            actual = get('application.argoproj.io', APP, 'argocd')
            patches = [{'op': 'test', 'path': '/metadata/uid', 'value': owner['uid']},
                       {'op': 'test', 'path': '/metadata/resourceVersion', 'value': actual['metadata']['resourceVersion']},
                       {'op': 'add', 'path': '/spec/source/helm/valuesObject/operation', 'value': value}]
            sync = phase_sync_patches(actual, owner['revision'])
            patches.extend([{'op': 'add', 'path': '/spec/source/targetRevision', 'value': revision}, sync[1]])
            kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=json',
                 '--field-manager=' + OWNER, '-p', json.dumps(patches))
        def ready():
            actual = get('application.argoproj.io', APP, 'argocd') or {}
            compared = actual.get('status', {}).get('sync', {}).get('comparedTo', {}).get('source', {})
            return contains(compared, actual.get('spec', {}).get('source', {})) and application_ready(APP, owner['revision'])
        if not before:
            wait(writer_idle, 'disposable enrollment writer idle', timeout=300)
            set_operation(operation, owner['revision'])
            wait(ready, 'disposable viewer creation-only job', timeout=900)
            created = current()
            if (len(created) != 1 or created[0].get('attributes', {}).get('cloudlab-primary-owner') != [nonce] or
                    created[0].get('enabled') is not True or created[0].get('email') != members[0]['email']):
                raise RuntimeError('Disposable enrollment did not create its exact owned identity')
            record.update(user_id=created[0]['id'], phase='created')
            atomic(checkpoint, record)
        if get('application.argoproj.io', APP, 'argocd')['spec']['source']['helm']['valuesObject'].get('operation') == operation:
            wait(writer_idle, 'disposable enrollment writer release', timeout=300)
            set_operation(None, 'main')
            wait(ready, 'normal reconciliation after disposable enrollment', timeout=900)
        record.update(phase='enrolled')
        atomic(checkpoint, record)
        return {'disposable_viewer_created': not before, 'existing_credentials_preserved': bool(before),
                'writer': 'serialized Argo config-cli', 'messages_sent': 0}


def local(request):
    from dotenv import dotenv_values
    from automation.connectivity.preflight import ssh
    scope(request)
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        os.environ[key] = environment[key]
    os.environ['VM_PORT'] = environment.get('VM_PORT') or '22'
    return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 /opt/cloudlab/automation/identity/session_fixture.py enroll',
        input=json.dumps(request), timeout=2400))


if __name__ == '__main__':
    try:
        request = json.load(sys.stdin)
        mode = sys.argv[1:]
        if mode not in (['enroll'], ['provision'], ['local']):
            raise ValueError('Unknown disposable enrollment operation')
        result = enroll(request) if mode == ['enroll'] else provision(request) if mode == ['provision'] else local(request)
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Disposable enrollment incomplete; retain its private ownership checkpoint. Diagnostics withheld.') from None
