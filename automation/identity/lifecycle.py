"""Execute reviewed client removal through the existing serialized Argo writer."""
import base64
import fcntl
import json
import os
import re
from pathlib import Path
import sys
import time
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.identity.bootstrap import BASE
from automation.identity.configuration import REALMS, compile_state, name, private_request
from automation.identity.lease import available
from automation.identity.maintenance import APP, NAMESPACE, OWNER
from automation.mesh.kube import application_ready, condition, contains, get, kube, wait
from automation.data.control import atomic


def remove(request):
    if set(request) != {'realm', 'client_id'} or request['realm'] not in REALMS:
        raise ValueError('Removal requires exactly a managed realm and client_id')
    realm, identifier = request['realm'], name(request['client_id'])
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        app = get('application.argoproj.io', APP, 'argocd') or {}
        state = json.loads((BASE / 'ownership.json').read_text())
        if (app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER or
                app['metadata']['uid'] != state['uid'] or state['phase'] != 'scoped'):
            raise RuntimeError('Removal requires the unchanged scoped identity owner')
        values = app['spec']['source']['helm']['valuesObject']
        if values.get('maintenance') or not values.get('privateStateEnabled'):
            raise RuntimeError('Removal requires active scoped private reconciliation')
        operation = {'action': 'remove-client', 'realm': realm, 'client': identifier}
        if values.get('operation') not in (None, {}, operation):
            raise RuntimeError('Another identity lifecycle operation is pending')
        private_app = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd') or {}
        revision = private_app.get('status', {}).get('sync', {}).get('revision')
        if not revision or not application_ready('cloudlab-identity-private', revision):
            raise RuntimeError('Private source must converge before removal')
        private = get('configmap', 'identity-private-state', NAMESPACE)
        if not private['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-identity-private:'):
            raise RuntimeError('Removal inputs have a conflicting source owner')
        source, registry = [json.loads(private['data'][key]) for key in ('desired_state', 'revocations')]
        denied = registry['realms'].get(realm, {})
        if identifier not in denied.get('clients', []) or identifier not in denied.get('removed_clients', []):
            raise ValueError('Publish the reviewed persistent removal tombstone first')
        credentials = json.loads(base64.b64decode(get('secret', 'keycloak-client-secrets', NAMESPACE)['data']['client_secrets'], validate=True))
        for target in REALMS:
            compile_state(target, values['loginHost'], source, credentials, registry)
        writers = get('secret', 'keycloak-realm-writers', NAMESPACE)
        secret = base64.b64decode(writers['data'][realm + '_client_secret'], validate=True).decode()
        origin = 'https://' + values['adminHost']
        token = private_request(origin + '/realms/' + realm + '/protocol/openid-connect/token', form={
            'grant_type': 'client_credentials', 'client_id': 'realm-writer', 'client_secret': secret})['access_token']
        rows = private_request(origin + '/admin/realms/' + realm + '/clients?clientId=' + identifier, token=token)
        if not isinstance(rows, list) or len(rows) > 1 or any(row.get('clientId') != identifier or row.get('enabled') is not False for row in rows):
            raise RuntimeError('Removal requires an unambiguous already disabled client')
        receipt = BASE / ('remove-' + realm + '-' + identifier + '.json')
        pending = json.loads(receipt.read_text()) if receipt.exists() else {
            'request': request, 'application_uid': state['uid'], 'disabled_verified_at': time.time()}
        if pending['request'] != request or pending['application_uid'] != state['uid']:
            raise RuntimeError('Removal checkpoint identity changed')
        atomic(receipt, pending)
        if rows:
            # No new grants while disabled. Let the longest declared client/IdP
            # session expire before deletion; JWT logout is not instant revocation.
            wait(lambda: time.time() >= pending['disabled_verified_at'] + 600,
                 'disabled client session and token expiry', timeout=660)
        def lease_available():
            lease = get('lease', 'identity-writer', NAMESPACE)
            return lease is not None and available(lease.get('spec', {}), time.time())
        def set_operation(value):
            kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=merge',
                 '--field-manager=' + OWNER, '-p', json.dumps({'spec': {'source': {'helm': {
                     'valuesObject': {'operation': value}}}}}))
        def reconciled():
            actual = get('application.argoproj.io', APP, 'argocd') or {}
            compared = actual.get('status', {}).get('sync', {}).get('comparedTo', {}).get('source', {})
            return contains(compared, actual.get('spec', {}).get('source', {})) and application_ready(APP, state['revision'])
        if rows or values.get('operation'):
            wait(lease_available, 'previous identity writer lease expiry', timeout=300)
            set_operation(operation)
            wait(reconciled, 'scoped removal job convergence', timeout=900)
            token = private_request(origin + '/realms/' + realm + '/protocol/openid-connect/token', form={
                'grant_type': 'client_credentials', 'client_id': 'realm-writer', 'client_secret': secret})['access_token']
            if private_request(origin + '/admin/realms/' + realm + '/clients?clientId=' + identifier, token=token):
                raise RuntimeError('Scoped client removal did not converge')
            # Its named inventory is rechecked inside the same Lease as both CLI
            # imports. Repeat operations skip absent clients instead of recreating them.
            wait(lease_available, 'removal writer lease expiry', timeout=300)
            set_operation(None)
            wait(reconciled, 'normal writer convergence after removal', timeout=900)
        atomic(receipt, dict(pending, complete=True, completed_at=time.time()))
        return {'client_removed': True, 'already_absent': not rows, 'configuration_writer': 'serialized Argo config-cli',
                'jwt_session_expiry_bound_seconds': 600, 'application_sessions_require_separate_verified_contract': True}


def local(request):
    from dotenv import dotenv_values
    from automation.connectivity.preflight import ssh
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        os.environ[key] = environment[key]
    os.environ['VM_PORT'] = environment.get('VM_PORT') or '22'
    return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 /opt/cloudlab/automation/identity/lifecycle.py remove',
        input=json.dumps(request), timeout=3300))


def offboard_scope(request):
    if (not isinstance(request, dict) or set(request) != {'realm', 'username', 'user_id', 'email'}
            or request['realm'] not in REALMS
            or not isinstance(request['username'], str) or not request['username']
            or request['username'].startswith('service-account-')
            or not isinstance(request['user_id'], str)
            or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', request['user_id'])
            or not isinstance(request['email'], str) or request['email'].count('@') != 1
            or request['email'] != request['email'].strip()
            or any(ord(c) < 33 or ord(c) == 127 for c in request['email'])):
        raise ValueError('Offboarding requires exact private human identity and immutable user ID')


def offboard(request):
    """Invalidate sessions only after the sole CLI writer applies a tombstone."""
    from automation.identity.bootstrap import private_inputs
    offboard_scope(request)
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads((BASE / 'ownership.json').read_text())
        app = get('application.argoproj.io', APP, 'argocd') or {}
        if (state.get('phase') != 'scoped' or app.get('metadata', {}).get('uid') != state.get('uid')
                or app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER
                or not application_ready(APP, state['revision'])):
            raise RuntimeError('Offboarding requires converged scoped identity')
        values = app['spec']['source']['helm']['valuesObject']
        if values.get('operation') or values.get('maintenance'):
            raise RuntimeError('Complete pending identity maintenance before offboarding')
        private = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd')
        source, registry, revision = private_inputs({'values': values,
            'private_repository': private['spec']['source']['repoURL']})
        realm, username = request['realm'], request['username']
        if (username not in registry['realms'].get(realm, {}).get('users', []) or
                not any(row['username'] == username for row in source['realms'].get(realm, {}).get('memberships', []))):
            raise RuntimeError('Publish the complete private membership and persistent user tombstone first')
        origin = 'https://' + values['adminHost']
        external = get('externalsecret.external-secrets.io', 'keycloak-realm-writers', NAMESPACE)
        credentials = get('secret', 'keycloak-realm-writers', NAMESPACE)
        if not condition(external, 'Ready') or not any(
                row.get('uid') == external['metadata']['uid'] and row.get('kind') == 'ExternalSecret'
                for row in (credentials or {}).get('metadata', {}).get('ownerReferences', [])):
            raise RuntimeError('Offboarding requires current ready ESO writer credentials')
        secret = base64.b64decode(credentials['data'][realm + '_client_secret'], validate=True).decode()
        token = private_request(origin + '/realms/' + realm + '/protocol/openid-connect/token', form={
            'grant_type': 'client_credentials', 'client_id': 'realm-writer', 'client_secret': secret})['access_token']
        root = origin + '/admin/realms/' + realm
        def verified():
            rows = private_request(root + '/users?' + urlencode({'username': username, 'exact': 'true', 'max': 2}), token=token)
            if (not isinstance(rows, list) or len(rows) != 1 or rows[0].get('id') != request['user_id']
                    or rows[0].get('username') != username or rows[0].get('enabled') is not False
                    or rows[0].get('email') != request['email'] or rows[0].get('emailVerified') is not True):
                raise RuntimeError('Offboarding requires the exact already disabled verified human identity')
            return rows[0]
        user = verified()
        path = root + '/users/' + quote(request['user_id'], safe='')
        before = private_request(path + '/credentials', token=token)
        started = time.monotonic()
        private_request(path + '/logout', token=token, method='POST', accepted_statuses=(204,))
        wait(lambda: private_request(path + '/sessions', token=token) == [], 'offboarded Keycloak sessions', timeout=60)
        if verified() != user or private_request(path + '/credentials', token=token) != before:
            raise RuntimeError('Session invalidation changed identity or credentials')
        if private_inputs({'values': values, 'private_repository': private['spec']['source']['repoURL']}) != (source, registry, revision):
            raise RuntimeError('Private offboarding source changed during invalidation')
        return {'keycloak_sessions_invalidated': True, 'user_credentials_preserved': True,
                'keycloak_logout_seconds': round(time.monotonic() - started, 3),
                'declared_managed_access_token_seconds': 300, 'declared_argo_session_seconds': 600,
                'integrated_offboarding_deadline_measured': False}


def local_offboard(request):
    """Use the existing independent external owner for Access revocation."""
    from dotenv import dotenv_values
    from automation.connectivity.preflight import ssh
    from automation.connectivity.checkpoint import transaction
    from automation.credentials.vault import fields
    from automation.connectivity.cloudflare import API
    offboard_scope(request)
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'OP_SERVICE_ACCOUNT_TOKEN'):
        os.environ[key] = environment.get(key) or ''
    os.environ['VM_PORT'] = environment.get('VM_PORT') or '22'
    with transaction() as receipts:
        if request['realm'] == 'platform':
            state = receipts.load('external') or {}
            owner = state.get('identity_provider') or {}
            if owner.get('phase') != 'accepted' or not owner.get('id'):
                raise RuntimeError('Coordinated platform offboarding requires accepted dedicated Access cutover')
            credentials = fields('cloudflare-management', ('API_TOKEN', 'ACCOUNT_ID'))
            if owner.get('binding', {}).get('account') != credentials['ACCOUNT_ID']:
                raise RuntimeError('Access offboarding account differs from its saved owner')
            api = API(credentials['API_TOKEN'])
            for key, entry in state.get('objects', {}).items():
                if key.startswith('app:'):
                    app = api.request('GET', 'accounts/' + credentials['ACCOUNT_ID'] + '/access/apps/' + entry['id'])
                    if any(p.get('decision') == 'allow' for p in app.get('policies', [])) and app.get('allowed_idps') != [owner['id']]:
                        raise RuntimeError('Human Access still permits another provider; offboarding would allow new login')
        result = json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 /opt/cloudlab/automation/identity/lifecycle.py offboard',
            input=json.dumps(request), timeout=180))
        if request['realm'] == 'platform':
            started = time.monotonic()
            accepted = api.request('POST', 'accounts/' + credentials['ACCOUNT_ID'] + '/access/organizations/revoke_user',
                {'email': request['email'], 'devices': False, 'warp_session_reauth': False})
            if accepted is not True:
                raise RuntimeError('Access session revocation did not acknowledge success')
            result.update(access_revocation_acknowledged=True, access_api_seconds=round(time.monotonic() - started, 3),
                          access_session_denial_measured=False, device_identity_changed=False)
        return result


if __name__ == '__main__':
    try:
        payload = json.load(sys.stdin)
        mode = sys.argv[1:]
        print(json.dumps(offboard(payload) if mode == ['offboard'] else
                         local_offboard(payload) if mode == ['--offboard'] else
                         remove(payload) if mode == ['remove'] else local(payload)))
    except Exception:
        raise SystemExit('Scoped lifecycle operation incomplete; preserve tombstone and checkpoint. Private diagnostics withheld.') from None
