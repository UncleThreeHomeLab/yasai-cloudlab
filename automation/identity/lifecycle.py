"""Execute reviewed client removal through the existing serialized Argo writer."""
import base64
import fcntl
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.identity.bootstrap import BASE
from automation.identity.configuration import REALMS, compile_state, name, private_request
from automation.identity.lease import available
from automation.identity.maintenance import APP, NAMESPACE, OWNER
from automation.mesh.kube import application_ready, contains, get, kube, wait
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


if __name__ == '__main__':
    try:
        payload = json.load(sys.stdin)
        print(json.dumps(remove(payload) if sys.argv[1:] == ['remove'] else local(payload)))
    except Exception:
        raise SystemExit('Scoped removal incomplete; preserve retirement and checkpoint. Private diagnostics withheld.') from None
