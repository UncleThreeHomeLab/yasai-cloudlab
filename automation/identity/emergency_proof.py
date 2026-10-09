"""Disposable offline emergency service and bootstrap retirement proof."""
import json
from pathlib import Path
import sys
import time
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from automation.identity.configuration import bootstrap_retirement
from automation.identity.local_proof import FIXTURE, request, reconcile


def emergency_token():
    return request('/realms/master/protocol/openid-connect/token', 'POST', {
        'grant_type': 'client_credentials', 'client_id': (FIXTURE / 'emergency-client').read_text(),
        'client_secret': (FIXTURE / 'emergency-secret').read_text()}, form=True)['access_token']


def main():
    deadline = time.monotonic() + 300
    while True:
        try:
            token = emergency_token()
            break
        except Exception:
            if time.monotonic() >= deadline:
                raise RuntimeError('Isolated emergency service did not become ready') from None
            time.sleep(2)
    root = '/admin/realms/master'
    users = request(root + '/users', token=token)
    primary = [row for row in users if row['username'] == 'fixture-master']
    if len(primary) != 1 or not primary[0]['enabled']:
        raise RuntimeError('Verified private master account missing before retirement')
    credentials = request(root + '/users/' + primary[0]['id'] + '/credentials', token=token)
    if not any(row['type'] == 'webauthn' for row in credentials):
        raise RuntimeError('Private master browser MFA must precede retirement')
    keys = request('/realms/master/protocol/openid-connect/certs')
    (FIXTURE / 'use-emergency').touch(mode=0o600)
    reconcile(bootstrap_retirement('fixture-admin'))
    reconcile(bootstrap_retirement('fixture-admin'))
    token = emergency_token()
    actual = request(root + '/users', token=token)
    if {row['id'] for row in actual} != {row['id'] for row in users}:
        raise RuntimeError('Bootstrap retirement changed unrelated master identities')
    if any(row['enabled'] for row in actual if row['username'] == 'fixture-admin'):
        raise RuntimeError('Bootstrap administrator remains enabled')
    if next(row for row in actual if row['id'] == primary[0]['id']) != primary[0]:
        raise RuntimeError('Retirement changed the verified master account')
    if request('/realms/master/protocol/openid-connect/certs') != keys:
        raise RuntimeError('Emergency work changed signing state')
    try:
        request('/realms/master/protocol/openid-connect/token', 'POST', {
            'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'fixture-admin',
            'password': 'fixture-only-isolated-admin'}, form=True)
    except urllib.error.HTTPError as error:
        if error.code not in (400, 401):
            raise
    else:
        raise RuntimeError('Retired bootstrap password still authenticates')
    # The emergency client is temporary. Disable it through the sole realm writer.
    try:
        reconcile({'realm': 'master', 'clients': [{'clientId': (FIXTURE / 'emergency-client').read_text(), 'enabled': False}]})
    except RuntimeError:
        # Keycloak revokes the writer's token when it disables its own client.
        # Success requires the precise authentication denial below, never an ignored error.
        pass
    try:
        emergency_token()
    except urllib.error.HTTPError as error:
        if error.code not in (400, 401) or json.loads(error.read()).get('error') not in ('invalid_client', 'unauthorized_client'):
            raise
    else:
        raise RuntimeError('Temporary emergency client remains usable')
    print(json.dumps({'offline_emergency_access': True, 'verified_master_mfa_before_retirement': True,
                      'bootstrap_account_disabled': True, 'master_password_grant_denied': True,
                      'temporary_emergency_client_disabled': True, 'unrelated_master_users_preserved': True,
                      'master_signing_state_preserved': True, 'retirement_repeat_safe': True,
                      'environment': 'isolated Compose fixture; no real emergency custody or vault retirement claim'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Isolated emergency proof failed; private diagnostics withheld') from None
