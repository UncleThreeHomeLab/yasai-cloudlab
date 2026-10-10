"""Retire bootstrap access only after real MFA and an offline recovery exercise."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from urllib.parse import urlencode, quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.data.control import atomic, sql
from automation.identity.bootstrap import writer_idle, reconciled, private_inputs
from automation.identity.configuration import email_profile, private_request
from automation.identity.maintenance import APP, BASE, NAMESPACE, OWNER, _set_maintenance
from automation.identity.recovery import signature_state
from automation.mesh.kube import get, kube, condition, contains, wait


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def phase_sync_patches(current, revision):
    if not re.fullmatch('[a-f0-9]{40}', revision) or current.get('operation'):
        raise RuntimeError('Emergency phase requires an immutable revision and no active Argo operation')
    # Hook-only changes do not make an Application OutOfSync. Request a full,
    # unpruned hook sync at the checkpoint revision, including after interruption.
    return [
        {'op': 'add', 'path': '/spec/source/targetRevision', 'value': revision},
        {'op': 'add', 'path': '/operation', 'value': {
            'initiatedBy': {'username': OWNER},
            'sync': {'revision': revision, 'prune': False, 'syncStrategy': {'hook': {}}}}}]


def vault_secret(name):
    external = get('externalsecret.external-secrets.io', name, NAMESPACE)
    secret = get('secret', name, NAMESPACE)
    if not condition(external, 'Ready') or not secret or not any(
            row.get('uid') == external['metadata']['uid'] and row.get('kind') == 'ExternalSecret'
            for row in secret['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Retirement requires current ESO-owned credentials')
    return {key: base64.b64decode(value, validate=True).decode() for key, value in secret['data'].items()}


def token(origin, credentials, service=False):
    form = ({'grant_type': 'client_credentials', 'client_id': credentials['client_id'],
             'client_secret': credentials['client_secret']} if service else
            {'grant_type': 'password', 'client_id': 'admin-cli',
             'username': credentials['username'], 'password': credentials['password']})
    response = private_request(origin + '/realms/master/protocol/openid-connect/token', form=form)
    if type(response.get('expires_in')) is not int or not 0 < response['expires_in'] <= 300:
        raise RuntimeError('Emergency access tokens must have a verified 300-second maximum')
    return response['access_token']


def human_mfa(origin, bearer, primary, now):
    """Credential presence plus a recent browser login under the required UV flow."""
    identities = {}
    for realm, client in (('master', 'security-admin-console'), ('platform', 'argocd')):
        root = origin + '/admin/realms/' + realm
        rows = private_request(root + '/users?' + urlencode({'username': primary[realm + '_username'], 'exact': 'true'}), token=bearer)
        if (not isinstance(rows, list) or len(rows) != 1 or rows[0].get('username') != primary[realm + '_username'] or
                rows[0].get('enabled') is not True or rows[0].get('emailVerified') is not True or
                rows[0].get('attributes', {}).get('cloudlab-primary-owner') != [primary['ownership_id']] or
                'webauthn-register' in rows[0].get('requiredActions', [])):
            raise RuntimeError('Real primary account enrollment and owner verification required before retirement')
        user = root + '/users/' + quote(rows[0]['id'], safe='')
        credentials = private_request(user + '/credentials', token=bearer)
        if not any(row.get('type') == 'webauthn' for row in credentials):
            raise RuntimeError('Real master and platform WebAuthn enrollment required before retirement')
        if realm == 'master':
            roles = private_request(user + '/role-mappings/realm/composite', token=bearer)
            if not any(row.get('name') == 'admin' for row in roles):
                raise RuntimeError('Permanent private master administration must survive retirement')
        elif not any(row.get('path') == '/platform-admin' for row in private_request(user + '/groups', token=bearer)):
            raise RuntimeError('Primary platform administration must survive retirement')
        settings = private_request(root, token=bearer)
        if (settings.get('browserFlow') != 'cloudlab-privileged' or
                settings.get('webAuthnPolicyUserVerificationRequirement') != 'required' or
                settings.get('accessTokenLifespan') != 300):
            raise RuntimeError('Required verified WebAuthn flow changed before retirement')
        flows = private_request(root + '/authentication/flows/cloudlab-privileged-forms/executions', token=bearer)
        required = {(row.get('providerId'), row.get('requirement')) for row in flows}
        if not {('auth-username-password-form', 'REQUIRED'), ('webauthn-authenticator', 'REQUIRED')} <= required:
            raise RuntimeError('Privileged browser MFA executions changed before retirement')
        events = private_request(root + '/events?' + urlencode({'user': rows[0]['id'], 'type': 'LOGIN', 'max': 100}), token=bearer)
        if not any(row.get('userId') == rows[0]['id'] and row.get('clientId') == client and
                   type(row.get('time')) is int and 0 <= now * 1000 - row['time'] <= 86400000 for row in events):
            raise RuntimeError('Recent real platform and private master browser login required before retirement')
        identities[realm] = rows[0]['id']
    return identities


def users(origin, bearer, excluded):
    result = {}
    for realm in ('master', 'platform', 'applications'):
        root = origin + '/admin/realms/' + realm
        for first in range(0, 10000, 100):
            rows = private_request(root + '/users?first=' + str(first) + '&max=100', token=bearer)
            if not isinstance(rows, list) or len(rows) > 100:
                raise RuntimeError('Retirement user inventory is malformed')
            for row in rows:
                if row.get('username') in excluded and realm == 'master':
                    continue
                identifier = realm + '/' + row['id']
                if identifier in result:
                    raise RuntimeError('Retirement user inventory is ambiguous')
                endpoint = root + '/users/' + quote(row['id'], safe='')
                result[identifier] = digest({'user': row,
                    'credentials': private_request(endpoint + '/credentials', token=bearer),
                    'roles': private_request(endpoint + '/role-mappings', token=bearer)})
            if len(rows) < 100:
                break
        else:
            raise RuntimeError('Retirement user inventory exceeds its bounded limit')
    return result


def current_private(values, primary):
    private = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd')
    source, revoked, _ = private_inputs({'values': values, 'private_repository': private['spec']['source']['repoURL']})
    members = source['realms'].get('platform', {}).get('memberships', [])
    if (primary['platform_username'] in revoked['realms'].get('platform', {}).get('users', []) or
            not any(row['username'] == primary['platform_username'] and 'platform-admin' in row['groups'] for row in members)):
        raise RuntimeError('Permanent platform administrator must remain active in the current private source')
    member = next(row for row in members if row['username'] == primary['platform_username'])
    return email_profile(member['profile'])['email'] if 'profile' in member else primary['email']


def owner():
    receipt = json.loads((BASE / 'ownership.json').read_text())
    app = get('application.argoproj.io', APP, 'argocd') or {}
    server = get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE) or {}
    if (receipt.get('phase') != 'scoped' or app.get('metadata', {}).get('uid') != receipt.get('uid') or
            app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER):
        raise RuntimeError('Retirement requires the unchanged scoped identity owner')
    return receipt, app, server


def prepare(request):
    if (not isinstance(request, dict) or set(request) != {'recovery_custody_confirmed'} or
            request['recovery_custody_confirmed'] is not True):
        raise ValueError('Confirm personal recovery custody explicitly before retirement')
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt, app, server = owner()
        path = BASE / 'retirement.json'
        if path.exists():
            saved = json.loads(path.read_text())
            if saved['application_uid'] != receipt['uid'] or saved['keycloak_uid'] != server['metadata']['uid']:
                raise RuntimeError('Retirement recovery identity changed')
            return {'nonce': saved['nonce'], 'already_accepted': saved['phase'] == 'accepted'}
        values = app['spec']['source']['helm']['valuesObject']
        if (values.get('maintenance') or values.get('operation') or values.get('bootstrapMode') or
                not reconciled(receipt['revision'], receipt['uid']) or not condition(server, 'Ready')):
            raise RuntimeError('Retirement requires current active scoped reconciliation')
        origin = 'https://' + values['adminHost']
        bootstrap, primary = vault_secret('keycloak-bootstrap-admin'), vault_secret('keycloak-primary-admin')
        current_private(values, primary)
        bearer = token(origin, bootstrap)
        human_mfa(origin, bearer, primary, time.time())
        rows = private_request(origin + '/admin/realms/master/users?' + urlencode({'username': bootstrap['username'], 'exact': 'true'}), token=bearer)
        if len(rows) != 1 or rows[0].get('username') != bootstrap['username'] or rows[0].get('enabled') is not True:
            raise RuntimeError('Temporary bootstrap account identity is ambiguous')
        nonce = secrets.token_hex(16)
        saved = {'phase': 'guarded', 'nonce': nonce, 'application_uid': receipt['uid'],
                 'keycloak_uid': server['metadata']['uid'], 'revision': receipt['revision'],
                 'bootstrap_username': bootstrap['username'], 'bootstrap_user_id': rows[0]['id'],
                 'custody_confirmed_at': time.time(), 'signing_state': signature_state(sql, values['database'])}
        saved['users'] = users(origin, bearer, (bootstrap['username'], 'service-account-emergency-' + nonce))
        atomic(path, saved)
        return {'nonce': nonce, 'already_accepted': False}


def run(nonce):
    if not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{32}', nonce):
        raise ValueError('Retirement requires its exact prepared identity')
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt, app, server = owner()
        path = BASE / 'retirement.json'
        saved = json.loads(path.read_text())
        if (saved['nonce'] != nonce or saved['application_uid'] != receipt['uid'] or
                saved['keycloak_uid'] != server['metadata']['uid'] or
                (saved['phase'] != 'accepted' and saved['revision'] != receipt['revision'])):
            raise RuntimeError('Retirement inputs or owner advanced; preserve the checkpoint')
        if saved['phase'] not in ('guarded', 'stopped', 'seeding', 'retiring', 'retiring-service', 'finishing', 'accepted'):
            raise RuntimeError('Unknown retirement checkpoint; no changes permitted')
        if saved['phase'] == 'accepted':
            values = app['spec']['source']['helm']['valuesObject']
            if (values.get('bootstrapAdminEnabled') is not False or values.get('maintenance') or
                    values.get('operation') or values.get('retiredEmergencyItem') != 'keycloak-emergency-' + nonce or
                    not condition(server, 'Ready') or not reconciled(receipt['revision'], receipt['uid'])):
                raise RuntimeError('Accepted retirement requires current active scoped state and retired inputs')
            return {'changed': False, 'bootstrap_admin_retired': True, 'prior_retirement_receipt_preserved': True}
        values = app['spec']['source']['helm']['valuesObject']
        origin = 'https://' + values['adminHost']
        operation = {'client': 'emergency-' + nonce, 'item': 'keycloak-emergency-' + nonce,
                     'keycloakUID': saved['keycloak_uid'], 'bootstrapUsername': saved['bootstrap_username'],
                     'bootstrapUserId': saved['bootstrap_user_id']}
        def checkpoint(phase):
            saved['phase'] = phase
            atomic(path, saved)
        def declare(action, maintenance):
            wait(lambda: not get('application.argoproj.io', APP, 'argocd').get('operation'),
                 'previous Argo operation completion', timeout=900)
            current = get('application.argoproj.io', APP, 'argocd')
            if current['metadata']['uid'] != saved['application_uid']:
                raise RuntimeError('Retirement Application identity changed')
            desired = dict(operation, action=action) if action else None
            patches = [
                    {'op': 'test', 'path': '/metadata/uid', 'value': saved['application_uid']},
                    {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                    {'op': 'add', 'path': '/spec/source/helm/valuesObject/maintenance', 'value': maintenance},
                    {'op': 'add', 'path': '/spec/source/helm/valuesObject/bootstrapAdminEnabled', 'value': action not in ('retire-emergency', None)}]
            if desired is not None:
                patches.append({'op': 'add', 'path': '/spec/source/helm/valuesObject/operation', 'value': desired})
            elif 'operation' in current['spec']['source']['helm']['valuesObject']:
                # Argo omits null Helm values from comparedTo; clear the field.
                patches.append({'op': 'remove', 'path': '/spec/source/helm/valuesObject/operation'})
            if action is None:
                patches.append({'op': 'add', 'path': '/spec/source/helm/valuesObject/retiredEmergencyItem', 'value': operation['item']})
            patches.extend(phase_sync_patches(current, receipt['revision']))
            kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=json', '--field-manager=' + OWNER, '-p', json.dumps(patches))
        if saved['phase'] == 'guarded':
            bootstrap = vault_secret('keycloak-bootstrap-admin')
            primary = vault_secret('keycloak-primary-admin')
            current_private(values, primary)
            human_mfa(origin, token(origin, bootstrap), primary, time.time())
            wait(writer_idle, 'previous writer completion before offline emergency', timeout=300)
            _set_maintenance(True, {'application_uid': saved['application_uid'], 'keycloak_uid': saved['keycloak_uid']})
            checkpoint('stopped')
        if saved['phase'] == 'stopped':
            declare('prepare-emergency', True)
            def prepared():
                actual = get('application.argoproj.io', APP, 'argocd')
                return (condition(get('externalsecret.external-secrets.io', 'keycloak-emergency', NAMESPACE), 'Ready') and
                    actual.get('status', {}).get('sync', {}).get('status') == 'Synced' and
                    actual.get('status', {}).get('operationState', {}).get('phase') == 'Succeeded' and
                    contains(actual.get('status', {}).get('sync', {}).get('comparedTo', {}).get('source', {}), actual['spec']['source']))
            wait(prepared, 'emergency inputs and ESO delivery', timeout=900)
            credentials = vault_secret('keycloak-emergency')
            if credentials['client_id'] != operation['client'] or len(credentials['client_secret']) < 32:
                raise RuntimeError('Emergency credentials differ from the scoped operation')
            checkpoint('seeding')
        if saved['phase'] == 'seeding':
            credentials = vault_secret('keycloak-emergency')
            if int(sql("SELECT count(*) FROM pg_stat_activity WHERE datname='" + values['database'] +
                       "' AND usename='" + values['databaseRole'] + "';")):
                raise RuntimeError('Every identity database client must stop before offline recovery')
            # An interrupted successful offline hook must never create a second client.
            present = json.loads(sql("SELECT json_build_object('count',count(*),'matched',count(*) FILTER (WHERE "
                          "encode(sha256(convert_to(c.secret,'UTF8')),'hex')='" + hashlib.sha256(credentials['client_secret'].encode()).hexdigest() +
                          "')) FROM client c JOIN realm r ON r.id=c.realm_id WHERE r.name='master' AND c.client_id='" + operation['client'] + "';", values['database']))
            if present['count'] not in (0, 1) or present['count'] != present['matched']:
                raise RuntimeError('Offline emergency service conflicts with its prepared credentials')
            if present['count'] == 0:
                declare('seed-emergency', True)
                wait(lambda: (get('application.argoproj.io', APP, 'argocd').get('status', {}).get('operationState', {}).get('phase') == 'Succeeded' and
                    any(row.get('name') == 'identity-emergency-seed' and row.get('hookPhase') == 'Succeeded'
                        for row in get('application.argoproj.io', APP, 'argocd').get('status', {}).get('operationState', {}).get('syncResult', {}).get('resources', []))),
                    'offline emergency service creation', timeout=900)
            checkpoint('retiring')
        if saved['phase'] == 'retiring':
            wait(writer_idle, 'offline writer lease expiry', timeout=300)
            declare('retire-bootstrap', False)
            wait(lambda: reconciled(receipt['revision'], receipt['uid']) and condition(
                get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE), 'Ready'), 'bootstrap retirement job', timeout=900)
            bearer = token(origin, vault_secret('keycloak-emergency'), True)
            row = private_request(origin + '/admin/realms/master/users/' + quote(saved['bootstrap_user_id'], safe=''), token=bearer)
            if row.get('username') != saved['bootstrap_username'] or row.get('enabled') is not False:
                raise RuntimeError('Bootstrap retirement did not disable its exact temporary user')
            private_request(origin + '/admin/realms/master/users/' + quote(saved['bootstrap_user_id'], safe='') + '/logout',
                            token=bearer, method='POST', accepted_statuses=(204,))
            if users(origin, bearer, (saved['bootstrap_username'], 'service-account-' + operation['client'])) != saved['users']:
                raise RuntimeError('Bootstrap retirement changed unrelated users, roles or credentials')
            if signature_state(sql, values['database']) != saved['signing_state']:
                raise RuntimeError('Emergency exercise changed production signing state')
            checkpoint('retiring-service')
        if saved['phase'] == 'retiring-service':
            credentials = vault_secret('keycloak-emergency')
            enabled = sql("SELECT c.enabled FROM client c JOIN realm r ON r.id=c.realm_id WHERE r.name='master' AND c.client_id='" + operation['client'] + "';", values['database']).strip()
            if enabled not in ('t', 'f'):
                raise RuntimeError('Temporary service inventory changed before retirement')
            bearer = token(origin, credentials, True) if enabled == 't' else None
            if enabled == 't':
                wait(writer_idle, 'retirement writer lease expiry', timeout=300)
                declare('retire-emergency', False)
                def service_retired():
                    try:
                        return reconciled(receipt['revision'], receipt['uid'])
                    except RuntimeError as error:
                        # Disabling its own client can deny config-cli's final read.
                        if str(error) != 'Identity reconciliation failed at the requested revision; preserve the phase checkpoint':
                            raise
                        if sql("SELECT c.enabled FROM client c JOIN realm r ON r.id=c.realm_id WHERE r.name='master' AND c.client_id='" + operation['client'] + "';", values['database']).strip() != 'f':
                            raise
                        return True
                wait(service_retired, 'temporary service retirement', timeout=900)
            response = private_request(origin + '/realms/master/protocol/openid-connect/token', form={
                'grant_type': 'client_credentials', 'client_id': credentials['client_id'], 'client_secret': credentials['client_secret']}, accepted_statuses=(400, 401))
            if response.get('error') not in ('invalid_client', 'unauthorized_client'):
                raise RuntimeError('Temporary emergency service remains usable')
            start = time.time()
            if bearer:
                def denied():
                    status, _ = private_request(origin + '/admin/realms/master', token=bearer,
                        accepted_statuses=(200, 401, 403), with_status=True)
                    return status in (401, 403)
                wait(denied, 'existing temporary administration token expiry', timeout=330)
                saved['temporary_token_denial_measured'] = True
            else:
                # Lost response: no JWT is retained. Wait a fresh full lifetime;
                # this is a conservative expiry bound, not a measured rejection.
                wait(lambda: time.time() >= start + 300, 'temporary administration token expiry bound', timeout=330)
                saved['temporary_token_denial_measured'] = False
            saved['temporary_token_retirement_seconds'] = round(time.time() - start, 3)
            checkpoint('finishing')
        if saved['phase'] == 'finishing':
            wait(writer_idle, 'temporary service writer lease expiry', timeout=300)
            declare(None, False)
            wait(lambda: reconciled(receipt['revision'], receipt['uid']), 'scoped reconciliation after retirement', timeout=900)
            checkpoint('accepted')
        return {'changed': True, 'bootstrap_admin_retired': True, 'offline_emergency_exercised': True,
                'temporary_emergency_client_retired': True, 'unrelated_users_credentials_and_signing_state_preserved': True,
                'temporary_admin_jwt_max_seconds': 300, 'temporary_token_denial_measured': saved['temporary_token_denial_measured'],
                'personal_recovery_custody_confirmed': True, 'configuration_writer': 'serialized Argo config-cli'}


def local(request):
    from dotenv import dotenv_values
    from automation.connectivity.preflight import ssh
    from automation.credentials.provision import ensure_items
    values = dotenv_values(ROOT / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        os.environ[key] = values[key]
    os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
    result = json.loads(ssh('VM', values['VM_HOST'], 'python3 /opt/cloudlab/automation/identity/emergency.py prepare', input=json.dumps(request), timeout=300))
    if result['already_accepted']:
        return json.loads(ssh('VM', values['VM_HOST'], 'python3 /opt/cloudlab/automation/identity/emergency.py run', input=json.dumps(result['nonce']), timeout=60))
    nonce = result['nonce']
    with Path('/state/identity-vault-provision.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ensure_items(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), {'keycloak-emergency-' + nonce: {
            'client_id': ('STRING', lambda: 'emergency-' + nonce),
            'client_secret': ('CONCEALED', lambda: secrets.token_urlsafe(48))}})
    return json.loads(ssh('VM', values['VM_HOST'], 'python3 /opt/cloudlab/automation/identity/emergency.py run', input=json.dumps(nonce), timeout=7200))


if __name__ == '__main__':
    try:
        value = json.load(sys.stdin)
        result = prepare(value) if sys.argv[1:] == ['prepare'] else run(value) if sys.argv[1:] == ['run'] else local(value)
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Bootstrap retirement incomplete; preserve the checkpoint and independent repair access. Private diagnostics withheld.') from None
