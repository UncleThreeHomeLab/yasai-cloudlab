"""Disposable real-server compatibility, convergence and OIDC contract checks."""
import base64
import copy
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from automation.identity.configuration import baseline, bootstrap_writer, bootstrap_health, client, compile_state, restrict_password_grants, prepare_master
from automation.identity.tokens import access_token, identity_token

SERVER = 'https://localhost:8443'
FIXTURE = Path('/fixture')


def request(path, method='GET', value=None, token=None, form=False):
    data = urllib.parse.urlencode(value).encode() if form else json.dumps(value).encode() if value is not None else None
    headers = {'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(SERVER + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


def administrator():
    return request('/realms/master/protocol/openid-connect/token', 'POST', {
        'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'fixture-admin',
        'password': 'fixture-only-isolated-admin'}, form=True)['access_token']


def reconcile(value, scope='main', remove=False, writer_secret=None):
    FIXTURE.joinpath('result').unlink(missing_ok=True)
    if scope == 'main' and value.get('realm') in ('platform', 'applications'):
        value = restrict_password_grants(value)
    FIXTURE.joinpath('input.json').write_text(json.dumps(value, sort_keys=True))
    if scope not in ('main', 'client-reference'):
        raise ValueError('Invalid disposable reconciliation scope')
    FIXTURE.joinpath('scope').write_text(scope)
    FIXTURE.joinpath('remove').unlink(missing_ok=True)
    if remove:
        FIXTURE.joinpath('remove').touch()
    FIXTURE.joinpath('scoped-secret').unlink(missing_ok=True)
    if writer_secret:
        target = FIXTURE / 'scoped-secret'
        target.write_text(writer_secret)
        os.chown(target, 1000, 1000)
        target.chmod(0o600)
    FIXTURE.joinpath('request').touch()
    deadline = time.monotonic() + 120
    while not FIXTURE.joinpath('result').exists():
        if time.monotonic() > deadline:
            raise RuntimeError('Disposable config-cli operation timed out')
        time.sleep(1)
    if FIXTURE.joinpath('result').read_text().strip() != '0':
        # Return only known compatibility/error categories; never realm/user data.
        raw = FIXTURE.joinpath('private-result').read_text()
        if 'version' in raw.lower():
            raise RuntimeError('Disposable config-cli version compatibility failed')
        raise RuntimeError('Disposable config-cli import failed; private diagnostics withheld')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LoginForm(HTMLParser):
    action = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'form' and values.get('id') == 'kc-form-login':
            self.action = values.get('action')


def login(password, client_id='reference', secret=None, invalid_verifier=False):
    state, nonce, verifier = [secrets.token_urlsafe(48) for _ in range(3)]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    callback = 'https://reference.example.invalid/callback'
    query = urllib.parse.urlencode({'client_id': client_id, 'response_type': 'code', 'scope': 'openid profile',
        'redirect_uri': callback, 'state': state, 'nonce': nonce,
        'code_challenge': challenge, 'code_challenge_method': 'S256'})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile='/fixture/ca.crt')),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())
    with opener.open(SERVER + '/realms/applications/protocol/openid-connect/auth?' + query, timeout=20) as response:
        form = LoginForm()
        form.feed(response.read().decode())
    if not form.action or not form.action.startswith(SERVER + '/realms/applications/'):
        raise RuntimeError('Reference login did not return a trusted form')
    try:
        opener.open(urllib.request.Request(form.action,
            urllib.parse.urlencode({'username': 'fixture-reader', 'password': password}).encode()), timeout=20)
        raise RuntimeError('Reference login failed to return an authorization code')
    except urllib.error.HTTPError as redirect:
        location = redirect.headers.get('Location', '')
        if redirect.code != 302 or location.split('?', 1)[0] != callback:
            raise RuntimeError('Reference callback mismatch') from None
    parameters = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query, strict_parsing=True)
    if parameters.get('state') != [state] or len(parameters.get('code', [])) != 1:
        raise RuntimeError('Reference state mismatch')
    exchange = {'grant_type': 'authorization_code', 'client_id': client_id, 'code': parameters['code'][0],
                'redirect_uri': callback, 'code_verifier': 'wrong-verifier' if invalid_verifier else verifier}
    if secret:
        exchange['client_secret'] = secret
    token = request('/realms/applications/protocol/openid-connect/token', 'POST', exchange, form=True)
    identity_token(token['id_token'], request('/realms/applications/protocol/openid-connect/certs'),
                   SERVER + '/realms/applications', client_id, nonce)
    return token


def main():
    urllib.request.install_opener(urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile='/fixture/ca.crt'))))
    os.chown(FIXTURE, 1000, 1000)
    FIXTURE.chmod(0o700)
    deadline = time.monotonic() + 180
    while True:
        try:
            admin = administrator()
            break
        except (urllib.error.URLError, OSError):
            if time.monotonic() > deadline:
                raise RuntimeError('Disposable identity server did not become ready') from None
            time.sleep(2)
    master = request('/admin/realms/master', token=administrator())
    master.setdefault('attributes', {})['fixture-preserve'] = 'unchanged'
    request('/admin/realms/master', 'PUT', master, administrator())
    master_credentials = FIXTURE / 'master-bootstrap-credentials'
    master_credentials.mkdir()
    (master_credentials / 'username').write_text('fixture-admin')
    (master_credentials / 'password').write_text('fixture-only-isolated-admin')
    master_inputs = FIXTURE / 'master-inputs'
    master_inputs.mkdir()
    prepare_master(master_inputs, 'admin.fixture.test', master_credentials)
    master_document = json.loads((master_inputs / 'master-bootstrap.json').read_text())
    try:
        reconcile(master_document)
    except RuntimeError:
        actual = request('/admin/realms/master', token=administrator())
        if actual.get('attributes', {}).get('frontendUrl') != 'https://admin.fixture.test': raise
        reconcile(master_document)
    master = request('/admin/realms/master', token=administrator())
    if master['attributes'].get('fixture-preserve') != 'unchanged':
        raise RuntimeError('Private master bootstrap overwrote unrelated attributes')
    master_discovery = request('/realms/master/.well-known/openid-configuration')
    if master_discovery['issuer'] != 'https://admin.fixture.test/realms/master':
        raise RuntimeError('Master issuer is not isolated to its private browser hostname')
    state = compile_state('applications', 'localhost', {'format': 1, 'realms': {'applications': {
        'clients': [{'id': 'reference', 'public': True, 'audience': 'reference-api',
            'callbacks': ['https://reference.example.invalid/callback'], 'roles': ['reader', 'denied'],
            'role_groups': {'reader': ['viewer']}}],
        'memberships': [{'username': 'fixture-reader', 'groups': ['viewer']}]}}})
    state['browserFlow'] = 'browser'
    state.pop('authenticationFlows')  # This fixture does not claim WebAuthn proof.
    password = secrets.token_urlsafe(32)
    state['users'] = [{'username': 'fixture-reader', 'enabled': True,
        'firstName': 'Fixture', 'lastName': 'Reader', 'email': 'fixture@example.invalid', 'emailVerified': True,
        'credentials': [{'type': 'password', 'value': password, 'temporary': False}],
        'groups': ['/viewer', '/client-reference/reader']}]
    writer_secret = secrets.token_urlsafe(48)
    health_secret = secrets.token_urlsafe(48)
    reconcile(bootstrap_health(bootstrap_writer(state, writer_secret), health_secret))
    root = '/admin/realms/applications'
    admin = administrator()
    reader = request(root + '/users?username=fixture-reader&exact=true', token=admin)[0]
    # Add unrelated state out of band; normal imports must preserve it.
    request(root + '/users', 'POST', {'username': 'unrelated-fixture', 'enabled': False}, admin)
    unrelated = request(root + '/users?username=unrelated-fixture&exact=true', token=admin)[0]
    unrelated = request(root + '/users/' + unrelated['id'], token=admin)
    desired = copy.deepcopy(state)
    desired.pop('users')  # Never replace existing credentials on repeat imports.
    before = request(root + '/users/' + reader['id'], token=admin)
    reconcile(desired, writer_secret=writer_secret)
    first = request(root, token=administrator())
    reconcile(desired, writer_secret=writer_secret)
    second = request(root, token=administrator())
    if first != second:
        raise RuntimeError('Identical import changed realm state')
    drift = dict(second, displayName='disposable-drift')
    request(root, 'PUT', drift, administrator())
    reconcile(desired, writer_secret=writer_secret)
    repaired = request(root, token=administrator())
    if repaired['displayName'] != desired['displayName']:
        raise RuntimeError('Unchanged-input drift repair failed')
    if request(root + '/users/' + reader['id'], token=administrator()) != before:
        raise RuntimeError('Repeat import changed existing user')
    if request(root + '/users/' + unrelated['id'], token=administrator()) != unrelated:
        raise RuntimeError('Import damaged unrelated user')
    scoped = request('/realms/applications/protocol/openid-connect/token', 'POST', {
        'grant_type': 'client_credentials', 'client_id': 'realm-writer', 'client_secret': writer_secret}, form=True)['access_token']
    health = request('/realms/applications/protocol/openid-connect/token', 'POST', {
        'grant_type': 'client_credentials', 'client_id': 'realm-health', 'client_secret': health_secret}, form=True)['access_token']
    for path in ('/events?max=10', '/admin-events?max=10'):
        request(root + path, token=health)
    try:
        request(root + '/users', token=health)
    except urllib.error.HTTPError as error:
        if error.code != 403:
            raise
    else:
        raise RuntimeError('Read-only audit identity can read unrelated personal accounts')
    for protected in ('/admin/realms/master', '/admin/realms/platform'):
        try:
            request(protected, token=scoped)
        except urllib.error.HTTPError as error:
            if error.code not in (403, 404):
                raise
        else:
            raise RuntimeError('Scoped writer can access another realm')
    try:
        request('/realms/applications/protocol/openid-connect/token', 'POST', {
            'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'fixture-reader',
            'password': password}, form=True)
    except urllib.error.HTTPError as error:
        if error.code != 400: raise
    else:
        raise RuntimeError('Built-in client allowed password-only authentication')
    token = login(password)
    discovery = request('/realms/applications/.well-known/openid-configuration')
    jwks = request('/realms/applications/protocol/openid-connect/certs')
    issuer = SERVER + '/realms/applications'
    if discovery['issuer'] != issuer:
        raise RuntimeError('Reference discovery issuer mismatch')
    claims = access_token(token['access_token'], jwks, issuer, 'reference-api', 'reader')
    for expected_issuer, audience, role, now in [
            (issuer + '-wrong', 'reference-api', 'reader', None),
            (issuer, 'wrong-api', 'reader', None), (issuer, 'reference-api', 'denied', None),
            (issuer, 'reference-api', 'reader', claims['exp'] + 1)]:
        try:
            access_token(token['access_token'], jwks, expected_issuer, audience, role, now)
        except ValueError:
            continue
        raise RuntimeError('Reference API accepted a negative token case')
    try:
        login(password, invalid_verifier=True)
    except urllib.error.HTTPError as error:
        if error.code != 400:
            raise
    else:
        raise RuntimeError('Identity server accepted an incorrect PKCE verifier')
    try:
        request('/realms/applications/protocol/openid-connect/auth?' + urllib.parse.urlencode({
            'client_id': 'reference', 'response_type': 'code', 'redirect_uri': 'https://unsafe.example.invalid/callback',
            'code_challenge': 'unused', 'code_challenge_method': 'S256'}))
    except urllib.error.HTTPError as error:
        if error.code != 400:
            raise
    else:
        raise RuntimeError('Identity server accepted an unsafe redirect')
    old_secret, new_secret = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    confidential = client({'id': 'rotation-fixture', 'public': False, 'audience': 'reference-api',
                           'callbacks': ['https://reference.example.invalid/callback']}, {'rotation-fixture': old_secret})
    rotating = copy.deepcopy(desired)
    rotating['clients'].append(confidential)
    reconcile(rotating)
    rotation_token = login(password, 'rotation-fixture', old_secret)
    rotating['clients'][-1]['secret'] = new_secret
    reconcile(rotating)
    refresh = {'grant_type': 'refresh_token', 'client_id': 'rotation-fixture',
               'refresh_token': rotation_token['refresh_token'], 'client_secret': old_secret}
    try:
        request('/realms/applications/protocol/openid-connect/token', 'POST', refresh, form=True)
    except urllib.error.HTTPError as error:
        if error.code not in (400, 401):
            raise
    else:
        raise RuntimeError('Identity server accepted a retired client credential')
    refresh['client_secret'] = new_secret
    request('/realms/applications/protocol/openid-connect/token', 'POST', refresh, form=True)
    disabled = copy.deepcopy(desired)
    disabled['clients'][0]['enabled'] = False
    reconcile(disabled)
    try:
        request('/realms/applications/protocol/openid-connect/token', 'POST', {
            'grant_type': 'refresh_token', 'client_id': 'reference', 'refresh_token': token['refresh_token']}, form=True)
    except urllib.error.HTTPError as error:
        if error.code not in (400, 401):
            raise
    else:
        raise RuntimeError('Disabled client refreshed tokens')
    # Deletion has its own remote inventory. It never shares the main writer's
    # inventory, and only the explicitly seeded disposable client is removable.
    reconcile({'realm': 'applications', 'clients': disabled['clients']}, scope='client-reference')
    reconcile({'realm': 'applications', 'clients': []}, scope='client-reference', remove=True)
    if request(root + '/clients?clientId=reference', token=administrator()):
        raise RuntimeError('Scoped disposable client removal failed')
    if not request(root + '/clients?clientId=rotation-fixture', token=administrator()):
        raise RuntimeError('Scoped removal deleted an unrelated client')
    browser_password = secrets.token_urlsafe(32)
    platform = baseline('platform', 'localhost')
    platform['clients'] = [client({'id': 'reference-ui', 'public': True, 'audience': 'reference-api',
                                  'callbacks': ['https://localhost/callback']}, {})]
    platform['roles']['client'] = {'reference-ui': [{'name': 'reader'}]}
    platform['users'] = [{'username': 'fixture-privileged', 'firstName': 'Fixture', 'lastName': 'Privileged',
        'email': 'privileged@example.invalid', 'emailVerified': True, 'enabled': True,
        'requiredActions': ['webauthn-register'], 'clientRoles': {'reference-ui': ['reader']},
        'credentials': [{'type': 'password', 'value': browser_password, 'temporary': False}]}]
    reconcile(platform)
    master_password = secrets.token_urlsafe(32)
    reconcile({'realm': 'master', 'users': [{'username': 'fixture-master', 'firstName': 'Fixture', 'lastName': 'Master',
        'email': 'master@example.invalid', 'emailVerified': True, 'enabled': True, 'realmRoles': ['admin'],
        'requiredActions': ['webauthn-register'], 'credentials': [{'type': 'password', 'value': master_password, 'temporary': False}]}]})
    target = FIXTURE / 'browser-input'
    offboard = compile_state('platform', 'localhost', {'format': 1, 'realms': {'platform': {
        'memberships': [{'username': 'fixture-privileged', 'groups': ['platform-admin']}]}}},
        revocations={'format': 1, 'realms': {'platform': {'users': ['fixture-privileged']}}})
    target.write_text(json.dumps({'username': 'fixture-privileged', 'password': browser_password,
                                 'offboarding_import': offboard, 'master_username': 'fixture-master', 'master_password': master_password}))
    os.chown(target, 1000, 1000)
    target.chmod(0o600)
    recovery_client = FIXTURE / 'emergency-client'
    recovery_client.write_text('fixture-recovery')
    os.chown(recovery_client, 1000, 1000)
    recovery_client.chmod(0o600)
    recovery_secret = FIXTURE / 'emergency-secret'
    recovery_secret.write_text(secrets.token_urlsafe(48))
    os.chown(recovery_secret, 1000, 1000)
    recovery_secret.chmod(0o600)
    print(json.dumps({'server': '26.8.0', 'config_cli': '6.5.1-26.5.5', 'repeat_unchanged': True,
        'unchanged_input_drift_repaired': True, 'unrelated_user_preserved': True,
        'existing_user_preserved': True, 'code_pkce_s256_state_nonce': True,
        'access_jwt_signature_issuer_audience_expiry_role': True, 'scoped_group_role_grant': True, 'built_in_password_grant_denied': True, 'client_disable': True,
        'unsafe_redirect_denied': True, 'wrong_pkce_denied': True, 'client_credential_rotation': True,
        'scoped_client_removal': True, 'unrelated_client_preserved': True,
        'scoped_writer_reconcile': True, 'writer_cross_realm_denied': True,
        'audit_identity_event_reads_only': True, 'private_master_issuer': True, 'master_unmanaged_attributes_preserved': True,
        'environment': 'isolated Compose fixture; verified localhost TLS; no production gateway or personal MFA claim'}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        location = traceback.extract_tb(error.__traceback__)[-1]
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Disposable identity proof failed: ' + type(error).__name__ +
                         ' at ' + Path(location.filename).name + ':' + str(location.lineno) +
                         (': ' + str(error) if isinstance(error, ValueError) and str(error).startswith('Token rejected: ') else '')) from None
