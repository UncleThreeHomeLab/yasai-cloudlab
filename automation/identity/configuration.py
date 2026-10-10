"""Compile scoped identity inputs; never accept unrestricted realm imports."""
import copy
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

REALMS = ('platform', 'applications')
GROUPS = ('platform-admin', 'developer', 'viewer')
RESERVED = {'master', 'admin-cli', 'account', 'account-console', 'broker',
            'realm-management', 'security-admin-console', 'admin-permissions', 'realm-writer', 'realm-health'}
MANAGED_CLIENT_FIELDS = ('clientId', 'enabled', 'protocol', 'publicClient', 'standardFlowEnabled',
                         'directAccessGrantsEnabled', 'implicitFlowEnabled', 'serviceAccountsEnabled',
                         'fullScopeAllowed', 'redirectUris', 'webOrigins', 'attributes',
                         'defaultClientScopes', 'optionalClientScopes', 'protocolMappers')
WRITER_ROLES = ['manage-realm', 'manage-users', 'manage-clients', 'view-realm',
                'view-users', 'view-clients', 'view-events', 'view-identity-providers']


def email_profile(profile):
    if (not isinstance(profile, dict) or set(profile) != {'email', 'verified'} or
            not isinstance(profile['email'], str) or
            not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', profile['email']) or
            type(profile['verified']) is not bool):
        raise ValueError('Email profile requires an explicit address and operator verification assertion')
    return {'email': profile['email'], 'emailVerified': profile['verified']}


def bootstrap_writer(state, secret):
    if state.get('realm') not in REALMS or not isinstance(secret, str) or len(secret) < 32:
        raise ValueError('Bootstrap writer requires a managed realm and vault secret')
    result = copy.deepcopy(state)
    result.setdefault('clients', []).append({
        'clientId': 'realm-writer', 'enabled': True, 'protocol': 'openid-connect',
        'publicClient': False, 'secret': secret, 'serviceAccountsEnabled': True,
        'standardFlowEnabled': False, 'directAccessGrantsEnabled': False,
        'implicitFlowEnabled': False, 'fullScopeAllowed': False,
        'redirectUris': [], 'webOrigins': [], 'defaultClientScopes': ['basic'],
        'optionalClientScopes': [],
    })
    result.setdefault('users', []).append({
        'username': 'service-account-realm-writer', 'serviceAccountClientId': 'realm-writer',
        'clientRoles': {'realm-management': WRITER_ROLES},
    })
    result['clientScopeMappings'] = {'realm-management': [{'client': 'realm-writer', 'roles': WRITER_ROLES}]}
    return result


def bootstrap_health(state, secret):
    health = bootstrap_writer({'realm': state['realm']}, secret)
    result = copy.deepcopy(state)
    health['clients'][0]['clientId'] = 'realm-health'
    user = health['users'][0]
    user.update(username='service-account-realm-health', serviceAccountClientId='realm-health')
    user['clientRoles']['realm-management'] = ['view-events']
    result.setdefault('clients', []).extend(health['clients'])
    result.setdefault('users', []).extend(health['users'])
    result.setdefault('clientScopeMappings', {}).setdefault('realm-management', []).append(
        {'client': 'realm-health', 'roles': ['view-events']})
    return result


def exact_url(value):
    if (not isinstance(value, str) or not value.isascii() or
            any(ord(c) <= 32 or ord(c) == 127 or c in '*\\' for c in value)):
        raise ValueError('Callbacks must be exact HTTPS URLs')
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError('Callback authority is invalid') from None
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or port not in (None, 443) or parsed.fragment or parsed.query
            or not parsed.path.startswith('/') or '%' in parsed.path or '..' in parsed.path):
        raise ValueError('Callbacks must be exact HTTPS URLs without query or fragments')
    return value


def name(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value)
            or value in RESERVED):
        raise ValueError('Invalid or reserved managed identity name')
    return value


def client(value, secrets):
    if not isinstance(value, dict) or set(value) - {'id', 'callbacks', 'audience', 'public', 'enabled', 'roles', 'scopes', 'role_groups'}:
        raise ValueError('Unsupported private client fields')
    identifier = name(value['id'])
    audience = name(value['audience'])
    if type(value.get('public')) is not bool or type(value.get('enabled', True)) is not bool:
        raise ValueError('Client public/enabled must be booleans')
    callbacks = value['callbacks']
    if not isinstance(callbacks, list) or not 1 <= len(callbacks) <= 8 or len(set(callbacks)) != len(callbacks):
        raise ValueError('Client requires distinct exact callbacks')
    callbacks = [exact_url(url) for url in callbacks]
    scopes = value.get('scopes', ['profile'])
    if not isinstance(scopes, list) or not scopes or set(scopes) - {'profile', 'email'}:
        raise ValueError('Only explicit profile/email scopes are supported')
    roles = value.get('roles', [])
    if not isinstance(roles, list) or len(set(roles)) != len(roles):
        raise ValueError('Client roles must be distinct names')
    for role in roles: name(role)
    mappings = value.get('role_groups', {})
    if (not isinstance(mappings, dict) or set(mappings) - set(roles) or any(
            not isinstance(groups, list) or not groups or len(set(groups)) != len(groups) or
            set(groups) - set(GROUPS) for groups in mappings.values())):
        raise ValueError('Client role groups must map declared roles to managed groups')
    result = {
        'clientId': identifier, 'enabled': value.get('enabled', True), 'protocol': 'openid-connect',
        'publicClient': value['public'], 'standardFlowEnabled': True,
        'directAccessGrantsEnabled': False, 'implicitFlowEnabled': False,
        'serviceAccountsEnabled': False, 'fullScopeAllowed': False,
        'redirectUris': callbacks, 'webOrigins': [],
        'attributes': {'pkce.code.challenge.method': 'S256', 'access.token.lifespan': '300',
                       'client.session.idle.timeout': '600', 'client.session.max.lifespan': '600'},
        'defaultClientScopes': ['basic', *scopes], 'optionalClientScopes': [],
        'protocolMappers': [
            {'name': 'api-audience', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
             'config': {'included.custom.audience': audience, 'access.token.claim': 'true', 'id.token.claim': 'false'}},
            {'name': 'groups', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-group-membership-mapper',
             'config': {'claim.name': 'groups', 'full.path': 'true', 'id.token.claim': 'true',
                        'access.token.claim': 'true', 'userinfo.token.claim': 'true'}},
            {'name': 'client-roles', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-usermodel-client-role-mapper',
             'config': {'usermodel.clientRoleMapping.clientId': identifier, 'claim.name': 'roles',
                        'jsonType.label': 'String', 'multivalued': 'true', 'access.token.claim': 'true',
                        'id.token.claim': 'false'}},
        ],
    }
    if not value['public']:
        secret = secrets.get(identifier)
        if not isinstance(secret, str) or len(secret) < 32:
            raise ValueError('Confidential client requires its vault-sourced secret')
        result['secret'] = secret
    elif identifier in secrets:
        raise ValueError('Public clients must not have secrets')
    return result


def baseline(realm, rp_id):
    if realm not in REALMS or not re.fullmatch(r'[a-z0-9.-]+', rp_id):
        raise ValueError('Invalid realm or WebAuthn RP ID')
    result = {
        'realm': realm, 'enabled': True, 'displayName': realm,
        'sslRequired': 'all', 'registrationAllowed': False, 'resetPasswordAllowed': False,
        'rememberMe': False, 'loginWithEmailAllowed': False, 'duplicateEmailsAllowed': False,
        'bruteForceProtected': True, 'permanentLockout': False,
        'accessTokenLifespan': 300, 'accessTokenLifespanForImplicitFlow': 300,
        'ssoSessionIdleTimeout': 600, 'ssoSessionMaxLifespan': 600,
        'offlineSessionIdleTimeout': 600, 'offlineSessionMaxLifespanEnabled': True,
        'offlineSessionMaxLifespan': 600, 'revokeRefreshToken': True, 'refreshTokenMaxReuse': 0,
        'eventsEnabled': True, 'eventsExpiration': 604800,
        'eventsListeners': [], 'adminEventsEnabled': True, 'adminEventsDetailsEnabled': False,
        'webAuthnPolicyRpId': rp_id, 'webAuthnPolicyRpEntityName': 'CloudLab',
        'webAuthnPolicyUserVerificationRequirement': 'required',
        'webAuthnPolicyAvoidSameAuthenticatorRegister': True,
        'roles': {'realm': [{'name': n} for n in GROUPS]},
        'groups': [{'name': n, 'realmRoles': [n]} for n in GROUPS],
    }
    if realm in REALMS:
        # Both realms can grant privileged roles; require verified MFA consistently.
        result.update(browserFlow='cloudlab-privileged', authenticationFlows=[{
            'alias': 'cloudlab-privileged', 'description': 'Password and verified WebAuthn; no OTP fallback',
            'providerId': 'basic-flow', 'topLevel': True, 'builtIn': False,
            'authenticationExecutions': [
                {'authenticator': 'auth-cookie', 'requirement': 'ALTERNATIVE',
                 'priority': 10, 'userSetupAllowed': False, 'authenticatorFlow': False},
                {'flowAlias': 'cloudlab-privileged-forms', 'requirement': 'ALTERNATIVE',
                 'priority': 20, 'userSetupAllowed': False, 'authenticatorFlow': True},
            ],
        }, {
            'alias': 'cloudlab-privileged-forms', 'description': 'Privileged MFA',
            'providerId': 'basic-flow', 'topLevel': False, 'builtIn': False,
            'authenticationExecutions': [
                {'authenticator': 'auth-username-password-form', 'requirement': 'REQUIRED',
                 'priority': 10, 'userSetupAllowed': False, 'authenticatorFlow': False},
                {'authenticator': 'webauthn-authenticator', 'requirement': 'REQUIRED',
                 'priority': 20, 'userSetupAllowed': False, 'authenticatorFlow': False},
            ],
        }])
    return result


def compile_state(realm, rp_id, source=None, credentials=None, revocations=None):
    result = baseline(realm, rp_id)
    if source is None:
        return result
    if not isinstance(source, dict) or set(source) != {'format', 'realms'} or type(source['format']) is not int or source['format'] != 1:
        raise ValueError('Unsupported private identity source')
    if set(source['realms']) - set(REALMS):
        raise ValueError('Private identity source cannot manage master')
    desired = source['realms'].get(realm, {})
    if set(desired) - {'clients', 'memberships'}:
        raise ValueError('Unsupported private realm fields')
    credentials = credentials or {}
    revocations = revocations or {'format': 1, 'realms': {}}
    if (set(revocations) != {'format', 'realms'} or type(revocations['format']) is not int or revocations['format'] != 1
            or set(revocations['realms']) - set(REALMS)):
        raise ValueError('Invalid revocation registry')
    denied = revocations['realms'].get(realm, {})
    if set(denied) - {'users', 'clients', 'removed_clients'}:
        raise ValueError('Unsupported revocation fields')
    for field in ('users', 'clients', 'removed_clients'):
        entries = denied.get(field, [])
        if (not isinstance(entries, list) or any(not isinstance(item, str) or not item for item in entries)
                or len(set(entries)) != len(entries)):
            raise ValueError('Revocations require distinct nonempty string lists')
    clients = desired.get('clients', [])
    if len({c['id'] for c in clients}) != len(clients):
        raise ValueError('Duplicate managed client')
    result['clients'] = [client(c, credentials.get(realm, {})) for c in clients]
    removed = denied.get('removed_clients', [])
    if (not isinstance(removed, list) or len(set(removed)) != len(removed) or
            any(name(identifier) not in denied.get('clients', []) for identifier in removed)):
        raise ValueError('Removed clients require persistent retirement tombstones')
    if any(c['id'] in removed for c in clients):
        raise ValueError('Private source still contains a removed client; reconciliation refused')
    result['roles']['client'] = {name(c['id']): [{'name': name(r)} for r in c.get('roles', [])] for c in clients}
    for configured in clients:
        if configured.get('role_groups'):
            result['groups'].append({'name': 'client-' + configured['id'], 'subGroups': [
                {'name': role, 'clientRoles': {configured['id']: [role]}}
                for role in configured['role_groups']]})
    for identifier in denied.get('clients', []):
        identifier = name(identifier)
        existing = next((c for c in result['clients'] if c['clientId'] == identifier), None)
        if existing is None and identifier not in removed:
            result['clients'].append({'clientId': identifier, 'enabled': False})
        elif existing is not None:
            existing['enabled'] = False
    users = []
    for member in desired.get('memberships', []):
        if (not {'username', 'groups'} <= set(member) or set(member) - {'username', 'groups', 'profile'} or
                not isinstance(member['username'], str) or not member['username']):
            raise ValueError('Memberships accept username, groups and an optional explicit email profile')
        if member['username'].startswith('service-account-'):
            raise ValueError('Human membership inputs cannot manage machine service accounts')
        if not isinstance(member['groups'], list) or set(member['groups']) - set(GROUPS):
            raise ValueError('Membership group is outside managed scope')
        # No enabled:true or credentials: offboarding never undone by memberships.
        groups = ['/' + g for g in member['groups']]
        for configured in clients:
            if configured.get('enabled', True) and configured['id'] not in denied.get('clients', []):
                groups.extend('/client-' + configured['id'] + '/' + role
                    for role, permitted in configured.get('role_groups', {}).items()
                    if set(permitted) & set(member['groups']))
        user = {'username': member['username'], 'groups': groups}
        if 'profile' in member:
            user.update(email_profile(member['profile']))
        users.append(user)
    if len({u['username'] for u in users}) != len(users):
        raise ValueError('Duplicate private membership')
    for username in denied.get('users', []):
        if not isinstance(username, str) or not username or username.startswith('service-account-'):
            raise ValueError('Invalid offboarded username')
        existing = next((u for u in users if u['username'] == username), None)
        if existing is None:
            users.append({'username': username, 'enabled': False, 'groups': []})
        else:
            existing.update(enabled=False, groups=[])
    if users:
        result['users'] = users
    return copy.deepcopy(result)


def restrict_password_grants(state):
    if state.get('realm') not in REALMS:
        raise ValueError('Normal reconciliation must not alter master login clients')
    result = copy.deepcopy(state)
    result.setdefault('clients', []).append({'clientId': 'admin-cli', 'directAccessGrantsEnabled': False})
    return result


def bootstrap_retirement(username):
    if not isinstance(username, str) or not username or username.startswith('service-account-'):
        raise ValueError('Retirement requires the inventoried temporary bootstrap administrator')
    return {'realm': 'master', 'users': [{'username': username, 'enabled': False}],
            'clients': [{'clientId': 'admin-cli', 'directAccessGrantsEnabled': False}]}


def prepare_retirement(directory, operation, admin_host, credentials_directory):
    from urllib.parse import quote
    if (set(operation) != {'action', 'client', 'item', 'keycloakUID', 'bootstrapUsername', 'bootstrapUserId'} or
            operation['action'] not in ('retire-bootstrap', 'retire-emergency') or
            not re.fullmatch('emergency-[a-f0-9]{32}', operation['client']) or
            operation['item'] != 'keycloak-' + operation['client']):
        raise ValueError('Retirement requires its bounded temporary service inventory')
    credentials = Path(credentials_directory)
    identifier, secret = [credentials.joinpath(key).read_text() for key in ('client_id', 'client_secret')]
    if identifier != operation['client'] or len(secret) < 32:
        raise ValueError('Retirement service differs from its vault owner')
    origin = exact_url('https://' + admin_host + '/')[:-1]
    bearer = private_request(origin + '/realms/master/protocol/openid-connect/token', form={
        'grant_type': 'client_credentials', 'client_id': identifier, 'client_secret': secret})['access_token']
    if operation['action'] == 'retire-bootstrap':
        row = private_request(origin + '/admin/realms/master/users/' + quote(operation['bootstrapUserId'], safe=''), token=bearer)
        if row.get('id') != operation['bootstrapUserId'] or row.get('username') != operation['bootstrapUsername']:
            raise RuntimeError('Temporary bootstrap user identity changed')
        value = bootstrap_retirement(operation['bootstrapUsername'])
        value['users'][0]['id'] = operation['bootstrapUserId']
    else:
        rows = private_request(origin + '/admin/realms/master/clients?clientId=' + identifier, token=bearer)
        if len(rows) != 1 or rows[0].get('clientId') != identifier:
            raise RuntimeError('Temporary service identity changed before retirement')
        value = {'realm': 'master', 'clients': [{'clientId': identifier, 'enabled': False}]}
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    path = target / 'master-retirement.json'
    path.write_text(json.dumps(value, sort_keys=True))
    path.chmod(0o600)


def prepare(directory, rp_id, private_directory=None, bootstrap_directory=None, health_directory=None, primary=False):
    if primary and (private_directory is None or bootstrap_directory is None):
        raise ValueError('Primary initialization requires complete private bootstrap inputs')
    source = credentials = revocations = None
    if private_directory is not None:
        # Missing/unreadable optional source is an error, never an empty import.
        private = Path(private_directory)
        source = json.loads((private / 'desired_state').read_text())
        credentials = json.loads((private / 'client_secrets').read_text())
        revocations = json.loads((private / 'revocations').read_text())
    documents = {realm: restrict_password_grants(compile_state(realm, rp_id, source, credentials, revocations))
                 for realm in REALMS}
    if bootstrap_directory is not None:
        if not primary:
            # Initialize machine access first; private people get creation-only
            # credentials in the explicit primary phase, before scoped imports.
            documents = {realm: restrict_password_grants(baseline(realm, rp_id)) for realm in REALMS}
        documents = {realm: bootstrap_writer(value, Path(bootstrap_directory).joinpath(realm + '_client_secret').read_text())
                     for realm, value in documents.items()}
        documents = {realm: bootstrap_health(value, Path(health_directory or bootstrap_directory).joinpath(realm + '_health_secret').read_text())
                     for realm, value in documents.items()}
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    for realm, value in documents.items():
        path = target / (realm + '.json')
        path.write_text(json.dumps(value, sort_keys=True))
        path.chmod(0o600)
    return documents


def private_request(url, token=None, form=None, accepted_statuses=(200,), *, method=None, with_status=False):
    import ssl
    import urllib.request
    import urllib.parse
    import urllib.error
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    headers = {'Accept': 'application/json', 'User-Agent': 'CloudLab-Identity-Reconciler/1.0'}
    data = None
    if token: headers['Authorization'] = 'Bearer ' + token
    if form is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(form).encode()
    try:
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            if error.code not in accepted_statuses: raise
            response = error
        with response:
            if response.status not in accepted_statuses: raise ValueError('Unexpected identity status')
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024: raise ValueError('Private identity response exceeds its limit')
        value = None if not raw and (response.status == 204 or with_status) else json.loads(raw)
        return (response.status, value) if with_status else value
    except Exception:
        raise RuntimeError('Private identity request failed; diagnostics withheld') from None


def _without_checksums(attributes):
    return {key: value for key, value in attributes.items()
            if not key.startswith('de.adorsys.keycloak.config.import-checksum-')}


def prepare_master(directory, admin_host, bootstrap_directory=None):
    # A separate bootstrap-only contract; private membership input cannot target master.
    private_origin = exact_url('https://' + admin_host + '/')[:-1]
    mfa = baseline('platform', admin_host)
    attributes = {}
    if bootstrap_directory is not None:
        credentials = Path(bootstrap_directory)
        token = private_request(private_origin + '/realms/master/protocol/openid-connect/token', form={
            'grant_type': 'password', 'client_id': 'admin-cli',
            'username': credentials.joinpath('username').read_text(),
            'password': credentials.joinpath('password').read_text()})['access_token']
        attributes = private_request(private_origin + '/admin/realms/master', token=token).get('attributes', {})
        if not isinstance(attributes, dict): raise ValueError('Master attributes must be a mapping')
    attributes = _without_checksums(attributes)
    value = {'realm': 'master', 'sslRequired': 'all', 'registrationAllowed': False,
             'resetPasswordAllowed': False, 'attributes': dict(attributes, frontendUrl=private_origin),
             'accessTokenLifespan': 300, 'ssoSessionIdleTimeout': 600, 'ssoSessionMaxLifespan': 600,
             'revokeRefreshToken': True, 'refreshTokenMaxReuse': 0,
             'browserFlow': mfa['browserFlow'], 'authenticationFlows': mfa['authenticationFlows'],
             'webAuthnPolicyRpId': admin_host, 'webAuthnPolicyRpEntityName': 'CloudLab master administration',
             'webAuthnPolicyUserVerificationRequirement': 'required',
             'eventsEnabled': True, 'eventsExpiration': 604800,
             'adminEventsEnabled': True, 'adminEventsDetailsEnabled': False}
    path = Path(directory) / 'master-bootstrap.json'
    path.write_text(json.dumps(value, sort_keys=True))
    path.chmod(0o600)


def initialize_primary(state, current, values):
    """Credentials are creation-only; existing people must never be adopted."""
    realm = state['realm']
    if realm not in ('master', 'platform'):
        raise ValueError('Primary initialization requires master or platform')
    username = name(values[realm + '_username'])
    password, marker, email = values[realm + '_password'], values['ownership_id'], values['email']
    if (not isinstance(password, str) or len(password) < 32 or not re.fullmatch('[a-f0-9]{32}', marker) or
            not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or values.get('email_verified') != 'true'):
        raise ValueError('Primary initialization requires complete verified private vault inputs')
    if not isinstance(current, list) or len(current) > 1 or any(row.get('username') != username for row in current):
        raise ValueError('Primary account lookup is ambiguous')
    result = copy.deepcopy(state)
    member = next((user for user in result.get('users', []) if user['username'] == username), None)
    if realm == 'platform' and (not member or '/platform-admin' not in member.get('groups', []) or member.get('enabled') is False):
        raise ValueError('Primary platform membership must be active and explicitly declared in the private source')
    if member is not None and 'email' in member:
        email = member['email']
    if current:
        if current[0].get('attributes', {}).get('cloudlab-primary-owner') != [marker]:
            raise ValueError('Primary initialization cannot adopt an unrelated existing account')
        return result
    if member is None:
        member = {'username': username, 'realmRoles': ['admin']}
        result.setdefault('users', []).append(member)
    member.update(enabled=True, email=email, emailVerified=member.get('emailVerified', True),
                  requiredActions=['webauthn-register'], attributes={'cloudlab-primary-owner': [marker]},
                  credentials=[{'type': 'password', 'value': password, 'temporary': False}])
    return result


def primary_profile(state, profile, attributes):
    if (not isinstance(profile, dict) or not isinstance(profile.get('attributes'), list) or
            not isinstance(attributes, dict) or len(profile['attributes']) > 1000 or
            any(not isinstance(row, dict) or not isinstance(row.get('name'), str) for row in profile['attributes']) or
            len({row['name'] for row in profile['attributes']}) != len(profile['attributes'])):
        raise ValueError('Complete unambiguous primary user profile is required')
    result = copy.deepcopy(state)
    result['attributes'] = dict(attributes)
    result['attributes'].update(state.get('attributes', {}))
    # Never feed the CLI's output checksum back into its next input checksum.
    result['attributes'] = _without_checksums(result['attributes'])
    result['attributes']['userProfileEnabled'] = 'true'
    result['userProfile'] = copy.deepcopy(profile)
    owned = {'name': 'cloudlab-primary-owner', 'multivalued': False,
             'permissions': {'view': ['admin'], 'edit': ['admin']},
             'validations': {'pattern': {'pattern': '[a-f0-9]{32}'}}}
    rows = result['userProfile']['attributes']
    for index, row in enumerate(rows):
        if row['name'] == owned['name']:
            rows[index] = owned
            break
    else:
        rows.append(owned)
    return result


def prepare_primary(directory, credentials_directory, bootstrap_directory, admin_host):
    from urllib.parse import urlencode
    credentials = Path(credentials_directory)
    fields = ('master_username', 'platform_username', 'master_password', 'platform_password',
              'ownership_id', 'email', 'email_verified')
    values = {field: credentials.joinpath(field).read_text() for field in fields}
    bootstrap = Path(bootstrap_directory)
    origin = exact_url('https://' + admin_host + '/')[:-1]
    token = private_request(origin + '/realms/master/protocol/openid-connect/token', form={
        'grant_type': 'password', 'client_id': 'admin-cli',
        'username': bootstrap.joinpath('username').read_text(),
        'password': bootstrap.joinpath('password').read_text()})['access_token']
    realms = private_request(origin + '/admin/realms', token=token)
    if not isinstance(realms, list) or len(realms) > 1000:
        raise ValueError('Primary realm inventory is unavailable or exceeds its bound')
    documents = {}
    for realm, filename in (('master', 'master-bootstrap.json'), ('platform', 'platform.json')):
        current = private_request(origin + '/admin/realms/' + realm + '/users?' + urlencode({
            'username': values[realm + '_username'], 'exact': 'true', 'max': 2}), token=token) if any(
                row.get('realm') == realm for row in realms) else []
        path = Path(directory) / filename
        state = primary_profile(json.loads(path.read_text()),
            private_request(origin + '/admin/realms/' + realm + '/users/profile', token=token),
            private_request(origin + '/admin/realms/' + realm, token=token).get('attributes', {}))
        documents[path] = initialize_primary(state, current, values)
        # Finish creation with credential-free canonical input, within the same Lease.
        documents[path.with_name(path.stem + '.steady.json')] = state
    # Validate both realms before writing either creation-only input.
    for path, document in documents.items():
        path.write_text(json.dumps(document, sort_keys=True))
        path.chmod(0o600)


def proof_user(state, current, values, nonce):
    """Create only the privately declared disposable viewer; never reset people."""
    if (not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{32}', nonce) or
            not isinstance(values, dict) or state.get('realm') != 'platform' or
            set(values) != {'username', 'password', 'email', 'ownership_id'} or
            values['username'] != 'proof-' + nonce or values['ownership_id'] != nonce or
            not isinstance(values['password'], str) or len(values['password']) < 48 or
            not isinstance(values['email'], str) or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', values['email'])):
        raise ValueError('Disposable enrollment requires exact vault ownership and private identity')
    members = [row for row in state.get('users', []) if row.get('username') == values['username']]
    if (len(members) != 1 or members[0].get('enabled') is False or
            '/viewer' not in members[0].get('groups', []) or
            any(group in members[0].get('groups', []) for group in ('/platform-admin', '/developer')) or
            members[0].get('email') != values['email'] or members[0].get('emailVerified') is not True):
        raise ValueError('Disposable enrollment requires an active private verified viewer membership')
    if (not isinstance(current, list) or len(current) > 1 or any(
            row.get('username') != values['username'] or
            row.get('attributes', {}).get('cloudlab-primary-owner') != [nonce]
            for row in current)):
        raise ValueError('Disposable enrollment cannot adopt an unrelated account')
    if current:
        return {'realm': 'platform', 'users': []}
    user = copy.deepcopy(members[0])
    user.update(enabled=True, requiredActions=['webauthn-register'],
                attributes={'cloudlab-primary-owner': [nonce]},
                credentials=[{'type': 'password', 'value': values['password'], 'temporary': False}])
    return {'realm': 'platform', 'users': [user]}


def prepare_proof_user(directory, nonce, admin_host):
    """Read-only validation; the serialized CLI performs the sole user write."""
    from urllib.parse import urlencode
    values = {key: Path('/proof-credentials', key).read_text()
              for key in ('username', 'password', 'email', 'ownership_id')}
    origin = exact_url('https://' + admin_host + '/')[:-1]
    token = private_request(origin + '/realms/platform/protocol/openid-connect/token', form={
        'grant_type': 'client_credentials', 'client_id': 'realm-writer',
        'client_secret': Path('/credentials/platform_client_secret').read_text()})['access_token']
    source = json.loads(Path('/private/desired_state').read_text())
    revoked = json.loads(Path('/private/revocations').read_text())
    credentials = json.loads(Path('/private/client_secrets').read_text())
    state = compile_state('platform', 'validation.invalid', source, credentials, revoked)
    current = private_request(origin + '/admin/realms/platform/users?' + urlencode({
        'username': 'proof-' + nonce, 'exact': 'true', 'max': 2}), token=token)
    document = proof_user(state, current, values, nonce)
    target = Path(directory, 'proof.json')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, sort_keys=True))
    target.chmod(0o600)


def prepare_removal(directory, realm, identifier, private_directory):
    if realm not in REALMS:
        raise ValueError('Removal requires a managed realm')
    identifier = name(identifier)
    private = Path(private_directory)
    source = json.loads((private / 'desired_state').read_text())
    registry = json.loads((private / 'revocations').read_text())
    if (source.get('format') != 1 or registry.get('format') != 1 or
            set(source.get('realms', {})) - set(REALMS) or set(registry.get('realms', {})) - set(REALMS)):
        raise ValueError('Removal requires current complete private inputs')
    denied = registry['realms'].get(realm, {})
    if identifier not in denied.get('clients', []) or identifier not in denied.get('removed_clients', []):
        raise ValueError('Removal requires a reviewed persistent tombstone')
    if any(c['id'] == identifier for c in source['realms'].get(realm, {}).get('clients', [])):
        raise ValueError('Stale source could recreate the client; removal refused')
    credentials = json.loads((private / 'client_secrets').read_text())
    for target_realm in REALMS:
        compile_state(target_realm, 'validation.invalid', source, credentials, registry)
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    for filename, value in [('seed', {'realm': realm, 'clients': [{'clientId': identifier, 'enabled': False}]}),
                            ('remove', {'realm': realm, 'clients': []})]:
        path = target / (filename + '.json')
        path.write_text(json.dumps(value, sort_keys=True))
        path.chmod(0o600)


def removal_inventory(directory, realm, identifier, admin_host):
    if realm not in REALMS:
        raise ValueError('Removal inventory requires a managed realm')
    identifier = name(identifier)
    exact_url('https://' + admin_host + '/')
    try:
        secret = Path('/credentials/' + realm + '_client_secret').read_text()
        token = private_request('https://' + admin_host + '/realms/' + realm + '/protocol/openid-connect/token',
                        form={'grant_type': 'client_credentials', 'client_id': 'realm-writer',
                              'client_secret': secret})['access_token']
        rows = private_request('https://' + admin_host + '/admin/realms/' + realm + '/clients?clientId=' + identifier, token=token)
        if not isinstance(rows, list) or len(rows) > 1 or any(row.get('clientId') != identifier for row in rows):
            raise ValueError('Ambiguous client inventory')
        if not rows:
            Path(directory).joinpath('skip').touch(mode=0o600)
        elif rows[0].get('enabled') is not False:
            raise ValueError('Client must already be disabled before removal')
    except Exception:
        raise RuntimeError('Scoped client inventory check failed; no client changes made') from None
