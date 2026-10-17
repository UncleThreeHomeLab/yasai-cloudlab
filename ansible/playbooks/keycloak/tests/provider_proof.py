"""Native provider experiment on the disposable identity server only."""
import copy
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from playbooks.keycloak.files.configuration import client
from playbooks.keycloak.tests.local_proof import administrator, request, login, SERVER
from playbooks.keycloak.files.tokens import access_token

WORK = Path('/candidate')
ROOT = '/admin/realms/applications'


def tofu(*arguments, expected=0):
    result = subprocess.run(['tofu', *arguments, '-no-color'], cwd=WORK,
                            capture_output=True, text=True)
    if result.returncode != expected:
        (WORK / 'private-error').write_text(result.stderr)
        summary = next((line for line in result.stderr.splitlines() if line.startswith('Error:')), 'No error summary')
        raise RuntimeError('Native fixture command failed: ' + arguments[0] + ': ' + summary)
    return result.stdout


def plan():
    result = subprocess.run(['tofu', 'plan', '-input=false', '-out=check.tfplan', '-no-color'],
                            cwd=WORK, capture_output=True, text=True)
    if result.returncode:
        (WORK / 'private-error').write_text(result.stderr)
        raise RuntimeError('Native fixture plan failed; private diagnostics withheld')
    return json.loads(tofu('show', '-json', 'check.tfplan'))


def actions(document):
    return {r['address']: r['change']['actions'] for r in document.get('resource_changes', [])
            if r['change']['actions'] != ['no-op']}


def main():
    os.umask(0o077)
    # Endpoints, credentials and scope cannot be supplied by callers.
    urllib.request.install_opener(urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile='/fixture/ca.crt'))))
    version = json.loads(tofu('version', '-json'))['terraform_version']
    if version != '1.13.1':
        raise RuntimeError('Unexpected OpenTofu fixture version')
    provider = {'keycloak': {'url': SERVER, 'client_id': 'admin-cli',
                            'username': 'fixture-admin', 'password': 'fixture-only-isolated-admin',
                            'root_ca_certificate': '${file("/fixture/ca.crt")}'}}
    secret = secrets.token_urlsafe(48)
    for existing in request(ROOT + '/clients?clientId=provider-fixture', token=administrator()):
        request(ROOT + '/clients/' + existing['id'], 'DELETE', token=administrator())
    desired = client({'id': 'provider-fixture', 'public': False, 'audience': 'reference-api',
                      'callbacks': ['https://reference.example.invalid/callback'],
                      'roles': ['reader']}, {'provider-fixture': secret})
    request(ROOT + '/clients', 'POST', desired, administrator())
    current = request(ROOT + '/clients?clientId=provider-fixture', token=administrator())[0]
    identifier = current['id']
    request(ROOT + '/clients/' + identifier + '/roles', 'POST', {'name': 'reader'}, administrator())
    role = request(ROOT + '/clients/' + identifier + '/roles/reader', token=administrator())
    password = secrets.token_urlsafe(32)
    for user in request(ROOT + '/users?username=provider-reader&exact=true', token=administrator()):
        request(ROOT + '/users/' + user['id'], 'DELETE', token=administrator())
    request(ROOT + '/users', 'POST', {'username': 'provider-reader', 'enabled': True,
            'firstName': 'Provider', 'lastName': 'Reader', 'email': 'provider@example.invalid',
            'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}, administrator())
    user = request(ROOT + '/users?username=provider-reader&exact=true', token=administrator())[0]
    for group in request(ROOT + '/groups?search=provider-readers&exact=true', token=administrator()):
        if group['name'] == 'provider-readers':
            request(ROOT + '/groups/' + group['id'], 'DELETE', token=administrator())
    request(ROOT + '/groups', 'POST', {'name': 'provider-readers'}, administrator())
    group = next(g for g in request(ROOT + '/groups?search=provider-readers', token=administrator())
                 if g['name'] == 'provider-readers')
    request(ROOT + '/groups/' + group['id'] + '/role-mappings/clients/' + identifier,
            'POST', [role], administrator())
    viewer = request(ROOT + '/roles/viewer', token=administrator())
    request(ROOT + '/groups/' + group['id'] + '/role-mappings/realm', 'POST', [viewer], administrator())
    request(ROOT + '/users/' + user['id'] + '/groups/' + group['id'], 'PUT', token=administrator())
    users = request(ROOT + '/users', token=administrator())
    signing = request('/realms/applications/protocol/openid-connect/certs')
    flows = request(ROOT + '/authentication/flows', token=administrator())
    resource = {
        'keycloak_realm': {'fixture': {'realm': 'applications', 'enabled': True,
                                      'display_name': 'applications', 'ssl_required': 'all'}},
        'keycloak_openid_client': {'fixture': {
            'realm_id': 'applications', 'client_id': 'provider-fixture', 'enabled': True,
            'access_type': 'CONFIDENTIAL', 'client_secret': secret,
            'standard_flow_enabled': True, 'implicit_flow_enabled': False,
            'direct_access_grants_enabled': False, 'service_accounts_enabled': False,
            'full_scope_allowed': False, 'pkce_code_challenge_method': 'S256',
            'valid_redirect_uris': desired['redirectUris'], 'web_origins': [],
            'access_token_lifespan': '300', 'client_session_idle_timeout': '600',
            'client_session_max_lifespan': '600', 'use_refresh_tokens': True}},
        'keycloak_role': {'reader': {'realm_id': 'applications',
                                    'client_id': '${keycloak_openid_client.fixture.id}', 'name': 'reader'}},
        'keycloak_group': {'readers': {'realm_id': 'applications', 'name': 'provider-readers'}},
        'keycloak_group_roles': {'readers': {'realm_id': 'applications',
            'group_id': '${keycloak_group.readers.id}', 'exhaustive': False,
            'role_ids': ['${keycloak_role.reader.id}']}},
        'keycloak_generic_protocol_mapper': {
            m['name']: {'realm_id': 'applications', 'client_id': '${keycloak_openid_client.fixture.id}', 'name': m['name'],
                        'protocol': m['protocol'], 'protocol_mapper': m['protocolMapper'], 'config': m['config']}
            for m in current['protocolMappers']},
        'keycloak_openid_client_default_scopes': {'fixture': {
            'realm_id': 'applications', 'client_id': '${keycloak_openid_client.fixture.id}', 'default_scopes': ['basic', 'profile']}},
        'keycloak_openid_client_optional_scopes': {'fixture': {
            'realm_id': 'applications', 'client_id': '${keycloak_openid_client.fixture.id}', 'optional_scopes': []}},
    }
    configuration = {'provider': provider, 'resource': resource}
    path = WORK / 'main.tf.json'
    path.write_text(json.dumps(configuration))
    imports = {'keycloak_realm.fixture': 'applications',
               'keycloak_openid_client.fixture': 'applications/' + identifier,
               'keycloak_role.reader': 'applications/' + role['id'],
               'keycloak_group.readers': 'applications/' + group['id'],
               'keycloak_group_roles.readers': 'applications/' + group['id'],
               'keycloak_openid_client_default_scopes.fixture': 'applications/' + identifier,
               'keycloak_openid_client_optional_scopes.fixture': 'applications/' + identifier}
    imports.update({'keycloak_generic_protocol_mapper.' + m['name']:
                    'applications/client/' + identifier + '/' + m['id'] for m in current['protocolMappers']})
    for address, remote in imports.items():
        tofu('import', '-input=false', address, remote)
    initial = plan()
    realm_change = next(r['change'] for r in initial['resource_changes'] if r['address'] == 'keycloak_realm.fixture')
    realm_differences = sorted(k for k, v in realm_change['before'].items()
                               if v != realm_change['after'].get(k))
    # An incomplete realm declaration must never be applied to hide the parity gap.
    tofu('state', 'rm', 'keycloak_realm.fixture')
    del resource['keycloak_realm']
    path.write_text(json.dumps(configuration))
    imported = plan()
    initial_differences = {r['address']: sorted(k for k, v in (r['change'].get('before') or {}).items()
                       if v != (r['change'].get('after') or {}).get(k))
                       for r in imported.get('resource_changes', []) if r['change']['actions'] != ['no-op']}
    if actions(imported):
        tofu('apply', '-input=false', '-auto-approve', 'check.tfplan')
    imported_repeat = actions(plan())
    state = tofu('show', '-json')
    if secret not in state:
        raise RuntimeError('Expected confidential secret state exposure was not observed')
    def preserved():
        if (request(ROOT + '/users', token=administrator()) != users or
                request('/realms/applications/protocol/openid-connect/certs') != signing or
                request(ROOT + '/authentication/flows', token=administrator()) != flows):
            raise RuntimeError('Provider changed users, signing keys or authentication flows')
    preserved()
    changed = copy.deepcopy(current)
    changed['redirectUris'] = ['https://drift.example.invalid/callback']
    changed['attributes']['pkce.code.challenge.method'] = 'plain'
    request(ROOT + '/clients/' + identifier, 'PUT', changed, administrator())
    if actions(plan()).get('keycloak_openid_client.fixture') != ['update']:
        raise RuntimeError('Client drift was not detected as in-place update')
    tofu('apply', '-input=false', '-auto-approve', 'check.tfplan')
    repaired = request(ROOT + '/clients/' + identifier, token=administrator())
    if repaired['id'] != identifier or repaired['redirectUris'] != desired['redirectUris'] or repaired['attributes']['pkce.code.challenge.method'] != 'S256':
        raise RuntimeError('Client identity/redirect/PKCE drift repair failed')
    if request(ROOT + '/clients/' + identifier + '/client-secret', token=administrator())['value'] != secret:
        raise RuntimeError('Import/update replaced the confidential secret')
    if request(ROOT + '/clients/' + identifier + '/roles/reader', token=administrator())['id'] != role['id']:
        raise RuntimeError('Import/update replaced the role identity')
    unrelated_grant_preserved = viewer['id'] in {r['id'] for r in request(
            ROOT + '/groups/' + group['id'] + '/role-mappings/realm', token=administrator())}
    if not unrelated_grant_preserved:
        # Restore only the disposable grant so remaining lifecycle tests can run.
        request(ROOT + '/groups/' + group['id'] + '/role-mappings/realm', 'POST', [viewer], administrator())
    repeat = actions(plan())
    # Operational rotation/disable are distinct writes: stale provider input must detect them.
    before_rotation = login(password, 'provider-fixture', secret, username='provider-reader')
    rotated = request(ROOT + '/clients/' + identifier + '/client-secret', 'POST', token=administrator())['value']
    try:
        request('/realms/applications/protocol/openid-connect/token', 'POST', {
                'grant_type': 'refresh_token', 'client_id': 'provider-fixture', 'client_secret': secret,
                'refresh_token': before_rotation['refresh_token']}, form=True)
    except urllib.error.HTTPError as error:
        if error.code not in (400, 401):
            raise
    else:
        raise RuntimeError('Retired native fixture credential refreshed tokens')
    rotation = actions(plan())
    if rotation.get('keycloak_openid_client.fixture') != ['update']:
        raise RuntimeError('Operational rotation interaction was not detected')
    resource['keycloak_openid_client']['fixture']['client_secret'] = rotated
    path.write_text(json.dumps(configuration))
    rotation_repeat = actions(plan())
    if 'keycloak_openid_client.fixture' in rotation_repeat:
        raise RuntimeError('Updated vault-equivalent rotation input did not converge')
    issued = login(password, 'provider-fixture', rotated, username='provider-reader')
    claims = access_token(issued['access_token'], signing, SERVER + '/realms/applications', 'reference-api', 'reader')
    for audience, required_role in (('wrong-api', 'reader'), ('reference-api', 'denied')):
        try:
            access_token(issued['access_token'], signing, SERVER + '/realms/applications', audience, required_role)
        except ValueError:
            continue
        raise RuntimeError('Provider-managed client lost audience/role denial')
    try:
        login(password, 'provider-fixture', rotated, invalid_verifier=True, username='provider-reader')
    except urllib.error.HTTPError as error:
        if error.code != 400:
            raise
    else:
        raise RuntimeError('Provider-managed client accepted invalid PKCE')
    repaired = request(ROOT + '/clients/' + identifier, token=administrator())
    repaired['enabled'] = False
    request(ROOT + '/clients/' + identifier, 'PUT', repaired, administrator())
    if actions(plan()).get('keycloak_openid_client.fixture') != ['update']:
        raise RuntimeError('Stale enabled input did not expose revocation conflict')
    resource['keycloak_openid_client']['fixture']['enabled'] = False
    path.write_text(json.dumps(configuration))
    disabled_repeat = actions(plan())
    if 'keycloak_openid_client.fixture' in disabled_repeat:
        raise RuntimeError('Persistent disabled input did not preserve revocation')
    try:
        request('/realms/applications/protocol/openid-connect/token', 'POST', {
                'grant_type': 'refresh_token', 'client_id': 'provider-fixture', 'client_secret': rotated,
                'refresh_token': issued['refresh_token']}, form=True)
    except urllib.error.HTTPError as error:
        if error.code not in (400, 401):
            raise
    else:
        raise RuntimeError('Provider fixture disabled client refreshed tokens')
    preserved()
    tofu('destroy', '-input=false', '-auto-approve')
    if request(ROOT + '/clients?clientId=provider-fixture', token=administrator()):
        raise RuntimeError('Disposable client delete did not remove the imported client')
    if not request(ROOT + '/clients?clientId=rotation-fixture', token=administrator()):
        raise RuntimeError('Disposable delete damaged an unrelated client')
    preserved()
    print(json.dumps({'opentofu': version, 'provider': 'keycloak/keycloak@5.10.0', 'api': 'Keycloak 26.8.0',
                      'imported_resources': len(imports), 'realm_default_differences': realm_differences,
                      'initial_static_differences': initial_differences,
                      'static_repeat_actions': imported_repeat,
                      'drift_repeat_actions': repeat, 'ids_and_secret_preserved': True,
                      'in_place_drift_repair': True, 'secret_in_state': True,
                      'stale_rotation_and_revocation_conflict': True,
                      'updated_client_operational_inputs_repeat_empty': True,
                      'additive_group_role_mapping_preserved_unrelated_grant': unrelated_grant_preserved,
                      'native_client_code_pkce_audience_role_and_refresh_denial': True,
                      'users_flows_signing_preserved': True, 'bounded_delete': True,
                      'scope': 'isolated Compose only; bootstrap admin, not scoped production credentials'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Native identity fixture failed; private diagnostics withheld') from None
    finally:
        # Raw provider state and plans contain disposable credentials; never export them.
        for name in ('main.tf.json', 'check.tfplan', 'terraform.tfstate', 'terraform.tfstate.backup'):
            (WORK / name).unlink(missing_ok=True)
