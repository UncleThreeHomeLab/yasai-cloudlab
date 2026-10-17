"""Prepare the existing isolated Keycloak fixture for pinned Grafana OSS."""
import base64
import configparser
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from playbooks.keycloak.files.configuration import baseline, client
from playbooks.keycloak.tests.local_proof import request, administrator
from playbooks.observability.files.configuration import grafana
from playbooks.observability.tests.native_proof import wait

FIXTURE = Path('/fixture')


def write(name, value):
    path = FIXTURE / name
    path.write_text(value)
    os.chown(path, 1000, 1000)
    path.chmod(0o400)


def main():
    urllib.request.install_opener(urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile='/fixture/ca.crt'))))
    wait(administrator, seconds=240)
    token = administrator()
    request('/admin/realms', 'POST', baseline('platform', 'localhost'), token)
    settings = grafana('https://login.example.invalid/realms/platform', 'https://grafana.internal.example.invalid')
    secret = secrets.token_urlsafe(48)
    configured = client(settings['client'], {'grafana': secret})
    # Only fixture transport changes: production callback validation remains exact HTTPS/443.
    configured['redirectUris'] = ['https://localhost:3443/login/generic_oauth']
    configured['webOrigins'] = ['https://localhost:3443']
    configured['attributes']['post.logout.redirect.uris'] = 'https://localhost:3443/login'
    request('/admin/realms/platform/clients', 'POST', configured, token)
    groups = {row['name']: row['id'] for row in request('/admin/realms/platform/groups', token=token)}
    users = []
    for role, group in (('Admin', 'platform-admin'), ('Editor', 'developer'), ('Viewer', 'viewer'), ('Unmapped', None)):
        username, password = 'grafana-fixture-' + role.lower(), secrets.token_urlsafe(40)
        request('/admin/realms/platform/users', 'POST', {'username': username, 'enabled': True,
            'firstName': 'Fixture', 'lastName': role, 'email': username + '@example.invalid', 'emailVerified': True,
            'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}, token)
        uid = request('/admin/realms/platform/users?username=' + username + '&exact=true', token=token)[0]['id']
        if group: request('/admin/realms/platform/users/' + uid + '/groups/' + groups[group], 'PUT', token=token)
        users.append({'username': username, 'password': password, 'uid': uid, 'role': role})
    emergency = secrets.token_urlsafe(48)
    ini = settings['ini']
    ini['server'].update(root_url='https://localhost:3443', protocol='https', http_port=3443,
                         cert_file='/fixture/tls.crt', cert_key='/fixture/tls.key')
    ini['security'].update(admin_user='fixture-emergency', admin_password='$__file{/fixture/grafana_password}',
                           secret_key='$__file{/fixture/grafana_key}')
    ini['auth']['signout_redirect_url'] = 'https://localhost:8443/realms/platform/protocol/openid-connect/logout?post_logout_redirect_uri=https%3A%2F%2Flocalhost%3A3443%2Flogin'
    for key in ('auth_url', 'token_url', 'api_url'):
        ini['auth.generic_oauth'][key] = ini['auth.generic_oauth'][key].replace('https://login.example.invalid', 'https://localhost:8443')
    ini['auth.generic_oauth']['client_secret'] = '$__file{/fixture/grafana_client_secret}'
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_dict({section: {key: str(value).lower() if isinstance(value, bool) else str(value)
                               for key, value in fields.items()} for section, fields in ini.items()})
    import io
    stream = io.StringIO()
    parser.write(stream)
    write('grafana.ini', stream.getvalue())
    write('grafana_password', emergency)
    write('grafana_key', secrets.token_urlsafe(48))
    write('grafana_client_secret', secret)
    certificate = x509.load_pem_x509_certificate((FIXTURE / 'tls.crt').read_bytes())
    public = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public)
    write('grafana-browser.json', json.dumps({'users': users, 'emergency': emergency,
          'spki': base64.b64encode(digest.finalize()).decode()}))
    print(json.dumps({'fixture_prepared': True, 'production_credentials': False, 'role_mapping': 'unchanged'}))


def reset():
    """Reset only exact nonce-free local fixture users, never a supplied endpoint."""
    urllib.request.install_opener(urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile='/fixture/ca.crt'))))
    data = json.loads((FIXTURE / 'grafana-browser.json').read_text())
    token = administrator()
    configured = request('/admin/realms/platform/clients?clientId=grafana', token=token)
    if len(configured) != 1 or configured[0]['redirectUris'] != ['https://localhost:3443/login/generic_oauth']:
        raise RuntimeError('Local SSO fixture scope changed; reset refused')
    for user in data['users']:
        if user['username'] != 'grafana-fixture-' + user['role'].lower():
            raise RuntimeError('Local fixture user scope changed')
        actual = request('/admin/realms/platform/users/' + user['uid'], token=token)
        if actual['username'] != user['username']:
            raise RuntimeError('Local fixture user identity changed')
        for credential in request('/admin/realms/platform/users/' + user['uid'] + '/credentials', token=token):
            if credential['type'] == 'webauthn':
                request('/admin/realms/platform/users/' + user['uid'] + '/credentials/' + credential['id'], 'DELETE', token=token)
        request('/admin/realms/platform/users/' + user['uid'], 'PUT', {'enabled': True, 'requiredActions': []}, token)
        request('/admin/realms/platform/users/' + user['uid'] + '/logout', 'POST', token=token)
    print(json.dumps({'local_fixture_reset': True, 'passwords_preserved': True}))


if __name__ == '__main__':
    try: reset() if sys.argv[1:] == ['reset'] else main()
    except Exception:
        raise SystemExit('Isolated Grafana SSO preparation failed; private diagnostics withheld') from None
