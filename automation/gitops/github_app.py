"""Verify the scoped Argo GitHub App without exposing credentials or repo names."""
import base64
import json
import os
from pathlib import Path
import sys
import time
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import dotenv_values

from github_setup import GitHub, repository

ROOT = Path(__file__).resolve().parents[2]
ITEM = 'github-argocd'
FIELDS = ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY')
REPOSITORIES = ('PRIVATE_CONFIG_REPOSITORY', 'PRIVATE_TEST_REPOSITORY')


def app_token(credentials):
    if not all(credentials[field].isascii() and credentials[field].isdigit()
               for field in FIELDS[:2]):
        raise RuntimeError('GitHub App IDs must be numeric')
    key = serialization.load_pem_private_key(credentials['PRIVATE_KEY'].encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise RuntimeError('GitHub App requires an RSA key of at least 2048 bits')
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
    now = int(time.time())
    message = encode({'alg': 'RS256', 'typ': 'JWT'}) + b'.' + encode(
        {'iat': now - 60, 'exp': now + 540, 'iss': credentials['APP_ID']})
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return (message + b'.' + base64.urlsafe_b64encode(signature).rstrip(b'=')).decode()


def verify_installation(installation, app_id):
    if (str(installation.get('app_id')) != app_id or
            installation.get('repository_selection') != 'selected' or
            installation.get('suspended_at') or
            installation.get('permissions') != {'contents': 'read', 'metadata': 'read'}):
        raise RuntimeError('App installation must select repositories and grant only Contents/Metadata read access')


def verify_repositories(document, targets):
    visible = {entry['full_name'].lower() for entry in document['repositories']}
    if document['total_count'] > 100:
        raise RuntimeError('App installation exceeds the supported 100-repository verification limit')
    missing = [field for field, target in targets.items() if target.lower() not in visible]
    if missing:
        raise RuntimeError('App installation lacks access to designated inputs: ' + ', '.join(missing))
    return {'app_key_valid': True, 'permissions_read_only': True,
            'designated_repositories_verified': len(targets)}


def verify(credentials, values):
    targets = {field: repository(values.get(field)) for field in REPOSITORIES}
    if len(set(value.lower() for value in targets.values())) != len(targets):
        raise RuntimeError('Private configuration and test repositories must be distinct')
    api = GitHub(app_token(credentials))
    path = 'app/installations/' + credentials['INSTALLATION_ID']
    verify_installation(api.request('GET', path), credentials['APP_ID'])
    token = api.request('POST', path + '/access_tokens', {'permissions': {'contents': 'read'}})['token']
    client = GitHub(token)
    try:
        return verify_repositories(client.request('GET', 'installation/repositories?per_page=100'), targets)
    finally:
        # Revoke this disposable token even when repository checks fail.
        request = urllib.request.Request('https://api.github.com/installation/token', method='DELETE',
            headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
        with client.opener.open(request, timeout=30) as response:
            if response.status != 204:
                raise RuntimeError('Disposable App token revocation failed')


def main():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    sys.path.insert(0, str(ROOT / 'automation/credentials'))
    from vault import fields
    return verify(fields(ITEM, FIELDS), values)


if __name__ == '__main__':
    try:
        print(json.dumps(main()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'GitHub App verification failed; private diagnostics withheld') from None
