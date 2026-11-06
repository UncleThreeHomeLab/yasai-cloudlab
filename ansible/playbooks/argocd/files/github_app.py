"""Verify the scoped Argo GitHub App without exposing credentials or repo names."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

try:
    from .github_setup import GitHub, repository
except ImportError:
    from github_setup import GitHub, repository

ROOT = next((parent for parent in Path(__file__).resolve().parents if (parent / 'platform').is_dir()), Path('/opt/cloudlab'))
ITEM = 'github-argocd'
FIELDS = ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY')
REPOSITORIES = ('PRIVATE_CONFIG_REPOSITORY',)
PUBLIC_READER = 'UncleThreeHomeLab/yasai-cloudlab'
PUBLIC_REPOSITORY = 'https://github.com/' + PUBLIC_READER + '.git'
PUBLIC_CLEANUP_SECONDS = 30
PUBLIC_METADATA_BYTES = 8 * 1024 * 1024


def app_token(credentials):
    if not all(credentials[field].isascii() and credentials[field].isdigit()
               for field in FIELDS[:2]):
        raise RuntimeError('GitHub App IDs must be numeric')
    pem = credentials['PRIVATE_KEY'].replace('\\n', '\n').strip()
    match = re.fullmatch(r'-----BEGIN (RSA )?PRIVATE KEY-----\s*(.*?)\s*-----END (RSA )?PRIVATE KEY-----', pem, re.S)
    if not match or match[1] != match[3]:
        raise RuntimeError('GitHub App requires one PEM private key')
    label = (match[1] or '') + 'PRIVATE KEY'
    body = re.sub(r'\s+', '', match[2])
    pem = '-----BEGIN ' + label + '-----\n' + body + '\n-----END ' + label + '-----\n'
    key = serialization.load_pem_private_key(pem.encode(), password=None)
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


def public_metadata_path(path):
    """Accept only fixed-repository metadata, never URLs or symbolic file refs."""
    prefix = 'repos/' + PUBLIC_READER + '/'
    if not isinstance(path, str) or not path.startswith(prefix):
        raise ValueError('Public metadata endpoint is outside the trusted reader role')
    suffix = path[len(prefix):]
    if not (suffix == 'branches/main' or
            re.fullmatch(r'git/commits/[a-f0-9]{40}', suffix) or
            re.fullmatch(r'git/trees/[a-f0-9]{40}[?]recursive=1', suffix) or
            re.fullmatch(r'contents/[A-Za-z0-9_./-]+[?]ref=[a-f0-9]{40}', suffix)):
        raise ValueError('Public metadata endpoint is outside the trusted reader role')
    if any(part in ('', '.', '..') for part in suffix.split('?')[0].split('/')):
        raise ValueError('Public metadata endpoint contains an unsafe path')
    return path


@contextmanager
def public_metadata(credentials, *, deadline):
    """One explicit fixed-role acquisition; successful cleanup precedes caller writes."""
    work_deadline = deadline - PUBLIC_CLEANUP_SECONDS
    token, client, stage, active = None, None, 'credentials', False
    try:
        try:
            if time.monotonic() >= work_deadline:
                raise RuntimeError('Public metadata acquisition expired')
            api = GitHub(app_token(credentials), deadline=work_deadline, max_response=PUBLIC_METADATA_BYTES)
            path = 'app/installations/' + credentials['INSTALLATION_ID']
            stage = 'installation'
            verify_installation(api.request('GET', path), credentials['APP_ID'])
            stage = 'issuance; token cleanup: issuance-unconfirmed'
            issued = api.request('POST', path + '/access_tokens', {
                'repositories': [PUBLIC_READER.split('/')[1]], 'permissions': {'contents': 'read'}})
            token = issued.get('token')
            if not isinstance(token, str) or not token or any(char in token for char in ('\n', '\r')):
                raise RuntimeError('Invalid public reader token')
            stage = 'token scope'
            expires = datetime.strptime(issued.get('expires_at', ''), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
            if (issued.get('permissions') != {'contents': 'read', 'metadata': 'read'} or
                    issued.get('repository_selection') != 'selected' or
                    not time.time() + max(0, work_deadline - time.monotonic()) < expires <= time.time() + 3660):
                raise RuntimeError('Public reader token scope or expiry differs')
            client = GitHub(token, deadline=work_deadline, max_response=PUBLIC_METADATA_BYTES)
            stage = 'public repository prerequisite'
            inventory = client.request('GET', 'installation/repositories?per_page=100')
            entries = inventory.get('repositories')
            if type(inventory.get('total_count')) is not int or inventory['total_count'] != 1 or not isinstance(entries, list) or len(entries) != 1:
                raise RuntimeError('Public reader requires exactly its trusted repository')
            entry = entries[0]
            if (not isinstance(entry, dict) or entry.get('full_name') != PUBLIC_READER or
                    any(entry.get(field) is not False for field in ('private', 'fork', 'archived', 'disabled')) or
                    entry.get('default_branch') != 'main'):
                raise RuntimeError('Public reader repository identity differs')
            active = True
        except Exception:
            raise RuntimeError('Public metadata acquisition failed at ' + stage +
                '; select the public repository in the existing read App before native handoff') from None
        def fetch(path, read_deadline):
            if not active:
                raise RuntimeError('Public metadata session is closed')
            path = public_metadata_path(path)
            client.deadline = min(work_deadline, read_deadline)
            try:
                return client.request('GET', path)
            except Exception:
                raise RuntimeError('Public metadata read failed; private diagnostics withheld') from None
        fetch.deadline = work_deadline
        yield fetch
        if time.monotonic() >= work_deadline:
            raise RuntimeError('Public metadata acquisition exceeded its deadline')
    finally:
        active = False
        if client is not None:
            client.token = ''
        if isinstance(token, str) and token:
            try:
                revoked = GitHub(token, deadline=min(deadline, time.monotonic() + PUBLIC_CLEANUP_SECONDS),
                    max_response=PUBLIC_METADATA_BYTES).request('DELETE', 'installation/token')
                if revoked is not None:
                    raise RuntimeError('Revocation was not acknowledged')
            except Exception:
                raise RuntimeError('Public metadata token cleanup: unconfirmed; writes blocked') from None
            if time.monotonic() > deadline:
                raise RuntimeError('Public metadata acquisition exceeded its deadline; token cleanup: revoked')


def verify(credentials, values):
    targets = {field: repository(values.get(field)) for field in REPOSITORIES}
    targets['PUBLIC_PLATFORM_REPOSITORY'] = PUBLIC_READER
    if len(set(value.lower() for value in targets.values())) != len(targets):
        raise RuntimeError('Private configuration repository inputs must be distinct')
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
    from dotenv import dotenv_values
    values = dotenv_values(ROOT / '.env', interpolate=False)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    from playbooks.secrets.files.vault import fields
    return verify(fields(ITEM, FIELDS), values)


def configuration_revision(values, *, read=None):
    """Read the actual configuration head with a disposable repository-scoped token."""
    from playbooks.secrets.files.vault import fields
    credentials = fields(ITEM, FIELDS)
    api = GitHub(app_token(credentials))
    path = 'app/installations/' + credentials['INSTALLATION_ID']
    verify_installation(api.request('GET', path), credentials['APP_ID'])
    repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
    token = api.request('POST', path + '/access_tokens', {
        'repositories': [repo.split('/')[1]], 'permissions': {'contents': 'read'}})['token']
    client = GitHub(token)
    try:
        current = client.request('GET', 'repos/' + repo)
        if (current.get('full_name', '').lower() != repo.lower() or current.get('private') is not True or
                current.get('fork') or current.get('archived') or current.get('disabled') or
                current.get('default_branch') != 'main'):
            raise RuntimeError('Private configuration repository identity or visibility differs')
        revision = client.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
        if not re.fullmatch('[a-f0-9]{40}', revision):
            raise RuntimeError('Private configuration head is invalid')
        return read(client, revision) if read else revision
    finally:
        client.request('DELETE', 'installation/token')


if __name__ == '__main__':
    try:
        print(json.dumps(main()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'GitHub App verification failed; private diagnostics withheld') from None
