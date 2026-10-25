"""Issue short-lived, single-repository tokens from accepted local release Apps."""
from datetime import datetime
import re
import time

from playbooks.argocd.files.github_app import app_token
from playbooks.argocd.files.github_setup import GitHub, configuration
from playbooks.harbor.files.scopes import APPS, verify_app
from playbooks.secrets.files.vault import fields


def revoke(lease):
    try:
        GitHub(lease['token']).request('DELETE', 'installation/token')
    except RuntimeError as error:
        # An expired or already revoked installation token has no remaining access.
        if 'HTTP 401' not in str(error):
            raise


def issue(values, role, permissions, *, include_requester=False):
    if (role not in ('public-platform', 'private-config') or
            set(permissions) != {'contents', 'pull_requests'} or
            any(level not in ('read', 'write') for level in permissions.values())):
        raise ValueError('Repository token requires a designated role and bounded permissions')
    targets = {name: (repo, private) for name, repo, private in configuration(values)}
    repo, private = targets[role]
    title = 'github-release-' + ('private' if private else 'public')
    credentials = fields(title, ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
    verify_app(credentials, {repo: private}, APPS[title][1])
    issuer = GitHub(app_token(credentials))
    if include_requester:
        app = issuer.request('GET', 'app')
        if (str(app.get('id')) != credentials['APP_ID'] or
                not re.fullmatch(r'[A-Za-z0-9-]+', app.get('slug', ''))):
            raise ValueError('Repository App identity differs')
    issued = issuer.request('POST', 'app/installations/' + credentials['INSTALLATION_ID'] + '/access_tokens',
        {'repositories': [repo.split('/')[1]], 'permissions': permissions})
    lease = {'token': issued['token']}
    try:
        reader = GitHub(lease['token'])
        expected = dict(permissions, metadata='read')
        instant = datetime.fromisoformat(issued['expires_at'].replace('Z', '+00:00'))
        expires = int(instant.timestamp())
        if instant.tzinfo is None or not 0 < expires - int(time.time()) <= 3660 or issued.get('permissions') != expected:
            raise ValueError('Issued repository token lifetime or permissions differ')
        inventory = reader.request('GET', 'installation/repositories?per_page=100')
        rows = inventory.get('repositories', [])
        if (inventory.get('total_count') != 1 or len(rows) != 1 or
                rows[0].get('full_name') != repo or rows[0].get('private') is not private or
                type(rows[0].get('id')) is not int or rows[0]['id'] < 1 or
                any(rows[0].get(key) for key in ('fork', 'archived', 'disabled'))):
            raise ValueError('Issued repository token selection differs')
        lease.update(repository=repo, repositoryId=rows[0]['id'], permissions=expected, expiresAt=expires)
        if include_requester:
            lease['requester'] = app['slug'] + '[bot]'
        return lease
    except Exception:
        revoke(lease)
        raise RuntimeError('Repository token validation failed; private diagnostics withheld') from None
