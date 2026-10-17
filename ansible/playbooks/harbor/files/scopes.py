"""Validate App grants and exact repository boundaries without write-capable tokens."""
from playbooks.secrets.files.vault import fields
from playbooks.argocd.files.github_app import app_token
from playbooks.argocd.files.github_setup import GitHub, configuration

APPS = {
    'github-arc': (('private-fixture',), {'administration': 'write', 'metadata': 'read'}),
    'github-release-public': (('public-platform', 'public-fixture'),
                              {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read'}),
    'github-release-private': (('private-config', 'private-fixture'),
                               {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read'}),
}


def verify_app(credentials, expected, permissions):
    if not expected or len({repo.split('/')[0].lower() for repo in expected}) != 1:
        raise ValueError('App targets require one designated organization')
    api = GitHub(app_token(credentials))
    app = api.request('GET', 'app')
    path = 'app/installations/' + credentials['INSTALLATION_ID']
    installation = api.request('GET', path)
    owner = next(iter(expected)).split('/')[0].lower()
    if (str(app.get('id')) != credentials['APP_ID'] or app.get('permissions') != permissions or
            str(installation.get('app_id')) != credentials['APP_ID'] or
            installation.get('permissions') != permissions or installation.get('suspended_at') or
            installation.get('repository_selection') != 'selected' or
            installation.get('account', {}).get('login', '').lower() != owner or
            installation.get('target_type') != 'Organization'):
        raise RuntimeError('App registration/installation grants differ from the designated repository contract')
    token = api.request('POST', path + '/access_tokens', {'permissions': {'metadata': 'read'}})['token']
    client = GitHub(token)
    try:
        document = client.request('GET', 'installation/repositories?per_page=100')
        rows = document['repositories']
        actual = {row['full_name'].lower(): row['private'] for row in rows}
        if (document['total_count'] != len(expected) or len(rows) != len(expected) or
                actual != {repo.lower(): private for repo, private in expected.items()} or
                any(row.get('fork') or row.get('archived') or row.get('disabled') for row in rows)):
            raise RuntimeError('App repository selection/visibility differs from its designated targets')
        return {'permissions_verified': True, 'repositories_verified': len(expected),
                'write_capable_token_created': False}
    finally:
        client.request('DELETE', 'installation/token')


def verify(values):
    targets = {role: (repo, private) for role, repo, private in configuration(values)}
    result, identities = {}, set()
    for title, (roles, permissions) in APPS.items():
        credentials = fields(title, ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
        if credentials['APP_ID'] in identities:
            raise RuntimeError('ARC and public/private release identities must be distinct')
        identities.add(credentials['APP_ID'])
        try:
            result[title] = verify_app(credentials, dict(targets[role] for role in roles), permissions)
        except RuntimeError:
            raise RuntimeError(title + ' scope verification failed; existing grants retained') from None
    return result
