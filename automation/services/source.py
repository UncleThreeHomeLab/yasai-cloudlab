"""Read versioned private intent with the existing scoped GitHub App."""
import json

from automation.credentials.vault import fields
from automation.gitops.github_app import app_token, verify_installation
from automation.gitops.github_setup import GitHub, repository
from automation.identity.private_source import decode_contents

WRITER = None


def read(values):
    credentials = fields('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
    api = GitHub(app_token(credentials))
    path = 'app/installations/' + credentials['INSTALLATION_ID']
    verify_installation(api.request('GET', path), credentials['APP_ID'])
    repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
    token = api.request('POST', path + '/access_tokens', {
        'repositories': [repo.split('/')[1]], 'permissions': {'contents': 'read'}})['token']
    client = GitHub(token)
    try:
        revision = client.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
        value = client.request('GET', 'repos/' + repo + '/contents/services/catalog.json?ref=' + revision)
        return json.loads(decode_contents(value))
    finally:
        client.request('DELETE', 'installation/token')


def publish(value, *, expected=None):
    global WRITER
    from automation.gitops.github_setup import inputs
    from automation.gitops.private_publish import publish as publish_owned
    if WRITER is None: WRITER = inputs()
    values, api = WRITER
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    current = api.request('GET', 'repos/' + repo + '/contents/services/catalog.json?ref=main', missing=True)
    before = json.loads(decode_contents(current)) if current else None
    if expected is not None and before != expected:
        raise RuntimeError('Private catalog advanced; reread its complete input before changing publication intent')
    if before:
        old = {row['approval']['name']: row for row in before['catalog']}
        new = {row['approval']['name']: row for row in value['catalog']}
        if set(old) - set(new):
            raise ValueError('Service catalog records must remain as explicit retired intent')
        for name, row in old.items():
            for kind, request in row['definition']['data'].items():
                if new[name]['definition']['data'].get(kind) != request:
                    raise ValueError('Existing service data requests must be retained')
    result = publish_owned(api, values, {'services/catalog.json': json.dumps(value, sort_keys=True, indent=2) + '\n'}, scope='services')
    if result['private_source_changed']:
        pull = api.request('GET', 'repos/' + repo + '/pulls/' + str(result['private_pull_request']))
        merged = api.request('PUT', 'repos/' + repo + '/pulls/' + str(pull['number']) + '/merge',
                             {'sha': pull['head']['sha'], 'merge_method': 'squash'})
        if not merged.get('merged'):
            raise RuntimeError('Reviewed private catalog PR requires its protected merge before publication can continue')
        result['private_source_merged'] = True
    return result
