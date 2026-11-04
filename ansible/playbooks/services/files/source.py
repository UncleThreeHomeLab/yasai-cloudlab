"""Read versioned private intent with the existing scoped GitHub App."""
import json
import yaml

from playbooks.secrets.files.vault import fields
from playbooks.argocd.files.github_app import app_token, verify_installation
from playbooks.argocd.files.github_setup import GitHub, repository
from playbooks.keycloak.files.private_source import decode_contents

WRITER = None


def read(values, *, include_revision=False):
    from playbooks.services.files.owner import configuration
    selected_path = configuration()['catalogPath']
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
        value = client.request('GET', 'repos/' + repo + '/contents/' + selected_path + '?ref=' + revision)
        catalog = yaml.safe_load(decode_contents(value))
        return (catalog, revision) if include_revision else catalog
    finally:
        client.request('DELETE', 'installation/token')


def publish(value, *, expected=None):
    global WRITER
    from playbooks.services.files.contract import ROOT
    from playbooks.services.files.inputs import validate_catalog
    from playbooks.services.files.owner import configuration
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    selected_path = configuration(public)['catalogPath']
    value = validate_catalog(value, public=public)
    from playbooks.argocd.files.github_setup import inputs
    from playbooks.argocd.files.private_publish import publish as publish_owned
    if WRITER is None: WRITER = inputs()
    values, api = WRITER
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    base = api.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
    current = api.request('GET', 'repos/' + repo + '/contents/' + selected_path + '?ref=' + base, missing=True)
    before = yaml.safe_load(decode_contents(current)) if current else None
    if expected is not None and before != expected:
        raise RuntimeError('Private catalog advanced; reread its complete input before changing publication intent')
    if before:
        old = {row['approval']['name']: row for row in before['catalog']}
        new = {row['approval']['name']: row for row in value['catalog']}
        if set(old) - set(new):
            raise ValueError('Service catalog records must remain as explicit retired intent')
        for name, row in old.items():
            from playbooks.services.files.contract import exposure_bindings
            if row['publication'] == 'published' and exposure_bindings(row['definition']) != exposure_bindings(new[name]['definition']):
                raise ValueError('Published exposure changes require retirement and explicit migration')
            for kind, request in row['definition']['data'].items():
                if new[name]['definition']['data'].get(kind) != request:
                    raise ValueError('Existing service data requests must be retained')
    content = (yaml.safe_dump(value, sort_keys=False) if selected_path.endswith('.yaml') else
               json.dumps(value, sort_keys=True, indent=2) + '\n')
    result = publish_owned(api, values, {selected_path: content}, scope='services', expected_base=base)
    if result['private_source_changed']:
        pull = api.request('GET', 'repos/' + repo + '/pulls/' + str(result['private_pull_request']))
        merged = api.request('PUT', 'repos/' + repo + '/pulls/' + str(pull['number']) + '/merge',
                             {'sha': pull['head']['sha'], 'merge_method': 'squash'})
        if not merged.get('merged'):
            raise RuntimeError('Reviewed private catalog PR requires its protected merge before publication can continue')
        result['private_source_merged'] = True
    return result
