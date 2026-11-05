"""Read versioned private intent with the existing scoped GitHub App."""
import json
import time
import yaml

from playbooks.secrets.files.vault import fields
from playbooks.argocd.files.github_app import app_token, verify_installation
from playbooks.argocd.files.github_setup import GitHub, repository
from playbooks.keycloak.files.private_source import decode_contents

WRITER = None
READ_SECONDS = 180
CLEANUP_SECONDS = 30
METADATA_BYTES = 64 * 1024
CONTENTS_BYTES = 2 * 1024 * 1024


def read(values, *, include_revision=False):
    from playbooks.services.files.owner import configuration
    deadline = time.monotonic() + READ_SECONDS
    work_deadline = deadline - CLEANUP_SECONDS
    stage, failure, cleanup = 'configuration', None, 'not-issued'
    token, result = None, None
    try:
        selected_path = configuration()['catalogPath']
        stage = 'credentials'
        credentials = fields('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
        if time.monotonic() >= work_deadline:
            raise RuntimeError('Read deadline expired')
        api = GitHub(app_token(credentials), deadline=work_deadline, max_response=METADATA_BYTES)
        path = 'app/installations/' + credentials['INSTALLATION_ID']
        stage = 'installation'
        verify_installation(api.request('GET', path), credentials['APP_ID'])
        repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
        if time.monotonic() >= work_deadline:
            raise RuntimeError('Read deadline expired')
        stage, cleanup = 'issuance', 'issuance-unconfirmed'
        token = api.request('POST', path + '/access_tokens', {
            'repositories': [repo.split('/')[1]], 'permissions': {'contents': 'read'}})['token']
        if not isinstance(token, str) or not token:
            raise RuntimeError('Invalid read credential')
        stage = 'catalog'
        client = GitHub(token, deadline=work_deadline, max_response=METADATA_BYTES)
        revision = client.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
        client = GitHub(token, deadline=work_deadline, max_response=CONTENTS_BYTES)
        value = client.request('GET', 'repos/' + repo + '/contents/' + selected_path + '?ref=' + revision)
        catalog = yaml.safe_load(decode_contents(value))
        if time.monotonic() >= work_deadline:
            raise RuntimeError('Read deadline expired')
        result = (catalog, revision) if include_revision else catalog
        stage = 'complete'
    except Exception:
        failure = stage
    finally:
        if isinstance(token, str) and token:
            cleanup = 'unconfirmed'
            try:
                # Revocation retains its reserved budget after the read expires.
                revoked = GitHub(token, deadline=min(deadline, time.monotonic() + CLEANUP_SECONDS), max_response=METADATA_BYTES).request(
                    'DELETE', 'installation/token')
                if revoked is not None:
                    raise RuntimeError('Token revocation was not acknowledged')
                cleanup = 'revoked'
            except Exception:
                state = 'complete' if stage == 'complete' else 'failed at ' + stage
                raise RuntimeError('Private catalog read: ' + state + '; token cleanup: unconfirmed') from None
    if time.monotonic() > deadline:
        failure = failure or 'deadline'
    if failure is not None:
        raise RuntimeError('Private catalog read failed at ' + failure + '; token cleanup: ' + cleanup) from None
    return result


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
