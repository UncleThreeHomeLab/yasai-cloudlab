"""Read versioned private intent with the existing scoped GitHub App."""
from contextlib import contextmanager
import json
import time
import yaml

from playbooks.secrets.files.vault import fields
from playbooks.argocd.files.github_app import app_token, verify_installation, public_metadata, PUBLIC_REPOSITORY
from playbooks.argocd.files.github_setup import GitHub, repository
from playbooks.keycloak.files.private_source import decode_contents

WRITER = None
READ_SECONDS = 180
CLEANUP_SECONDS = 30
METADATA_BYTES = 64 * 1024
CONTENTS_BYTES = 2 * 1024 * 1024


def _read(values, select, consume, *, deadline=None):
    deadline = deadline if deadline is not None else time.monotonic() + READ_SECONDS
    work_deadline = deadline - CLEANUP_SECONDS
    stage, failure, cleanup = 'configuration', None, 'not-issued'
    token, result = None, None
    try:
        selected = select()
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
        result = consume(client, repo, revision, selected)
        if time.monotonic() >= work_deadline:
            raise RuntimeError('Read deadline expired')
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


def read(values, *, include_revision=False, public=None):
    from playbooks.services.files.owner import configuration
    def select():
        return (configuration() if public is None else configuration(public))['catalogPath']
    def consume(client, repo, revision, selected):
        value = client.request('GET', 'repos/' + repo + '/contents/' + selected + '?ref=' + revision)
        catalog = yaml.safe_load(decode_contents(value))
        return (catalog, revision) if include_revision else catalog
    return _read(values, select, consume)


@contextmanager
def public_source_metadata(values, public_repository, *, deadline):
    """Use runner vault custody only after validating its original private scope."""
    private_repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
    public_repo = repository(public_repository)
    if (public_repository != PUBLIC_REPOSITORY or private_repo.casefold() == public_repo.casefold()
            or private_repo.split('/')[0].casefold() != public_repo.split('/')[0].casefold()):
        raise ValueError('Consumer requires its designated private repository')
    credentials = fields('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
    with public_metadata(credentials, deadline=deadline) as fetch:
        yield fetch


def read_consumer(values, consumer, *, public=None):
    """Authenticate public approval, then read its complete immutable private bundle."""
    from playbooks.argocd.files.private_sources import consumer_contract, accepted_consumer
    from playbooks.services.files.owner import configuration
    from playbooks.data.files.native import published_source, PrivateLoader
    import base64
    import hashlib
    deadline = time.monotonic() + READ_SECONDS
    try:
        coordinates = configuration()
        with public_source_metadata(values, coordinates['repository'], deadline=deadline) as fetch:
            current, public_revision = published_source({'publicSource': {'repository': coordinates['repository'], 'branch': 'main'}},
                deadline=deadline - CLEANUP_SECONDS, fetch=fetch)
        contract = consumer_contract(current, consumer)
        if public is not None and json.dumps(consumer_contract(public, consumer), sort_keys=True) != json.dumps(contract, sort_keys=True):
            raise ValueError('Consumer source context differs from current public authority')
        result = {'consumer': consumer, 'publicRevision': public_revision, 'proposalRevision': None, 'acceptedRevision': None,
            'acceptanceCommitment': contract['acceptanceCommitment'], 'acceptanceReceipt': None, 'inputs': {}}
        if time.monotonic() >= deadline - CLEANUP_SECONDS: raise RuntimeError('Read deadline expired')
        if not contract['enabled']: return result
        repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
        if repo.casefold() == repository(current['repository']).casefold(): raise ValueError('Private repository is required')
        if time.monotonic() >= deadline - CLEANUP_SECONDS: raise RuntimeError('Read deadline expired')
    except Exception as error:
        if isinstance(error, RuntimeError) and str(error).startswith('Public metadata '):
            raise RuntimeError(str(error)) from None
        raise RuntimeError('Private consumer read failed at configuration; token cleanup: not-issued') from None
    def consume(client, selected_repo, head, _):
        if selected_repo != repo: raise ValueError('Consumer source repository changed')
        accepted = accepted_consumer(client, values['PRIVATE_CONFIG_REPOSITORY'], head, current, consumer)
        documents = {}
        for path in contract['paths']:
            value = client.request('GET', 'repos/' + repo + '/contents/' + path + '?ref=' + accepted['acceptedRevision'])
            if (not isinstance(value, dict) or value.get('type') != 'file' or value.get('path') != path
                    or value.get('encoding') != 'base64' or type(value.get('size')) is not int or not 0 < value['size'] <= 1048576
                    or not isinstance(value.get('content'), str) or len(value['content']) > CONTENTS_BYTES): raise ValueError('Invalid consumer file')
            raw = base64.b64decode(value['content'].replace('\n', '').replace('\r', ''), validate=True)
            if len(raw) != value['size'] or hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != value.get('sha'):
                raise ValueError('Consumer file integrity changed')
            if consumer == 'permissions':
                # Native Git normalization and admission own permission semantics.
                documents[path] = {'sha': value['sha'], 'size': value['size']}
            else:
                document = yaml.load(raw, Loader=PrivateLoader)
                if not isinstance(document, dict): raise ValueError('Consumer input must be a complete document')
                documents[path] = document
        return dict(result, proposalRevision=head, inputs=documents, **accepted)
    return _read(values, lambda: None, consume, deadline=deadline)


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
