"""Explicit fixture journal and catalog deltas; no automatic service operations."""
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from urllib.parse import quote

from playbooks.previews.files.contract import canonical, digest, names, runtime_catalog, repository as validate_repository
from playbooks.keycloak.files.private_source import decode_contents
from playbooks.argocd.files.github_setup import GitHubHTTPError

JOURNALS = Path('/recovery/previews')


def inspect(api, repository):
    validate_repository(repository)
    prefix = 'repos/' + repository
    revision = api.request('GET', prefix + '/git/ref/heads/main')['object']['sha']
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Fixture inspection requires an exact main revision')
    blob = api.request('GET', prefix + '/contents/previews/catalog.json?ref=' + revision, missing=True)
    if blob is None:
        return {'revision': revision, 'blob': None, 'raw': None, 'catalog': None}
    raw = decode_contents(blob)
    expected = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if blob.get('sha') != expected:
        raise ValueError('Fixture catalog bytes do not match the inspected Git blob')
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {'catalog'}:
        raise ValueError('Fixture catalog document differs from its owning schema')
    runtime_catalog(value['catalog'])
    return {'revision': revision, 'blob': expected, 'raw': base64.b64encode(raw).decode(), 'catalog': value['catalog']}


def journal(path, value, *, expected=None):
    """Durable Linux-volume journal; CAS updates cannot overwrite another observation."""
    target = Path(path)
    if (target.name != 'journal.json' or target.parent.parent != JOURNALS or
            not re.fullmatch('[a-f0-9]{32}', target.parent.name)):
        raise ValueError('Fixture journal requires its nonce-owned recovery directory')
    if JOURNALS.is_symlink() or target.parent.is_symlink() or target.is_symlink():
        raise ValueError('Fixture journal has conflicting filesystem ownership')
    JOURNALS.mkdir(exist_ok=True, mode=0o700)
    target.parent.mkdir(exist_ok=True, mode=0o700)
    lock = os.open(target.parent / 'journal.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = target.read_bytes() if target.exists() else None
        if (expected is None and previous is not None) or (expected is not None and (
                previous is None or digest(previous) != expected)):
            raise ValueError('Fixture journal advanced; overwrite refused')
        temporary = target.with_name(target.name + '.' + secrets.token_hex(8))
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(value, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            for path in (target.parent, JOURNALS, JOURNALS.parent):
                directory = os.open(path, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return digest(target.read_bytes())
    finally:
        os.close(lock)


def entries(settings, instances):
    if any(not re.fullmatch('[a-f0-9]{32}', instance) for instance in instances):
        raise ValueError('Fixture instances must be immutable nonces')
    rows = {row['instance']: row for row in settings['approvals']}
    return {instance: {'approval': copy.deepcopy(rows.get(instance)),
        'ownership': settings['ownership'].get('cloudlab-preview-' + instance)} for instance in instances}


def require_fixture_only(settings, owned):
    """Task-driven activation must never activate an unrelated catalog entry."""
    runtime_catalog(settings)
    if (any(row['instance'] not in owned for row in settings['approvals']) or
            any(namespace != 'cloudlab-preview-' + value.split(':')[0] or value.split(':')[0] not in owned
                for namespace, value in settings['ownership'].items())):
        raise ValueError('Unrelated preview activation refused')


def update(snapshot, expected, replacements, *, empty=None, absent=()):
    """Change journaled entries only; preserve every current nonfixture field."""
    settings = copy.deepcopy(snapshot['catalog'] if snapshot['catalog'] is not None else empty)
    runtime_catalog(settings)
    if set(replacements) != set(expected) or entries(settings, expected) != expected:
        raise ValueError('Owned fixture entries changed since inspection')
    if not set(absent) <= set(expected):
        raise ValueError('Absence receipts must belong to this fixture journal')
    untouched = [row for row in settings['approvals'] if row['instance'] not in expected]
    for instance, row in replacements.items():
        namespace = 'cloudlab-preview-' + instance
        if row is None:
            # Withdrawal preserves deletion authorization until both namespace and client are absent.
            if instance in absent:
                settings['ownership'].pop(namespace, None)
        else:
            if row['instance'] != instance:
                raise ValueError('Fixture replacement cannot change instance identity')
            if expected[instance]['approval'] is not None and row != expected[instance]['approval']:
                raise ValueError('Changed fixture approval requires a fresh instance')
            untouched.append(copy.deepcopy(row))
            settings['ownership'][names(row)['namespace']] = instance + ':' + digest(canonical(row))
    settings['approvals'] = untouched
    runtime_catalog(settings)
    return {'catalog': settings, 'expectedBase': snapshot['revision']}


def reviewed(snapshot, current, pull, head):
    if (not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head) or
            snapshot != current or pull.get('state') != 'open' or pull.get('draft') is not False or
            pull.get('head', {}).get('sha') != head or pull.get('base', {}).get('sha') != snapshot['revision']):
        raise ValueError('Fixture review is stale; inspect and regenerate before merge')


def restoration(original, current, expected, *, absent):
    result = update(current, expected, {instance: None for instance in expected}, absent=absent)
    settings = result['catalog']
    if settings == original['catalog']:
        return {'expectedBase': current['revision'], 'raw': original['raw']}
    # In particular an originally absent file must survive concurrent user population.
    return {'expectedBase': current['revision'], 'raw': base64.b64encode(
        (json.dumps({'catalog': settings}, sort_keys=True, indent=2) + '\n').encode()).decode()}


def pull_repository(api, repository):
    validate_repository(repository)
    repo = api.request('GET', 'repos/' + repository)
    if (repo.get('full_name') != repository or repo.get('private') is not True or repo.get('fork') is not False or
            repo.get('default_branch') != 'main' or type(repo.get('id')) is not int or repo['id'] < 1 or
            not isinstance(repo.get('node_id'), str) or not 1 <= len(repo['node_id']) <= 256 or
            not repo['node_id'].isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in repo['node_id'])):
        raise ValueError('Fixture PR requires its designated private nonfork repository')
    return repo


def pull_receipt(api, repository, nonce, slot):
    if not re.fullmatch('[a-f0-9]{32}', nonce) or slot not in ('a', 'b', 'c', 'd'):
        raise ValueError('Fixture PR requires its journal nonce and bounded slot')
    repo = pull_repository(api, repository)
    base = api.request('GET', 'repos/' + repository + '/git/ref/heads/main')['object']['sha']
    return {'repository': repository, 'repositoryId': repo['id'], 'repositoryNodeId': repo['node_id'], 'base': base,
            'branch': 'cloudlab-preview-fixture/' + nonce + '/' + slot, 'head': None,
            'number': None, 'generation': -1, 'pending': None, 'pullIntent': False, 'closed': False, 'deleted': False}


def pull_scope(receipt, nonce, slot):
    validate_repository(receipt['repository'])
    if (not re.fullmatch('[a-f0-9]{32}', nonce) or slot not in ('a', 'b', 'c', 'd') or
            receipt['branch'] != 'cloudlab-preview-fixture/' + nonce + '/' + slot or
            not re.fullmatch('[a-f0-9]{40}', receipt['base']) or type(receipt['repositoryId']) is not int or
            receipt['repositoryId'] < 1):
        raise ValueError('Fixture PR receipt differs from its journal')
    return 'repos/' + receipt['repository']


def verified_pull(api, receipt, nonce, slot):
    prefix = pull_scope(receipt, nonce, slot)
    pull = api.request('GET', prefix + '/pulls/' + str(receipt['number']))
    if (pull.get('number') != receipt['number'] or pull.get('head', {}).get('sha') != receipt['head'] or
            pull.get('head', {}).get('ref') != receipt['branch'] or pull.get('base', {}).get('ref') != 'main' or
            any(pull.get(side, {}).get('repo', {}).get('id') != receipt['repositoryId'] for side in ('head', 'base')) or
            pull.get('head', {}).get('repo', {}).get('fork') is not False or pull.get('merged') is True):
        raise ValueError('Fixture PR identity or exact head changed')
    return pull


def commit_pull(api, receipt, nonce, slot, save, *, advance=False):
    """Journal intent before Git objects/ref writes; an interrupted ref is inspected exactly."""
    from playbooks.previews.files.contract import SOURCE_PATH, source
    prefix = pull_scope(receipt, nonce, slot)
    if receipt['closed'] or receipt['deleted']:
        raise ValueError('Closed fixture branches cannot be reactivated')
    if advance and receipt['number'] is None:
        raise ValueError('Create the owned fixture PR before advancing it')
    if advance and receipt['pending'] is None:
        if verified_pull(api, receipt, nonce, slot).get('state') != 'open':
            raise ValueError('Only an open owned fixture PR may advance')
    if receipt['pending'] is None:
        if not advance and receipt['head'] is not None:
            return
        receipt['pending'] = {'parent': receipt['head'] or receipt['base'], 'head': None,
                              'generation': receipt['generation'] + 1}
        save()
    pending = receipt['pending']
    raw = canonical({'profile': 'synthetic', 'message': 'synthetic fixture ' + slot + ' revision ' + str(pending['generation'])})
    source(raw)
    route = prefix + '/git/ref/heads/' + quote(receipt['branch'], safe='/')
    current = api.request('GET', route, missing=True)
    actual = current['object']['sha'] if current else None
    if actual not in (receipt['head'], pending['head']):
        raise ValueError('Fixture branch collision or concurrent commit; overwrite refused')
    if not advance and pending['parent'] == receipt['base'] and api.request('GET', prefix + '/git/ref/heads/main')['object']['sha'] != receipt['base']:
        raise ValueError('Fixture baseline advanced before branch creation')
    if pending['head'] is None:
        parent = api.request('GET', prefix + '/git/commits/' + pending['parent'])
        tree = api.request('POST', prefix + '/git/trees', {'base_tree': parent['tree']['sha'], 'tree': [
            {'path': SOURCE_PATH, 'mode': '100644', 'type': 'blob', 'content': raw.decode()}]})
        pending['head'] = api.request('POST', prefix + '/git/commits', {
            'message': 'Update synthetic preview fixture', 'tree': tree['sha'], 'parents': [pending['parent']]})['sha']
        save()
    if actual != pending['head']:
        if receipt['head'] is None:
            api.request('POST', prefix + '/git/refs', {'ref': 'refs/heads/' + receipt['branch'], 'sha': pending['head']})
        else:
            api.request('PATCH', prefix + '/git/refs/heads/' + quote(receipt['branch'], safe='/'), {'sha': pending['head'], 'force': False})
    blob = api.request('GET', prefix + '/contents/' + SOURCE_PATH + '?ref=' + pending['head'])
    difference = api.request('GET', prefix + '/compare/' + pending['parent'] + '...' + pending['head'])
    if (decode_contents(blob) != raw or difference.get('total_commits') != 1 or
            len(difference.get('files', [])) != 1 or difference['files'][0].get('filename') != SOURCE_PATH or
            difference['files'][0].get('status') not in ('added', 'modified') or 'previous_filename' in difference['files'][0]):
        raise ValueError('Fixture commit differs from its single synthetic source file')
    receipt.update(head=pending['head'], generation=pending['generation'], pending=None)
    save()


def open_pull(api, receipt, nonce, slot, save):
    prefix = pull_scope(receipt, nonce, slot)
    if receipt['number'] is not None:
        pull = verified_pull(api, receipt, nonce, slot)
        if pull.get('state') != 'open' or pull.get('draft') is not False:
            raise ValueError('Fixture PR is not an open approved source')
        return
    if receipt['head'] is None or receipt['pending'] is not None or receipt['closed'] or receipt['deleted']:
        raise ValueError('Fixture branch is not ready for a PR')
    pulls = api.request('GET', prefix + '/pulls?state=all&head=' + quote(receipt['repository'].split('/')[0] + ':' + receipt['branch'], safe=''))
    if len(pulls) > 1 or (pulls and not receipt['pullIntent']):
        raise ValueError('Unjournaled or ambiguous fixture PR; adoption refused')
    receipt['pullIntent'] = True
    save()
    pull = pulls[0] if pulls else api.request('POST', prefix + '/pulls', {
        'head': receipt['branch'], 'base': 'main', 'title': 'Synthetic private preview fixture',
        'body': 'Disposable synthetic configuration fixture; no production credentials or release.',
        'draft': False, 'maintainer_can_modify': False})
    receipt['number'] = pull['number']
    pull = verified_pull(api, receipt, nonce, slot)
    if pull.get('state') != 'open' or pull.get('draft') is not False:
        raise ValueError('Fixture PR is not an open approved source')
    save()


def cleanup_pull(api, receipt, nonce, slot, save):
    prefix = pull_scope(receipt, nonce, slot)
    repository = pull_repository(api, receipt['repository'])
    if repository['id'] != receipt['repositoryId'] or repository['node_id'] != receipt.get('repositoryNodeId'):
        raise ValueError('Fixture cleanup repository identity changed')
    if not isinstance(receipt.get('head'), str) or not re.fullmatch('[a-f0-9]{40}', receipt['head']):
        raise ValueError('Fixture atomic deletion requires its exact journaled head')
    if receipt['pending'] is not None:
        raise ValueError('Inspect the interrupted fixture commit before cleanup')
    if receipt['number'] is not None:
        pull = verified_pull(api, receipt, nonce, slot)
        if pull.get('state') != 'closed':
            receipt['closeIntent'] = True
            save()
            api.request('PATCH', prefix + '/pulls/' + str(receipt['number']), {'state': 'closed'})
            if verified_pull(api, receipt, nonce, slot).get('state') != 'closed':
                raise RuntimeError('Fixture PR close did not converge')
        receipt['closed'] = True
        save()
    delete_branch(api, receipt['repository'], repository['node_id'], receipt['branch'], receipt['head'], receipt, save)


def delete_branch(api, repository, node_id, branch, head, receipt, save):
    """Delete only a bounded fixture/proposal ref with native expected-head CAS."""
    validate_repository(repository)
    if (not isinstance(node_id, str) or not node_id or not re.fullmatch('[a-f0-9]{40}', head) or
            not re.fullmatch(r'(?:cloudlab-preview-fixture/[a-f0-9]{32}/[abcd]|(?:identity|previews)/desired-[a-f0-9]{20})', branch)):
        raise ValueError('Fixture ref deletion requires exact scoped coordinates')
    prefix = 'repos/' + repository
    route = prefix + '/git/ref/heads/' + quote(branch, safe='/')
    def observe():
        try: value = api.request('GET', route)
        except GitHubHTTPError as error:
            if error.status == 404: return None
            raise
        if (not isinstance(value, dict) or not isinstance(value.get('object'), dict) or
                not isinstance(value['object'].get('sha'), str) or not re.fullmatch('[a-f0-9]{40}', value['object']['sha']) or
                'ref' in value and value['ref'] != 'refs/heads/' + branch):
            raise ValueError('Fixture ref observation is unavailable or malformed')
        return value
    current = observe()
    if current is not None:
        if current['object']['sha'] != head:
            raise ValueError('Fixture cleanup head changed; branch deletion refused')
        receipt['deleteIntent'] = True
        save()
        # Native compare-and-swap rejects a push racing the inspection above.
        mutation_id = digest(canonical({'repository': node_id, 'ref': branch, 'head': head}))
        result = api.request('POST', 'graphql', {
            'query': 'mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}',
            'variables': {'input': {'repositoryId': node_id, 'clientMutationId': mutation_id,
                'refUpdates': [{'name': 'refs/heads/' + branch, 'beforeOid': head,
                                'afterOid': '0' * 40, 'force': False}]}}})
        if (not isinstance(result, dict) or ('errors' in result and result['errors'] != []) or not isinstance(result.get('data'), dict) or
                not isinstance(result['data'].get('updateRefs'), dict) or
                result['data']['updateRefs'].get('clientMutationId') != mutation_id):
            raise RuntimeError('Fixture atomic deletion failed; provider diagnostics withheld')
        if observe() is not None:
            raise RuntimeError('Fixture branch absence not confirmed; deletion receipt withheld')
    elif not receipt.get('deleteIntent'):
        raise ValueError('Fixture branch disappeared without deletion intent')
    receipt['deleted'] = True
    save()
