"""Explicit owned approval artifacts, private proposals and lifecycle evidence."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from types import SimpleNamespace
from urllib.parse import quote

from playbooks.previews.files import contract
from playbooks.previews.tests import catalog_fixture as fixture
from playbooks.argocd.files import private_publish, repository_tokens
from playbooks.argocd.files.github_setup import GitHubHTTPError, repository
from playbooks.keycloak.tests import scoped_session as session
from playbooks.keycloak.files.private_source import decode_contents

PATH = 'previews/catalog.json'
MODES = ('approve', 'withdraw', 'cleanup', 'finalize')


def slots(batch):
    if batch not in ('ab', 'cd'):
        raise ValueError('Approval batch must be the fixed owned pair')
    return tuple(batch)


def rows(state):
    return {record['row']['instance']: record['row'] for record in state.get('approvals', {}).values() if 'row' in record}


def abandon_preparation(state, save):
    """Release only expired preparation into permanent authority-reducing cleanup."""
    if state.get('abandonedPreparation') and state.get('intent') is None:
        return
    intent = state.get('intent')
    if (not isinstance(intent, dict) or set(intent) != {'action', 'slot', 'batch', 'lifetime'} or
            intent['action'] != 'approval-prepare' or intent['slot'] is not None or
            type(intent['lifetime']) is not int or not 60 <= intent['lifetime'] <= contract.PRIVATE_MAX_LIFETIME):
        raise ValueError('Only an interrupted exact approval preparation can be abandoned')
    selected = slots(intent['batch'])
    now = int(time.time())
    for slot in selected:
        record = state.get('approvals', {}).get(slot)
        if record is None:
            continue
        created = record.get('createdAt')
        if (type(created) is not int or created <= 0 or record.get('lifetime') != intent['lifetime'] or
                now < created + record['lifetime']):
            raise ValueError('Saved preparation must expire before abandonment')
        if 'row' in record:
            contract.approval(record['row'])
            if (record['row']['instance'] != record['instance'] or record['row']['createdAt'] != created or
                    record['row']['expiresAt'] != created + record['lifetime']):
                raise ValueError('Saved approval differs from its immutable preparation')
    state['abandonedPreparation'] = copy.deepcopy(intent)
    state['intent'] = None
    save()


def artifact(state, record):
    """Publish only the exact fully journaled row in its private nonce directory."""
    row = record['row']
    contract.approval(row)
    raw = contract.canonical(row)
    if record.get('artifact') != {'instance': row['instance'], 'sha256': contract.digest(raw)}:
        raise ValueError('Approval artifact intent differs from its immutable row')
    root = fixture.JOURNALS / state['nonce']
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Approval artifact requires the existing private journal directory')
    directory = root / 'approvals'
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise ValueError('Approval artifact directory ownership changed')
    target = directory / (row['instance'] + '.json')
    if target.is_symlink():
        raise ValueError('Approval artifact cannot follow a link')
    if target.exists():
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            observed = os.fstat(stream.fileno())
            if not stat.S_ISREG(observed.st_mode) or stat.S_IMODE(observed.st_mode) != 0o600 or stream.read(16385) != raw:
                raise ValueError('Approval artifact differs from its saved intent')
        return
    temporary = directory / ('.' + row['instance'] + '-' + secrets.token_hex(8))
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link publication is atomic and never replaces a concurrently created file.
        os.link(temporary, target, follow_symlinks=False)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def prepare(values, state, save, batch, lifetime):
    from playbooks.previews.files.command import verified_row
    from playbooks.previews.files.github import GitHub
    selected = slots(batch)
    if state.get('abandonedPreparation'):
        raise ValueError('Abandoned preparation cannot renew execution authority')
    if type(lifetime) is not int or not 60 <= lifetime <= contract.PRIVATE_MAX_LIFETIME:
        raise ValueError('Fixture lifetime exceeds the private approval boundary')
    if not state.get('enrolled') or state.get('offboarding') or not state.get('identity', {}).get('enabled'):
        raise ValueError('Approval preparation requires its enrolled enabled viewer')
    if batch == 'cd' and any(not state.get('evidence', {}).get(state.get('approvals', {}).get(slot, {}).get('instance'), {}).get('absent')
                             for slot in ('a', 'b')):
        raise ValueError('Prior preview pair must be absent before the next batch')
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    records = state.setdefault('approvals', {})
    active = [record for record in records.values() if not state.get('evidence', {}).get(record['instance'], {}).get('absent')]
    if len(active) + sum(slot not in records for slot in selected) > contract.MAX_ACTIVE:
        raise ValueError('Fixture capacity includes pending and retiring approvals')
    for slot in selected:
        pull = state.get('pulls', {}).get(slot)
        if not pull or pull.get('repository') != repo or pull.get('closed') or pull.get('deleted') or pull.get('pending'):
            raise ValueError('Approval requires its exact current owned PR receipt')
        if slot not in records:
            records[slot] = {'instance': secrets.token_hex(16), 'createdAt': int(time.time()),
                'head': pull['head'], 'platform': state['executionPlatform'], 'lifetime': lifetime}
            save()
        record = records[slot]
        if (record['head'] != pull['head'] or record['platform'] != state['executionPlatform'] or record['lifetime'] != lifetime):
            raise ValueError('Prepared approval cannot change revision, platform or lifetime')
        lease = repository_tokens.issue(values, 'private-config', {'contents': 'read', 'pull_requests': 'read'})
        try:
            request = {'repository': repo, 'pullRequest': pull['number'], 'image': contract.IMAGE,
                'platformRevision': record['platform'], 'lifetimeSeconds': lifetime, 'private': True}
            api = GitHub(lease['token'], private=True, lease={key: value for key, value in lease.items() if key != 'token'})
            inspected = fixture.verified_pull(SimpleNamespace(request=lambda method, path: api.request(path)), pull, state['nonce'], slot)
            contract.validate_pull(dict(instance=record['instance'], repository=repo, repositoryId=pull['repositoryId'],
                pullRequest=pull['number'], sourceSha=record['head']), inspected)
            row = verified_row(request, api, instance=record['instance'], created_at=record['createdAt'], verification_time=int(time.time()))
            if row['sourceSha'] != record['head'] or row['repositoryId'] != pull['repositoryId'] or row['definition']['profile'] != 'synthetic':
                raise ValueError('Verified approval differs from its owned source receipt')
            if 'row' in record and record['row'] != row:
                raise ValueError('Approval retry cannot renew or replace its saved row')
            record.update(row=row, artifact={'instance': row['instance'], 'sha256': contract.digest(contract.canonical(row))})
            save()
            artifact(state, record)
            state.setdefault('instances', [])
            if row['instance'] not in state['instances']:
                state['instances'].append(row['instance'])
            if batch == 'ab':
                state.setdefault('browserApprovals', {})[slot] = {'instance': row['instance'], 'approvalDigest': contract.digest(contract.canonical(row))}
            save()
        finally:
            repository_tokens.revoke(lease)


class Publication:
    """Receipt only exact ref/PR writes performed by the existing owner publisher."""
    def __init__(self, api, repo, record, save, scope, files, base):
        self.api, self.repo, self.record, self.save = api, repo, record, save
        target = fixture.pull_repository(api, repo)
        source = {'repository': repo, 'id': target['id'], 'nodeId': target['node_id']}
        if record.get('source', source) != source:
            raise ValueError('Private proposal repository identity changed')
        record['source'] = source
        save()
        fingerprint = hashlib.sha256(json.dumps({'base': base, 'files': files}, sort_keys=True).encode()).hexdigest()
        self.branch = scope + '/desired-' + fingerprint[:20]
        if record.get('branch', self.branch) != self.branch:
            raise ValueError('Private proposal branch differs from its saved request')
        record['branch'] = self.branch
        self.prefix = 'repos/' + repo

    def owns_pull(self, pull):
        return (bool(self.record.get('pullIntent')) and bool(self.record.get('pullBody')) and not self.record.get('pullRejected') and
            pull.get('body') == self.record.get('pullBody') and
            pull.get('head', {}).get('ref') == self.branch and
            pull.get('head', {}).get('sha') == self.record.get('createdHead') and
            pull.get('base', {}).get('ref') == 'main' and
            all(pull.get(side, {}).get('repo', {}).get('id') == self.record['source']['id'] for side in ('head', 'base')) and
            self.record.get('number', pull.get('number')) == pull.get('number'))

    def associations(self):
        pulls = self.api.request('GET', self.prefix + '/pulls?state=all&head=' +
            quote(self.repo.split('/')[0] + ':' + self.branch, safe='') + '&per_page=100')
        if not isinstance(pulls, list) or len(pulls) > 1 or any(not self.owns_pull(pull) for pull in pulls):
            raise ValueError('Foreign or ambiguous PR association prevents proposal reuse or cleanup')
        return pulls

    def request(self, method, path, body=None, missing=False):
        ref_path = self.prefix + '/git/ref/heads/' + quote(self.branch, safe='/')
        create_ref = method == 'POST' and path == self.prefix + '/git/refs'
        create_pull = method == 'POST' and path == self.prefix + '/pulls'
        if self.record.get('refRejected') or self.record.get('pullRejected'):
            raise ValueError('Rejected proposal creation cannot establish ownership on retry')
        if method == 'GET' and path == ref_path:
            self.associations()
        if create_ref:
            if self.record.get('refIntent'):
                raise ValueError('A missing previously requested proposal ref cannot be recreated')
            if (set(body) != {'ref', 'sha'} or body['ref'] != 'refs/heads/' + self.branch or
                    body['sha'] != self.record.get('createdHead')):
                raise ValueError('Private proposal ref write differs from its recorded commit')
            self.record['refIntent'] = copy.deepcopy(body)
            self.save()
        if create_pull:
            if body.get('head') != self.branch or body.get('base') != 'main' or not self.record.get('refIntent'):
                raise ValueError('Private proposal PR lacks its owned ref intent')
            if self.record.get('pullIntent'):
                raise ValueError('A missing previously requested proposal PR cannot be recreated')
            body = copy.deepcopy(body)
            body['body'] += '\n\n<!-- owned-request:' + secrets.token_hex(16) + ' -->'
            self.record['pullBody'] = body['body']
            self.record['pullIntent'] = True
            self.save()
        try:
            result = self.api.request(method, path, body, missing=missing)
        except GitHubHTTPError as error:
            if 400 <= error.status < 500 and (create_ref or create_pull):
                self.record['refRejected' if create_ref else 'pullRejected'] = error.status
                self.save()
            raise
        if method == 'GET' and path == ref_path and result is not None:
            if self.record.get('refIntent') != {'ref': 'refs/heads/' + self.branch, 'sha': result['object']['sha']}:
                raise ValueError('Pre-existing proposal branch is not journal-owned')
        if method == 'GET' and '/pulls?state=open&head=' in path and result:
            if any(not self.owns_pull(pull) for pull in result):
                raise ValueError('Pre-existing private proposal PR is not journal-owned')
        if method == 'POST' and path == self.prefix + '/git/commits':
            self.record['createdHead'] = result['sha']
            self.save()
        if method == 'POST' and path == self.prefix + '/git/refs':
            self.record['refCreated'] = True
            self.save()
        if (method == 'POST' and path == self.prefix + '/pulls') or (method == 'GET' and '/pulls?state=open&head=' in path and result):
            pull = result if isinstance(result, dict) else result[0]
            if not self.owns_pull(pull):
                raise ValueError('Private proposal PR response differs from its saved request')
            self.record.update(number=pull['number'], head=pull['head']['sha'])
            self.save()
        return result


def current(state):
    history = state.get('catalogProposals', [])
    if not history:
        raise ValueError('Prepare the exact catalog delta first')
    if state.get('abandonedPreparation') and history[-1]['mode'] == 'approve':
        raise ValueError('Abandoned preparation cannot resume an execution approval proposal')
    return history[-1]


def proposal_scope(api, values, record):
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    target = fixture.pull_repository(api, repo)
    if record.get('source') != {'repository': repo, 'id': target['id'], 'nodeId': target['node_id']}:
        raise ValueError('Catalog proposal repository identity differs from its prepared source')
    return repo


def catalog_prepare(api, values, state, save, batch, mode):
    if mode not in MODES:
        raise ValueError('Unknown bounded catalog transition')
    if mode == 'approve' and state.get('abandonedPreparation'):
        raise ValueError('Abandoned preparation cannot publish execution authority')
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    snapshot = fixture.inspect(api, repo)
    if snapshot['catalog'] is None:
        raise ValueError('Fixture catalog must already have its declared empty settings')
    owned = rows(state)
    if mode == 'approve':
        fixture.require_fixture_only(snapshot['catalog'], owned)
    selected = [state.get('approvals', {}).get(slot, {}).get('row') for slot in slots(batch)]
    if any(row is None for row in selected) and mode != 'finalize':
        raise ValueError('Prepare the exact pair before catalog publication')
    ids = list(owned) if mode == 'finalize' else [row['instance'] for row in selected]
    expected = fixture.entries(snapshot['catalog'], ids)
    for instance, entry in expected.items():
        authorized = instance + ':' + contract.digest(contract.canonical(owned[instance]))
        if entry['approval'] not in (None, owned[instance]) or entry['ownership'] not in (None, authorized):
            raise ValueError('Owned catalog entry changed since its immutable approval')
        if mode == 'approve' and state.get('evidence', {}).get(instance, {}).get('absent'):
            raise ValueError('Retired approval cannot be reauthorized')
    absent = []
    if mode in ('cleanup', 'finalize'):
        if any(not state.get('evidence', {}).get(instance, {}).get('absent') for instance in ids):
            raise ValueError('Namespace, generated resources and client absence must be confirmed first')
        absent = ids
    replacements = {instance: owned[instance] if mode == 'approve' else None for instance in ids}
    document = fixture.update(snapshot, expected, replacements, absent=absent)
    if mode == 'approve':
        now = int(time.time())
        if any(not row['createdAt'] <= now < row['expiresAt'] for row in selected):
            raise ValueError('Expired approvals cannot be published')
        document['catalog']['privateDiscovery'] = True
    if mode == 'finalize':
        if document['catalog']['approvals'] or document['catalog']['ownership']:
            raise ValueError('Discovery retirement requires an empty catalog')
        document['catalog']['privateDiscovery'] = False
    contract.runtime_catalog(document['catalog'])
    record = {'snapshot': snapshot, 'document': document, 'mode': mode, 'batch': batch, 'stage': 'prepared'}
    target = fixture.pull_repository(api, repo)
    record['source'] = {'repository': repo, 'id': target['id'], 'nodeId': target['node_id']}
    previous = state.get('catalogProposals', [])
    if len(previous) >= 32:
        raise ValueError('Fixture proposal history reached its bounded capacity')
    if previous and previous[-1].get('stage') not in ('merged', 'retired') and previous[-1]['snapshot'] == snapshot:
        if previous[-1]['document'] != document:
            raise ValueError('Finish or explicitly reprepare the pending catalog transition')
        return
    state.setdefault('catalogProposals', []).append(record)
    save()


def reprepare_check(api, values, state):
    record = current(state)
    repo = proposal_scope(api, values, record)
    if record['stage'] in ('merged', 'retired') or fixture.inspect(api, repo) == record['snapshot']:
        raise ValueError('Only an unmerged stale catalog proposal can be regenerated')
    if record.get('number'):
        pull = api.request('GET', 'repos/' + repository(values['PRIVATE_CONFIG_REPOSITORY']) + '/pulls/' + str(record['number']))
        if pull.get('merged') is True or pull.get('head', {}).get('sha') != record.get('head'):
            raise ValueError('Reconcile the exact catalog merge/head before regeneration')


def reprepare(api, values, state, save):
    reprepare_check(api, values, state)
    record = current(state)
    record['stage'] = 'abandoned'
    save()
    catalog_prepare(api, values, state, save, record['batch'], record['mode'])


def propose(api, values, state, save):
    record = current(state)
    repo = proposal_scope(api, values, record)
    if record['stage'] == 'merged':
        return
    if fixture.inspect(api, repo) != record['snapshot']:
        raise ValueError('Catalog base advanced; prepare a fresh delta without overwriting')
    files = {PATH: json.dumps({'catalog': record['document']['catalog']}, sort_keys=True, indent=2) + '\n'}
    wrapped = Publication(api, repo, record, save, 'previews', files, record['snapshot']['revision'])
    result = private_publish.publish(wrapped, values, files, scope='previews', expected_base=record['snapshot']['revision'])
    if not result['private_source_changed']:
        record.update(stage='merged', revision=result['private_revision'])
    else:
        pull = api.request('GET', 'repos/' + repo + '/pulls/' + str(result['private_pull_request']))
        if record.get('number') != pull['number'] or record.get('head') != pull['head']['sha']:
            raise ValueError('Published catalog proposal lacks its exact creation receipt')
        record['stage'] = 'proposed'
    save()


def review(api, values, state, save):
    record = current(state)
    repo = proposal_scope(api, values, record)
    prefix = 'repos/' + repo
    number, head = record.get('number'), record.get('head')
    if type(number) is not int or not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head):
        raise ValueError('Catalog review requires its exact proposed PR/head')
    pull = api.request('GET', prefix + '/pulls/' + str(number))
    fixture.reviewed(record['snapshot'], fixture.inspect(api, repo), pull, head)
    branch = record['branch']
    if (pull.get('number') != number or pull.get('head', {}).get('ref') != branch or pull.get('base', {}).get('ref') != 'main' or
            not record.get('pullBody') or pull.get('body') != record['pullBody'] or record.get('pullRejected') or
            any(pull.get(side, {}).get('repo', {}).get('full_name') != repo for side in ('head', 'base')) or
            record.get('refIntent') != {'ref': 'refs/heads/' + branch, 'sha': head}):
        raise ValueError('Catalog proposal identity differs from its ref receipt')
    commit = api.request('GET', prefix + '/git/commits/' + head)
    files = api.request('GET', prefix + '/pulls/' + str(number) + '/files?per_page=100')
    blob = api.request('GET', prefix + '/contents/' + PATH + '?ref=' + head)
    raw = (json.dumps({'catalog': record['document']['catalog']}, sort_keys=True, indent=2) + '\n').encode()
    blob_hash = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if ([parent['sha'] for parent in commit.get('parents', [])] != [record['snapshot']['revision']] or
            len(files) != 1 or files[0].get('filename') != PATH or files[0].get('status') not in ('added', 'modified') or
            'previous_filename' in files[0] or blob.get('type') != 'file' or blob.get('sha') != blob_hash or decode_contents(blob) != raw):
        raise ValueError('Catalog proposal bytes or commit scope changed')
    if (api.request('GET', prefix + '/git/ref/heads/main')['object']['sha'] != record['snapshot']['revision'] or
            api.request('GET', prefix + '/pulls/' + str(number))['head']['sha'] != head):
        raise ValueError('Reviewed catalog references advanced')
    record['stage'] = 'reviewed'
    save()


def merge(api, values, state, save):
    record = current(state)
    repo = proposal_scope(api, values, record)
    if record['stage'] == 'merged':
        return
    prefix = 'repos/' + repo
    pull = api.request('GET', prefix + '/pulls/' + str(record.get('number')))
    if pull.get('merged') is not True:
        if record['stage'] not in ('reviewed', 'merging'):
            raise ValueError('Review the exact catalog proposal before its separate merge stage')
        review(api, values, state, save)
        record['stage'] = 'merging'
        save()
        result = api.request('PUT', prefix + '/pulls/' + str(record['number']) + '/merge', {'sha': record['head'], 'merge_method': 'squash'})
        if result.get('merged') is not True:
            raise RuntimeError('Protected catalog merge incomplete')
        revision = result['sha']
    else:
        if (record['stage'] != 'merging' or pull.get('head', {}).get('sha') != record.get('head') or
                any(pull.get(side, {}).get('repo', {}).get('full_name') != repo for side in ('head', 'base'))):
            raise ValueError('Completed merge lacks its recorded exact merge intent')
        revision = pull.get('merge_commit_sha')
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Catalog merge result is not immutable')
    merged = fixture.inspect(api, repo)
    blob = api.request('GET', prefix + '/contents/' + PATH + '?ref=' + revision)
    raw = (json.dumps({'catalog': record['document']['catalog']}, sort_keys=True, indent=2) + '\n').encode()
    if decode_contents(blob) != raw or merged['raw'] != base64.b64encode(raw).decode():
        raise ValueError('Merged catalog changed; preserve ownership and inspect before continuing')
    record.update(stage='merged', revision=revision)
    save()


def retire_proposals(api, values, state, save):
    if any(not state.get('evidence', {}).get(instance, {}).get('absent') for instance in rows(state)):
        raise ValueError('Owned execution must be absent before proposal ref cleanup')
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    target = fixture.pull_repository(api, repo)
    current_catalog = fixture.inspect(api, repo)['catalog']
    if any(row['instance'] in rows(state) for row in current_catalog['approvals']):
        raise ValueError('Withdraw owned execution approvals before proposal cleanup')
    records = list(state.get('catalogProposals', [])) + [state[key] for key in ('membership', 'offboarding') if key in state]
    for record in records:
        if record.get('stage') == 'retired' or not record.get('refIntent'):
            continue
        if record.get('refRejected'):
            raise ValueError('Rejected ref creation has no cleanup ownership')
        proposal_scope(api, values, record)
        head, branch = record['refIntent']['sha'], record['branch']
        if record['refIntent'] != {'ref': 'refs/heads/' + branch, 'sha': head} or record.get('createdHead') != head:
            raise ValueError('Proposal cleanup lacks an exact owned ref creation intent')
        prefix = 'repos/' + repo
        files = record.get('prepared') or {PATH: json.dumps({'catalog': record['document']['catalog']}, sort_keys=True, indent=2) + '\n'}
        scope = branch.split('/')[0]
        Publication(api, repo, record, save, scope, files, record['snapshot']['revision']).associations()
        commit = api.request('GET', prefix + '/git/commits/' + head)
        difference = api.request('GET', prefix + '/compare/' + record['snapshot']['revision'] + '...' + head)
        if ([parent['sha'] for parent in commit.get('parents', [])] != [record['snapshot']['revision']] or
                difference.get('total_commits') != 1 or {item['filename'] for item in difference.get('files', [])} != set(files) or
                any(item.get('status') not in ('added', 'modified') or 'previous_filename' in item for item in difference.get('files', []))):
            raise ValueError('Owned proposal commit scope changed before cleanup')
        for path, raw in files.items():
            if decode_contents(api.request('GET', prefix + '/contents/' + path + '?ref=' + head)) != raw.encode():
                raise ValueError('Owned proposal content differs before cleanup')
        if record.get('number'):
            pull = api.request('GET', prefix + '/pulls/' + str(record['number']))
            if (pull['head']['sha'] != head or pull['head']['ref'] != branch or
                    not record.get('pullBody') or pull.get('body') != record['pullBody'] or record.get('pullRejected') or
                    pull.get('base', {}).get('ref') != 'main' or
                    any(pull.get(side, {}).get('repo', {}).get('id') != target['id'] for side in ('base', 'head'))):
                raise ValueError('Proposal PR identity changed before cleanup')
            if pull['state'] != 'closed':
                api.request('PATCH', prefix + '/pulls/' + str(record['number']), {'state': 'closed'})
        fixture.delete_branch(api, repo, target['node_id'], branch, head, record, save)
        record['stage'] = 'retired'
        save()


def preserve_baseline(state, observed):
    original = state['baseline']['cluster']
    for group in ('persistent', 'clients'):
        for kind, record in original[group].items():
            actual = observed[group][kind]['identities']
            if any(actual.get(key) != value for key, value in record['identities'].items()):
                raise ValueError('Pre-existing resource identity changed; fixture evidence refused')


def remember(state, observed, save):
    known = rows(state)
    if set(observed.get('entries', {})) != set(known):
        raise ValueError('Lifecycle observation differs from exact journal-owned instances')
    for instance, value in observed['entries'].items():
        row = known[instance]
        if value.get('approvalDigest') != contract.digest(contract.canonical(row)):
            raise ValueError('Observed approval digest changed')
        record = state.setdefault('evidence', {}).setdefault(instance, {})
        if value.get('active'):
            previous = record.get('active')
            if previous and (previous['uids'] != value['uids'] or previous['client']['id'] != value['client']['id']):
                raise ValueError('Active fixture resource identity changed')
            record['active'] = copy.deepcopy(value)
        if value.get('disabled'):
            if (not record.get('active') or value['client']['id'] != record['active']['client']['id'] or
                    value['client'].get('enabled') is not False or value.get('disabledAt', 0) > value['observedAt']):
                raise ValueError('Disabled identity does not match its captured active UUID')
            if record.get('disabled') and record['disabled']['disabledAt'] != value['disabledAt']:
                raise ValueError('Owner disabled time changed during grace')
            record['disabled'] = copy.deepcopy(value)
        if value.get('absent'):
            if (not record.get('active') or not record.get('disabled') or
                    value['observedAt'] < record['disabled']['disabledAt'] + 600):
                raise ValueError('Actual disable and complete wall-time grace evidence required')
            record['absent'] = copy.deepcopy(value)
        record['latest'] = copy.deepcopy(value)
        save()
