"""Credential-free immutable preview examples."""
import copy
import json
import base64
from playbooks.previews.files.contract import IMAGE, SOURCE_PATH, canonical, digest, names


def approval(instance='a' * 32):
    definition = {'profile': 'synthetic', 'message': 'synthetic preview'}
    return {'instance': instance, 'repository': 'example/platform', 'repositoryId': 123, 'pullRequest': 7,
        'sourceSha': 'b' * 40, 'sourcePath': SOURCE_PATH, 'sourceDigest': digest(canonical(definition)),
        'definition': definition, 'image': IMAGE, 'platformRevision': 'c' * 40,
        'createdAt': 1000, 'expiresAt': 2000}


def catalog(rows=None):
    rows = [approval()] if rows is None else rows
    return {'hostname': 'preview.internal.example.invalid', 'issuer': 'https://login.example.invalid/realms/applications',
            'privateDiscovery': False, 'approvals': rows, 'artifacts': {},
            'ownership': {names(row)['namespace']: row['instance'] + ':' + digest(canonical(row)) for row in rows}}


def pull(row=None):
    row = row or approval()
    repo = {'id': row['repositoryId'], 'full_name': row['repository'], 'fork': False, 'private': False}
    return {'number': row['pullRequest'], 'state': 'open', 'draft': False,
            'head': {'sha': row['sourceSha'], 'repo': copy.deepcopy(repo)}, 'base': {'repo': repo}}


def source_responses(row, mode='100644'):
    raw = canonical(row['definition'])
    root, directory, blob = ('1' * 40, '2' * 40, '3' * 40)
    prefix = 'repos/' + row['repository']
    return {
        prefix + '/git/commits/' + row['sourceSha']: {'sha': row['sourceSha'], 'tree': {'sha': root}},
        prefix + '/git/trees/' + root: {'sha': root, 'truncated': False,
            'tree': [{'path': 'previews', 'mode': '040000', 'type': 'tree', 'sha': directory}]},
        prefix + '/git/trees/' + directory: {'sha': directory, 'truncated': False,
            'tree': [{'path': 'definition.json', 'mode': mode, 'type': 'blob', 'sha': blob, 'size': len(raw)}]},
        prefix + '/contents/' + row['sourcePath'] + '?ref=' + row['sourceSha']: {
            'path': row['sourcePath'], 'type': 'file', 'encoding': 'base64', 'sha': blob, 'size': len(raw),
            'content': base64.b64encode(raw).decode()}}


class Keycloak:
    def __init__(self):
        self.rows, self.deleted = {}, []

    def __call__(self, action, value):
        if action == 'find':
            return [copy.deepcopy(row) for row in self.rows.values() if row['clientId'] == value]
        if action == 'create':
            self.rows['owned-client-uuid'] = dict(copy.deepcopy(value), id='owned-client-uuid')
        if action == 'update':
            self.rows[value['id']] = copy.deepcopy(value)
        if action == 'delete':
            self.deleted.append(value)
            del self.rows[value]


class PrivatePreviewGit:
    """Synthetic Git server with response loss after owned writes."""
    def __init__(self):
        self.main, self.head, self.last_head = 'b' * 40, None, None
        self.commits, self.trees, self.writes = {}, {}, []
        self.number, self.closed, self.fail = None, False, None
        self.branch = ''
        self.race_head, self.graphql_result, self.retain_ref = None, NotImplemented, False
        self.repository_id, self.repository_node = 123, 'R_synthetic_private'

    def request(self, method, path, body=None, missing=False):
        if method != 'GET':
            self.writes.append((method, path, copy.deepcopy(body)))
        def written(kind, result):
            if self.fail == kind:
                self.fail = None
                raise RuntimeError('synthetic lost response')
            return result
        if path == 'repos/example/private':
            return {'full_name': 'example/private', 'private': True, 'fork': False, 'default_branch': 'main',
                    'id': self.repository_id, 'node_id': self.repository_node}
        if path == 'graphql':
            if self.graphql_result is not NotImplemented:
                return self.graphql_result
            value = body['variables']['input']
            updates = value['refUpdates']
            if (value['repositoryId'] != self.repository_node or len(updates) != 1 or
                    updates[0]['name'] != 'refs/heads/' + self.branch or updates[0]['afterOid'] != '0' * 40 or
                    updates[0]['force'] is not False):
                raise AssertionError('Fixture atomic deletion scope differs')
            if self.race_head is not None:
                self.head = self.race_head
            if updates[0]['beforeOid'] != self.head:
                return {'errors': [{'message': 'synthetic private provider mismatch'}], 'data': {'updateRefs': None}}
            if not self.retain_ref:
                self.head = None
            return written('delete', {'data': {'updateRefs': {'clientMutationId': value['clientMutationId']}}})
        if path.endswith('/git/ref/heads/main'):
            return {'object': {'sha': self.main}}
        if '/git/ref/heads/' in path:
            return {'object': {'sha': self.head}} if self.head else None
        if method == 'POST' and path.endswith('/git/trees'):
            name = str(len(self.trees))
            self.trees[name] = body['tree'][0]['content'].encode()
            return {'sha': name}
        if method == 'POST' and path.endswith('/git/commits'):
            name = format(len(self.commits) + 1, '040x')
            self.commits[name] = self.trees[body['tree']]
            return {'sha': name}
        if '/git/commits/' in path:
            return {'tree': {'sha': 'base-tree'}}
        if method == 'POST' and path.endswith('/git/refs'):
            self.head = self.last_head = body['sha']
            self.branch = body['ref'].removeprefix('refs/heads/')
            return written('ref', {})
        if method == 'PATCH' and '/git/refs/heads/' in path:
            if body.get('force') is not False:
                raise AssertionError('Fixture attempted a forced ref')
            self.head = self.last_head = body['sha']
            return written('advance', {})
        if method == 'DELETE' and '/git/refs/heads/' in path:
            self.head = None
            return written('delete', {})
        if '/contents/' in path:
            return {'content': base64.b64encode(self.commits[path.split('?ref=')[1]]).decode()}
        if '/compare/' in path:
            return {'total_commits': 1, 'files': [{'filename': 'previews/definition.json', 'status': 'added'}]}
        if '/pulls?' in path:
            return [self.pull()] if self.number else []
        if method == 'POST' and path.endswith('/pulls'):
            self.number = 7
            return written('pull', self.pull())
        if method == 'PATCH' and '/pulls/' in path:
            self.closed = True
            return written('close', self.pull())
        if '/pulls/' in path:
            return self.pull()
        raise AssertionError('Unexpected fixture API operation')

    def pull(self):
        return {'number': self.number, 'state': 'closed' if self.closed else 'open', 'merged': False, 'draft': False,
                'head': {'sha': self.head or self.last_head, 'ref': self.branch, 'repo': {'id': 123, 'fork': False}},
                'base': {'ref': 'main', 'repo': {'id': 123}}}
