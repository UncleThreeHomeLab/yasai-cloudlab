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
