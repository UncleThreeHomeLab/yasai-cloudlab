"""Explicit private-App publication for the preview viewer; legacy helpers stay independent."""
import copy
from contextlib import contextmanager
import json
import os
import re

import yaml

from playbooks.argocd.files.github_setup import GitHub, repository
from playbooks.argocd.files import repository_tokens, private_publish
from playbooks.keycloak.files.private_source import decode_contents
from playbooks.keycloak.files.operations import change, private_files
from playbooks.keycloak.files.session_fixture import membership, scope
from playbooks.secrets.files.vault import fields

PATH = 'identity/configmap.yaml'
OVERLAY = 'identity/argo-values.yaml'


def viewer(request):
    scope(request)
    if request.get('realm') != 'applications':
        raise ValueError('Preview viewer requires its explicit applications realm')
    return request


@contextmanager
def private_context(values, *, write=False):
    previous = os.environ.get('OP_SERVICE_ACCOUNT_TOKEN')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    lease = None
    try:
        permissions = {'contents': 'write' if write else 'read', 'pull_requests': 'write' if write else 'read'}
        lease = repository_tokens.issue(values, 'private-config', permissions)
        yield GitHub(lease['token'])
    finally:
        try:
            if lease is not None:
                repository_tokens.revoke(lease)
        finally:
            if previous is None:
                os.environ.pop('OP_SERVICE_ACCOUNT_TOKEN', None)
            else:
                os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = previous


def inspect(api, values, revision=None):
    prefix = 'repos/' + repository(values['PRIVATE_CONFIG_REPOSITORY'])
    revision = revision or api.request('GET', prefix + '/git/ref/heads/main')['object']['sha']
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Viewer inspection requires immutable private main')
    documents = {}
    for path in (PATH, OVERLAY):
        blob = api.request('GET', prefix + '/contents/' + path + '?ref=' + revision, missing=path == OVERLAY)
        if blob is not None and (blob.get('type') != 'file' or blob.get('encoding') != 'base64'):
            raise ValueError('Viewer identity source must be a regular private file')
        documents[path] = decode_contents(blob).decode() if blob is not None else None
    manifest = yaml.safe_load(documents[PATH])
    if (not isinstance(manifest, dict) or manifest.get('apiVersion') != 'v1' or manifest.get('kind') != 'ConfigMap' or
            manifest.get('metadata', {}).get('name') != 'identity-private-state' or
            manifest.get('metadata', {}).get('namespace') != 'cloudlab-identity' or
            set(manifest.get('data', {})) != {'desired_state', 'revocations'}):
        raise ValueError('Viewer requires the complete owned identity source')
    return {'revision': revision, 'files': documents, 'manifest': manifest}


def prepare(snapshot, request, *, offboard=False):
    viewer(request)
    manifest = copy.deepcopy(snapshot['manifest'])
    source, revoked = [json.loads(manifest['data'][key]) for key in ('desired_state', 'revocations')]
    credentials = fields('keycloak-proof-' + request['nonce'], ('username', 'password', 'email', 'ownership_id'))
    if offboard:
        # Membership validates the exact nonce-owned user, while existing tombstones stay irreversible.
        if credentials.get('username') != 'proof-' + request['nonce'] or credentials.get('ownership_id') != request['nonce']:
            raise ValueError('Viewer offboarding identity differs from its journal')
        expected = {'username': credentials['username'], 'groups': ['viewer'],
                    'profile': {'email': credentials['email'], 'verified': True}}
        if [row for row in source['realms'].get('applications', {}).get('memberships', [])
                if row['username'] == expected['username']] != [expected]:
            raise ValueError('Viewer membership changed; offboarding refused')
        source, revoked = change(source, revoked, {'action': 'offboard-user', 'realm': 'applications', 'username': expected['username']})
    else:
        source = membership(source, revoked, credentials, request)
    secrets = json.loads(fields('keycloak-client-secrets', ('client_secrets',))['client_secrets'])
    private_files(source, revoked, secrets, 'validation.invalid')
    manifest['data'] = {'desired_state': json.dumps(source, sort_keys=True), 'revocations': json.dumps(revoked, sort_keys=True)}
    return {PATH: yaml.safe_dump(manifest, sort_keys=True)}


def propose(api, values, snapshot, prepared):
    if set(prepared) != {PATH}:
        raise ValueError('Viewer publication may change only its identity ConfigMap')
    return private_publish.publish(api, values, prepared, scope='identity', expected_base=snapshot['revision'])


def review(api, values, snapshot, prepared, number, head):
    if type(number) is not int or number < 1 or not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head):
        raise ValueError('Viewer review requires its exact journaled PR and head')
    prefix = 'repos/' + repository(values['PRIVATE_CONFIG_REPOSITORY'])
    pull = api.request('GET', prefix + '/pulls/' + str(number))
    files = api.request('GET', prefix + '/pulls/' + str(number) + '/files?per_page=100')
    current = inspect(api, values)
    proposed = inspect(api, values, head)
    if (current != snapshot or pull.get('state') != 'open' or pull.get('draft') is not False or
            pull.get('base', {}).get('sha') != snapshot['revision'] or pull.get('head', {}).get('sha') != head or
            pull.get('head', {}).get('repo', {}).get('full_name') != repository(values['PRIVATE_CONFIG_REPOSITORY']) or
            len(files) != 1 or files[0].get('filename') != PATH or files[0].get('status') != 'modified' or
            proposed['files'][PATH] != prepared[PATH] or proposed['files'][OVERLAY] != snapshot['files'][OVERLAY]):
        raise RuntimeError('Viewer publication review changed; merge refused')
    # Repeat both mutable references immediately before the protected merge call.
    if (api.request('GET', prefix + '/git/ref/heads/main')['object']['sha'] != snapshot['revision'] or
            api.request('GET', prefix + '/pulls/' + str(number))['head']['sha'] != head):
        raise RuntimeError('Viewer reviewed references advanced; merge refused')


def merge(api, values, snapshot, prepared, number, head):
    if type(number) is not int or number < 1 or not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head):
        raise ValueError('Viewer merge requires its exact journaled PR and head')
    prefix = 'repos/' + repository(values['PRIVATE_CONFIG_REPOSITORY'])
    pull = api.request('GET', prefix + '/pulls/' + str(number))
    if pull.get('merged') is True:
        # A lost merge response resumes only the same reviewed head and exact resulting bytes.
        if (pull.get('head', {}).get('sha') != head or
                not isinstance(pull.get('merge_commit_sha'), str) or not re.fullmatch('[a-f0-9]{40}', pull['merge_commit_sha']) or
                any(pull.get(side, {}).get('repo', {}).get('full_name') != repository(values['PRIVATE_CONFIG_REPOSITORY']) for side in ('base', 'head'))):
            raise RuntimeError('Completed viewer merge has another identity')
        merged = inspect(api, values, pull.get('merge_commit_sha'))
        current = inspect(api, values)
        if (merged['files'][PATH] != prepared[PATH] or merged['files'][OVERLAY] != snapshot['files'][OVERLAY] or
                current['files'] != merged['files']):
            raise RuntimeError('Completed viewer merge bytes changed; resume refused')
        return current['revision']
    review(api, values, snapshot, prepared, number, head)
    result = api.request('PUT', prefix + '/pulls/' + str(number) + '/merge', {'sha': head, 'merge_method': 'squash'})
    if result.get('merged') is not True:
        raise RuntimeError('Protected viewer merge incomplete')
    current = inspect(api, values)
    if (current['revision'] != result['sha'] or current['files'][PATH] != prepared[PATH] or
            current['files'][OVERLAY] != snapshot['files'][OVERLAY]):
        raise RuntimeError('Merged viewer source changed; reinspect before runtime enrollment')
    return current['revision']
