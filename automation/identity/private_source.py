"""Publish complete identity inputs to a reviewable private pull request."""
import base64
import hashlib
import json
from urllib.parse import quote

from automation.gitops.github_setup import inspect, repository


def publish(api, values, files):
    repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
    target = inspect(api, 'private-config', repo, True)
    if target is None:
        raise RuntimeError('Designated private identity repository is missing')
    if not files or set(files) - {'identity/configmap.yaml', 'identity/argo-values.yaml'} or 'identity/configmap.yaml' not in files:
        raise ValueError('Identity publication requires a complete bounded private bundle')
    prefix = 'repos/' + repo
    try:
        base = api.request('GET', prefix + '/git/ref/heads/main')['object']['sha']
    except RuntimeError as error:
        if str(error) != 'GitHub repository operation failed: HTTP 409' or target.get('size') != 0:
            raise
        # GitHub cannot create a PR in an empty repository. Seed no identity data;
        # provider branch protection still applies to this initial empty commit.
        api.request('PUT', prefix + '/contents/.gitkeep', {
            'message': 'Initialize private configuration repository', 'content': '', 'branch': 'main'})
        base = api.request('GET', prefix + '/git/ref/heads/main')['object']['sha']
    changed = {}
    for path, content in files.items():
        current = api.request('GET', prefix + '/contents/' + path + '?ref=' + base, missing=True)
        if not current or base64.b64decode(current['content'], validate=True) != content.encode():
            changed[path] = content
    if not changed:
        return {'private_source_changed': False, 'private_revision': base}
    digest = hashlib.sha256(json.dumps({'base': base, 'files': files}, sort_keys=True).encode()).hexdigest()
    branch = 'identity/desired-' + digest[:20]
    ref_path = prefix + '/git/ref/heads/' + quote(branch, safe='/')
    existing = api.request('GET', ref_path, missing=True)
    if existing:
        # A retry must not adopt a branch whose content was changed independently.
        commit = api.request('GET', prefix + '/git/commits/' + existing['object']['sha'])
        difference = api.request('GET', prefix + '/compare/' + base + '...' + existing['object']['sha'])
        if ([row['sha'] for row in commit['parents']] != [base] or
                difference.get('total_commits') != 1 or
                {row['filename'] for row in difference.get('files', [])} != set(changed) or
                any(row['status'] not in ('added', 'modified') or 'previous_filename' in row
                    for row in difference.get('files', []))):
            raise RuntimeError('Existing private identity branch exceeds its scoped change')
        for path, content in files.items():
            current = api.request('GET', prefix + '/contents/' + path + '?ref=' + existing['object']['sha'])
            if base64.b64decode(current['content'], validate=True) != content.encode():
                raise RuntimeError('Existing private identity branch differs; overwrite refused')
    else:
        parent = api.request('GET', prefix + '/git/commits/' + base)
        tree = []
        for path, content in changed.items():
            blob = api.request('POST', prefix + '/git/blobs', {'content': content, 'encoding': 'utf-8'})
            tree.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']})
        tree = api.request('POST', prefix + '/git/trees', {'base_tree': parent['tree']['sha'], 'tree': tree})
        commit = api.request('POST', prefix + '/git/commits', {
            'message': 'Reconcile scoped private identity inputs', 'tree': tree['sha'], 'parents': [base]})
        api.request('POST', prefix + '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': commit['sha']})
    if api.request('GET', prefix + '/git/ref/heads/main')['object']['sha'] != base:
        raise RuntimeError('Private base changed during preparation; regenerate before merge')
    pulls = api.request('GET', prefix + '/pulls?state=open&head=' + quote(repo.split('/')[0] + ':' + branch, safe=''))
    if len(pulls) > 1:
        raise RuntimeError('Private identity pull request ownership is ambiguous')
    pull = pulls[0] if pulls else api.request('POST', prefix + '/pulls', {
        'head': branch, 'base': 'main', 'title': 'Reconcile scoped identity inputs',
        'body': 'Apply the complete private identity inventory and persistent revocations. '
                'Only identity inputs change; omitted overlays and unrelated files are retained. '
                'Realm changes remain owned by serialized keycloak-config-cli reconciliation.'})
    return {'private_source_changed': True, 'private_pull_request': pull['number'],
            'private_source_merged': False}
