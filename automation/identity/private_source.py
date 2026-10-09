"""Publish complete identity inputs to a reviewable private pull request."""
import base64
import hashlib
import json
import re
from urllib.parse import quote

import yaml

from automation.gitops.github_setup import inspect, repository
from automation.identity.integrations import argo


def argo_values(api, values, revision, identity_issuer, origin, additional_origins):
    """Accept only the native client producer's exact immutable private overlay."""
    if not re.fullmatch('[a-f0-9]{40}', revision or ''):
        raise ValueError('Private Argo values require an immutable commit')
    repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
    if inspect(api, 'private-config', repo, True) is None:
        raise RuntimeError('Designated private identity repository is unavailable')
    contract = argo(identity_issuer, origin, additional_origins)
    documents = {}
    for filename in ('configmap.yaml', 'argo-values.yaml'):
        obj = api.request('GET', 'repos/' + repo + '/contents/identity/' + filename + '?ref=' + revision)
        if obj.get('type') != 'file' or obj.get('encoding') != 'base64' or obj.get('size', 1048577) > 1048576:
            raise RuntimeError('Private Argo source must be a bounded regular file')
        raw = base64.b64decode(obj['content'], validate=True)
        if len(raw) > 1048576:
            raise RuntimeError('Private Argo source exceeds its limit')
        documents[filename] = yaml.safe_load(raw)
    if documents['argo-values.yaml'] != contract['helm']:
        raise RuntimeError('Private Argo overlay differs from its scoped native OIDC contract')
    manifest = documents['configmap.yaml']
    if (not isinstance(manifest, dict) or manifest.get('kind') != 'ConfigMap' or manifest.get('apiVersion') != 'v1' or
            manifest.get('metadata', {}).get('name') != 'identity-private-state' or
            manifest.get('metadata', {}).get('namespace') != 'cloudlab-identity' or
            set(manifest.get('data', {})) != {'desired_state', 'revocations'}):
        raise RuntimeError('Private Argo source requires the complete owned identity inventory')
    source = json.loads(manifest['data']['desired_state'])
    revoked = json.loads(manifest['data']['revocations'])
    clients = [client for client in source['realms'].get('platform', {}).get('clients', []) if client.get('id') == 'argocd']
    denied = revoked['realms'].get('platform', {})
    if (clients != [contract['client']] or 'argocd' in denied.get('clients', []) or
            'argocd' in denied.get('removed_clients', [])):
        raise RuntimeError('Private Argo overlay requires its active exact-callback public client')
    return contract


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
