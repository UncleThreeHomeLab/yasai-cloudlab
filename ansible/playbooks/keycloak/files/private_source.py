"""Publish complete identity inputs to a reviewable private pull request."""
import base64
import hashlib
import json
import re
from urllib.parse import quote

import yaml

from playbooks.argocd.files.github_setup import inspect, repository
from playbooks.keycloak.files.integrations import argo


def decode_contents(document):
    encoded = document.get('content')
    if not isinstance(encoded, str) or len(encoded) > 2 * 1024 * 1024:
        raise RuntimeError('Private identity source exceeds its bounded content contract')
    # GitHub's Contents API wraps base64 with line endings; other garbage fails.
    raw = base64.b64decode(encoded.replace('\r', '').replace('\n', ''), validate=True)
    if len(raw) > 1024 * 1024:
        raise RuntimeError('Private identity source exceeds its bounded content contract')
    return raw


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
        raw = decode_contents(obj)
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
    from playbooks.argocd.files.private_publish import publish as publish_owned
    return publish_owned(api, values, files, scope='identity')
