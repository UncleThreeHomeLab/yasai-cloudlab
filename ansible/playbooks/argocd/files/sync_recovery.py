"""Retry an exhausted secret-only sync after its inputs demonstrably recover."""
from datetime import datetime
import re


def recovered_secret_sync(application, revision, read_secret):
    metadata = application.get('metadata', {})
    spec = application.get('spec', {})
    status = application.get('status', {})
    operation = status.get('operationState', {})
    scope = {
        'cloudlab-public-root': ('cloudlab-root', 'gitops/roots/public', 'argocd'),
        'cloudlab-identity': ('cloudlab-identity', 'platform/identity/keycloak', 'cloudlab-identity'),
    }.get(metadata.get('name'))
    if (not scope or metadata.get('namespace') != 'argocd' or application.get('operation') or
            metadata.get('deletionTimestamp') or not metadata.get('uid') or not metadata.get('resourceVersion') or
            not re.fullmatch('[a-f0-9]{40}', revision) or spec.get('sources') or
            spec.get('project') != scope[0] or spec.get('source', {}).get('path') != scope[1] or
            spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': scope[2]} or
            status.get('sync', {}).get('revision') != revision or operation.get('phase') not in ('Failed', 'Error') or
            any(c.get('type', '').endswith('Error') and c['type'] != 'SyncError'
                for c in status.get('conditions', [])) or
            status.get('sync', {}).get('comparedTo', {}).get('source') != spec.get('source') or
            operation.get('syncResult', {}).get('source') != spec.get('source')):
        return []
    failed = [row for row in operation.get('syncResult', {}).get('resources', [])
              if row.get('hookPhase') in ('Failed', 'Error') or row.get('status') == 'SyncFailed']
    if not failed or any(row.get('group') != 'external-secrets.io' or row.get('kind') != 'ExternalSecret' or
                         row.get('namespace') != scope[2] or not row.get('name') for row in failed):
        return []
    try:
        finished = datetime.fromisoformat(operation['finishedAt'].replace('Z', '+00:00'))
        for row in failed:
            secret = read_secret(row['name'], scope[2]) or {}
            ready = [c for c in secret.get('status', {}).get('conditions', [])
                     if c.get('type') == 'Ready' and c.get('status') == 'True']
            if (len(ready) != 1 or secret.get('metadata', {}).get('deletionTimestamp') or
                    ready[0].get('observedGeneration', secret.get('metadata', {}).get('generation')) !=
                    secret.get('metadata', {}).get('generation') or
                    datetime.fromisoformat(ready[0]['lastTransitionTime'].replace('Z', '+00:00')) <= finished):
                return []
    except (KeyError, ValueError, TypeError):
        return []
    return [
        {'op': 'test', 'path': '/metadata/uid', 'value': metadata['uid']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': metadata['resourceVersion']},
        {'op': 'add', 'path': '/operation', 'value': {
            'initiatedBy': {'username': 'cloudlab-secret-recovery'},
            'sync': {'revision': revision, 'prune': False, 'syncStrategy': {'hook': {}}}}},
    ]
