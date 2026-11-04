"""Pure public-root identity, readiness and pending-intent checks."""
import re

ROOT = 'cloudlab-public-root'


class ProofError(RuntimeError):
    pass


def idle(app):
    return (app.get('operation') is None
            and app.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'))


def root_ready(app):
    status = app.get('status', {})
    return (idle(app) and status.get('sync', {}).get('status') == 'Synced'
            and status.get('health', {}).get('status') == 'Healthy'
            and status.get('operationState', {}).get('phase') in (None, 'Succeeded'))


def root_gate(contract, root, baseline=None, *, require_idle=False):
    metadata, spec = root.get('metadata', {}), root.get('spec', {})
    source = spec.get('source', {})
    policy = spec.get('syncPolicy', {}).get('automated', {})
    binding = source.get('helm', {}).get('valuesObject', {}).get('identity', {}).get('argo', {})
    if (metadata.get('name') != ROOT or metadata.get('namespace') != 'argocd'
            or not metadata.get('uid') or metadata.get('deletionTimestamp') or metadata.get('ownerReferences')
            or metadata.get('finalizers') or spec.get('project') != 'cloudlab-root' or spec.get('sources')
            or source.get('repoURL') != contract['repository'] or source.get('targetRevision') != 'main'
            or source.get('path') != 'gitops/roots/public'
            or not isinstance(binding, dict) or binding.get('valuesRepository') != contract['private_repository']
            or not isinstance(binding.get('valuesRevision'), str) or not re.fullmatch('[a-f0-9]{40}', binding['valuesRevision'])
            or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
            or policy not in ({'prune': False, 'selfHeal': True, 'allowEmpty': False},
                              {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False})
            or policy.get('enabled', True) is not True
            or str(metadata.get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() == 'true'
            or root.get('status', {}).get('sync', {}).get('revision') != contract['public_revision']
            or any(condition.get('type', '').endswith('Error') for condition in root.get('status', {}).get('conditions', []))
            or (baseline is not None and (metadata['uid'] != baseline['metadata']['uid'] or spec != baseline['spec']))
            or (require_idle and not idle(root))):
        raise ProofError('Public root identity, source or pending intent changed')
