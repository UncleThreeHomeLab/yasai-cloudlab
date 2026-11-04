"""Observe the catalog Application owned by the public GitOps root."""
import json
import sys

sys.path.insert(0, '/opt/cloudlab')
try:
    from playbooks.argocd.files.service_activation import APP, OWNER, TRACKING, sources_match
except ModuleNotFoundError:
    sys.path.insert(0, '/opt/cloudlab/gitops')
    from service_activation import APP, OWNER, TRACKING, sources_match
from playbooks.istio.files.kube import get, wait


def converged(payload):
    app = get('application.argoproj.io', APP, 'argocd') or {}
    status = app.get('status', {})
    meta = app.get('metadata', {})
    spec = app.get('spec', {})
    return (meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') == TRACKING
            and meta.get('labels', {}).get('cloudlab.io/owner') == OWNER
            and not meta.get('deletionTimestamp') and not meta.get('finalizers') and not meta.get('ownerReferences')
            and spec.get('project') == APP
            and spec.get('destination') == {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
            and spec.get('syncPolicy', {}).get('automated') ==
                {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False}
            and sources_match(app, payload)
            and status.get('sync', {}).get('revisions') == [payload['revision'], payload['private_revision']]
            and status['sync'].get('status') == 'Synced'
            and status.get('health', {}).get('status') == 'Healthy' and not app.get('operation')
            and status.get('operationState', {}).get('phase') in (None, 'Succeeded')
            and not any(c.get('type', '').endswith('Error') for c in status.get('conditions', [])))


def observe(payload):
    wait(lambda: converged(payload), 'Git-owned service catalog convergence', timeout=600)
    return {'changed': False, 'catalog_owner_converged': True}


if __name__ == '__main__':
    try:
        print(json.dumps(observe(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Git-owned service catalog has not converged; resources and data retained') from None
