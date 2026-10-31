"""One bounded owner for the runtime catalog Application; Argo owns its resources."""
import fcntl
import json
from pathlib import Path
import sys

sys.path.insert(0, '/opt/cloudlab')
from playbooks.istio.files.kube import get, contains, kube, application_ready, wait
from playbooks.services.files.contract import exposure_bindings

APP = 'cloudlab-services'
OWNER = 'service-platform'


def converged(payload):
    app = get('application.argoproj.io', APP, 'argocd') or {}
    status = app.get('status', {})
    sources = app.get('spec', {}).get('sources', [])
    return (len(sources) == 2 and sources[0].get('repoURL') == payload['repository']
            and sources[0].get('targetRevision') == payload['revision']
            and sources[0].get('path') == 'platform/delivery/services'
            and sources[0].get('helm', {}).get('valueFiles') == ['$values/services/catalog.json', '$values/identity/argo-values.yaml']
            and sources[1] == {'repoURL': payload['private_repository'], 'targetRevision': 'main', 'ref': 'values'}
            and status.get('sync', {}).get('revisions') == [payload['revision'], payload['private_revision']]
            and status['sync'].get('status') == 'Synced'
            and status.get('health', {}).get('status') == 'Healthy' and not app.get('operation')
            and status.get('operationState', {}).get('phase') in (None, 'Succeeded')
            and not any(c.get('type', '').endswith('Error') for c in status.get('conditions', [])))


def application(payload):
    """Complete declaration shared by bootstrap and scoped source operations."""
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
               'metadata': {'name': APP, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
               'spec': {'project': APP, 'sources': [
                   {'repoURL': payload['repository'], 'targetRevision': payload['revision'],
                    'path': 'platform/delivery/services', 'helm': {
                        'valueFiles': ['$values/services/catalog.json', '$values/identity/argo-values.yaml'],
                        'valuesObject': {'repository': payload['repository'], 'revision': payload['revision'], 'telemetry': payload['telemetry']}}},
                   {'repoURL': payload['private_repository'], 'targetRevision': 'main', 'ref': 'values'}],
                        'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                        'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                                       'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}


def configure(payload):
    if set(payload) != {'repository', 'revision', 'private_repository', 'private_revision', 'telemetry', 'values'}:
        raise ValueError('Catalog configuration requires its complete committed source')
    if any(row['approval'].get('composition') for row in payload['values']['catalog']):
        from playbooks.istio.files.kube import condition_status_ready as policy_ready
        wait(lambda: policy_ready(get('validatingpolicy.policies.kyverno.io', 'cloudlab-composition-namespace')),
             'composition namespace admission readiness', timeout=600)
    desired = application(payload)
    with Path('/run/lock/cloudlab-services.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for row in payload['values']['catalog']:
            approval = row['approval']
            namespace = get('namespace', approval['namespace'])
            if namespace and (namespace['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER or
                              not namespace['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(APP + ':')):
                raise RuntimeError('Service namespace already has another owner; implicit adoption refused')
            for kind in ('appproject.argoproj.io', 'applicationset.argoproj.io'):
                obj = get(kind, approval['name'], 'argocd')
                if obj and not obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(APP + ':'):
                    raise RuntimeError('Service declaration collides with an existing platform object')
        current = get('application.argoproj.io', APP, 'argocd')
        if current and (current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER or
                        current['metadata'].get('finalizers') or current['metadata'].get('ownerReferences')):
            raise RuntimeError('Catalog Application has a conflicting owner')
        if current:
            before = current['spec'].get('source', {}).get('helm', {}).get('valuesObject', {}).get('catalog', [])
            after = payload['values']['catalog']
            if {row['approval']['name'] for row in before} - {row['approval']['name'] for row in after}:
                raise ValueError('Catalog removal requires persistent retired intent; preserve namespaces and data')
            old = {row['approval']['name']: row for row in before}
            for row in after:
                previous = old.get(row['approval']['name'])
                if previous:
                    if exposure_bindings(previous['definition']) != exposure_bindings(row['definition']):
                        raise ValueError('Exposure changes require explicit migration; catalog apply cannot perform cutover')
        changed = not current or not contains(current, desired)
        if changed:
            kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
        wait(lambda: converged(payload), 'service catalog convergence', timeout=600)
        return {'changed': changed}


if __name__ == '__main__':
    try:
        print(json.dumps(configure(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Service catalog configuration failed; existing workloads and data retained') from None
