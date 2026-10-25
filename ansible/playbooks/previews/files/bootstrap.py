"""Bounded Application bootstrap; Git and the preview controller own convergence."""
import fcntl
import json
from pathlib import Path
import sys

sys.path.insert(0, '/opt/cloudlab')
from playbooks.istio.files.kube import kube, get, wait, contains
from playbooks.previews.files.contract import OWNER, catalog
from playbooks.previews.files.admission import native

APP = 'cloudlab-previews'
BASE = Path('/var/lib/cloudlab/previews')


def application(payload, permissions):
    catalog(payload['catalog'])
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {
        'name': APP, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': APP, 'sources': [
            {'repoURL': payload['repository'], 'targetRevision': payload['revision'], 'path': 'platform/delivery/previews',
             'helm': {'releaseName': APP, 'valueFiles': ['$values/previews/catalog.json'],
                      'valuesObject': {'enabled': True, 'permissionsEnabled': permissions, 'platformRepository': payload['repository']}}},
            {'repoURL': payload['privateRepository'], 'targetRevision': 'main', 'ref': 'values'}],
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                           'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}


def configure(payload):
    if set(payload) != {'repository', 'revision', 'privateRepository', 'privateRevision', 'catalog'}:
        raise ValueError('Preview bootstrap requires its complete published payload')
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        desired = application(payload, True)
        current = get('application.argoproj.io', APP, 'argocd')
        if current and (current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER or
                current['metadata'].get('ownerReferences') or current['metadata'].get('finalizers')):
            raise ValueError('Preview Application has conflicting ownership')
        changed = not current or not contains(current, desired)
        def converged(permissions):
            obj = get('application.argoproj.io', APP, 'argocd') or {}
            sync = obj.get('status', {}).get('sync', {})
            return (contains(obj, application(payload, permissions)) and sync.get('status') == 'Synced' and
                    sync.get('revisions') == [payload['revision'], payload['privateRevision']] and
                    obj.get('status', {}).get('health', {}).get('status') in ('Healthy', 'Progressing') and
                    not obj.get('operation') and obj.get('status', {}).get('operationState', {}).get('phase') in (None, 'Succeeded'))
        if changed:
            kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=application(payload, False))
            wait(lambda: converged(False), 'preview admission staging', timeout=600)
            # No controller privilege is enabled until native policy compilation and dry-run denials pass.
            namespace = None
            if payload['catalog']['approvals']:
                from playbooks.previews.files.resources import resources
                namespace = resources(payload['catalog']['approvals'][0], payload['catalog'], payload['repository'], 'admission-proof')[0]
                if get('namespace', namespace['metadata']['name']):
                    namespace = None
            native(lambda kind, name: get(kind, name), payload['catalog'], namespace)
            kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
        wait(lambda: converged(True), 'preview controller convergence', timeout=600)
        return {'changed': changed, 'owner': OWNER, 'controller_enabled': True}


if __name__ == '__main__':
    try:
        print(json.dumps(configure(json.load(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Preview bootstrap failed; resources and private diagnostics retained') from None
