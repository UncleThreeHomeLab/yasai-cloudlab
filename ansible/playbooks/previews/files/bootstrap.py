"""Bounded Application bootstrap; Git and the preview controller own convergence."""
import fcntl
import base64
import json
from pathlib import Path
import sys

sys.path.insert(0, '/opt/cloudlab')
from playbooks.istio.files.kube import kube, get, wait, contains, condition
from playbooks.argocd.files.source_transition import accepted_identity_binding
from playbooks.argocd.files.private_sources import PEM_TEMPLATE
from playbooks.keycloak.files.maintenance import accepted_scoped_identity
from playbooks.previews.files.contract import OWNER, approval, obsolete, runtime_catalog
from playbooks.previews.files.admission import native

APP = 'cloudlab-previews'
BASE = Path('/var/lib/cloudlab/previews')


def prerequisites(payload):
    if set(payload) != {'repository', 'branch', 'revision', 'privateRepository', 'privateRevision', 'catalog'}:
        raise ValueError('Preview bootstrap requires its complete published payload')
    target = accepted_identity_binding(repository=payload['repository'], branch=payload['branch'],
        revision=payload['revision'], private_repository=payload['privateRepository'])
    if not target or accepted_scoped_identity(revision=payload['revision']) != {'identity_ready': True}:
        raise RuntimeError('Accepted native identity prerequisites are unavailable')
    expected = {
        'sourceRepos': [payload['repository'], target['valuesRepository']],
        'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': namespace} for namespace in ('argocd', 'cloudlab-identity')],
        'clusterResourceWhitelist': [{'group': group, 'kind': kind} for group, kind in (
            ('rbac.authorization.k8s.io', 'ClusterRole'), ('rbac.authorization.k8s.io', 'ClusterRoleBinding'),
            ('admissionregistration.k8s.io', 'ValidatingAdmissionPolicy'), ('admissionregistration.k8s.io', 'ValidatingAdmissionPolicyBinding'))],
        'namespaceResourceWhitelist': [{'group': group, 'kind': kind} for group, kind in (
            ('', 'ServiceAccount'), ('', 'ConfigMap'), ('rbac.authorization.k8s.io', 'Role'),
            ('rbac.authorization.k8s.io', 'RoleBinding'), ('batch', 'CronJob'), ('networking.k8s.io', 'NetworkPolicy'))]}
    project = get('appproject.argoproj.io', APP, 'argocd') or {}
    spec = project.get('spec', {})
    if (any(spec.get(key) != value for key, value in expected.items()) or spec.get('namespaceResourceBlacklist') or
            spec.get('clusterResourceBlacklist') or not project.get('metadata', {}).get('uid') or
            project['metadata'].get('deletionTimestamp') or project['metadata'].get('ownerReferences') or
            project['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APP):
        raise RuntimeError('Native preview project does not match its accepted private contract')
    name = APP + '-source'
    external = get('externalsecret.external-secrets.io', name, 'argocd') or {}
    meta, spec = external.get('metadata', {}), external.get('spec', {})
    target = spec.get('target', {})
    data = {'type': 'git', 'url': payload['privateRepository'], 'project': APP, 'githubAppID': '{{ .APP_ID }}',
            'githubAppInstallationID': '{{ .INSTALLATION_ID }}', 'githubAppPrivateKey': PEM_TEMPLATE}
    if (not meta.get('uid') or not meta.get('resourceVersion') or type(meta.get('generation')) is not int or meta['generation'] < 1 or
            meta.get('deletionTimestamp') or meta.get('ownerReferences') or
            meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-public-root:external-secrets.io/ExternalSecret:argocd/' + name or
            not {'Prune=false', 'Delete=false'} <= set(meta.get('annotations', {}).get('argocd.argoproj.io/sync-options', '').split(',')) or
            not condition(external, 'Ready') or spec.get('secretStoreRef') != {'name': 'cloudlab', 'kind': 'ClusterSecretStore'} or
            target.get('name') != name or target.get('creationPolicy') != 'Owner' or target.get('deletionPolicy') != 'Retain' or
            not contains(target.get('template', {}), {'engineVersion': 'v2', 'mergePolicy': 'Replace',
                'metadata': {'labels': {'argocd.argoproj.io/secret-type': 'repository'}}}) or
            target.get('template', {}).get('data') != data or spec.get('data') or
            len(spec.get('dataFrom', [])) != 1 or set(spec['dataFrom'][0]) != {'extract'} or
            spec['dataFrom'][0]['extract'].get('key') != 'github-argocd'):
        raise RuntimeError('Accepted preview repository ExternalSecret is not ready or owned')
    secret = get('secret', name, 'argocd') or {}
    metadata, observed = secret.get('metadata', {}), secret.get('data', {})
    refs = metadata.get('ownerReferences', [])
    if (not metadata.get('uid') or not metadata.get('resourceVersion') or metadata.get('deletionTimestamp') or secret.get('type') != 'Opaque' or
            metadata.get('labels', {}).get('argocd.argoproj.io/secret-type') != 'repository' or len(refs) != 1 or
            not contains(refs[0], {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'name': name, 'uid': meta['uid'], 'controller': True}) or
            set(observed) != set(data) or any(not isinstance(value, str) or not value for value in observed.values()) or
            any(base64.b64decode(observed[key], validate=True).decode() != data[key] for key in ('type', 'url', 'project'))):
        raise RuntimeError('Accepted preview repository credential has conflicting ownership')
    return {'prerequisites_ready': True}


def application(payload, permissions):
    runtime_catalog(payload['catalog'])
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
    prerequisites(payload)
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
            positive = next((row for row in payload['catalog']['approvals'] if not obsolete(row)), None)
            if positive is not None:
                approval(positive)
                from playbooks.previews.files.resources import resources
                namespace = resources(positive, payload['catalog'], payload['repository'], 'admission-proof')[0]
                if get('namespace', namespace['metadata']['name']):
                    namespace = None
            native(lambda kind, name: get(kind, name), payload['catalog'], namespace)
            kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
        wait(lambda: converged(True), 'preview controller convergence', timeout=600)
        return {'changed': changed, 'owner': OWNER, 'controller_enabled': True}


if __name__ == '__main__':
    try:
        request = json.load(sys.stdin)
        if sys.argv[1:] not in ([], ['check']):
            raise ValueError('Unknown preview bootstrap mode')
        print(json.dumps(prerequisites(request) if sys.argv[1:] == ['check'] else configure(request), sort_keys=True))
    except Exception:
        raise SystemExit('Preview bootstrap failed; resources and private diagnostics retained') from None
