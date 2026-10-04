"""Render optional private roots from ignored inputs; never log their values."""
import json
from pathlib import Path, PurePosixPath
import re


OWNER = 'private-gitops'
LABEL = 'cloudlab.io/owner'


def sources(raw):
    from github_setup import repository
    entries = json.loads(raw or '[]')
    if not isinstance(entries, list) or len(entries) > 20:
        raise RuntimeError('Private sources must be a list of at most 20 entries')
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'name', 'repository', 'revision', 'path'}:
            raise RuntimeError('Private sources require name, repository, revision, and path')
        if not all(isinstance(value, str) for value in entry.values()):
            raise RuntimeError('Private source fields must be strings')
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,28}[a-z0-9]|[a-z]', entry['name']):
            raise RuntimeError('Private source name must be a DNS label of at most 30 characters')
        repository(entry['repository'])
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_.-]*', entry['revision']):
            raise RuntimeError('Private source revision is invalid')
        path = PurePosixPath(entry['path'])
        if path.is_absolute() or '..' in path.parts or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_.-]*', entry['path']):
            raise RuntimeError('Private source path must stay inside its repository')
        result.append(dict(entry))
    if len({entry['name'] for entry in result}) != len(result):
        raise RuntimeError('Private source names must be unique')
    return result


def resources(entry, store_name):
    name = 'cloudlab-private-' + entry['name']
    def metadata(object_name, namespace='argocd'):
        return dict(name=object_name, labels={LABEL: OWNER}, **({'namespace': namespace} if namespace else {}))
    namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': metadata(name, None)}
    namespace['metadata']['labels'].update({'pod-security.kubernetes.io/enforce': 'restricted',
                                          'pod-security.kubernetes.io/enforce-version': 'v1.36'})
    project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject', 'metadata': metadata(name),
        'spec': {'sourceRepos': [entry['repository']],
            'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': name}],
            'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [
                {'group': group, 'kind': kind} for group, kind in (
                    ('', 'ConfigMap'), ('', 'Service'), ('', 'ServiceAccount'), ('', 'PersistentVolumeClaim'),
                    ('apps', 'Deployment'), ('apps', 'StatefulSet'), ('batch', 'Job'), ('batch', 'CronJob'),
                    ('networking.k8s.io', 'NetworkPolicy'), ('policy', 'PodDisruptionBudget'))]}}
    credential = {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'metadata': metadata(name),
        'spec': {'refreshInterval': '5m', 'secretStoreRef': {'name': store_name, 'kind': 'ClusterSecretStore'},
            'target': {'name': name, 'creationPolicy': 'Owner', 'deletionPolicy': 'Retain',
                'template': {'engineVersion': 'v2', 'metadata': {
                    'labels': {'argocd.argoproj.io/secret-type': 'repository', LABEL: OWNER}},
                    'data': {'type': 'git', 'url': entry['repository'], 'project': name,
                             'githubAppID': '{{ .APP_ID }}', 'githubAppInstallationID': '{{ .INSTALLATION_ID }}',
                             'githubAppPrivateKey': '{{ .PRIVATE_KEY }}'}}},
            'data': [{'secretKey': key, 'remoteRef': {'key': 'github-argocd/' + key}}
                     for key in ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY')]}}
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': metadata(name),
        'spec': {'project': name, 'source': {'repoURL': entry['repository'],
            'targetRevision': entry['revision'], 'path': entry['path']},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': name},
            'syncPolicy': {'automated': {'prune': False, 'selfHeal': True, 'allowEmpty': False},
                           'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}
    return [namespace, project, credential, app]


if __name__ == '__main__':
    try:
        from dotenv import dotenv_values
        values = dotenv_values(Path(__file__).resolve().parents[2] / '.env', interpolate=False)
        removal = values.get('PRIVATE_GITOPS_REMOVE') or ''
        if removal and not re.fullmatch(r'[a-z][a-z0-9-]{0,28}[a-z0-9]|[a-z]', removal):
            raise RuntimeError('Invalid private source removal selector')
        print(json.dumps({'sources': sources(values.get('PRIVATE_GITOPS_SOURCES')), 'remove': removal,
                          'fixture_repository': values.get('PRIVATE_TEST_REPOSITORY') or ''}))
    except Exception:
        raise SystemExit('Invalid private GitOps inputs; values withheld') from None
