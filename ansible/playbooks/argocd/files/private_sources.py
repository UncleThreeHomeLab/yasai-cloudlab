"""Render optional private roots from ignored inputs; never log their values."""
import json
from pathlib import Path, PurePosixPath
import re


OWNER = 'private-gitops'
LABEL = 'cloudlab.io/owner'
PEM_TEMPLATE = r'''{{- $key := .PRIVATE_KEY | trim -}}
{{- $header := regexFind "^-----BEGIN (RSA )?PRIVATE KEY-----" $key -}}
{{- $footer := replace "BEGIN" "END" $header -}}
{{- $body := $key | trimPrefix $header | trimSuffix $footer -}}
{{- printf "%s\n%s\n%s\n" $header (regexReplaceAll "[[:space:]]+" $body "") $footer -}}'''


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
        'spec': {'refreshInterval': '24h', 'secretStoreRef': {'name': store_name, 'kind': 'ClusterSecretStore'},
            'target': {'name': name, 'creationPolicy': 'Owner', 'deletionPolicy': 'Retain',
                'template': {'engineVersion': 'v2', 'mergePolicy': 'Replace', 'metadata': {
                    'labels': {'argocd.argoproj.io/secret-type': 'repository', LABEL: OWNER}},
                    'data': {'type': 'git', 'url': entry['repository'], 'project': name,
                             'githubAppID': '{{ .APP_ID }}', 'githubAppInstallationID': '{{ .INSTALLATION_ID }}',
                             'githubAppPrivateKey': PEM_TEMPLATE}}},
            'dataFrom': [{'extract': {'key': 'github-argocd'}}]}}
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': metadata(name),
        'spec': {'project': name, 'source': {'repoURL': entry['repository'],
            'targetRevision': entry['revision'], 'path': entry['path']},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': name},
            'syncPolicy': {'automated': {'prune': False, 'selfHeal': True, 'allowEmpty': False},
                           'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}
    return [namespace, project, credential, app]


def registry_enabled(public):
    settings = public.get('privateSources', {})
    if not isinstance(settings, dict):
        raise ValueError('Private source settings must be a mapping')
    enabled = settings.get('enabled', False)
    if type(enabled) is not bool:
        raise ValueError('privateSources.enabled must be a YAML boolean')
    if enabled and (public.get('admission', {}).get('enabled') is not True or
                    public.get('externalSecrets', {}).get('enabled') is not True or
                    public.get('externalSecrets', {}).get('reconcile') is not True):
        raise ValueError('Private source catalog requires admission and External Secrets')
    return enabled


def validate_registry(value):
    """Validate the complete private input with the same native chart Argo consumes."""
    import subprocess
    if (not isinstance(value, dict) or set(value) != {'sources'} or not isinstance(value['sources'], list)
            or len(value['sources']) > 20 or any(not isinstance(row, dict) or
                set(row) != {'name', 'repository', 'revision', 'path'} or
                any(not isinstance(item, str) for item in row.values()) for row in value['sources'])):
        raise ValueError('Private registry requires its explicit complete sources list')
    chart = Path(__file__).resolve().parents[4] / 'platform/delivery/private-sources'
    result = subprocess.run(['helm', 'template', 'private-sources', str(chart), '-n', 'argocd', '-f', '-'],
                            input=json.dumps(value), capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError('Private registry violates its bounded native chart contract')
    return value


def registry(client, values, public, revision):
    """Read the required registry at the exact identity revision, never mutable main."""
    if not registry_enabled(public):
        return None
    if json.loads(values.get('PRIVATE_GITOPS_SOURCES') or '[]') != [] or values.get('PRIVATE_GITOPS_REMOVE'):
        raise ValueError('Populated legacy private source inputs require an explicitly scoped migration')
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Private registry requires its immutable private source revision')
    import yaml
    from playbooks.argocd.files.github_setup import repository
    from playbooks.keycloak.files.private_source import decode_contents
    document = client.request('GET', 'repos/' + repository(values['PRIVATE_CONFIG_REPOSITORY']) +
                              '/contents/platform/sources.yaml?ref=' + revision)
    if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('encoding') != 'base64'
            or type(document.get('size')) is not int or not 0 <= document['size'] <= 1048576):
        raise ValueError('Private registry must be a bounded regular file')
    return validate_registry(yaml.safe_load(decode_contents(document)))


def policy_specs(names):
    """Capture trusted public definitions; live policy objects are never expectations."""
    import subprocess
    import yaml
    chart = Path(__file__).resolve().parents[4] / 'platform/delivery/admission/policies'
    result = subprocess.run(['helm', 'template', 'cloudlab-workload-policy', str(chart)],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError('Private source ownership policy definitions cannot be rendered')
    return {row['metadata']['name']: row['spec'] for row in yaml.safe_load_all(result.stdout)
            if row and row['kind'] == 'ValidatingPolicy' and row['metadata']['name'] in names}


if __name__ == '__main__':
    try:
        import os
        import sys
        from dotenv import dotenv_values
        values = dotenv_values(Path(__file__).resolve().parents[4] / '.env', interpolate=False)
        removal = values.get('PRIVATE_GITOPS_REMOVE') or ''
        if removal and not re.fullmatch(r'[a-z][a-z0-9-]{0,28}[a-z0-9]|[a-z]', removal):
            raise RuntimeError('Invalid private source removal selector')
        payload = {'sources': sources(values.get('PRIVATE_GITOPS_SOURCES')), 'remove': removal,
                   'configuration_repository': values.get('PRIVATE_CONFIG_REPOSITORY') or ''}
        if sys.argv[1:] == ['verify'] and payload['configuration_repository']:
            from playbooks.argocd.files.github_app import configuration_revision
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
            payload['configuration_revision'] = configuration_revision(values)
        print(json.dumps(payload))
    except Exception:
        raise SystemExit('Invalid private GitOps inputs; values withheld') from None
