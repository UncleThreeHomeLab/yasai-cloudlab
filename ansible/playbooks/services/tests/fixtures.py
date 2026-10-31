"""Synthetic inputs; no VM, vault or service credentials."""
from pathlib import Path
import yaml


def definition():
    return yaml.safe_load((Path(__file__).resolve().parents[4] / 'charts/service/values.yaml').read_text())


def approval():
    return {'name': 'synthetic', 'namespace': 'cloudlab-app-synthetic',
            'repository': 'https://github.com/example/fixture.git', 'revision': 'a' * 40,
            'valuesPath': 'apps/synthetic.yaml', 'secretReferences': [], 'configMaps': []}


def catalog_payload():
    return {'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
            'private_repository': 'https://github.com/example/private.git', 'private_revision': 'b' * 40,
            'telemetry': False, 'values': {'catalog': [], 'dataApprovals': []}}


def composition_approval():
    value = approval()
    images = {'web': 'registry.example.invalid/cloudlab-public/synthetic@sha256:' + 'a' * 64,
              'worker': 'registry.example.invalid/cloudlab-public/synthetic@sha256:' + 'b' * 64}
    workloads = []
    for name, image in images.items():
        workloads.append({'name': name, 'replicas': 1, 'podSpec': {
            'automountServiceAccountToken': False, 'enableServiceLinks': False,
            'securityContext': {'runAsUser': 0, 'runAsGroup': 0, 'runAsNonRoot': False,
                                'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': name, 'image': image, 'command': ['sh', '/' + name],
                'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                                    'capabilities': {'drop': ['ALL'], 'add': ['CHOWN']}},
                'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'},
                              'limits': {'cpu': '200m', 'memory': '256Mi'}}}], 'volumes': []}})
    value['composition'] = {
        'chart': {'repository': 'https://github.com/example/application.git', 'revision': 'c' * 40,
                  'path': 'deploy/helm/application'},
        'images': images, 'imageValues': {'web': 'images.web', 'worker': 'images.worker'},
        'workloads': workloads, 'claims': [],
        'budget': {'requests.cpu': '500m', 'requests.memory': '512Mi', 'limits.cpu': '1000m',
                   'limits.memory': '1024Mi', 'pods': 4, 'persistentvolumeclaims': 0, 'requests.storage': '1Gi'},
        'backends': {'web.internal.example.invalid': {'service': 'web', 'port': 8080, 'selector': {'component': 'web'}}}, 'secrets': []}
    return value


"""Pre-handoff semantic reference used only by parity checks."""
import copy
import hashlib

import yaml

from playbooks.services.files.contract import ROOT, validate


def notes_values(definition, issuer, database_ca, telemetry=False):
    definition = validate(definition)
    if definition['name'] != 'notes' or not definition['oidc']['enabled'] or not definition['oidc']['public']:
        raise ValueError('Notes requires its approved public PKCE client')
    if set(definition['data']) != {'database', 'bucket'}:
        raise ValueError('Notes requires scoped SQL and S3 requests')
    if not issuer.startswith('https://') or not issuer.endswith('/realms/applications'):
        raise ValueError('Notes requires the approved application realm issuer')
    if 'BEGIN CERTIFICATE' not in database_ca:
        raise ValueError('Notes requires the existing CNPG public CA')
    result = yaml.safe_load((ROOT / 'apps/notes/values.yaml').read_text())
    private = [e for e in definition.get('additionalExposures', []) if e['class'] == 'private']
    if len(private) != 1:
        raise ValueError('Notes requires one private operations exposure')
    for name in ('web', 'api'):
        value = result[name]
        value.pop('renderDisabled', None)
        files = ('web.py', 'app.js', 'index.html', 'style.css') if name == 'web' else ('api.py', 'requirements.txt', 'lib.zip')
        files += ('telemetry.py', 'telemetry-requirements.txt')
        # ConfigMap source changes must also change the Deployment template.
        value['environment']['SOURCE_SHA256'] = hashlib.sha256(b''.join(hashlib.sha256(
            (ROOT / 'apps/notes' / filename).read_bytes().replace(b'\r\n', b'\n')).digest() for filename in files)).hexdigest()
        for field in ('owner', 'image', 'replicas', 'resources'):
            value[field] = copy.deepcopy(definition[field])
        value['exposure'] = copy.deepcopy(definition['exposure'])
        value['additionalExposures'] = copy.deepcopy(private)
        value['oidc'] = copy.deepcopy(definition['oidc'])
        value['environment']['OIDC_ISSUER'] = issuer
        value['environment']['OIDC_AUDIENCE'] = definition['oidc']['audience']
        value['environment']['OPERATIONS_HOST'] = private[0]['hostname']
    result['web']['environment']['OIDC_CLIENT'] = definition['oidc']['client']
    result['web']['environment']['OIDC_SCOPES'] = ' '.join(['openid', *definition['oidc']['scopes']])
    result['web']['data'] = {}
    result['web']['secrets'] = []
    result['api']['exposure']['path'] = '/api'
    result['api']['additionalExposures'][0]['path'] = '/api'
    result['api']['data'] = copy.deepcopy(definition['data'])
    result['api']['environment']['PGDATABASE'] = definition['data']['database']['name']
    result['api']['environment']['PGHOST'] = 'cloudlab-postgres-rw.cloudlab-data.svc'
    result['api']['secrets'] = [
        {'name': definition['data']['database']['credentialReference'], 'mountPath': '/secrets/database'},
        {'name': definition['data']['bucket']['credentialReference'], 'mountPath': '/secrets/objects'}]
    result['databaseCA'] = database_ca
    if telemetry:
        for name in ('web', 'api'):
            value = result[name]
            value['ports'].append({'name': 'http-metrics', 'port': 9091})
            value['environment'].update(OTEL_ENABLED='1', PYTHONPATH='/dependencies:/config/source:/config/source/lib.zip',
                OTEL_EXPORTER_OTLP_TRACES_ENDPOINT='http://cloudlab-alloy.cloudlab-observability.svc:4318/v1/traces')
        result['api']['initCommand'] += ['-r', '/config/source/telemetry-requirements.txt']
        result['web']['initCommand'] = ['python', '-m', 'pip', 'install', '--index-url', 'https://pypi.org/simple',
            '--disable-pip-version-check', '--no-cache-dir', '--require-hashes', '--only-binary=:all:',
            '--target', '/dependencies', '-r', '/config/source/telemetry-requirements.txt']
    for kind, budget in (('requests', 1000), ('limits', 2000)):
        for unit, suffix in (('cpu', 1), ('memory', 2)):
            if (2 * definition['replicas'] + 1) * int(definition['resources'][kind][unit][:-suffix]) > budget:
                raise ValueError('Combined notes workloads exceed their namespace budget')
    for name in ('web', 'api'): validate(result[name])
    return result


def composition_definition():
    value = definition()
    value['exposure'] = {'class': 'private', 'hostname': 'web.internal.example.invalid',
                         'access': 'tailnet', 'path': '/', 'port': 8080}
    return value


def composition_runtime():
    """A fully owned synthetic runtime, including native policy and real Pod authority."""
    import copy
    import json
    from playbooks.services.files.gitops import resources
    definition, approval = composition_definition(), composition_approval()
    entry = {'definition': definition, 'approval': approval, 'publication': 'ready'}
    namespace = approval['namespace']
    objects = resources(definition, approval, 'https://github.com/example/platform.git', 'd' * 40)
    application_name = approval['name'] + '-' + definition['name']
    state = {}
    for row in objects:
        row['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = 'cloudlab-services:owned'
        state[(row['kind'], row['metadata']['name'], row['metadata'].get('namespace'))] = row
    policy = state[('ValidatingPolicy', 'cloudlab-composition-synthetic', None)]
    policy['metadata']['generation'] = 1
    policy['status'] = {'conditionStatus': {'ready': True, 'conditions': [{'status': 'True', 'observedGeneration': 1}]}}
    guard = copy.deepcopy(policy)
    guard['metadata']['name'] = 'cloudlab-composition-namespace'
    guard['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'cloudlab-workload-policy:owned'
    state[('ValidatingPolicy', guard['metadata']['name'], None)] = guard
    for name, target in (('synthetic', application_name), ('synthetic-profile', 'synthetic-profile')):
        app = copy.deepcopy(state[('ApplicationSet', name, 'argocd')]['spec']['template'])
        app['metadata']['name'] = target
        app['status'] = {'health': {'status': 'Healthy'}, 'sync': {'status': 'Synced'}}
        state[('Application', target, 'argocd')] = app
    state[('Application', 'cloudlab-services', 'argocd')] = {'spec': {'sources': [
        {'repoURL': 'https://github.com/example/platform.git', 'targetRevision': 'd' * 40},
        {'repoURL': approval['repository'], 'targetRevision': 'main', 'ref': 'values'}]}}
    state[('ConfigMap', 'composition-synthetic', 'cloudlab-policy')] = {'metadata': {'name': 'composition-synthetic'},
        'data': {'release.json': json.dumps({'approval': policy['metadata']['annotations']['cloudlab.io/composition-profile'],
                                           'images': approval['composition']['images']})}}
    profiles = next(row['expression'] for row in policy['spec']['variables'] if row['name'] == 'profiles')
    profiles = json.loads(json.loads(profiles[len('yaml.parse('):-1]))
    for index, row in enumerate(profiles):
        name = row['name']
        state[('Deployment', name, namespace)] = {'metadata': {'name': name, 'uid': name + '-deployment', 'generation': 1},
            'spec': {'replicas': row['replicas'], 'template': {'spec': copy.deepcopy(row['podSpec'])}},
            'status': {'observedGeneration': 1, **{field: row['replicas'] for field in
                ('replicas', 'updatedReplicas', 'readyReplicas', 'availableReplicas')}}}
        state[('ReplicaSet', name + '-rs', namespace)] = {'metadata': {'name': name + '-rs', 'uid': name + '-rs',
            'ownerReferences': [{'kind': 'Deployment', 'name': name, 'uid': name + '-deployment', 'controller': True}]}}
        spec = copy.deepcopy(row['podSpec'])
        spec.update(nodeName='node-a', tolerations=copy.deepcopy([
            {'key': 'node.kubernetes.io/not-ready', 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300},
            {'key': 'node.kubernetes.io/unreachable', 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300}]))
        spec['containers'][0]['command'] = ['python', '-m', name]
        # Keep declared and observed commands identical for this Python health caller.
        row['podSpec']['containers'][0]['command'] = spec['containers'][0]['command']
        approval['composition']['workloads'][index]['podSpec']['containers'][0]['command'] = spec['containers'][0]['command']
        state[('Deployment', name, namespace)]['spec']['template']['spec']['containers'][0]['command'] = spec['containers'][0]['command']
        state[('Pod', name + '-pod', namespace)] = {'metadata': {'name': name + '-pod', 'uid': name + '-pod', 'generation': 1,
            'labels': {'component': name}, 'annotations': {'ambient.istio.io/redirection': 'enabled'},
            'ownerReferences': [{'kind': 'ReplicaSet', 'name': name + '-rs', 'uid': name + '-rs', 'controller': True}]},
            'spec': spec, 'status': {'phase': 'Running', 'podIP': '10.42.0.' + str(index + 10),
                                   'conditions': [{'type': 'Ready', 'status': 'True'}]}}
    # Re-render policy after choosing the concrete approved commands.
    updated = resources(definition, approval, 'https://github.com/example/platform.git', 'd' * 40)
    new_policy = next(row for row in updated if row['kind'] == 'ValidatingPolicy')
    profile_digest = new_policy['metadata']['annotations']['cloudlab.io/composition-profile']
    new_policy['metadata'] = policy['metadata']
    new_policy['metadata']['annotations']['cloudlab.io/composition-profile'] = profile_digest
    new_policy['status'] = policy['status']
    state[('ValidatingPolicy', 'cloudlab-composition-synthetic', None)] = new_policy
    profile_app = state[('Application', 'synthetic-profile', 'argocd')]
    profile_app['spec']['source']['helm']['valuesObject']['approval'] = new_policy['metadata']['annotations']['cloudlab.io/composition-profile']
    current = json.loads(state[('ConfigMap', 'composition-synthetic', 'cloudlab-policy')]['data']['release.json'])
    current['approval'] = new_policy['metadata']['annotations']['cloudlab.io/composition-profile']
    state[('ConfigMap', 'composition-synthetic', 'cloudlab-policy')]['data']['release.json'] = json.dumps(current)
    state[('Service', 'web', namespace)] = {'metadata': {'name': 'web'}, 'spec': {
        'type': 'ClusterIP', 'selector': {'component': 'web'}, 'ports': [{'port': 8080, 'protocol': 'TCP'}]}}
    state[('Node', 'node-a', None)] = {'metadata': {'name': 'node-a'}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
    state[('Namespace', 'cloudlab-app-other', None)] = {'metadata': {'name': 'cloudlab-app-other', 'labels': {
        'cloudlab.io/owner': 'service-platform', 'pod-security.kubernetes.io/enforce': 'restricted'}}}
    state[('Pod', 'other-pod', 'cloudlab-app-other')] = {'metadata': {'name': 'other-pod'},
        'spec': {'nodeName': 'node-b', 'containers': [{'name': 'client', 'command': ['python']}]},
        'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
    kinds = {'namespace': 'Namespace', 'nodes': 'Node', 'deployment': 'Deployment', 'pods': 'Pod',
        'replicasets': 'ReplicaSet', 'configmap': 'ConfigMap', 'service': 'Service', 'resourcequota': 'ResourceQuota',
        'application.argoproj.io': 'Application', 'validatingpolicy.policies.kyverno.io': 'ValidatingPolicy',
        'authorizationpolicies.security.istio.io': 'AuthorizationPolicy', 'networkpolicies': 'NetworkPolicy'}
    def get(kind, name=None, namespace=None):
        kind = kinds[kind]
        if name: return state.get((kind, name, namespace))
        return {'items': [value for (actual, _, ns), value in state.items() if actual == kind and (namespace is None or ns == namespace)]}
    return entry, state, get
