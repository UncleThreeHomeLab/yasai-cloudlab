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
