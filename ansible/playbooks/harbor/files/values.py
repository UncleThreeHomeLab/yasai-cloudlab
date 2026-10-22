"""Independent bounded Harbor storage and immutable external bootstrap images."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if not (ROOT / 'platform').is_dir():
    ROOT = ROOT.parent
BASE = ROOT / 'platform/harbor'
POLICY = json.loads((BASE / 'policy.json').read_text())


def resources(cpu, memory, requested_cpu=20, requested_memory=64):
    return {'requests': {'cpu': f'{requested_cpu}m', 'memory': f'{requested_memory}Mi'},
            'limits': {'cpu': f'{cpu}m', 'memory': f'{memory}Mi'}}


def values():
    images = json.loads((BASE / 'images.lock.json').read_text())
    def image(name):
        repository, tag = images[name].split('@')[0].rsplit(':', 1)
        return {'repository': repository, 'tag': tag + '@' + images[name].split('@')[1]}
    def component(name, cpu, memory):
        return {'image': image(name), 'replicas': 1, 'resources': resources(cpu, memory),
                'automountServiceAccountToken': False, 'serviceAccountName': 'cloudlab-harbor',
                'revisionHistoryLimit': 2}
    core = component('harbor-core', 500, 768)
    core.update(existingSecret='harbor-runtime', secretName='harbor-token-signing',
                existingXsrfSecret='harbor-runtime', existingXsrfSecretKey='CSRF_KEY',
                extraEnvVars=[{'name': 'CONFIG_OVERWRITE_JSON', 'valueFrom': {
                    'secretKeyRef': {'name': 'harbor-oidc', 'key': 'configuration'}}}])
    core['initContainers'] = [{
        'name': 'token-key-format', 'image': images['harbor-core'],
        'command': ['/bin/sh', '-ec', 'umask 077; exec openssl rsa -traditional -in /source/tls.key -out /output/registry-private-key.pem'],
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 10000, 'allowPrivilegeEscalation': False,
                            'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']},
                            'seccompProfile': {'type': 'RuntimeDefault'}},
        'resources': resources(100, 64, 10, 16),
        'volumeMounts': [{'name': 'token-service-private-key', 'mountPath': '/source', 'readOnly': True},
                         {'name': 'psc', 'mountPath': '/output'}]}]
    job = component('harbor-jobservice', 200, 256)
    job.update(existingSecret='harbor-runtime', existingSecretKey='JOBSERVICE_SECRET',
               maxJobWorkers=1, jobLoggers=['stdout'])
    database = component('harbor-db', 400, 1536)
    database.update(password='', shmSizeLimit='256Mi', initContainer={
        'permissions': {'resources': resources(50, 128)}})
    registry = {name: component(image_name, cpu, memory) for name, image_name, cpu, memory in (
        ('registry', 'registry-photon', 400, 512), ('controller', 'harbor-registryctl', 100, 128))}
    registry.update(replicas=1, serviceAccountName='cloudlab-harbor', automountServiceAccountToken=False,
                    existingSecret='harbor-runtime', existingSecretKey='REGISTRY_HTTP_SECRET',
                    credentials={'username': 'harbor_registry_user', 'password': '', 'existingSecret': 'harbor-runtime'})
    return {
        'expose': {'type': 'clusterIP', 'tls': {'enabled': False}},
        'externalURL': 'https://harbor.internal.example.invalid',
        'existingSecretAdminPassword': 'harbor-emergency', 'existingSecretAdminPasswordKey': 'password',
        'existingSecretSecretKey': 'harbor-runtime', 'harborAdminPassword': '', 'secretKey': '',
        'persistence': {'enabled': True, 'resourcePolicy': 'keep', 'persistentVolumeClaim': {
            name: {'existingClaim': 'harbor-' + name, 'storageClass': 'cloudlab-harbor', 'size': f'{size}Gi'}
            for name, size in POLICY['claims_gib'].items()},
            'imageChartStorage': {'type': 'filesystem', 'disableredirect': True}},
        'updateStrategy': {'type': 'Recreate'},
        'nginx': component('nginx-photon', 100, 128), 'portal': component('harbor-portal', 100, 128),
        'core': core, 'jobservice': job, 'registry': registry,
        'database': {'type': 'internal', 'internal': database, 'external': {'existingSecret': 'harbor-database'},
                     'maxOpenConns': 50, 'maxIdleConns': 10},
        'redis': {'type': 'internal', 'internal': component('valkey-photon', 100, 256)},
        'trivy': {'enabled': False}, 'exporter': {'enabled': False}, 'metrics': {'enabled': False},
        'containerSecurityContext': {'privileged': False, 'allowPrivilegeEscalation': False,
            'runAsNonRoot': True, 'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'RuntimeDefault'}},
    }
