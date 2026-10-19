"""Validate the pinned controller chart without registry or GitHub credentials."""
import hashlib
import json
from pathlib import Path
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[4]
CONTROLLER = ROOT / 'platform/delivery/ci/controller'
POOL = ROOT / 'platform/delivery/ci/pool'


def render(values=None, *, chart=CONTROLLER, parameters=None, namespace=None, release='cloudlab-arc-controller', include_crds=True):
    namespace = namespace or ('cloudlab-ci-private' if chart == POOL else 'cloudlab-ci-system')
    command = ['helm', 'template', release, str(chart),
               '--namespace', namespace, '--kube-version', '1.36.5',
               '--skip-tests', '-f', str(chart / 'values.json'), '-f', '-']
    if include_crds:
        command.append('--include-crds')
    for name, value in (parameters or {}).items():
        command += ['--set-string', name + '=' + value]
    outputs = [subprocess.run(command, input=yaml.safe_dump(values or {}), capture_output=True,
                              text=True, check=True, timeout=60).stdout for _ in range(2)]
    if outputs[0] != outputs[1]:
        raise ValueError('CI chart rendering must preserve credentials and stable declarations')
    return [row for row in yaml.safe_load_all(outputs[0]) if row]


def check():
    lock = json.loads((CONTROLLER / 'artifact.lock.json').read_text())
    if hashlib.sha256((CONTROLLER / lock['archive']).read_bytes()).hexdigest() != lock['sha256']:
        raise ValueError('CI controller chart differs from its upstream checksum')
    # Schema validation uses an unreachable example; live inputs require accepted bootstrap digests.
    image = {'repository': 'registry.example.invalid/cloudlab-public/ci-controller',
             'tag': '0.15.0@sha256:' + 'a' * 64}
    objects = render({'arc': {'image': image}})
    deployments = [row for row in objects if row['kind'] == 'Deployment']
    if len(deployments) != 1:
        raise ValueError('CI requires one controller Deployment')
    deployment = deployments[0]
    pod = deployment['spec']['template']['spec']
    container, = pod['containers']
    security = container['securityContext']
    if (deployment['metadata']['namespace'] != 'cloudlab-ci-system' or deployment['spec']['replicas'] != 1 or
            container['image'] != image['repository'] + ':' + image['tag'] or
            '--watch-single-namespace=cloudlab-ci-private' not in container['args'] or
            '--auto-scaling-runner-set-only' not in container['args'] or
            container['resources']['limits'] != {'cpu': '200m', 'memory': '256Mi', 'ephemeral-storage': '128Mi'} or
            security.get('allowPrivilegeEscalation') is not False or
            security.get('readOnlyRootFilesystem') is not True or security['capabilities'] != {'drop': ['ALL']} or
            pod['securityContext']['runAsUser'] != 65532 or
            pod['securityContext']['seccompProfile'] != {'type': 'RuntimeDefault'} or
            not container.get('livenessProbe') or not container.get('readinessProbe')):
        raise ValueError('CI controller escaped its namespace, resources or security profile')
    namespaces = {'cloudlab-ci-system', 'cloudlab-ci-private'}
    if {row['metadata']['name'] for row in objects if row['kind'] == 'Namespace' and
            row['metadata'].get('labels', {}).get('cloudlab.io/service-secrets') == 'approved'} != namespaces:
        raise ValueError('CI namespaces require explicit approval for existing read-only secret delivery')
    for row in objects:
        kind = row['kind']
        if kind in ('ClusterRole', 'ClusterRoleBinding', 'Secret', 'Job', 'PersistentVolumeClaim'):
            raise ValueError('CI controller requires scoped roles and external secret delivery')
        if kind in ('Role', 'RoleBinding'):
            if row['metadata']['namespace'] not in namespaces:
                raise ValueError('CI RBAC escaped its two namespaces')
            if any(subject.get('namespace') != 'cloudlab-ci-system' for subject in row.get('subjects', [])):
                raise ValueError('CI RBAC delegates to an unexpected service account namespace')
        if kind == 'ExternalSecret' and row['spec']['dataFrom'] != [{'extract': {'key': 'harbor-cloudlab-public-pull'}}]:
            raise ValueError('Controller image bootstrap must use only the public project pull robot')
    quota = next(row for row in objects if row['kind'] == 'ResourceQuota' and row['metadata']['namespace'] == 'cloudlab-ci-private')
    if any(quota['spec']['hard'][field] != value for field, value in {
            'pods': '1', 'limits.cpu': '3', 'limits.memory': '6Gi', 'limits.ephemeral-storage': '32Gi'}.items()):
        raise ValueError('CI must admit at most one bounded build pod')
    crds = [row for row in objects if row['kind'] == 'CustomResourceDefinition']
    if len(crds) != 4 or any(row['spec']['group'] != 'actions.github.com' for row in crds):
        raise ValueError('CI must use only the selected runner scale-set API')
    return {'controller_replicas': 1, 'runner_namespace_count': 1, 'max_build_pods': 1,
            'cluster_role_grants': 0, 'chart_checksum_verified': True}


def check_pool(values):
    lock = json.loads((POOL / 'artifact.lock.json').read_text())
    if hashlib.sha256((POOL / lock['archive']).read_bytes()).hexdigest() != lock['sha256']:
        raise ValueError('CI pool chart differs from its upstream checksum')
    objects = render(values, chart=POOL)
    scale_set, = [row for row in objects if row['kind'] == 'AutoscalingRunnerSet']
    spec = scale_set['spec']
    pod = spec['template']['spec']
    runner, = pod['containers']
    builder, = pod['initContainers']
    baseline = yaml.safe_load((POOL.parent / 'runner.values.yaml').read_text())['template']['spec']
    qualified = next(row for row in baseline['containers'] if row['name'] == 'builder')
    if any(builder[field] != qualified[field] for field in ('command', 'args', 'env', 'securityContext', 'resources')):
        raise ValueError('CI builder differs from its independently qualified rootless profile')
    if (spec['minRunners'] != 0 or spec['maxRunners'] != 1 or
            pod['restartPolicy'] != 'Never' or pod['activeDeadlineSeconds'] != 1800 or
            pod['terminationGracePeriodSeconds'] != 30 or pod['hostUsers'] is not False or
            pod['automountServiceAccountToken'] is not False or
            pod['serviceAccountName'] != 'cloudlab-ci-health' or
            builder['restartPolicy'] != 'Always' or not builder.get('startupProbe') or
            any(row['name'] in ('workspace', 'health', 'eligibility') for row in builder['volumeMounts']) or
            not runner.get('livenessProbe') or
            runner['securityContext'] != baseline['containers'][0]['securityContext'] or
            runner['resources'] != baseline['containers'][0]['resources'] or
            runner['args'] != ['python3 -I -S /usr/local/libexec/cloudlab-ci-health.py && exec /home/runner/run.sh']):
        raise ValueError('CI runner escaped its lifecycle, health or isolation profile')
    roles = [row for row in objects if row['kind'] == 'ClusterRole']
    if len(roles) != 1 or roles[0]['rules'] != [
            {'apiGroups': [''], 'resources': ['nodes'], 'verbs': ['list']},
            {'nonResourceURLs': ['/readyz'], 'verbs': ['get']}]:
        raise ValueError('Runner health requires only node listing and API readiness')
    if any(row['kind'] in ('Secret', 'Job', 'Deployment', 'PersistentVolumeClaim') for row in objects):
        raise ValueError('CI pool cannot embed credentials, deploy applications or retain builds')
    return {'max_build_pods': 1, 'builder_restartable_sidecar': True,
            'runner_api_write_permissions': 0, 'chart_checksum_verified': True}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
