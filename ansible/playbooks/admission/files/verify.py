"""Observe controller convergence and exercise admission without creating workloads."""
import copy
import json
import re
import sys
import time
import urllib.parse

sys.path.insert(0, '/opt/cloudlab')

from playbooks.istio.files.kube import application_ready, condition, get, kube, wait


def probe(namespace):
    return {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': 'cloudlab-admission-proof', 'namespace': namespace},
            'spec': {'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                     'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532,
                                         'seccompProfile': {'type': 'RuntimeDefault'}},
                     'containers': [{'name': 'proof',
                         'image': 'docker.io/library/python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed',
                         'command': ['true'],
                         'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                             'capabilities': {'drop': ['ALL']}},
                         'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                                       'limits': {'cpu': '100m', 'memory': '64Mi'}}}]}}


def dry_run(document):
    return kube('create', '--dry-run=server', '-f', '-', '-o', 'json',
                document=document, allow_failure=True)


def admission(namespace):
    good = probe(namespace)
    if dry_run(good).returncode:
        raise RuntimeError('Restricted digest workload did not pass server admission')
    mutable = copy.deepcopy(good)
    mutable['spec']['containers'][0]['image'] = 'docker.io/library/python:3.13-slim-bookworm'
    unbounded = copy.deepcopy(good)
    unbounded['spec']['containers'][0]['resources']['requests']['cpu'] = '0'
    unbounded['spec']['containers'][0]['resources']['limits']['cpu'] = '0'
    token = copy.deepcopy(good)
    token['spec']['volumes'] = [{'name': 'api', 'projected': {
        'sources': [{'serviceAccountToken': {'path': 'token'}}]}}]
    for document, message in (
            (mutable, 'Workload images must use an immutable SHA-256 digest.'),
            (unbounded, 'Every workload container requires positive CPU and memory requests and limits.'),
            (token, 'Workloads must not project Kubernetes service account tokens.')):
        result = dry_run(document)
        if result.returncode or message not in result.stderr:
            raise RuntimeError('Audit policy must admit and warn about each workload violation')
    privileged = copy.deepcopy(good)
    privileged['spec']['containers'][0]['securityContext']['privileged'] = True
    denied = dry_run(privileged)
    if not denied.returncode or 'violates PodSecurity' not in denied.stderr:
        raise RuntimeError('Application Pod Security must reject privileged workloads')


def ephemeral_admission(namespace):
    pods = get('pod', namespace=namespace)['items']
    target = next((row for row in pods if condition(row, 'Ready') and
                   not row['metadata'].get('deletionTimestamp')), None)
    if not target:
        raise RuntimeError('Ephemeral admission requires an existing ready workload')
    path = ('/api/v1/namespaces/' + urllib.parse.quote(namespace, safe='') + '/pods/' +
            urllib.parse.quote(target['metadata']['name'], safe='') + '/ephemeralcontainers?dryRun=All')
    container = copy.deepcopy(probe(namespace)['spec']['containers'][0])
    container.pop('resources')  # Kubernetes forbids per-container resources on this subresource.
    container['name'] = 'cloudlab-admission-proof'
    container['securityContext'].update(runAsNonRoot=True, runAsUser=65532,
                                        seccompProfile={'type': 'RuntimeDefault'})
    target = copy.deepcopy(target)
    target['spec'].setdefault('ephemeralContainers', []).append(container)
    for mutable in (False, True):
        if mutable:
            container['image'] = 'docker.io/library/python:3.13-slim-bookworm'
        result = kube('replace', '--raw', path, '-f', '-', document=target, allow_failure=True)
        warned = 'Workload images must use an immutable SHA-256 digest.' in result.stderr
        if result.returncode or warned != mutable:
            raise RuntimeError('Ephemeral image admission did not preserve its audited digest rule')


def policy_ready(policy):
    if not policy:
        return False
    ready = policy.get('status', {}).get('conditionStatus', {})
    conditions = ready.get('conditions', [])
    return ready.get('ready') is True and bool(conditions) and all(
        row.get('status') == 'True' and row.get('observedGeneration', policy['metadata']['generation']) ==
        policy['metadata']['generation'] for row in conditions)


def controllers():
    deployments = get('deployment', namespace='cloudlab-policy')['items']
    pods = get('pod', namespace='cloudlab-policy')['items']
    if len(deployments) != 2 or any(not condition(row, 'Available') for row in deployments):
        raise RuntimeError('Admission deployments are not available')
    admission_pods = [row for row in pods if row['metadata'].get('labels', {}).get(
        'app.kubernetes.io/component') == 'admission-controller' and condition(row, 'Ready')]
    if len(admission_pods) != 2 or len({row['spec']['nodeName'] for row in admission_pods}) != 2:
        raise RuntimeError('Admission replicas must be ready on both nodes')
    return sorted((row['metadata']['uid'], row['spec']['nodeName'],
                   tuple((container['name'], container.get('restartCount', 0))
                         for container in row.get('status', {}).get('containerStatuses', [])))
                  for row in pods if condition(row, 'Ready'))


def run(revision):
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Admission verification requires the exact published source revision')
    names = ('cloudlab-kyverno', 'cloudlab-workload-policy')
    wait(lambda: all(application_ready(name, revision) for name in names),
         'admission GitOps convergence', timeout=600)
    for name, background, resources in (
            ('cloudlab-workload-contract', True, ['pods']),
            ('cloudlab-workload-ephemeral', False, ['pods/ephemeralcontainers'])):
        wait(lambda: policy_ready(get('validatingpolicy.policies.kyverno.io', name)),
             'native workload policy readiness', timeout=180)
        policy = get('validatingpolicy.policies.kyverno.io', name)
        if (not policy_ready(policy) or policy['spec']['validationActions'] != ['Audit', 'Warn'] or
                policy['spec']['failurePolicy'] != 'Fail' or
                policy['spec']['evaluation']['background']['enabled'] is not background or
                policy['spec']['matchConstraints']['resourceRules'][0]['resources'] != resources or
                policy['spec']['matchConstraints']['namespaceSelector'] != {
                    'matchLabels': {'cloudlab.io/owner': 'service-platform'}}):
            raise RuntimeError('Native workload audit policy is not ready or its scope changed')
    namespace = get('namespace', 'cloudlab-policy')
    if namespace['metadata'].get('labels', {}).get('pod-security.kubernetes.io/enforce') != 'restricted':
        raise RuntimeError('Admission controllers require restricted Pod Security')
    workloads = [row for row in get('namespace')['items'] if
                 row['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'service-platform']
    if not workloads or any(row['metadata']['labels'].get('pod-security.kubernetes.io/enforce') != 'restricted'
                            for row in workloads):
        raise RuntimeError('Application namespaces require their existing restricted Pod Security owner')
    for row in workloads:
        admission(row['metadata']['name'])
        ephemeral_admission(row['metadata']['name'])
    initial = controllers()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        time.sleep(5)
        if controllers() != initial or not all(application_ready(name, revision) for name in names):
            raise RuntimeError('Admission controllers changed during bounded stability verification')
    return {'applications_converged': 2, 'admission_nodes': 2, 'policy_mode': 'audit',
            'mutable_image_warned': True, 'zero_resources_warned': True, 'projected_token_warned': True,
            'ephemeral_image_warned': True,
            'restricted_workload_admitted': True,
            'privileged_workload_denied': True, 'workloads_created': 0, 'controllers_stable': True}


if __name__ == '__main__':
    try:
        print(json.dumps(run(sys.argv[1]), sort_keys=True))
    except Exception:
        raise SystemExit('Admission verification incomplete; existing workloads and policy mode retained') from None
