"""Observe controller convergence and exercise admission without creating workloads."""
import copy
import json
import re
import sys
import time
import urllib.parse

sys.path.insert(0, '/opt/cloudlab')

from playbooks.istio.files.kube import application_ready, condition, get, kube, wait, condition_status_ready as policy_ready


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


def digest_result(result, enforce):
    native = 'Workload images must use an immutable SHA-256 digest.' in result.stderr
    # The repository webhook can reject the tag before the digest webhook runs.
    artifact = all(message in result.stderr for message in (
        'application-artifacts', 'approved-repositories',
        'Images require the approved application repository or retained bootstrap digest.'))
    return bool(result.returncode) == enforce and (native or (enforce and artifact))


def admission(namespace, enforce):
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
    if not digest_result(dry_run(mutable), enforce):
        raise RuntimeError('Mutable image did not match the declared policy mode')
    for document, message in (
            (unbounded, 'Every workload container requires positive CPU and memory requests and limits.'),
            (token, 'Workloads must not project Kubernetes service account tokens.')):
        result = dry_run(document)
        if bool(result.returncode) != enforce or message not in result.stderr:
            raise RuntimeError('Workload violation did not match the declared policy mode')
    privileged = copy.deepcopy(good)
    privileged['spec']['containers'][0]['securityContext'].update(privileged=True, allowPrivilegeEscalation=True)
    denied = dry_run(privileged)
    if not denied.returncode or 'violates PodSecurity' not in denied.stderr:
        raise RuntimeError('Application Pod Security must reject privileged workloads')


def ephemeral_admission(namespace, enforce):
    pods = (get('pod', namespace=namespace) or {}).get('items', [])
    target = next((row for row in pods if condition(row, 'Ready') and
                   not row['metadata'].get('deletionTimestamp')), None)
    if not target:
        return False
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
        if ((mutable and not digest_result(result, enforce)) or
                (not mutable and (result.returncode or warned))):
            raise RuntimeError('Ephemeral image admission did not preserve its declared digest rule')
    return True


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


def composition_guard():
    name = 'cloudlab-composition-namespace'
    wait(lambda: policy_ready(get('validatingpolicy.policies.kyverno.io', name)),
         'composition namespace guard readiness', timeout=180)
    policy = get('validatingpolicy.policies.kyverno.io', name)
    if (not policy_ready(policy) or policy['spec'].get('validationActions') != ['Deny'] or
            policy['spec'].get('failurePolicy') != 'Fail' or
            policy['spec'].get('evaluation', {}).get('admission') != {'enabled': True} or
            policy['spec'].get('matchConstraints', {}).get('resourceRules') != [{
                'apiGroups': [''], 'apiVersions': ['v1'], 'operations': ['CREATE', 'UPDATE'], 'resources': ['namespaces']}] or
            not policy['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-workload-policy:')):
        raise RuntimeError('Composition namespace guard is absent or differs from its fail-closed owner')
    namespace = 'cloudlab-app-admission-proof'
    if get('namespace', namespace) or get('validatingpolicy.policies.kyverno.io', 'cloudlab-composition-admission-proof'):
        raise RuntimeError('Composition guard proof requires its unused synthetic name')
    result = kube('create', '--dry-run=server', '-f', '-', allow_failure=True, document={
        'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace, 'labels': {
            'cloudlab.io/owner': 'service-platform', 'cloudlab.io/composition': 'approved',
            'pod-security.kubernetes.io/enforce': 'privileged', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
            'pod-security.kubernetes.io/audit': 'restricted', 'pod-security.kubernetes.io/warn': 'restricted'}}})
    if not result.returncode or name not in result.stderr:
        raise RuntimeError('Composition namespace without a profile was not denied by its native guard')


def namespaces(workloads, enforce, catalog):
    approved = {}
    for entry in catalog or []:
        if entry['approval'].get('composition') and entry['publication'] != 'retired':
            namespace = entry['approval']['namespace']
            if namespace in approved: raise RuntimeError('Composition namespace approval is ambiguous')
            approved[namespace] = entry
    ephemeral_checked = 0
    composition_checked = 0
    restricted_checked = 0
    if set(approved) - {row['metadata']['name'] for row in workloads}:
        raise RuntimeError('Approved composition namespace has not converged')
    for row in workloads:
        namespace = row['metadata']['name']
        if namespace in approved or row['metadata']['labels'].get('cloudlab.io/composition'):
            if namespace not in approved:
                raise RuntimeError('Privileged composition namespace has no current catalog approval')
            from playbooks.services.files.composition_verify import admission as composition_admission
            evidence = composition_admission(approved[namespace], get, condition, kube)
            composition_checked += 1
            ephemeral_checked += bool(evidence['ephemeral_denied'])
        else:
            if row['metadata']['labels'].get('pod-security.kubernetes.io/enforce') != 'restricted':
                raise RuntimeError('Application namespaces require their existing restricted Pod Security owner')
            admission(namespace, enforce)
            ephemeral_checked += ephemeral_admission(namespace, enforce)
            restricted_checked += 1
    if not ephemeral_checked:
        raise RuntimeError('Ephemeral admission requires at least one existing ready workload')
    return ephemeral_checked, composition_checked, restricted_checked


def run(revision, actions, catalog=None):
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Admission verification requires the exact published source revision')
    if actions not in (['Audit', 'Warn'], ['Deny']):
        raise ValueError('Admission verification requires the declared audit or enforcement actions')
    enforce = actions == ['Deny']
    names = ('cloudlab-kyverno', 'cloudlab-workload-policy')
    wait(lambda: all(application_ready(name, revision) for name in names),
         'admission GitOps convergence', timeout=600)
    for name, background, resources in (
            ('cloudlab-workload-contract', True, ['pods']),
            ('cloudlab-workload-ephemeral', False, ['pods/ephemeralcontainers'])):
        wait(lambda: policy_ready(get('validatingpolicy.policies.kyverno.io', name)),
             'native workload policy readiness', timeout=180)
        policy = get('validatingpolicy.policies.kyverno.io', name)
        if (not policy_ready(policy) or policy['spec']['validationActions'] != actions or
                policy['spec']['failurePolicy'] != 'Fail' or
                policy['spec']['evaluation']['background']['enabled'] is not background or
                policy['spec']['matchConstraints']['resourceRules'][0]['resources'] != resources or
                policy['spec']['matchConstraints']['namespaceSelector'] != {
                    'matchLabels': {'cloudlab.io/owner': 'service-platform'}}):
            raise RuntimeError('Native workload policy is not ready or its declared mode or scope changed')
    namespace = get('namespace', 'cloudlab-policy')
    if namespace['metadata'].get('labels', {}).get('pod-security.kubernetes.io/enforce') != 'restricted':
        raise RuntimeError('Admission controllers require restricted Pod Security')
    composition_guard()
    workloads = [row for row in get('namespace')['items'] if
                 row['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'service-platform']
    if not workloads:
        raise RuntimeError('Application namespaces require their existing restricted Pod Security owner')
    ephemeral_checked, composition_checked, restricted_checked = namespaces(workloads, enforce, catalog)
    initial = controllers()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        time.sleep(5)
        if controllers() != initial or not all(application_ready(name, revision) for name in names):
            raise RuntimeError('Admission controllers changed during bounded stability verification')
    outcome = 'denied' if enforce else 'warned'
    return {'applications_converged': 2, 'admission_nodes': 2, 'policy_mode': 'enforce' if enforce else 'audit',
            **{name + '_' + outcome: True for name in (
                'mutable_image', 'zero_resources', 'projected_token', 'ephemeral_image')},
            'ephemeral_namespaces_checked': ephemeral_checked,
            'composition_namespaces_checked': composition_checked,
            'unapproved_composition_namespace_denied': True,
            'restricted_workload_admitted': restricted_checked > 0,
            'privileged_workload_denied': True, 'workloads_created': 0, 'controllers_stable': True}


if __name__ == '__main__':
    try:
        raw = sys.stdin.read() if not sys.stdin.isatty() else ''
        print(json.dumps(run(sys.argv[1], json.loads(sys.argv[2]), json.loads(raw) if raw.strip() else []), sort_keys=True))
    except Exception:
        raise SystemExit('Admission verification incomplete; existing workloads and policy mode retained') from None
