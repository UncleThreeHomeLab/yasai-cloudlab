"""Prove shared runner admission and API boundaries using server dry-run only."""
import copy
import json
import sys
import urllib.parse

sys.path.insert(0, '/opt/cloudlab')

from playbooks.istio.files.kube import condition, get, kube, wait


NAMES = ('cloudlab-ci-boundary', 'cloudlab-ci-runner', 'cloudlab-ci-namespace')


def dry_run(document, controller=None):
    return kube('create', '--dry-run=server', '-f', '-', '-o', 'json',
                *(['--as', controller] if controller else []), document=document, allow_failure=True)


def outcome(result, enforce, policy):
    if bool(result.returncode) != enforce or policy not in result.stderr:
        raise RuntimeError('CI admission did not match its declared scope and policy mode')


def runner_pod(namespace, profile):
    document = {'apiVersion': 'v1', 'kind': 'Pod',
                'metadata': {'name': 'cloudlab-admission-proof', 'namespace': namespace},
                'spec': copy.deepcopy(profile['spec'])}
    document['spec']['containers'][0]['env'] += [
        {'name': 'ACTIONS_RUNNER_INPUT_JITCONFIG', 'valueFrom': {
            'secretKeyRef': {'name': document['metadata']['name'], 'key': 'jitToken'}}},
        {'name': 'GITHUB_ACTIONS_RUNNER_EXTRA_USER_AGENT', 'value': 'actions-runner-controller/0.15.0'},
        {'name': 'ACTIONS_RUNNER_RETURN_VERSION_DEPRECATED_EXIT_CODE', 'value': '1'}]
    return document


def violations(document):
    changes = {
        'foreign_image': lambda p: p['containers'][0].update(image='example.invalid/foreign@sha256:' + 'b' * 64),
        'other_account': lambda p: p.update(serviceAccountName='default'),
        'automatic_token': lambda p: p.update(automountServiceAccountToken=True),
        'runner_escalation': lambda p: p['containers'][0]['securityContext'].update(allowPrivilegeEscalation=True),
        'root_user': lambda p: p['containers'][0]['securityContext'].update(runAsUser=0),
        'extra_secret': lambda p: p['volumes'].append({'name': 'foreign', 'secret': {'secretName': 'github-arc'}}),
        'builder_health_token': lambda p: p['initContainers'][0]['volumeMounts'].append(
            {'name': 'health', 'mountPath': '/foreign', 'readOnly': True}),
        'extra_environment_secret': lambda p: p['containers'][0].update(envFrom=[{'secretRef': {'name': 'github-arc'}}]),
        'command_override': lambda p: p['containers'][0].update(args=['echo bypass']),
        'disabled_health_probe': lambda p: p['containers'][0].pop('livenessProbe'),
        'extra_token': lambda p: p['volumes'].append({'name': 'foreign', 'projected': {
            'sources': [{'serviceAccountToken': {'path': 'token'}}]}}),
        'unapproved_budget': lambda p: p['containers'][0]['resources']['limits'].update(memory='1Gi'),
    }
    for name, change in changes.items():
        bad = copy.deepcopy(document)
        change(bad['spec'])
        yield name, bad


def api_boundary(namespace, controller):
    health = 'system:serviceaccount:' + namespace + ':cloudlab-ci-health'
    for identity, verb, resource, name, scope in (
            (health, 'list', 'secrets', None, namespace),
            (health, 'get', 'pods', None, namespace),
            (health, 'create', 'pods', None, namespace),
            (health, 'patch', 'configmaps', 'cloudlab-ci-eligibility', namespace),
            (health, 'patch', 'namespaces', namespace, None),
            (health, 'create', 'rolebindings.rbac.authorization.k8s.io', None, namespace),
            (health, 'create', 'serviceaccounts', None, namespace),
            (health, 'impersonate', 'serviceaccounts', controller.rsplit(':', 1)[-1], 'cloudlab-ci-system'),
            (controller, 'patch', 'configmaps', 'cloudlab-ci-eligibility', namespace)):
        result = kube('auth', 'can-i', verb, resource + ('/' + name if name else ''), '--as', identity,
                      *(['-n', scope] if scope else []),
                      *(['--subresource', 'token'] if resource == 'serviceaccounts' and verb == 'create' else []), allow_failure=True)
        if result.returncode != 1 or result.stdout.strip() != 'no':
            raise RuntimeError('Runner or controller API permissions exceed their declared boundary')


def debug_boundary(enforce):
    pods = (get('pod', namespace='cloudlab-ci-system') or {}).get('items', [])
    target = next((p for p in pods if condition(p, 'Ready') and not p['metadata'].get('deletionTimestamp')), None)
    if not target:
        raise RuntimeError('CI debug admission requires an existing ready controller or listener')
    target = copy.deepcopy(target)
    target['spec'].setdefault('ephemeralContainers', []).append({
        'name': 'cloudlab-admission-proof', 'image': target['spec']['containers'][0]['image'],
        'command': ['true'], 'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532,
            'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
            'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'RuntimeDefault'}}})
    path = ('/api/v1/namespaces/cloudlab-ci-system/pods/' +
            urllib.parse.quote(target['metadata']['name'], safe='') + '/ephemeralcontainers?dryRun=All')
    result = kube('replace', '--raw', path, '-f', '-', document=target, allow_failure=True)
    outcome(result, enforce, 'CI pods cannot add ephemeral debug containers.')


def run(actions):
    if actions not in (['Audit', 'Warn'], ['Deny']):
        raise ValueError('CI verification requires explicit audit or enforcement actions')
    enforce = actions == ['Deny']
    for name in NAMES:
        def ready():
            row = get('validatingpolicy.policies.kyverno.io', name) or {}
            status = row.get('status', {}).get('conditionStatus', {})
            return row.get('spec', {}).get('validationActions') == actions and status.get('ready') is True
        wait(ready, 'shared CI admission readiness', timeout=180)
    namespaces = [n for n in get('namespace')['items'] if n['metadata']['name'].startswith('cloudlab-ci-')]
    pools, checks, existing = 0, 0, 0
    for namespace in namespaces:
        name, labels = namespace['metadata']['name'], namespace['metadata'].get('labels', {})
        role = 'controller' if name == 'cloudlab-ci-system' else 'qualification' if name.startswith('cloudlab-ci-proof-') else 'runner'
        if labels.get('cloudlab.io/owner') != 'ci-platform' or labels.get('cloudlab.io/ci-role') != role:
            raise RuntimeError('CI namespace escaped automatic policy selection')
        changed = kube('label', 'namespace', name, 'cloudlab.io/owner=unmanaged', '--overwrite',
                       '--dry-run=server', '-o', 'json', allow_failure=True)
        outcome(changed, enforce, 'CI namespaces must retain automatic guardrail selection')
        for pod in (get('pods', namespace=name) or {}).get('items', []):
            if pod['metadata'].get('deletionTimestamp') or pod.get('status', {}).get('phase') in ('Succeeded', 'Failed'):
                continue
            result = kube('replace', '--dry-run=server', '-f', '-', '-o', 'json', document=pod, allow_failure=True)
            if result.returncode or any(p in result.stderr for p in NAMES):
                raise RuntimeError('Existing CI pod violates the shared admission boundary')
            existing += 1
        if role != 'runner':
            continue
        sets = (get('autoscalingrunnerset.actions.github.com', namespace=name) or {}).get('items', [])
        for scale_set in sets:
            policy_name = next(v['configMap']['name'] for v in scale_set['spec']['template']['spec']['volumes'] if v['name'] == 'eligibility')
            profile = json.loads(get('configmap', policy_name, name)['data']['admission.json'])
            controller = profile['controller']
            document = runner_pod(name, profile)
            result = dry_run(document, controller)
            if result.returncode or any(p in result.stderr for p in NAMES):
                raise RuntimeError('Approved runner profile did not pass clean admission')
            outcome(dry_run(document), enforce, 'Only the assigned ARC controller')
            for _, bad in violations(document):
                outcome(dry_run(bad, controller), enforce, 'cloudlab-ci-runner')
                checks += 1
            for field, value in (('hostNetwork', True), ('volumes', [{'name': 'host', 'hostPath': {'path': '/'}}])):
                bad = copy.deepcopy(document)
                bad['spec'][field] = value
                rejected = dry_run(bad, controller)
                if not rejected.returncode or not any(x in rejected.stderr for x in ('violates PodSecurity', 'cloudlab-ci-boundary')):
                    raise RuntimeError('CI host access was not rejected by its admission boundary')
            api_boundary(name, controller)
            pools += 1
    if not pools:
        raise RuntimeError('CI admission requires at least one registered runner pool')
    debug_boundary(enforce)
    return {'runner_namespaces': sum(n['metadata']['labels']['cloudlab.io/ci-role'] == 'runner' for n in namespaces),
            'runner_pools': pools, 'profile_violations_checked': checks,
            'runner_mode': 'enforce' if enforce else 'audit', 'approved_profiles_admitted': True,
            'namespace_selection_protected': True, 'api_writes_and_credentials_denied': True,
            'controller_profile_write_denied': True, 'debug_admission_checked': True,
            'host_access_denied': True, 'existing_pods_checked': existing, 'workloads_created': 0}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.loads(sys.argv[1])), sort_keys=True))
    except Exception:
        raise SystemExit('CI admission verification incomplete; no workload or credentials changed') from None
