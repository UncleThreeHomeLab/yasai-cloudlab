"""Observe approved composition authority and real pods without creating probe workloads."""
import copy
import hashlib
import json
import urllib.parse

from playbooks.istio.files.kube import condition_status_ready
from playbooks.services.files.compositions import DEFAULT_TOLERATIONS, backend, normalized_spec, workload_labels


def profile_hash(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    for character, escaped in (('&', r'\u0026'), ('<', r'\u003c'), ('>', r'\u003e'),
                               ('\u2028', r'\u2028'), ('\u2029', r'\u2029')):
        raw = raw.replace(character, escaped)
    return hashlib.sha256(raw.encode()).hexdigest()


def decoded(expression):
    if not expression.startswith('yaml.parse(') or not expression.endswith(')'):
        raise RuntimeError('Composition policy profile is not its protected literal')
    return json.loads(json.loads(expression[len('yaml.parse('):-1]))


def authority(entry, get):
    definition, approval = entry['definition'], entry['approval']
    namespace, value = approval['namespace'], approval['composition']
    actual = get('namespace', namespace) or {}
    labels = actual.get('metadata', {}).get('labels', {})
    if (any(labels.get(key) != expected for key, expected in {
            'cloudlab.io/owner': 'service-platform', 'cloudlab.io/composition': 'approved',
            'pod-security.kubernetes.io/enforce': 'privileged', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
            'pod-security.kubernetes.io/audit': 'restricted', 'pod-security.kubernetes.io/warn': 'restricted',
            'istio.io/dataplane-mode': 'ambient'}.items()) or
            not actual['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-services:')):
        raise RuntimeError('Composition namespace lacks its reviewed security owner')
    for name, owner in (('cloudlab-composition-namespace', 'cloudlab-workload-policy:'),
                        ('cloudlab-composition-' + approval['name'], 'cloudlab-services:')):
        policy = get('validatingpolicy.policies.kyverno.io', name)
        if (not condition_status_ready(policy) or policy['spec'].get('validationActions') != ['Deny'] or
                policy['spec'].get('failurePolicy') != 'Fail' or not policy['metadata'].get(
                    'annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(owner)):
            raise RuntimeError('Composition admission guard is missing, stale or has different authority')
    policy = get('validatingpolicy.policies.kyverno.io', 'cloudlab-composition-' + approval['name'])
    match = policy['spec']['matchConstraints']
    if (match.get('namespaceSelector') != {'matchLabels': {'kubernetes.io/metadata.name': namespace}} or
            len(match.get('resourceRules', [])) != 1 or match['resourceRules'][0] != {
                'apiGroups': [''], 'apiVersions': ['v1'], 'operations': ['CREATE', 'UPDATE'],
                'resources': ['pods', 'pods/ephemeralcontainers', 'pods/resize']} or
            not policy['spec'].get('validations')):
        raise RuntimeError('Composition policy scope differs from its approved namespace')
    variables = {row['name']: row['expression'] for row in policy['spec']['variables']}
    profiles = decoded(variables['profiles'])
    expected = value['workloads']
    if (len(profiles) != len(expected) or json.loads(variables['components']) != value['images'] or
            decoded(variables['defaultTolerations']) != DEFAULT_TOLERATIONS or
            variables['state'] != "yaml.parse(resource.Get('v1', 'configmaps', 'cloudlab-policy', 'composition-" +
                approval['name'] + "').data['release.json'])" or
            any(a['name'] != b['name'] or a['replicas'] != b['replicas'] or
                a.get('selector') != b.get('selector') or
                normalized_spec(a['podSpec']) != normalized_spec(b['podSpec']) for a, b in zip(profiles, expected))):
        raise RuntimeError('Composition policy differs from the exact reviewed workload profiles')
    state = get('configmap', 'composition-' + approval['name'], 'cloudlab-policy') or {}
    state = json.loads(state.get('data', {}).get('release.json', '{}'))
    expected_hash = profile_hash(value)
    if (state.get('approval') != expected_hash or policy['metadata']['annotations'].get(
            'cloudlab.io/composition-profile') != expected_hash or set(state.get('images', {})) != set(value['images'])):
        raise RuntimeError('Protected composition release state differs from its approved profile')
    return state['images']


def owned_pods(entry, images, get, condition):
    approval, value = entry['approval'], entry['approval']['composition']
    namespace = approval['namespace']
    sets = (get('replicasets', namespace=namespace) or {}).get('items', [])
    pods = (get('pods', namespace=namespace) or {}).get('items', [])
    nodes = {row['metadata']['name'] for row in (get('nodes') or {}).get('items', []) if condition(row, 'Ready')}
    if len(sets) > 512 or len(pods) > 64:
        raise RuntimeError('Composition observation exceeds its bounded workload inventory')
    accepted = []
    for workload in value['workloads']:
        deployment = get('deployment', workload['name'], namespace)
        replicasets = {row['metadata']['uid'] for row in sets if any(
            owner.get('kind') == 'Deployment' and owner.get('name') == workload['name'] and
            owner.get('uid') == deployment['metadata']['uid'] and owner.get('controller') is True
            for owner in row['metadata'].get('ownerReferences', []))}
        actual = [pod for pod in pods if any(owner.get('kind') == 'ReplicaSet' and
            owner.get('uid') in replicasets and owner.get('controller') is True
            for owner in pod['metadata'].get('ownerReferences', []))]
        if len(actual) != workload['replicas']:
            raise RuntimeError('Composition pods do not match their real Deployment authority')
        expected = copy.deepcopy(workload['podSpec'])
        for row in expected['containers'] + expected.get('initContainers', []):
            component = next(name for name, image in value['images'].items() if image == row['image'])
            row['image'] = images[component]
        for pod in actual:
            if 'connections' in value:
                workload_labels(workload, pod['metadata'])
            spec = copy.deepcopy(pod['spec'])
            node = spec.pop('nodeName', '')
            if (node not in nodes or pod['metadata'].get('deletionTimestamp') or pod.get('status', {}).get('phase') != 'Running' or
                    not condition(pod, 'Ready') or pod['metadata'].get('annotations', {}).get(
                        'ambient.istio.io/redirection') != 'enabled' or normalized_spec(spec) != normalized_spec(expected)):
                raise RuntimeError('Composition pod is unhealthy or differs from its approved identity and profile')
        accepted.extend(actual)
    if {row['metadata']['uid'] for row in accepted} != {row['metadata']['uid'] for row in pods}:
        raise RuntimeError('Composition namespace contains an undeclared or differently owned pod')
    return accepted


def admission(entry, get, condition, kube):
    backend(entry['definition'], entry['approval'], get, condition)
    images = authority(entry, get)
    pods = owned_pods(entry, images, get, condition)
    namespace = copy.deepcopy(get('namespace', entry['approval']['namespace']))
    namespace['metadata']['labels']['pod-security.kubernetes.io/audit'] = 'privileged'
    guard = kube('replace', '--dry-run=server', '-f', '-', document=namespace, allow_failure=True)
    if not guard.returncode or 'cloudlab-composition-namespace' not in guard.stderr:
        raise RuntimeError('Composition namespace guard did not deny unreviewed security settings')
    target = pods[0]
    unchanged = copy.deepcopy(target)
    unchanged['metadata'].setdefault('annotations', {})['cloudlab.io/admission-proof'] = 'dry-run'
    result = kube('replace', '--dry-run=server', '-f', '-', document=unchanged, allow_failure=True)
    if result.returncode:
        raise RuntimeError('Exact approved composition profile did not pass server update admission')
    positive = copy.deepcopy(target)
    positive['metadata'] = {'name': 'composition-admission-proof', 'namespace': entry['approval']['namespace'],
                            'ownerReferences': copy.deepcopy(target['metadata']['ownerReferences']),
                            'labels': copy.deepcopy(target['metadata'].get('labels', {}))}
    positive.pop('status', None)
    positive['spec'].pop('nodeName', None)
    def dry(document):
        return kube('create', '--dry-run=server', '-f', '-', document=document, allow_failure=True)
    for field, change in (
            ('privileged', lambda p: p['spec']['containers'][0]['securityContext'].update(
                privileged=True, allowPrivilegeEscalation=True)),
            ('command', lambda p: p['spec']['containers'][0].update(command=['unapproved-command'])),
            ('host', lambda p: p['spec'].update(hostPID=True)),
            ('token', lambda p: p['spec'].update(automountServiceAccountToken=True))):
        bad = copy.deepcopy(positive)
        change(bad)
        result = dry(bad)
        if not result.returncode or 'cloudlab-composition-' + entry['approval']['name'] not in result.stderr:
            raise RuntimeError('Composition mutation did not reach its fail-closed profile policy')
    if 'connections' in entry['approval']['composition']:
        impersonation = copy.deepcopy(target)
        workload = next(row for row in entry['approval']['composition']['workloads']
                        if row['podSpec']['serviceAccountName'] == target['spec']['serviceAccountName'])
        label = next(iter(workload['selector']))
        impersonation['metadata']['labels'][label] = 'unapproved-identity'
        result = kube('replace', '--dry-run=server', '-f', '-', document=impersonation, allow_failure=True)
        if not result.returncode or 'cloudlab-composition-' + entry['approval']['name'] not in result.stderr:
            raise RuntimeError('Composition metadata impersonation did not reach its profile policy')
    ephemeral = copy.deepcopy(target)
    ephemeral['spec']['ephemeralContainers'] = [{'name': 'unapproved-debug', 'image': positive['spec']['containers'][0]['image'],
                                                'command': ['true']}]
    path = '/api/v1/namespaces/' + urllib.parse.quote(entry['approval']['namespace'], safe='') + '/pods/' + urllib.parse.quote(
        target['metadata']['name'], safe='') + '/ephemeralcontainers?dryRun=All'
    result = kube('replace', '--raw', path, '-f', '-', document=ephemeral, allow_failure=True)
    if not result.returncode or 'cloudlab-composition-' + entry['approval']['name'] not in result.stderr:
        raise RuntimeError('Composition ephemeral denial did not reach its profile policy')
    return {'owned_pods': len(pods), 'namespace_guard_denied': True,
            'profile_mutations_denied': True, 'ephemeral_denied': True, 'workloads_created': 0}
