"""Owned Deployment history used to verify real digest pulls and Harbor recovery."""
import json
from pathlib import Path
import re
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from automation.harbor import recovery
from automation.mesh.kube import condition, contains, get, kube, wait

NAMESPACE = 'cloudlab-harbor-deployment-proof'
RECORD = recovery.BASE / 'deployment-proof.json'
PROJECTS = ('cloudlab-public', 'cloudlab-private')
LABEL = {'cloudlab.io/fixture': 'harbor-deployment-proof'}
NAMESPACE_LABELS = dict(LABEL, **{'cloudlab.io/service-secrets': 'approved',
    'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.36'})
QUOTA = {'pods': '6', 'requests.cpu': '300m', 'limits.cpu': '600m', 'requests.memory': '192Mi',
         'limits.memory': '384Mi', 'persistentvolumeclaims': '0', 'services': '0'}


def artifacts(document):
    if not isinstance(document, dict) or set(document) != set(PROJECTS):
        raise ValueError('Deployment proof requires both designated project inventories')
    for project, rows in document.items():
        if not isinstance(rows, list) or len(rows) != 6 or len({row.get('digest') for row in rows}) != 6:
            raise ValueError('Deployment proof requires six distinct retained image digests per project')
        for index, row in enumerate(rows):
            size = (256 * 1024**2 if project == 'cloudlab-public' else 1024**2) if index == 0 else 4096
            if (set(row) != {'digest', 'payload_bytes', 'payload_sha256'} or row['payload_bytes'] != size or
                    not re.fullmatch(r'sha256:[a-f0-9]{64}', row.get('digest') or '') or
                    not re.fullmatch('[a-f0-9]{64}', row.get('payload_sha256') or '')):
                raise ValueError('Deployment proof payload or digest differs from its bounded bootstrap recipe')
    return document


def host():
    return recovery.application('cloudlab-harbor-configuration')['spec']['source']['helm']['valuesObject']['harborHost']


def metadata(name):
    return {'name': name, 'namespace': NAMESPACE, 'labels': LABEL}


def deployment(project, row, registry):
    program = '''import hashlib,pathlib,time
p=pathlib.Path('/cloudlab-proof/payload.bin');h=hashlib.sha256()
with p.open('rb') as stream:
 for block in iter(lambda:stream.read(1048576),b''):h.update(block)
assert p.stat().st_size==SIZE and h.hexdigest()==HASH
pathlib.Path('/tmp/ready').touch()
while True:time.sleep(3600)
'''.replace('SIZE', str(row['payload_bytes'])).replace('HASH', repr(row['payload_sha256']))
    labels = dict(LABEL, **{'cloudlab.io/project': project})
    return {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': metadata(project), 'spec': {
        'replicas': 2, 'revisionHistoryLimit': 5, 'progressDeadlineSeconds': 600,
        'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxSurge': 0, 'maxUnavailable': 1}},
        'selector': {'matchLabels': labels}, 'template': {'metadata': {'labels': labels}, 'spec': {
            'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 1,
            'imagePullSecrets': [{'name': project + '-pull'}],
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532,
                                'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
            'affinity': {'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [{
                'labelSelector': {'matchLabels': labels}, 'topologyKey': 'kubernetes.io/hostname'}]}},
            'containers': [{'name': 'proof', 'image': registry + '/' + project + '/bootstrap@' + row['digest'],
                'imagePullPolicy': 'Always', 'command': ['python', '-c', program],
                'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                    'capabilities': {'drop': ['ALL']}},
                'resources': {'requests': {'cpu': '50m', 'memory': '32Mi'},
                              'limits': {'cpu': '100m', 'memory': '64Mi'}},
                'readinessProbe': {'exec': {'command': ['python', '-c',
                    "import pathlib;assert pathlib.Path('/tmp/ready').is_file()"]}, 'periodSeconds': 5},
                'volumeMounts': [{'name': 'temporary', 'mountPath': '/tmp'}]}],
            'volumes': [{'name': 'temporary', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '1Mi'}}]}}}}


def delivery(project, registry):
    # ESO reads the existing pull-only item. No credential enters local commands.
    template = '{{ dict "auths" (dict "' + registry + '" (dict "auth" (printf "%s:%s" .username .password | b64enc))) | toJson }}'
    return {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret',
        'metadata': metadata(project + '-pull'), 'spec': {'refreshInterval': '24h',
            'secretStoreRef': {'name': 'cloudlab', 'kind': 'ClusterSecretStore'},
            'target': {'name': project + '-pull', 'creationPolicy': 'Owner', 'deletionPolicy': 'Retain',
                'template': {'engineVersion': 'v2', 'type': 'kubernetes.io/dockerconfigjson',
                             'data': {'.dockerconfigjson': template}}},
            'dataFrom': [{'extract': {'key': 'harbor-' + project + '-pull'}}]}}


def owned(record):
    namespace = get('namespace', NAMESPACE)
    if (not namespace or namespace['metadata']['uid'] != record.get('uid') or
            namespace['metadata'].get('labels', {}).get('cloudlab.io/proof-owner') != record['nonce'] or
            not contains(namespace['metadata'].get('labels', {}), NAMESPACE_LABELS)):
        raise RuntimeError('Harbor Deployment namespace ownership changed')
    return namespace


def posture():
    quota = get('resourcequota', 'bounded', NAMESPACE)
    policy = get('networkpolicy', 'deny-all', NAMESPACE)
    if not quota or not contains(quota['spec'].get('hard', {}), QUOTA):
        raise RuntimeError('Harbor Deployment quota changed')
    spec = policy.get('spec', {}) if policy else {}
    if (spec.get('podSelector') != {} or set(spec.get('policyTypes', [])) != {'Ingress', 'Egress'} or
            spec.get('ingress') or spec.get('egress')):
        raise RuntimeError('Harbor Deployment deny-all networking changed')


def apply(document):
    kube('apply', '--server-side', '--field-manager=harbor-deployment-proof', '-f', '-', document=document)


def ready(project, row, registry):
    desired = deployment(project, row, registry)
    def check():
        current = get('deployment', project, NAMESPACE)
        if not current or not contains(current['spec'], desired['spec']):
            return False
        status = current.get('status', {})
        return (status.get('observedGeneration') == current['metadata']['generation'] and
                all(status.get(key) == 2 for key in ('replicas', 'updatedReplicas', 'availableReplicas', 'readyReplicas')))
    wait(check, 'Harbor Deployment digest and payload readiness', timeout=660)


def history(record):
    owned(record)
    registry = host()
    result = {}
    rows = (get('replicaset', namespace=NAMESPACE) or {}).get('items', [])
    if len(rows) != 12:
        raise RuntimeError('Harbor requires exactly six native ReplicaSets per project')
    for project in PROJECTS:
        current = get('deployment', project, NAMESPACE)
        if not current or current['metadata']['uid'] != record['deployments'][project]:
            raise RuntimeError('Harbor Deployment identity changed')
        selected = [row for row in rows if row['metadata'].get('ownerReferences') == [{
            'apiVersion': 'apps/v1', 'kind': 'Deployment', 'name': project,
            'uid': current['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}]]
        digests = {row['spec']['template']['spec']['containers'][0]['image'].split('@')[-1]: row['metadata']['uid']
                   for row in selected}
        if len(selected) != 6 or set(digests) != {row['digest'] for row in record['artifacts'][project]}:
            raise RuntimeError('Harbor native rollback history differs from its retained digests')
        for replica in selected:
            image = replica['spec']['template']['spec']['containers'][0]['image']
            expected = next(row for row in record['artifacts'][project] if image.endswith('@' + row['digest']))
            if not contains(replica['spec']['template']['spec'], deployment(project, expected, registry)['spec']['template']['spec']):
                raise RuntimeError('Harbor retained ReplicaSet security or payload recipe changed')
        result[project] = digests
    return result


def ready_pods(project, row, registry, nodes, *, removed=None):
    pods = [pod for pod in (get('pods', namespace=NAMESPACE) or {}).get('items', [])
            if pod['metadata'].get('labels', {}).get('cloudlab.io/project') == project and
            not pod['metadata'].get('deletionTimestamp')]
    reference = registry + '/' + project + '/bootstrap@' + row['digest']
    if (len(pods) != 2 or {pod['spec'].get('nodeName') for pod in pods} != nodes or any(
            pod['metadata']['uid'] == removed or not condition(pod, 'Ready') or
            pod['spec']['containers'][0]['image'] != reference or
            len(pod.get('status', {}).get('containerStatuses', [])) != 1 or
            not pod['status']['containerStatuses'][0].get('imageID', '').endswith(row['digest']) for pod in pods)):
        return False
    return pods


def verify(*, repull=False):
    if not RECORD.exists():
        if get('namespace', NAMESPACE):
            raise RuntimeError('Unrecorded Harbor Deployment namespace must not be adopted')
        return {'active': False}
    record = json.loads(RECORD.read_text())
    if record.get('phase') != 'ready':
        raise RuntimeError('Resume the recorded Harbor Deployment proof before recovery')
    posture()
    registry = host()
    before = history(record)
    if before != record['history']:
        raise RuntimeError('Original Harbor ReplicaSet identities changed')
    nodes = {row['metadata']['name'] for row in get('nodes')['items'] if condition(row, 'Ready')}
    if len(nodes) != 2:
        raise RuntimeError('Harbor Deployment proof requires both existing nodes')
    for project in PROJECTS:
        ready(project, record['artifacts'][project][0], registry)
        pods = ready_pods(project, record['artifacts'][project][0], registry, nodes)
        if not pods:
            raise RuntimeError('Harbor project must have one ready digest workload on each node')
        if repull:
            for pod in pods:
                # Replace one owned pod at a time; rollout restart would evict history.
                owner = pod['metadata'].get('ownerReferences', [])
                if len(owner) != 1 or owner[0].get('uid') not in before[project].values():
                    raise RuntimeError('Foreign Harbor proof pod cannot be replaced')
                kube('delete', '--raw=/api/v1/namespaces/' + NAMESPACE + '/pods/' + pod['metadata']['name'], '-f', '-',
                     document={'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {
                         'uid': pod['metadata']['uid'], 'resourceVersion': pod['metadata']['resourceVersion']}})
                wait(lambda: not get('pod', pod['metadata']['name'], NAMESPACE), 'old Harbor proof pod removed', timeout=120)
                ready(project, record['artifacts'][project][0], registry)
                wait(lambda: ready_pods(project, record['artifacts'][project][0], registry, nodes,
                                       removed=pod['metadata']['uid']), 'new Harbor digest pods ready', timeout=180)
    if history(record) != before:
        raise RuntimeError('Harbor repull changed Deployment rollback history')
    return {'active': True, 'deployments': 2, 'rollback_replicasets': 10, 'nodes': 2,
            'native_rollback_verified': True, 'payloads_verified': True, 'fresh_kubelet_pulls': 4 if repull else 0}


def prepare(document):
    document = artifacts(document)
    registry = host()
    if RECORD.exists():
        record = json.loads(RECORD.read_text())
        if record['artifacts'] != document:
            raise RuntimeError('Preserve original deployed and rollback artifact inputs')
    else:
        if get('namespace', NAMESPACE):
            raise RuntimeError('Foreign Harbor Deployment namespace must not be adopted')
        record = {'nonce': secrets.token_hex(16), 'artifacts': document, 'phase': 'preparing',
                  'steps': {project: 0 for project in PROJECTS}, 'deployments': {}}
        recovery.atomic(RECORD, record)
    if not record.get('uid'):
        namespace = get('namespace', NAMESPACE)
        if not namespace:
            kube('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
                'name': NAMESPACE, 'labels': dict(NAMESPACE_LABELS, **{'cloudlab.io/proof-owner': record['nonce']})}})
            namespace = get('namespace', NAMESPACE)
        if namespace['metadata'].get('labels', {}).get('cloudlab.io/proof-owner') != record['nonce']:
            raise RuntimeError('Interrupted Harbor namespace belongs to another owner')
        record['uid'] = namespace['metadata']['uid']
        recovery.atomic(RECORD, record)
    owned(record)
    if record['phase'] == 'ready':
        return verify()
    apply({'apiVersion': 'v1', 'kind': 'ResourceQuota', 'metadata': metadata('bounded'), 'spec': {'hard': QUOTA}})
    apply({'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': metadata('deny-all'),
           'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}})
    for project in PROJECTS:
        apply(delivery(project, registry))
        wait(lambda: condition(get('externalsecret', project + '-pull', NAMESPACE), 'Ready'),
             'Harbor pull-only ESO delivery', timeout=300)
        for index in range(record['steps'][project], 6):
            row = document[project][index]
            desired = deployment(project, row, registry)
            desired['metadata']['labels'] = dict(LABEL, **{'cloudlab.io/proof-owner': record['nonce']})
            current = get('deployment', project, NAMESPACE)
            if current:
                expected = record['deployments'].get(project)
                if (expected is not None and current['metadata']['uid'] != expected or
                        current['metadata'].get('labels', {}).get('cloudlab.io/proof-owner') != record['nonce'] or
                        expected is None and not contains(current['spec'], desired['spec'])):
                    raise RuntimeError('Unrecorded Harbor Deployment cannot be adopted')
            apply(desired)
            record['deployments'][project] = get('deployment', project, NAMESPACE)['metadata']['uid']
            recovery.atomic(RECORD, record)
            ready(project, row, registry)
            record['steps'][project] = index + 1
            recovery.atomic(RECORD, record)
        first = document[project][0]
        current = get('deployment', project, NAMESPACE)
        if current['spec']['template']['spec']['containers'][0]['image'] != registry + '/' + project + '/bootstrap@' + first['digest']:
            candidates = [row for row in get('replicaset', namespace=NAMESPACE)['items'] if
                row['metadata'].get('ownerReferences', [{}])[0].get('uid') == record['deployments'][project] and
                row['spec']['template']['spec']['containers'][0]['image'] == registry + '/' + project + '/bootstrap@' + first['digest']]
            if len(candidates) != 1:
                raise RuntimeError('Original native Harbor rollback revision is ambiguous')
            revision = candidates[0]['metadata']['annotations']['deployment.kubernetes.io/revision']
            kube('rollout', 'undo', 'deployment/' + project, '-n', NAMESPACE, '--to-revision=' + revision)
        ready(project, first, registry)
    record['history'] = history(record)
    record['phase'] = 'ready'
    recovery.atomic(RECORD, record)
    return verify(repull=True)


def cleanup():
    if not RECORD.exists():
        return verify()
    record = json.loads(RECORD.read_text())
    namespace = get('namespace', NAMESPACE)
    if record.get('phase') != 'cleaning':
        verify()
        if len(get('pods', namespace=NAMESPACE)['items']) != 4:
            raise RuntimeError('Foreign pods prevent Harbor Deployment cleanup')
        record['phase'] = 'cleaning'
        recovery.atomic(RECORD, record)
    if namespace:
        owned(record)
        kube('delete', '--raw=/api/v1/namespaces/' + NAMESPACE, '-f', '-', document={
            'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': record['uid']}})
        wait(lambda: not get('namespace', NAMESPACE), 'Harbor Deployment fixture removed', timeout=300)
    RECORD.unlink()
    return {'owned_deployments_removed': True, 'registry_artifacts_removed': False}


if __name__ == '__main__':
    try:
        with recovery.locked():
            recovery.resume()
            if sys.argv[1:] == ['prepare']:
                result = prepare(json.load(sys.stdin))
            elif sys.argv[1:] == ['verify']:
                result = verify(repull=True)
            elif sys.argv[1:] == ['cleanup']:
                result = cleanup()
            else:
                raise ValueError('Unknown Harbor Deployment proof action')
            print(json.dumps(result, sort_keys=True))
    except Exception:
        raise SystemExit('Harbor Deployment proof incomplete; original namespace, credentials and history retained') from None
