"""Keep an owned, attached volume checking data throughout storage adoption."""
import hashlib
import secrets

from kube import create, delete, get, kubectl, wait
from verify_health import conditions_ready, healthy_volume

NAMESPACE = 'cloudlab-storage-handoff'


def prepare(config, receipt):
    """The caller durably records intent before creating any fixture resources."""
    namespaces = get('namespace', namespace=None)['items']
    existing = next((x for x in namespaces if x['metadata']['name'] == NAMESPACE), None)
    if existing and existing['metadata'].get('labels', {}).get('cloudlab.io/handoff') != receipt['nonce']:
        raise RuntimeError('Storage handoff namespace belongs to another operation')
    if not existing:
        kubectl('create', '-f', '-', body={'apiVersion': 'v1', 'kind': 'Namespace',
            'metadata': {'name': NAMESPACE, 'labels': {'cloudlab.io/handoff': receipt['nonce']}}})
    if not any(x['metadata']['name'] == 'continuity' for x in get('pvc', namespace=NAMESPACE)['items']):
        create('PersistentVolumeClaim', 'continuity', {'accessModes': ['ReadWriteOnce'],
            'storageClassName': config['policy']['storage_class'],
            'resources': {'requests': {'storage': '1Gi'}}}, namespace=NAMESPACE)
    if not any(x['metadata']['name'] == 'continuity' for x in get('pod', namespace=NAMESPACE)['items']):
        # The marker is synthetic and contains no deployment metadata. A failed
        # checksum or I/O ends the pod; Never restart preserves failure evidence.
        script = ('set -eu; printf %s ' + receipt['nonce'] + ' > /data/marker; sync; '
                  'sha256sum /data/marker > /data/expected; n=0; '
                  'while true; do sha256sum -c /data/expected >/dev/null; '
                  'n=$((n+1)); printf "%s\\n" "$n" > /data/ticks.next; '
                  'mv /data/ticks.next /data/ticks; sync; sleep 1; done')
        create('Pod', 'continuity', {'nodeSelector': {'kubernetes.io/hostname': config['nodes'][0]},
            'restartPolicy': 'Never', 'containers': [{'name': 'continuity', 'image': config['image'],
                'command': ['sh', '-ec', script], 'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                    'limits': {'cpu': '250m', 'memory': '64Mi'}},
                'volumeMounts': [{'name': 'data', 'mountPath': '/data'}]}],
            'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'continuity'}}]}, namespace=NAMESPACE)
    wait('Attached handoff fixture ready', lambda: conditions_ready(
        get('pod', 'continuity', NAMESPACE).get('status', {}).get('conditions', []), ['Ready']))
    pvc = get('pvc', 'continuity', NAMESPACE)
    pv = get('pv', pvc['spec']['volumeName'], None)
    volume = pv['spec']['csi']['volumeHandle']
    wait('Handoff volume has two healthy replicas', lambda: healthy_volume(volume, config['nodes']))
    return dict(receipt, pod_uid=get('pod', 'continuity', NAMESPACE)['metadata']['uid'],
                namespace_uid=get('namespace', NAMESPACE, None)['metadata']['uid'], volume=volume)


def intent():
    return {'nonce': secrets.token_hex(24)}


def verify(config, receipt):
    namespace = get('namespace', NAMESPACE, None)
    if (namespace['metadata']['uid'] != receipt['namespace_uid']
            or namespace['metadata'].get('labels', {}).get('cloudlab.io/handoff') != receipt['nonce']):
        raise RuntimeError('Storage handoff namespace identity changed')
    pod = get('pod', 'continuity', NAMESPACE)
    if (pod['metadata']['uid'] != receipt['pod_uid'] or pod.get('status', {}).get('phase') != 'Running'
            or any(s.get('restartCount') for s in pod.get('status', {}).get('containerStatuses', []))):
        raise RuntimeError('Attached storage handoff workload was interrupted or replaced')
    checksum = kubectl('exec', '-n', NAMESPACE, 'continuity', '--', 'sha256sum', '/data/marker').split()[0]
    if checksum != hashlib.sha256(receipt['nonce'].encode()).hexdigest():
        raise RuntimeError('Attached storage handoff data changed')
    first = int(kubectl('exec', '-n', NAMESPACE, 'continuity', '--', 'cat', '/data/ticks'))
    wait('Attached workload continues disk writes', lambda: int(kubectl(
        'exec', '-n', NAMESPACE, 'continuity', '--', 'cat', '/data/ticks')) > first, timeout=30)
    wait('Handoff replicas remain healthy', lambda: healthy_volume(receipt['volume'], config['nodes']))


def cleanup(receipt):
    namespaces = get('namespace', namespace=None)['items']
    obj = next((x for x in namespaces if x['metadata']['name'] == NAMESPACE), None)
    if obj:
        if (obj['metadata']['uid'] != receipt['namespace_uid']
                or obj['metadata'].get('labels', {}).get('cloudlab.io/handoff') != receipt['nonce']):
            raise RuntimeError('Refusing to remove a foreign handoff namespace')
        delete('namespace', NAMESPACE, None)
    wait('Accepted handoff fixture volume removed', lambda: all(
        x['metadata']['name'] != receipt['volume'] for x in get('volumes.longhorn.io')['items']), timeout=180)
