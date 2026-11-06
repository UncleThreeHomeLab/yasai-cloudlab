"""Native checkpoint mechanics; callers own authenticated authority, locks and journal.

This module does not quiesce Alertmanager, call Kubernetes, convert storage or
qualify native disk loading. Those operations require the handoff integration.
"""
import copy
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

FILES = ('nflog', 'silences')
LIMIT = 16 * 1024 * 1024
NAMESPACE = 'cloudlab-observability'
APPLICATION = 'cloudlab-prometheus'
RETENTION = {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}
CLAIM_SPEC = {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'cloudlab-telemetry',
              'volumeMode': 'Filesystem', 'resources': {'requests': {'storage': '1Gi'}}}
CLAIM_ANNOTATIONS = {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}
UID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
SHA = re.compile(r'[a-f0-9]{64}')
SNAPSHOT_SCRIPT = ('set -eu; date +%s; for name in nflog silences; do '
    'if test ! -e /alertmanager/$name && test ! -L /alertmanager/$name; then '
    'printf "missing\\nmissing\\n"; continue; fi; '
    'test -f /alertmanager/$name; test ! -L /alertmanager/$name; '
    'stat -c %i:%Y:%Z:%s:%f:%h /alertmanager/$name; sha256sum /alertmanager/$name; done')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def identity(obj):
    metadata = obj.get('metadata', {})
    require(isinstance(metadata.get('uid'), str) and UID.fullmatch(metadata['uid'])
            and not metadata.get('deletionTimestamp'), 'Object identity is absent or deleting')
    return {key: metadata.get(key) for key in ('name', 'namespace', 'uid')}


def source_identity(pod):
    require(pod.get('kind') == 'Pod' and pod.get('apiVersion') == 'v1', 'Invalid source Pod')
    rows = [row for row in pod.get('status', {}).get('containerStatuses', []) if row.get('name') == 'alertmanager']
    require(len(rows) == 1 and rows[0].get('state', {}).get('running')
            and type(rows[0].get('restartCount')) is int and rows[0]['restartCount'] == 0
            and re.fullmatch(r'containerd://[a-f0-9]{64}', rows[0].get('containerID', ''))
            and isinstance(rows[0]['state']['running'].get('startedAt'), str), 'Source process is absent or restarted')
    return identity(pod) | {'containerID': rows[0]['containerID'],
                            'startedAt': rows[0]['state']['running']['startedAt']}


def source_unchanged(pod, expected):
    require(source_identity(pod) == expected, 'Source process changed; checkpoint refused')


def owner(obj, parent):
    require(obj.get('metadata', {}).get('ownerReferences') == [{
        'apiVersion': parent['apiVersion'], 'kind': parent['kind'], 'name': parent['metadata']['name'],
        'uid': parent['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}], 'Native owner lineage changed')


def approved_pins(pins):
    require(isinstance(pins, dict) and set(pins) == {'operator', 'alertmanager'}
            and isinstance(pins['operator'], str) and re.fullmatch(
                r'quay[.]io/prometheus-operator/prometheus-operator:v0[.]94[.]1@sha256:[a-f0-9]{64}', pins['operator'])
            and isinstance(pins['alertmanager'], str) and re.fullmatch(
                r'quay[.]io/prometheus/alertmanager:v0[.]34[.]1@sha256:[a-f0-9]{64}', pins['alertmanager']),
            'Unsupported native binary pins')


def state_mount(pod, pins):
    approved_pins(pins)
    containers = [row for row in pod['spec'].get('containers', []) if row.get('name') == 'alertmanager']
    require(len(containers) == 1 and containers[0].get('image') == pins['alertmanager'], 'Pinned source binary changed')
    mounts = [row for row in containers[0].get('volumeMounts', []) if row.get('mountPath') == '/alertmanager']
    require(len(mounts) == 1 and mounts[0].get('subPath') == 'alertmanager-db'
            and not mounts[0].get('subPathExpr') and not mounts[0].get('readOnly'), 'Unexpected native state mount')
    return containers[0], mounts[0]


def bind_source(application, manager, statefulset, pod, operator, approved_application_spec, pins):
    """Authenticate approved_application_spec and pins before calling; equality grants no authority."""
    approved_pins(pins)
    require(application.get('kind') == 'Application' and application.get('apiVersion') == 'argoproj.io/v1alpha1'
            and identity(application)['name'] == APPLICATION and application['metadata'].get('namespace') == 'argocd'
            and application['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'observability-platform'
            and application.get('spec') == approved_application_spec, 'Approved telemetry Application changed')
    require(manager.get('kind') == 'Alertmanager' and manager.get('apiVersion') == 'monitoring.coreos.com/v1'
            and identity(manager)['name'] == 'cloudlab' and manager['metadata'].get('namespace') == NAMESPACE
            and manager['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') ==
                APPLICATION + ':monitoring.coreos.com/Alertmanager:' + NAMESPACE + '/cloudlab', 'Alertmanager source owner changed')
    spec = manager['spec']
    require(spec.get('replicas') == 1 and spec.get('forceEnableClusterMode', False) is False
            and spec.get('storage') == {'emptyDir': {'sizeLimit': '64Mi'}}
            and spec.get('persistentVolumeClaimRetentionPolicy', RETENTION) == RETENTION
            and spec.get('image') == pins['alertmanager']
            and spec.get('additionalArgs', []) in ([], [{'name': 'data.maintenance-interval', 'value': '15m'}]),
            'Unsupported production Alertmanager profile')
    require(statefulset.get('kind') == 'StatefulSet' and statefulset.get('apiVersion') == 'apps/v1'
            and identity(statefulset)['name'] == 'alertmanager-cloudlab' and statefulset['metadata'].get('namespace') == NAMESPACE
            and statefulset['spec'].get('replicas') == 1 and not statefulset['spec'].get('volumeClaimTemplates'), 'Source StatefulSet changed')
    owner(statefulset, manager)
    require(pod['metadata'].get('name') == 'alertmanager-cloudlab-0' and pod['metadata'].get('namespace') == NAMESPACE,
            'Source Pod escaped production singleton')
    owner(pod, statefulset)
    container, mount = state_mount(pod, pins)
    arguments = container.get('args', [])
    require([arg for arg in arguments if arg.startswith('--cluster.listen-address')] == ['--cluster.listen-address=']
            and [arg for arg in arguments if arg.startswith('--data.maintenance-interval')] in ([], ['--data.maintenance-interval=15m']),
            'Singleton clustering or production maintenance interval changed')
    volumes = [row for row in pod['spec'].get('volumes', []) if row.get('name') == mount['name']]
    require(mount['name'] == 'alertmanager-cloudlab-db' and volumes == [{'name': mount['name'], 'emptyDir': {'sizeLimit': '64Mi'}}],
            'Source storage is not canonical native emptyDir')
    require(operator.get('kind') == 'Deployment' and operator.get('apiVersion') == 'apps/v1'
            and identity(operator)['name'] == 'cloudlab-prometheus-operator'
            and operator['metadata'].get('namespace') == NAMESPACE
            and operator['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') ==
                APPLICATION + ':apps/Deployment:' + NAMESPACE + '/cloudlab-prometheus-operator'
            and [row.get('image') for row in operator['spec']['template']['spec']['containers']] == [pins['operator']],
            'Pinned Operator owner or binary changed')
    return {'objects': {name: identity(obj) | {'specSHA256': digest(canonical(obj['spec']))}
            for name, obj in [('application', application), ('manager', manager), ('statefulset', statefulset), ('operator', operator)]},
            'source': source_identity(pod), 'podSpecSHA256': digest(canonical(pod['spec']))}


def snapshot_metadata(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= 4096, 'Snapshot metadata exceeds bound')
    lines = raw.decode('ascii').splitlines()
    require(len(lines) == 5 and re.fullmatch(r'[0-9]{1,12}', lines[0]), 'Invalid snapshot metadata framing')
    now, metadata, hashes = int(lines[0]), {}, {}
    for index, name in enumerate(FILES):
        stat_line, hash_line = lines[1 + index * 2:3 + index * 2]
        if stat_line == 'missing':
            require(hash_line == 'missing', 'Invalid missing snapshot marker')
            metadata[name] = {'present': False, 'inode': 0, 'mtime': 0, 'ctime': 0, 'size': 0, 'regular': False, 'links': 0}
            hashes[name] = None
            continue
        require(re.fullmatch(r'[0-9]{1,20}:[0-9]{1,12}:[0-9]{1,12}:[0-9]{1,12}:[a-f0-9]{1,8}:[0-9]{1,8}', stat_line),
                'Invalid snapshot stat fields')
        fields = stat_line.split(':')
        inode, modified, changed, size = map(int, fields[:4])
        checksum, separator, filename = hash_line.partition('  ')
        require(separator and SHA.fullmatch(checksum) and filename == '/alertmanager/' + name,
                'Snapshot checksum path differs')
        row = {'present': True, 'inode': inode, 'mtime': modified, 'ctime': changed, 'size': size,
               'regular': stat.S_ISREG(int(fields[4], 16)), 'links': int(fields[5])}
        valid_metadata({name: row}, names=(name,))
        require(modified <= now and changed <= now, 'Snapshot timestamp exceeds source clock')
        metadata[name], hashes[name] = row, checksum
    return now, metadata, hashes


def valid_metadata(metadata, names=FILES):
    require(isinstance(metadata, dict) and set(metadata) == set(names), 'Incomplete snapshot metadata')
    for row in metadata.values():
        require(isinstance(row, dict) and set(row) == {'present', 'inode', 'mtime', 'ctime', 'size', 'regular', 'links'}
                and type(row['present']) is bool and type(row['regular']) is bool
                and all(type(row[key]) is int and row[key] >= 0 for key in ('inode', 'mtime', 'ctime', 'size', 'links')),
                'Invalid snapshot metadata types')
        if row['present']:
            require(row['regular'] and row['links'] == 1 and row['inode'] > 0 and row['size'] <= LIMIT // 2,
                    'Unsafe native snapshot file')
        else:
            require(row == {'present': False, 'inode': 0, 'mtime': 0, 'ctime': 0, 'size': 0, 'regular': False, 'links': 0},
                    'Missing snapshot has ambiguous metadata')


class Generations:
    def __init__(self, boundary, baseline):
        require(type(boundary) is int and boundary > 0, 'Invalid quiescence boundary')
        valid_metadata(baseline)
        self.boundary, self.baseline = boundary, copy.deepcopy(baseline)
        self.seen = {name: set() for name in FILES}

    def observe(self, metadata):
        valid_metadata(metadata)
        for name, row in metadata.items():
            if row['present']:
                generation = tuple(row[key] for key in ('inode', 'mtime', 'ctime'))
                previous = tuple(self.baseline[name][key] for key in ('inode', 'mtime', 'ctime'))
                if generation != previous and row['mtime'] > self.boundary and row['ctime'] > self.boundary:
                    self.seen[name].add(generation)
        return all(len(rows) >= 2 for rows in self.seen.values()) and all(row['present'] for row in metadata.values())


def parse_archive(raw, hashes):
    require(isinstance(raw, bytes) and 0 < len(raw) <= LIMIT and len(raw) % 512 == 0
            and set(hashes) == set(FILES) and all(isinstance(value, str) and SHA.fullmatch(value) for value in hashes.values()),
            'Checkpoint archive bound or hashes differ')
    values = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                require(member.name in FILES and member.name not in values and member.isreg()
                        and 0 <= member.size <= LIMIT // 2 and not member.pax_headers, 'Unsafe checkpoint archive member')
                value = archive.extractfile(member).read(member.size + 1)
                require(len(value) == member.size and digest(value) == hashes[member.name], 'Checkpoint bytes changed or truncated')
                values[member.name] = value
            require(not raw[archive.offset:].strip(b'\0'), 'Unexpected checkpoint archive trailer')
    except (tarfile.TarError, EOFError, ValueError):
        raise RuntimeError('Invalid checkpoint archive') from None
    require(set(values) == set(FILES), 'Incomplete checkpoint archive')
    return values


def captured(before, after, raw, generations):
    """Caller brackets these reads with unchanged source and continuing quiescence checks."""
    require(before[1:] == after[1:] and after[0] >= before[0] >= generations.boundary,
            'Native snapshot changed during capture')
    require(generations.observe(after[1]), 'Two post-boundary generations per store are required')
    values = parse_archive(raw, after[2])
    require(all(len(values[name]) == after[1][name]['size'] for name in FILES), 'Captured file size differs')
    return values


def capture(read_source, read_metadata, read_archive, quiescent, expected, generations):
    """Adapters must bind the exact Pod and verify continuing maintenance plus API DENY."""
    def guard():
        source_unchanged(read_source(), expected)
        require(quiescent() is True, 'Maintenance or writer isolation no longer holds')
    guard()
    before = read_metadata()
    require(generations.observe(before[1]), 'Post-boundary snapshots are not ready')
    guard()
    raw = read_archive()
    guard()
    after = read_metadata()
    guard()
    return captured(before, after, raw, generations)


def write_payloads(directory, values):
    require(set(values) == set(FILES) and all(isinstance(raw, bytes) and len(raw) <= LIMIT // 2 for raw in values.values()),
            'Incomplete or oversized checkpoint payload')
    directory = Path(directory)
    require(directory.is_absolute(), 'Checkpoint payload directory must be absolute')
    for parent in (*reversed(directory.parents), directory):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                'Unsafe checkpoint payload ancestry')
    require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'Checkpoint payload directory must be private')
    for name in FILES:
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(values[name])
            stream.flush()
            os.fsync(stream.fileno())
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {name: digest(raw) for name, raw in values.items()}


def final_claim(statefulset, pod, storage, operation, pins):
    require(isinstance(operation, str) and re.fullmatch(r'[a-f0-9]{16}', operation), 'Invalid handoff operation')
    require(storage == {'volumeClaimTemplate': {'metadata': {'annotations': CLAIM_ANNOTATIONS}, 'spec': CLAIM_SPEC}},
            'Noncanonical retained storage template')
    require(identity(statefulset)['name'] == 'alertmanager-cloudlab' and statefulset['metadata'].get('namespace') == NAMESPACE
            and statefulset['metadata'].get('labels', {}).get('alertmanager') == 'cloudlab', 'Native StatefulSet name differs')
    require(pod['metadata'].get('name') == 'alertmanager-cloudlab-0'
            and pod['metadata'].get('namespace') == NAMESPACE, 'Final claim source Pod differs')
    owner(pod, statefulset)
    container, mount = state_mount(pod, pins)
    require(mount['name'] == 'alertmanager-cloudlab-db'
            and {'name': mount['name'], 'emptyDir': {'sizeLimit': '64Mi'}} in pod['spec'].get('volumes', []),
            'Final claim source is not canonical emptyDir')
    template = copy.deepcopy(storage['volumeClaimTemplate'])
    template['metadata'].update(name=mount['name'] + '-alertmanager-cloudlab-0', namespace=NAMESPACE,
        labels=copy.deepcopy(statefulset['spec']['selector']['matchLabels']))
    template['metadata']['labels'].update({'cloudlab.io/owner': 'observability-platform', 'cloudlab.io/observability-handoff': operation})
    return template | {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim'}


def fresh_storage_identity(claim, pv, volume, storage_class, baseline, expected_claim, desired_class):
    """Validate freshness and identity independently of a consumer attachment."""
    require(baseline.get('complete') is True and set(baseline) == {'complete', 'boundary', 'storageClassUID', 'pvs', 'volumes'},
            'Complete storage baseline is required')
    identity(storage_class)
    require(all(storage_class.get(key) == desired_class.get(key) for key in
            ('provisioner', 'reclaimPolicy', 'volumeBindingMode', 'allowVolumeExpansion', 'parameters', 'mountOptions')),
            'StorageClass differs from its accepted owner declaration')
    require(storage_class['metadata']['name'] == 'cloudlab-telemetry'
            and storage_class['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'observability-platform'
            and storage_class['metadata']['uid'] == baseline['storageClassUID']
            and storage_class.get('provisioner') == 'driver.longhorn.io' and storage_class.get('reclaimPolicy') == 'Retain'
            and storage_class.get('parameters', {}).get('numberOfReplicas') == '2', 'Telemetry StorageClass changed')
    require([(obj.get('kind'), obj.get('apiVersion')) for obj in (claim, pv, volume, storage_class)] ==
            [('PersistentVolumeClaim', 'v1'), ('PersistentVolume', 'v1'), ('Volume', 'longhorn.io/v1beta2'),
             ('StorageClass', 'storage.k8s.io/v1')], 'Native storage object types differ')
    claim_id, pv_id, volume_id = identity(claim), identity(pv), identity(volume)
    spec, metadata = claim['spec'], claim['metadata']
    require(claim_id['name'] == expected_claim['metadata']['name'] and claim_id['namespace'] == NAMESPACE
            and all(spec.get(key) == value for key, value in CLAIM_SPEC.items())
            and not any(spec.get(key) for key in ('dataSource', 'dataSourceRef', 'selector'))
            and claim.get('status', {}).get('phase') == 'Bound' and not metadata.get('ownerReferences')
            and claim.get('status', {}).get('capacity', {}).get('storage') == '1Gi'
            and all(metadata.get('labels', {}).get(key) == value for key, value in expected_claim['metadata']['labels'].items())
            and all(metadata.get('annotations', {}).get(key) == value for key, value in CLAIM_ANNOTATIONS.items())
            and metadata.get('annotations', {}).get('volume.kubernetes.io/storage-provisioner') == 'driver.longhorn.io',
            'Claim ownership, storage profile or restore source differs')
    handle = 'pvc-' + metadata['uid']
    require(spec.get('volumeName') == handle and pv_id['name'] == handle and pv_id['namespace'] is None
            and pv.get('metadata', {}).get('annotations', {}).get('pv.kubernetes.io/provisioned-by') == 'driver.longhorn.io'
            and pv['spec'].get('claimRef', {}).get('uid') == metadata['uid']
            and pv['spec']['claimRef'].get('name') == metadata['name'] and pv['spec']['claimRef'].get('namespace') == NAMESPACE
            and pv['spec'].get('capacity', {}).get('storage') == '1Gi'
            and pv['spec'].get('storageClassName') == 'cloudlab-telemetry'
            and pv['spec'].get('volumeMode', 'Filesystem') == CLAIM_SPEC['volumeMode']
            and pv['spec'].get('persistentVolumeReclaimPolicy') == 'Retain'
            and pv['spec'].get('csi', {}).get('driver') == 'driver.longhorn.io'
            and pv['spec']['csi'].get('volumeHandle') == handle, 'PV is not this fresh dynamic claim')
    require(volume_id['name'] == handle and volume_id['namespace'] == 'longhorn-system'
            and volume['spec'].get('numberOfReplicas') == 2 and str(volume['spec'].get('size')) == '1073741824', 'Longhorn backing identity changed')
    require(not any(volume['spec'].get(key) for key in ('fromBackup', 'dataSource', 'cloneMode', 'backingImage', 'standby', 'Standby'))
            and not any(volume.get('status', {}).get(key) for key in ('restoreRequired', 'restoreInitiated', 'lastBackup', 'lastRestoredBackup'))
            and not any(volume.get('status', {}).get('cloneStatus', {}).get(key) for key in ('sourceVolume', 'snapshot', 'state')),
            'Restored or cloned backing storage is unsupported')
    boundary = datetime.fromisoformat(baseline['boundary'].replace('Z', '+00:00'))
    created = datetime.fromisoformat(metadata['creationTimestamp'].replace('Z', '+00:00'))
    require(created.tzinfo is not None and boundary.tzinfo is not None and created >= boundary, 'Claim predates storage baseline')
    for key, obj in [('pvs', pv), ('volumes', volume)]:
        old, now = baseline[key], obj['metadata']
        require(set(old) == {'uids', 'names'} and all(isinstance(old[field], list)
                and all(isinstance(value, str) and SHA.fullmatch(value) for value in old[field]) for field in ('uids', 'names')),
                'Invalid baseline inventory')
        require(digest(now['uid'].encode()) not in old['uids'] and digest(now['name'].encode()) not in old['names']
                and datetime.fromisoformat(now['creationTimestamp'].replace('Z', '+00:00')) >= created,
                'Preexisting backing storage cannot become a fresh checkpoint')
    linked = volume.get('status', {}).get('kubernetesStatus', {})
    require(linked.get('pvcName') == metadata['name'] and linked.get('namespace') == NAMESPACE and linked.get('pvName') == handle,
            'Longhorn linkage differs')
    return {'claim': claim_id, 'pv': pv_id, 'volume': volume_id, 'handle': handle}


def fresh_storage(claim, pv, volume, storage_class, baseline, expected_claim, desired_class):
    """Preserve the original active-replica health contract for existing callers."""
    binding = fresh_storage_identity(claim, pv, volume, storage_class, baseline, expected_claim, desired_class)
    require(volume.get('status', {}).get('robustness') == 'healthy', 'Longhorn replica health differs')
    return binding


class StorageUsageNotReady(RuntimeError):
    """Valid storage is still converging toward the required consumer state."""


def storage_usage(volume, usage):
    require(usage in ('unmounted', 'mounted'), 'Unsupported checkpoint storage usage')
    status, spec = volume.get('status', {}), volume.get('spec', {})
    state, health = status.get('state'), status.get('robustness')
    require(state in ('creating', 'attaching', 'attached', 'detaching', 'detached')
            and health in ('unknown', 'healthy', 'degraded'), 'Longhorn storage state is invalid or faulted')
    if usage == 'unmounted':
        ready = state == 'detached' and health in ('unknown', 'healthy') and not spec.get('nodeID') and not status.get('currentNodeID')
    else:
        ready = state == 'attached' and health == 'healthy' and bool(spec.get('nodeID')) and spec.get('nodeID') == status.get('currentNodeID')
    if not ready:
        raise StorageUsageNotReady('Longhorn has not reached the required checkpoint consumer state')


def validation_plan(source, claim, name, pins):
    require(re.fullmatch(r'cloudlab-checkpoint-[a-f0-9]{16}', name), 'Invalid checkpoint validator name')
    state_mount(source, pins)
    claim_id = identity(claim)
    require(claim.get('kind') == 'PersistentVolumeClaim' and claim.get('apiVersion') == 'v1'
            and claim_id['namespace'] == NAMESPACE and claim_id['name'] == 'alertmanager-cloudlab-db-alertmanager-cloudlab-0'
            and claim['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'observability-platform'
            and not claim['metadata'].get('ownerReferences')
            and all(claim.get('spec', {}).get(key) == value for key, value in CLAIM_SPEC.items())
            and not any(claim['spec'].get(key) for key in ('dataSource', 'dataSourceRef', 'selector')),
            'Validator claim differs from final native claim')
    container, _ = state_mount(source, pins)
    security = source['spec'].get('securityContext', {})
    effective = {key: container.get('securityContext', {}).get(key, security.get(key)) for key in ('runAsUser', 'runAsGroup')}
    require(all(type(value) is int and value > 0 for value in effective.values())
            and type(security.get('fsGroup')) is int and security['fsGroup'] > 0, 'Native source UID/group is unsupported')
    config = {'route': {'receiver': 'checkpoint-validation'}, 'receivers': [{'name': 'checkpoint-validation'}]}
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': NAMESPACE},
        'spec': {'automountServiceAccountToken': False, 'restartPolicy': 'Never',
            'securityContext': effective | {'runAsNonRoot': True, 'fsGroup': security['fsGroup'], 'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': 'validator', 'image': pins['alertmanager'], 'command': ['/bin/alertmanager'],
                'args': ['--config.file=/config/alertmanager.yaml', '--storage.path=/alertmanager', '--cluster.listen-address='],
                'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '128Mi'}},
                'volumeMounts': [{'name': 'data', 'mountPath': '/alertmanager', 'subPath': 'alertmanager-db'},
                                 {'name': 'config', 'mountPath': '/config', 'readOnly': True}]}],
            'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': claim_id['name']}},
                        {'name': 'config', 'configMap': {'name': name}}]}}
    return {'configuration': config, 'pod': pod, 'claimUID': claim_id['uid']}


def with_preserved_source(validate, read_source, expected):
    """Guard an externally supplied native validation; never stop or replace the source."""
    source_unchanged(read_source(), expected)
    try:
        return validate()
    finally:
        source_unchanged(read_source(), expected)
