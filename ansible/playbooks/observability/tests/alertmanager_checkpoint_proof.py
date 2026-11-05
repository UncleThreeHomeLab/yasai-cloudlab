"""Scoped synthetic proof of live native snapshots and retained CSI adoption."""
import argparse
import base64
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import io
import json
import math
import os
from pathlib import Path
import re
import resource
import secrets
import select
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

OWNER = 'observability-checkpoint-proof'
LABEL = 'cloudlab.io/checkpoint-proof'
PREFIX = 'cloudlab-observability-checkpoint-'
HOST_BASE = Path('/var/lib/cloudlab/proofs')
FILES = ('nflog', 'silences')
LIMIT = 16 * 1024 * 1024
DIAGNOSTIC_DIRECTORY = None
SECURITY = {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
            'capabilities': {'drop': ['ALL']}}
POD_SECURITY = {'runAsNonRoot': True, 'runAsUser': 65534, 'runAsGroup': 65534,
                'fsGroup': 65534, 'seccompProfile': {'type': 'RuntimeDefault'}}
RESOURCES = {'requests': {'cpu': '10m', 'memory': '32Mi'},
             'limits': {'cpu': '100m', 'memory': '128Mi'}}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def namespace_controls(current):
    values = current['metadata'].get('labels', {})
    expected = {'pod-security.kubernetes.io/enforce': 'restricted',
                'pod-security.kubernetes.io/enforce-version': 'v1.36',
                'istio.io/dataplane-mode': 'ambient', 'istio-injection': 'disabled'}
    require(all(values.get(key) == value for key, value in expected.items())
            and values.get('cloudlab.io/service-secrets') != 'approved'
            and values.get('service-secrets') != 'approved', 'Fixture namespace security controls changed')


def strict_root_policy(policies):
    roots = [row for row in policies if not row.get('spec', {}).get('selector', {}).get('matchLabels')]
    require(len(roots) == 1 and roots[0]['spec'].get('mtls', {}).get('mode') == 'STRICT'
            and not roots[0]['spec'].get('portLevelMtls'), 'Root mTLS policy is ambiguous or not uniformly STRICT')


def pod_enrolled(pod):
    require(pod['metadata'].get('annotations', {}).get('ambient.istio.io/redirection') == 'enabled',
            'Fixture network participant is not enrolled in ambient')


def protected_directory(path, create=False):
    path = Path(path)
    require(path.is_absolute(), 'Proof directory must be absolute')
    for current in reversed((path, *path.parents)):
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            require(create, 'Proof directory is absent')
            current.mkdir(mode=0o700)
            metadata = current.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and not metadata.st_mode & 0o022, 'Unsafe proof directory ancestry')
    return path


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def host_preflight(directory, operation, driver_hash, cleanup_existing):
    require(re.fullmatch(r'[a-f0-9]{16}', operation) and re.fullmatch(r'[a-f0-9]{64}', driver_hash),
            'Invalid host proof identity')
    expected = HOST_BASE / ('observability-checkpoint-' + operation)
    require(Path(directory) == expected, 'Host proof directory override refused')
    if cleanup_existing:
        protected_directory(expected)
        receipt = Receipt.load(expected / 'state', operation)
        provenance = receipt.value.get('provenance', {})
        for name, expected_hash in [('proof.py', driver_hash), ('input.json', provenance.get('input'))]:
            path = expected / name
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    and not metadata.st_mode & 0o077 and metadata.st_size <= LIMIT, 'Unsafe retained proof input')
            actual = digest(canonical(json.loads(path.read_bytes()))) if name == 'input.json' else digest(path.read_bytes())
            require(expected_hash and actual == expected_hash, 'Retained proof input is incompatible')
        require(provenance.get('driver') == driver_hash, 'Retained driver is incompatible with reviewed cleanup')
    else:
        protected_directory(HOST_BASE, create=True)
        require(not os.path.lexists(expected), 'Existing proof operation cannot be overwritten')
        expected.mkdir(mode=0o700)
        descriptor = os.open(HOST_BASE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class Receipt:
    def __init__(self, directory, operation):
        require(re.fullmatch(r'[a-f0-9]{16}', operation), 'Invalid proof operation')
        self.directory = protected_directory(directory, create=True)
        self.path = self.directory / 'receipt.json'
        require(not self.path.exists(), 'Interrupted or existing operation cannot be adopted')
        self.value = {'operation': operation, 'namespace': PREFIX + operation,
                      'resources': [], 'phase': 'prepared', 'evidence': {}}
        write_new(self.path, canonical(self.value))

    def save(self):
        pending = self.directory / ('receipt.pending-' + secrets.token_hex(16))
        write_new(pending, canonical(self.value))
        pending.replace(self.path)
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def intent(self, document):
        metadata = document['metadata']
        row = {'apiVersion': document['apiVersion'], 'kind': document['kind'],
               'name': metadata['name'], 'namespace': metadata.get('namespace'),
               'specHash': digest(canonical(document)), 'uid': None}
        if document['kind'] == 'Service':
            row['serviceBinding'] = service_binding(document)
        if document['kind'] in ('Pod', 'Deployment'):
            spec = document.get('spec', {}) if document['kind'] == 'Pod' else document['spec']['template']['spec']
            row['podProfile'] = pod_profile(spec)
        require(not any(all(old[k] == row[k] for k in ('kind', 'name', 'namespace'))
                        for old in self.value['resources']), 'Duplicate proof creation intent')
        self.value['resources'].append(row)
        self.save()
        return row

    def created(self, row, current):
        require(current['metadata'].get('uid'), 'Created resource lacks UID')
        row['uid'] = current['metadata']['uid']
        if row['kind'] == 'Namespace':
            row['createdAt'] = current['metadata'].get('creationTimestamp')
        self.save()

    def phase(self, phase, **evidence):
        self.value['phase'] = phase
        self.value['evidence'].update(evidence)
        self.save()

    def deletion(self, identity):
        rows = [row for row in self.value.get('deletions', [])
                if all(row[key] == identity[key] for key in ('kind', 'name', 'namespace'))]
        require(len(rows) <= 1, 'Ambiguous deletion receipt')
        if rows:
            require(rows[0]['uid'] == identity['uid'], 'Deletion identity replaced')
            return rows[0]
        return None

    def deleting(self, current, scope_hash):
        identity = object_identity(current)
        row = self.deletion(identity)
        if row is None:
            row = dict(identity, scopeHash=scope_hash, complete=False)
            self.value.setdefault('deletions', []).append(row)
        require(row['scopeHash'] == scope_hash and not row['complete'], 'Deletion scope changed or completed resource reappeared')
        row['resourceVersion'] = current['metadata']['resourceVersion']
        self.save()
        return row

    def deleted(self, identity):
        row = self.deletion(identity)
        require(row is not None, 'Absence without verified deletion intent')
        row['complete'] = True
        self.save()

    @classmethod
    def load(cls, directory, operation):
        directory = protected_directory(directory)
        path = directory / 'receipt.json'
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and not metadata.st_mode & 0o077, 'Unsafe proof receipt')
        value = json.loads(path.read_bytes())
        require(re.fullmatch(r'[a-f0-9]{16}', operation) and value['operation'] == operation
                and value['namespace'] == PREFIX + operation, 'Cleanup operation does not match receipt')
        result = object.__new__(cls)
        result.directory, result.path, result.value = directory, path, value
        return result


def command(arguments, body=None, limit=LIMIT, timeout=90, allow_failure=False):
    """Capture bounded output without writing diagnostics or state bytes to logs."""
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit + 1, limit + 1))
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(arguments, input=body, stdout=output, stderr=errors,
                                timeout=timeout, preexec_fn=limits, check=False)
        require(output.tell() <= limit and errors.tell() <= limit, 'Proof command output exceeded bound')
        output.seek(0)
        errors.seek(0)
        raw, diagnostic = output.read(limit + 1), errors.read(limit + 1)
    if not allow_failure:
        if result.returncode and DIAGNOSTIC_DIRECTORY is not None and diagnostic:
            write_new(DIAGNOSTIC_DIRECTORY / ('command-error-' + secrets.token_hex(8) + '.txt'), diagnostic)
        require(result.returncode == 0, 'Proof command failed; protected operation retained')
    return result.returncode, raw, diagnostic


def kubectl(*arguments, body=None, limit=LIMIT, timeout=90, reject_warnings=False):
    _, raw, errors = command(['kubectl', '--request-timeout=30s', *arguments], body=body,
                             limit=limit, timeout=timeout)
    require(not reject_warnings or not errors, 'Native archive emitted warnings')
    return raw


def get(kind, name=None, namespace=None, managed_fields=False):
    args = ['get', kind]
    if name:
        args += [name, '--ignore-not-found']
    if namespace:
        args += ['-n', namespace]
    if managed_fields:
        args += ['--show-managed-fields=true']
    raw = kubectl(*args, '-o', 'json')
    return json.loads(raw) if raw.strip() else None


def api_path(current):
    api, kind, metadata = current['apiVersion'], current['kind'], current['metadata']
    plurals = {'Namespace': 'namespaces', 'ServiceAccount': 'serviceaccounts', 'Secret': 'secrets',
               'ConfigMap': 'configmaps', 'ResourceQuota': 'resourcequotas', 'NetworkPolicy': 'networkpolicies',
               'Role': 'roles', 'RoleBinding': 'rolebindings', 'ClusterRole': 'clusterroles',
               'ClusterRoleBinding': 'clusterrolebindings', 'Deployment': 'deployments', 'Service': 'services',
               'Pod': 'pods', 'Alertmanager': 'alertmanagers', 'PersistentVolumeClaim': 'persistentvolumeclaims',
               'PersistentVolume': 'persistentvolumes', 'Volume': 'volumes',
               'AuthorizationPolicy': 'authorizationpolicies', 'StatefulSet': 'statefulsets',
               'ReplicaSet': 'replicasets', 'ControllerRevision': 'controllerrevisions',
               'EndpointSlice': 'endpointslices', 'Endpoints': 'endpoints', 'Event': 'events'}
    require(kind in plurals, 'Unsupported proof resource kind')
    path = '/api/v1' if api == 'v1' else '/apis/' + api
    if metadata.get('namespace'):
        path += '/namespaces/' + metadata['namespace']
    return path + '/' + plurals[kind] + '/' + metadata['name']


class Cluster:
    def __init__(self, receipt):
        self.receipt = receipt
        self.namespace = receipt.value['namespace']
        self.operation = receipt.value['operation']

    def owned(self, current, row=None):
        require(current and current.get('metadata', {}).get('labels', {}).get(LABEL) == self.operation
                and current['metadata'].get('labels', {}).get('cloudlab.io/owner') == OWNER,
                'Foreign proof resource')
        metadata = current['metadata']
        self.scope(current['kind'], metadata)
        if current['kind'] == 'Namespace':
            namespace_controls(current)
        if row:
            require(metadata['name'] == row['name'] and metadata.get('namespace') == row['namespace']
                    and current['kind'] == row['kind'] and metadata.get('uid') == row['uid'],
                    'Proof resource identity changed')
        return current

    def scope(self, kind, metadata):
        if kind == 'Namespace':
            require(metadata['name'] == self.namespace and not metadata.get('namespace'), 'Foreign namespace')
        elif kind in ('ClusterRole', 'ClusterRoleBinding'):
            require(metadata['name'] == 'checkpoint-' + self.operation and not metadata.get('namespace'),
                    'Foreign cluster RBAC')
        else:
            require(metadata.get('namespace') == self.namespace, 'Resource outside proof namespace')
            if kind == 'AuthorizationPolicy':
                require(metadata['name'] in ('fixture-readers', 'source-quiescence'), 'Unknown proof authorization policy')

    def create(self, document, dry_run=False):
        metadata = document['metadata']
        self.scope(document['kind'], metadata)
        require(metadata.get('labels', {}).get(LABEL) == self.operation
                and metadata.get('labels', {}).get('cloudlab.io/owner') == OWNER, 'Creation has foreign owner')
        require(get(document['kind'], metadata['name'], metadata.get('namespace')) is None,
                'Existing resource cannot be adopted')
        if dry_run:
            simulated = json.loads(kubectl('create', '--dry-run=server', '-f', '-', '-o', 'json', body=canonical(document)))
            if document['kind'] == 'Namespace':
                namespace_controls(simulated)
            return simulated
        row = self.receipt.intent(document)
        current = json.loads(kubectl('create', '-f', '-', '-o', 'json', body=canonical(document)))
        self.owned(current)
        self.receipt.created(row, current)
        return current

    def row(self, kind, name, namespace=None):
        rows = [r for r in self.receipt.value['resources'] if r['kind'] == kind and r['name'] == name
                and r['namespace'] == namespace and r['uid']]
        require(len(rows) == 1, 'Resource missing from proof receipt')
        return rows[0]

    def current(self, kind, name, namespace=None):
        return self.owned(get(kind, name, namespace), self.row(kind, name, namespace))

    def patch(self, kind, name, patches, namespace=None):
        current = self.current(kind, name, namespace)
        metadata = current['metadata']
        checks = [{'op': 'test', 'path': '/metadata/uid', 'value': metadata['uid']},
                  {'op': 'test', 'path': '/metadata/resourceVersion', 'value': metadata['resourceVersion']}]
        args = ['patch', kind, name, '--type=json', '-p', json.dumps(checks + patches), '-o', 'json']
        if namespace:
            args += ['-n', namespace]
        updated = json.loads(kubectl(*args))
        if kind == 'Service':
            row = self.row(kind, name, namespace)
            row['serviceBinding'] = service_binding(updated)
            self.receipt.save()
        return updated

    def delete(self, kind, name, namespace=None):
        row = self.row(kind, name, namespace)
        current = get(kind, name, namespace)
        identity = {key: row[key] for key in ('kind', 'name', 'namespace', 'uid')}
        if current is None:
            self.receipt.deleted(identity)
            return
        self.owned(current, row)
        request_delete(self.receipt, current, row['specHash'])


def object_identity(current):
    metadata = current['metadata']
    return {'kind': current['kind'], 'name': metadata['name'], 'namespace': metadata.get('namespace'), 'uid': metadata['uid']}


def request_delete(receipt, current, scope_hash):
    row = receipt.deleting(current, scope_hash)
    if not current['metadata'].get('deletionTimestamp'):
        kubectl('delete', '--raw', api_path(current), '-f', '-', body=canonical(delete_options(current)))
    row['accepted'] = True
    receipt.save()


def deletion_finished(receipt, identity):
    kind = 'volumes.longhorn.io' if identity['kind'] == 'Volume' else identity['kind']
    current = get(kind, identity['name'], identity['namespace'])
    if current is not None:
        require(current['metadata']['uid'] == identity['uid'], 'Resource replaced during cleanup')
        return False
    receipt.deleted(identity)
    return True


def wait(label, predicate, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(1)
    raise RuntimeError('Proof timed out: ' + label + '; protected operation retained; inspect receipt')


def source_identity(pod):
    statuses = [s for s in pod.get('status', {}).get('containerStatuses', []) if s['name'] == 'alertmanager']
    require(len(statuses) == 1 and statuses[0].get('state', {}).get('running'), 'Source is not running')
    status = statuses[0]
    require(status.get('restartCount') == 0, 'Source restarted')
    return {'uid': pod['metadata']['uid'], 'containerID': status['containerID'],
            'startedAt': status['state']['running']['startedAt']}


def source_unchanged(pod, identity):
    require(source_identity(pod) == identity, 'Source process changed; checkpoint refused')


def parse_archive(raw, expected_hashes):
    require(0 < len(raw) <= LIMIT and len(raw) % 512 == 0 and set(expected_hashes) == set(FILES),
            'Checkpoint archive exceeded bound or is incomplete')
    result = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                require(member.name in FILES and member.name not in result and member.isreg()
                        and 0 < member.size <= LIMIT // 2 and not member.pax_headers,
                        'Unsafe checkpoint archive member')
                stream = archive.extractfile(member)
                value = stream.read(member.size + 1)
                require(len(value) == member.size and digest(value) == expected_hashes.get(member.name),
                        'Checkpoint bytes changed or were truncated')
                result[member.name] = value
            require(not raw[archive.offset:].strip(b'\0'), 'Unexpected trailing checkpoint archive bytes')
    except (tarfile.TarError, EOFError, ValueError):
        raise RuntimeError('Invalid checkpoint archive') from None
    require(set(result) == set(FILES), 'Incomplete checkpoint archive')
    return result


class Generations:
    def __init__(self, boundary, baseline):
        self.boundary = boundary
        self.baseline = baseline
        self.seen = {name: set() for name in FILES}

    def observe(self, metadata):
        require(set(metadata) == set(FILES), 'Incomplete snapshot metadata')
        for name, row in metadata.items():
            if not row.get('present', True):
                continue
            require(row['regular'] and 0 <= row['size'] <= LIMIT // 2, 'Unsafe synthetic snapshot')
            generation = tuple(row[k] for k in ('inode', 'mtime', 'ctime'))
            baseline = tuple(self.baseline[name][k] for k in ('inode', 'mtime', 'ctime'))
            if generation != baseline and row['mtime'] > self.boundary and row['ctime'] > self.boundary:
                self.seen[name].add(generation)
        return all(len(rows) >= 2 for rows in self.seen.values()) and all(
            row.get('present', True) and row['size'] > 0 for row in metadata.values())


def final_claim(statefulset, pod, storage, namespace, operation):
    storage = approved_retained_storage(storage)
    template = copy.deepcopy(storage['volumeClaimTemplate'])
    require(not template.get('metadata', {}).get('name'), 'Explicit native template name unsupported')
    require(storage['volumeClaimTemplate']['spec'] == {'accessModes': ['ReadWriteOnce'],
            'storageClassName': 'cloudlab-telemetry', 'resources': {'requests': {'storage': '1Gi'}}},
            'Unexpected native retained storage')
    container = next(c for c in pod['spec']['containers'] if c['name'] == 'alertmanager')
    mounts = [m for m in container.get('volumeMounts', []) if m['mountPath'] == '/alertmanager']
    require(len(mounts) == 1 and mounts[0].get('subPath') == 'alertmanager-db', 'Unexpected native state mount')
    volume = mounts[0]['name']
    require(any(v['name'] == volume and 'emptyDir' in v for v in pod['spec']['volumes']),
            'Source is not native emptyDir')
    expected = 'alertmanager-' + statefulset['metadata']['labels']['alertmanager']
    require(statefulset['metadata']['name'] == expected and volume == expected + '-db',
            'Pinned Operator naming changed')
    metadata = template.setdefault('metadata', {})
    metadata.update(name=volume + '-' + expected + '-0', namespace=namespace)
    metadata.setdefault('labels', {}).update(statefulset['spec']['selector']['matchLabels'])
    metadata['labels'].update({LABEL: operation, 'cloudlab.io/owner': OWNER})
    require(not metadata.get('ownerReferences'), 'Temporary ownership on final claim')
    return dict(template, apiVersion='v1', kind='PersistentVolumeClaim')


def maintenance_config(configuration):
    value = copy.deepcopy(configuration)
    value['receivers'] = [{'name': row['name']} for row in value['receivers']]
    return value


def native_maintenance_text(original):
    # This recognizes only the pinned synthetic fixture, not arbitrary production YAML.
    receiver = '- name: proof\n  labels:\n    name: proof\n'
    integration = ('  - send_resolved: true\n    http_config:\n      follow_redirects: true\n'
                   '      enable_http2: true\n    url: <secret>\n    url_file: ""\n'
                   '    max_alerts: 0\n    timeout: 0s\n')
    route = ('\nroute:\n  receiver: proof\n  group_by:\n  - alertname\n  continue: false\n'
             '  group_wait: 0s\n  group_interval: 1s\n  repeat_interval: 1h')
    require(isinstance(original, str) and len(original) <= 65536
            and original.count('\nreceivers:\n') == 1, 'Unexpected native synthetic receiver section')
    prefix, _, tail = original.partition('\nreceivers:\n')
    require(prefix.startswith('global:\n') and prefix.count('\nroute:\n') == 1 and prefix.endswith(route)
            and tail == receiver + '  webhook_configs:\n' + integration * 2 + 'templates: []\n',
            'Native synthetic route, receiver or integration profile differs')
    return prefix + '\nreceivers:\n' + receiver + 'templates: []\n'


def prepare():
    import yaml
    from playbooks.observability.tests.fixtures import native_source_inputs, native_overrides, helm
    from playbooks.observability.files.chart import render
    root = Path(__file__).resolve().parents[4]
    chart = root / 'platform/observability/prometheus'
    lock = json.loads((chart / 'artifact.lock.json').read_text())
    require(digest((chart / lock['archive']).read_bytes()) == lock['sha256'], 'Native chart artifact changed')
    overrides = native_overrides(native_source_inputs())
    values = overrides['cloudlab-prometheus']
    manager = next(o for o in render('prometheus', values) if o['kind'] == 'Alertmanager')
    baseline = next(o for o in render('prometheus') if o['kind'] == 'Alertmanager')
    source_storage = approved_source_storage(baseline['spec'].get('storage'))
    require(manager['spec']['persistentVolumeClaimRetentionPolicy'] == {'whenDeleted': 'Retain', 'whenScaled': 'Retain'},
            'Native claim policy changed')
    pins = json.loads((root / 'platform/observability/images.lock.json').read_text())
    storage_class = next(row for row in helm('platform/observability', overrides['cloudlab-observability'])
                         if row['kind'] == 'StorageClass')
    python = (Path(__file__).with_name('proof.Dockerfile')).read_text().splitlines()[0].removeprefix('FROM ')
    require(re.fullmatch(r'python:[A-Za-z0-9.-]+@sha256:[a-f0-9]{64}', python), 'Unpinned fixture Python image')
    manifests = list(yaml.safe_load_all(Path(__file__).with_name('alertmanager-checkpoint-fixture.yaml').read_text()))
    return {'images': {key: pins[key] for key in ('operator', 'reloader', 'alertmanager')} | {'python': python},
            'storage': approved_retained_storage(manager['spec']['storage']), 'securityContext': manager['spec']['securityContext'],
            'sourceStorage': source_storage,
            'storageClass': storage_class,
            'retention': manager['spec']['persistentVolumeClaimRetentionPolicy'], 'manifests': manifests}


def approved_source_storage(value):
    require(type(value) is dict and type(value.get('emptyDir')) is dict
            and value == {'emptyDir': {'sizeLimit': '64Mi'}}, 'Unsupported canonical source storage declaration')
    return copy.deepcopy(value)


def approved_retained_storage(value):
    require(type(value) is dict and set(value) in ({'volumeClaimTemplate'}, {'volumeClaimTemplate', 'emptyDir'})
            and ('emptyDir' not in value or value['emptyDir'] is None), 'Unsupported expected retained storage mode')
    result = copy.deepcopy(value)
    result.pop('emptyDir', None)
    require(result == {'volumeClaimTemplate': {
        'metadata': {'annotations': {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}},
        'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'cloudlab-telemetry',
                 'resources': {'requests': {'storage': '1Gi'}}}}}, 'Unexpected retained template, metadata or retention annotations')
    return result


def calibrate_retained_storage(cluster, target):
    canonical_target = approved_retained_storage(target)
    require(target == canonical_target, 'Calibration requires canonical expected storage')
    current = cluster.current('Alertmanager', 'primary', cluster.namespace)
    source_spec = copy.deepcopy(current['spec'])
    approved_source_storage(source_spec.get('storage'))
    require(source_spec.get('replicas') == 0 and source_spec.get('persistentVolumeClaimRetentionPolicy') == {
        'whenDeleted': 'Retain', 'whenScaled': 'Retain'}, 'Storage calibration requires retained zero-replica source')
    metadata = current['metadata']
    row = cluster.row('Alertmanager', 'primary', cluster.namespace)
    expected = copy.deepcopy(source_spec)
    expected['storage'] = canonical_target
    for candidate in (canonical_target, dict(copy.deepcopy(canonical_target), emptyDir=None)):
        fresh = cluster.current('Alertmanager', 'primary', cluster.namespace)
        require(fresh['metadata']['uid'] == metadata['uid'] and fresh['spec'] == source_spec,
                'Source changed before native storage calibration candidate')
        approved_source_storage(fresh['spec'].get('storage'))
        patches = [{'op': 'test', 'path': '/metadata/uid', 'value': fresh['metadata']['uid']},
                   {'op': 'test', 'path': '/metadata/resourceVersion', 'value': fresh['metadata']['resourceVersion']},
                   {'op': 'replace', 'path': '/spec/storage', 'value': candidate}]
        returned = json.loads(kubectl('patch', 'Alertmanager', 'primary', '-n', cluster.namespace, '--type=json',
            '--dry-run=server', '-p', json.dumps(patches), '-o', 'json'))
        cluster.owned(returned, row)
        require(returned['metadata']['resourceVersion'] == fresh['metadata']['resourceVersion'] and returned['spec'] == expected,
                'Native dry-run storage round trip or full source profile changed')
    latest = cluster.current('Alertmanager', 'primary', cluster.namespace)
    require(latest['metadata']['uid'] == metadata['uid'] and latest['spec'] == source_spec,
            'Source changed during native storage calibration')
    approved_source_storage(latest['spec'].get('storage'))
    claims = get('PersistentVolumeClaim', namespace=cluster.namespace)
    require(not claims.get('metadata', {}).get('continue') and claims['items'] == [], 'Storage calibration found an unexpected claim')


def source_volume(spec, claims=None):
    require(not claims, 'Zero-replica source unexpectedly declares PVC templates')
    containers = [row for row in spec.get('containers', []) if row['name'] == 'alertmanager']
    require(len(containers) == 1, 'Source template lacks one native Alertmanager container')
    mounts = [row for row in containers[0].get('volumeMounts', []) if row.get('mountPath') == '/alertmanager']
    expected = {'name': 'alertmanager-primary-db', 'mountPath': '/alertmanager', 'subPath': 'alertmanager-db'}
    require(mounts == [expected] and not any(any(key in row for key in ('persistentVolumeClaim', 'hostPath', 'ephemeral'))
            for row in spec.get('volumes', [])),
            'Source template mount or unexpected PVC differs from canonical emptyDir mode')
    volumes = [row for row in spec.get('volumes', []) if row.get('name') == expected['name']]
    require(volumes == [{'name': expected['name'], 'emptyDir': {'sizeLimit': '64Mi'}}],
            'Source native volume is not the approved bounded emptyDir')


def create_source_manager(cluster, manager):
    approved_source_storage(manager['spec'].get('storage'))
    current = cluster.create(manager, dry_run=True)
    approved_source_storage(current['spec'].get('storage'))
    require(current['spec'].get('replicas') == 0, 'Source admission changed zero-replica safety gate')
    current = cluster.create(manager)
    approved_source_storage(current['spec'].get('storage'))
    require(current['spec'].get('replicas') == 0, 'Created source lost zero-replica safety gate')
    current = cluster.current('Alertmanager', 'primary', cluster.namespace)
    approved_source_storage(current['spec'].get('storage'))
    require(current['spec'].get('replicas') == 0, 'Persisted source lost zero-replica safety gate')


def substitute(value, bindings):
    if isinstance(value, dict):
        return {key: substitute(row, bindings) for key, row in value.items()}
    if isinstance(value, list):
        return [substitute(row, bindings) for row in value]
    if isinstance(value, str):
        if value in {'${' + key + '}' for key in bindings}:
            return bindings[value[2:-1]]
        for key, row in bindings.items():
            value = value.replace('${' + key + '}', str(row))
        require(not re.search(r'\$\{[A-Z_]+\}', value), 'Unknown fixture placeholder')
    return value


def labels(operation, role=None):
    result = {'cloudlab.io/owner': OWNER, LABEL: operation}
    if role:
        result['checkpoint-role'] = role
    return result


def pod_document(name, namespace, operation, image, arguments, volumes=None, mounts=None,
                 security=None, role='client', service_account='proof-client'):
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace,
            'labels': labels(operation, role)}, 'spec': {'restartPolicy': 'Never',
            'serviceAccountName': service_account, 'automountServiceAccountToken': False,
            'securityContext': security or copy.deepcopy(POD_SECURITY),
            'containers': [{'name': name, 'image': image, 'command': arguments,
                            'securityContext': copy.deepcopy(SECURITY), 'resources': copy.deepcopy(RESOURCES),
                            'env': [{'name': 'PYTHONDONTWRITEBYTECODE', 'value': '1'}],
                            'volumeMounts': mounts or []}], 'volumes': volumes or []}}


def pod_ready(name, namespace):
    pod = get('pod', name, namespace)
    if pod and any(row['type'] == 'Ready' and row['status'] == 'True'
                   for row in pod.get('status', {}).get('conditions', [])):
        if pod['metadata'].get('annotations', {}).get('ambient.istio.io/redirection') != 'enabled':
            return None
        pod_enrolled(pod)
        return pod
    if pod:
        require(pod.get('status', {}).get('phase') not in ('Failed', 'Succeeded'), 'Fixture Pod terminated')
    return None


def exec_pod(namespace, name, *arguments, body=None, container=None, limit=LIMIT, reject_warnings=False, timeout=90):
    args = ['exec', '-i', '-n', namespace, name]
    if container:
        args += ['-c', container]
    return kubectl(*args, '--', *arguments, body=body, limit=limit, reject_warnings=reject_warnings, timeout=timeout)


def request(namespace, url, value=None, method=None, expected_denied=False, client='client'):
    require(client in ('client', 'unauthorized'), 'Unknown fixture request identity')
    payload = {'url': url, 'value': value, 'method': method, 'expectedDenied': expected_denied}
    result = json.loads(exec_pod(namespace, client, 'python', '/proof/proof.py', '--request', body=canonical(payload)))
    if expected_denied or result.get('inconclusive'):
        record_probe_outcome('fresh-http', 'request', result.get('outcome', 'error'))
    require(not result.get('inconclusive'), 'Fixture HTTP probe is inconclusive')
    return result


def http_request():
    payload = json.load(sys.stdin)
    require(re.fullmatch(r'http://(?:receiver:8080|validator:9093|alertmanager-primary-0\.alertmanager-operated:9093)/[^\s]*',
                         payload['url']), 'Request outside synthetic fixture')
    value = payload.get('value')
    require(payload.get('method') in (None, 'GET', 'POST', 'DELETE'), 'Unsupported fixture HTTP method')
    req = urllib.request.Request(payload['url'], data=canonical(value) if value is not None else None,
        headers={'Content-Type': 'application/json'}, method=payload.get('method'))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=8) as response:
            raw = response.read(LIMIT + 1)
    except urllib.error.HTTPError as error:
        if payload.get('expectedDenied') and error.code in (401, 403):
            print(json.dumps({'denied': True, 'denial': 'authorization', 'outcome': 'authorization', 'status': error.code}))
        else:
            print(json.dumps({'denied': False, 'inconclusive': True, 'outcome': 'http-status'}))
        return
    except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException) as error:
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        outcome = ('dns' if isinstance(reason, socket.gaierror) else 'timeout' if isinstance(reason, TimeoutError)
                   else 'refused' if isinstance(reason, ConnectionRefusedError) else 'closed' if isinstance(reason, ConnectionError)
                   else 'protocol' if isinstance(reason, http.client.HTTPException) else 'error')
        denied = bool(payload.get('expectedDenied') and outcome in ('closed', 'refused'))
        print(json.dumps({'denied': denied, 'inconclusive': not denied, 'outcome': outcome,
                          'denial': 'transport' if denied else None, 'status': None}))
        return
    require(len(raw) <= LIMIT, 'Fixture HTTP response exceeded bound')
    print(json.dumps({'text': raw.decode(), 'denied': False, 'outcome': 'success'}))


def record_probe_outcome(actor, stage, outcome, baseline=None):
    require(actor in ('fresh-http', 'held-http') and stage in ('request', 'connect', 'baseline', 'control', 'revocation')
            and outcome in ('success', 'authorization', 'closed', 'refused', 'dns', 'timeout', 'protocol', 'http-status', 'validation', 'error'),
            'Unknown fixture probe outcome')
    value = {'actor': actor, 'stage': stage, 'outcome': outcome}
    if baseline is not None:
        require((actor, stage, outcome) == ('held-http', 'baseline', 'success')
                and type(baseline) in (int, float) and math.isfinite(baseline) and baseline >= 0,
                'Invalid held baseline clock')
        value['baselineMonotonic'] = baseline
    if DIAGNOSTIC_DIRECTORY is not None:
        raw = canonical(value)
        require(len(raw) <= 256, 'Probe evidence exceeds bound')
        write_new(protected_directory(DIAGNOSTIC_DIRECTORY) / ('probe-' + secrets.token_hex(8) + '.json'), raw)


def held_http_probe():
    stage = ['connect']
    try:
        held_http_exchange(stage)
    except Exception as error:
        outcome = ('dns' if isinstance(error, socket.gaierror) else 'timeout' if isinstance(error, TimeoutError)
                   else 'closed' if isinstance(error, ConnectionError) else 'protocol' if isinstance(error, http.client.HTTPException)
                   else 'validation' if isinstance(error, RuntimeError) else 'error')
        print(json.dumps({'error': {'stage': stage[0], 'outcome': outcome}}), flush=True)
        raise RuntimeError('Held HTTP actor is inconclusive') from None


def held_http_exchange(stage):
    # Exactly one connection; HTTPResponse never opens or reconnects a socket.
    with socket.create_connection(('alertmanager-primary-0.alertmanager-operated', 9093), timeout=5) as connection:
        def exchange():
            connection.sendall(b'GET /api/v2/status HTTP/1.1\r\nHost: alertmanager-primary-0.alertmanager-operated:9093\r\n'
                               b'Connection: keep-alive\r\n\r\n')
            response = http.client.HTTPResponse(connection)
            try:
                response.begin()
                require(response.status == 200 and not response.will_close, 'Held source connection is not reusable HTTP200')
                require(len(response.read(LIMIT + 1)) <= LIMIT, 'Held source response exceeded bound')
            finally:
                response.close()
        stage[0] = 'baseline'
        exchange()
        exchange()
        time.sleep(45)
        exchange()
        ready = time.monotonic()
        print(json.dumps({'ready': True, 'requests': 3, 'idleSeconds': 45, 'connections': 1}), flush=True)
        stage[0] = 'control'
        if not select.select([sys.stdin], [], [], max(0, 25 - (time.monotonic() - ready)))[0]:
            raise TimeoutError()
        require(sys.stdin.readline(32) == 'check\n', 'Held connection control changed')
        if time.monotonic() - ready >= 25:
            raise TimeoutError()
        try:
            stage[0] = 'revocation'
            remaining = 40 - (time.monotonic() - ready)
            if remaining <= 0 or not select.select([connection], [], [], remaining)[0]:
                raise TimeoutError()
            require(connection.recv(1, socket.MSG_PEEK) == b'', 'Held connection received unexpected data instead of EOF')
        except TimeoutError:
            raise
        except ConnectionError:
            pass
        if time.monotonic() - ready >= 40:
            raise TimeoutError()
        print(json.dumps({'revoked': True, 'connections': 1}), flush=True)


def probe_message(process, timeout, stage='control'):
    def inconclusive(outcome):
        record_probe_outcome('held-http', stage, outcome)
        raise RuntimeError('Held connection child is inconclusive')
    deadline, raw = time.monotonic() + timeout, b''
    while b'\n' not in raw:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
            inconclusive('timeout')
        chunk = os.read(process.stdout.fileno(), 1025 - len(raw))
        if not chunk or len(raw) + len(chunk) > 1024:
            inconclusive('protocol')
        raw += chunk
    if not raw.endswith(b'\n') or raw.count(b'\n') != 1:
        inconclusive('protocol')
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        inconclusive('protocol')
    if isinstance(result, dict) and set(result) == {'error'}:
        error = result['error']
        if not (isinstance(error, dict) and set(error) == {'stage', 'outcome'}
                and error['stage'] in ('connect', 'baseline', 'control', 'revocation')
                and error['outcome'] in ('dns', 'timeout', 'closed', 'protocol', 'validation', 'error')):
            inconclusive('protocol')
        record_probe_outcome('held-http', error['stage'], error['outcome'])
        raise RuntimeError('Held connection actor is inconclusive')
    return result


@contextmanager
def held_source_connection(namespace):
    require(re.fullmatch(PREFIX + r'[a-f0-9]{16}', namespace), 'Held connection namespace outside proof')
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16384, 16384))
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(['kubectl', '--request-timeout=270s', 'exec', '-i', '-n', namespace, 'client', '--',
            'python', '/proof/proof.py', '--held-http-probe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=errors, bufsize=0, preexec_fn=limits)
        try:
            ready = probe_message(process, 80, stage='baseline')
            if ready != {'ready': True, 'requests': 3, 'idleSeconds': 45, 'connections': 1}:
                record_probe_outcome('held-http', 'baseline', 'protocol')
                raise RuntimeError('Held connection idle positive controls missing; proof inconclusive')
            baseline = time.monotonic()
            record_probe_outcome('held-http', 'baseline', 'success', baseline=baseline)
            def revoked():
                held_time_budget(baseline, 25)
                process.stdin.write(b'check\n')
                process.stdin.flush()
                result = probe_message(process, held_time_budget(baseline, 40), stage='revocation')
                if result != {'revoked': True, 'connections': 1}:
                    record_probe_outcome('held-http', 'revocation', 'protocol')
                    raise RuntimeError('Established source connection was not revoked; proof inconclusive')
                held_time_budget(baseline, 40)
                try:
                    status = process.wait(timeout=min(5, held_time_budget(baseline, 40)))
                except subprocess.TimeoutExpired:
                    record_probe_outcome('held-http', 'revocation', 'timeout')
                    raise RuntimeError('Held connection child exit timed out; proof inconclusive') from None
                if status != 0:
                    record_probe_outcome('held-http', 'revocation', 'error')
                    raise RuntimeError('Held connection child failed; proof inconclusive')
                held_time_budget(baseline, 40)
                record_probe_outcome('held-http', 'revocation', 'closed')
            yield revoked, baseline
        finally:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.stdout.close()


def held_time_budget(baseline, limit):
    remaining = limit - (time.monotonic() - baseline)
    if remaining <= 0:
        record_probe_outcome('held-http', 'control' if limit == 25 else 'revocation', 'timeout')
        raise RuntimeError('Held connection causal time budget expired; proof inconclusive')
    return remaining


def serve():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    events, lock = [], threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, code, value):
            raw = canonical(value)
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            with lock:
                self.reply(200, list(events)) if self.path == '/events' else self.reply(404, {})

        def do_POST(self):
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if self.path not in ('/alerts/0', '/alerts/1') or not 0 < size <= 65536:
                    return self.reply(400, {})
                value = json.loads(self.rfile.read(size))
                rows = value['alerts']
                if not isinstance(rows, list) or len(rows) > 16:
                    return self.reply(400, {})
                additions = []
                for row in rows:
                    name, status_value = row['labels']['alertname'], row['status']
                    if not re.fullmatch(r'Fixture[A-Za-z0-9]{1,48}', name) or status_value not in ('firing', 'resolved'):
                        return self.reply(400, {})
                    additions.append({'integration': self.path[-1], 'name': name, 'status': status_value})
                with lock:
                    if len(events) + len(additions) > 256:
                        return self.reply(429, {})
                    events.extend(additions)
                self.reply(200, {})
            except (KeyError, ValueError, TypeError, UnicodeDecodeError):
                self.reply(400, {})

    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()


def write_checkpoint():
    payload = json.load(sys.stdin)
    values = {name: base64.b64decode(raw, validate=True) for name, raw in payload['files'].items()}
    require(set(values) == set(FILES), 'Incomplete checkpoint write')
    root = Path('/data')
    require(root.is_dir() and not root.is_symlink(), 'Unsafe claim root')
    target = root / 'alertmanager-db'
    target.mkdir(mode=0o700)
    for name in FILES:
        require(0 < len(values[name]) <= LIMIT // 2 and digest(values[name]) == payload['hashes'][name],
                'Invalid checkpoint write bytes')
        write_new(target / name, values[name])
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(json.dumps({name: digest((target / name).read_bytes()) for name in FILES}))


def snapshot_metadata(namespace, pod):
    script = ('set -eu; date +%s; for name in nflog silences; do '
              'if test ! -e /alertmanager/$name && test ! -L /alertmanager/$name; then '
              'printf "missing\\nmissing\\n"; continue; fi; '
              'test -f /alertmanager/$name; test ! -L /alertmanager/$name; '
              'stat -c %i:%Y:%Z:%s:%f /alertmanager/$name; sha256sum /alertmanager/$name; done')
    lines = exec_pod(namespace, pod, '/bin/sh', '-ec', script, container='alertmanager').decode().splitlines()
    require(len(lines) == 5, 'Invalid native snapshot metadata')
    metadata, hashes = {}, {}
    for index, name in enumerate(FILES):
        if lines[1 + index * 2] == 'missing':
            require(lines[2 + index * 2] == 'missing', 'Invalid missing snapshot marker')
            metadata[name] = {'present': False, 'inode': 0, 'mtime': 0, 'ctime': 0, 'size': 0, 'regular': False}
            hashes[name] = None
            continue
        fields = lines[1 + index * 2].split(':')
        require(len(fields) == 5, 'Invalid snapshot stat output')
        inode, modified, changed, size = (int(value) for value in fields[:4])
        mode = int(fields[4], 16)
        checksum, filename = lines[2 + index * 2].split()
        require(filename == '/alertmanager/' + name and re.fullmatch(r'[a-f0-9]{64}', checksum),
                'Invalid snapshot checksum output')
        metadata[name] = {'inode': inode, 'mtime': modified, 'ctime': changed, 'size': size,
                          'regular': stat.S_ISREG(mode)}
        hashes[name] = checksum
    return int(lines[0]), metadata, hashes


def native_http_request(path, value=None):
    require(isinstance(path, str), 'Invalid native API path')
    silence = re.fullmatch(r'/api/v2/silence/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', path)
    require((value is None and (path in ('/api/v2/status', '/metrics') or silence))
            or (path == '/api/v2/alerts' and isinstance(value, list) and 0 < len(value) <= 16),
            'Native request outside approved API profile')
    body = b'' if value is None else canonical(value)
    require(len(body) <= 1024 * 1024, 'Native request body exceeds bound')
    method = 'GET' if value is None else 'POST'
    header = (method + ' ' + path + ' HTTP/1.1\r\nHost: 127.0.0.1:9093\r\nConnection: close\r\n'
              'Accept-Encoding: identity\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)) + '\r\n\r\n')
    return header.encode('ascii') + body


def parse_native_http(raw):
    require(isinstance(raw, bytes) and len(raw) <= 2 * 1024 * 1024, 'Native HTTP response exceeds bound')
    split = raw.find(b'\r\n\r\n')
    require(0 < split <= 32768, 'Native HTTP headers missing or excessive')
    lines, body = raw[:split].split(b'\r\n'), raw[split + 4:]
    require(re.fullmatch(rb'HTTP/1\.[01] 200(?: [\x20-\x7e]*)?', lines[0]) and len(lines) <= 101,
            'Native HTTP requires one exact200 response and bounded headers')
    headers = {}
    for line in lines[1:]:
        key, colon, value = line.partition(b':')
        require(colon and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                and all(32 <= byte <= 126 or byte == 9 for byte in value), 'Malformed native HTTP header')
        headers.setdefault(key.lower(), []).append(value.strip().lower())
    length, transfer, encoding = (headers.get(key, []) for key in (b'content-length', b'transfer-encoding', b'content-encoding'))
    require(len(length) <= 1 and len(transfer) <= 1 and len(encoding) <= 1
            and not (length and transfer) and encoding in ([], [b'identity']), 'Ambiguous or encoded native HTTP framing')
    if length:
        require(re.fullmatch(rb'[0-9]{1,10}', length[0]) and int(length[0]) == len(body),
                'Truncated or trailing native content-length response')
        framing = 'length'
    elif transfer:
        require(transfer == [b'chunked'], 'Unsupported native transfer encoding')
        cursor, total, chunks = 0, 0, 0
        while True:
            end = body.find(b'\r\n', cursor)
            require(end >= cursor and re.fullmatch(rb'[0-9a-fA-F]{1,16}', body[cursor:end]), 'Invalid native chunk length')
            size, cursor = int(body[cursor:end], 16), end + 2
            chunks += 1
            require(chunks <= 65536, 'Excessive native HTTP chunks')
            if not size:
                require(body[cursor:] == b'\r\n', 'Unexpected native chunk trailers or trailing bytes')
                break
            total += size
            require(total <= 1024 * 1024 and body[cursor + size:cursor + size + 2] == b'\r\n',
                    'Native chunk truncated or excessive')
            cursor += size + 2
        framing = 'chunked'
    else:
        raise RuntimeError('Close-delimited native HTTP is unsupported by bounded nc transport')
    class BufferedSocket:
        def makefile(self, *_args, **_kwargs):
            return io.BytesIO(raw)
    response = http.client.HTTPResponse(BufferedSocket())
    try:
        response.begin()
        value = response.read(1024 * 1024 + 1)
    except (http.client.HTTPException, ValueError):
        raise RuntimeError('Malformed or truncated native HTTP response') from None
    finally:
        response.close()
    require(len(value) <= 1024 * 1024, 'Native HTTP body exceeds bound')
    return value, framing


def native_actor(cluster, name):
    require(name in ('alertmanager-primary-0', 'validator'), 'Unknown native request Pod')
    pod = get('Pod', name, cluster.namespace)
    cluster.owned(pod)
    rows = [row for row in cluster.receipt.value['resources'] if row['kind'] == 'Pod' and row['name'] == name
            and row['namespace'] == cluster.namespace and row.get('uid') == pod['metadata']['uid']]
    require(len(rows) == 1, 'Native request Pod UID is not receipted')
    require(not pod['spec'].get('ephemeralContainers')
            and ([owner['uid'] for owner in pod['metadata'].get('ownerReferences', [])] == rows[0].get('owners', [])
                 if rows[0].get('observed') else not pod['metadata'].get('ownerReferences')
                    and pod_profile(pod['spec']) == rows[0].get('podProfile')),
            'Native request ownership or executable profile changed')
    container = 'alertmanager' if name == 'alertmanager-primary-0' else 'validator'
    containers = [row for row in pod['spec']['containers'] if row['name'] == container]
    statuses = [row for row in pod.get('status', {}).get('containerStatuses', []) if row['name'] == container]
    require(len(containers) == len(statuses) == 1
            and containers[0]['image'] == cluster.receipt.value['evidence']['fixtureImages']['alertmanager']
            and statuses[0].get('restartCount') == 0 and statuses[0].get('state', {}).get('running'),
            'Native request process or pinned image changed')
    return container, {'uid': pod['metadata']['uid'], 'container': container, 'image': containers[0]['image'],
                       'containerID': statuses[0]['containerID'], 'startedAt': statuses[0]['state']['running']['startedAt']}


def native_request(cluster, name, path, value=None):
    body = native_http_request(path, value)
    container, before = native_actor(cluster, name)
    raw = exec_pod(cluster.namespace, name, '/bin/nc', '-n', '-w', '8', '127.0.0.1', '9093',
                   container=container, body=body, limit=2 * 1024 * 1024, timeout=20, reject_warnings=True)
    require(native_actor(cluster, name) == (container, before), 'Native request actor changed during exec')
    result, framing = parse_native_http(raw)
    profiles = cluster.receipt.value['evidence'].setdefault('nativeHTTPFraming', [])
    if framing not in profiles:
        profiles.append(framing)
        cluster.receipt.save()
    return result.decode('utf-8')


def maintenance_errors(cluster):
    raw = source_get(cluster, '/metrics')
    metrics = {}
    for component in ('nflog', 'silences'):
        name = 'alertmanager_' + component + '_maintenance_errors_total'
        rows = [line for line in raw.splitlines() if line.startswith(name + ' ')]
        require(len(rows) == 1, 'Native maintenance error metric unavailable')
        metrics[component] = float(rows[0].split()[1])
    return metrics


def source_get(cluster, path):
    require(path in ('/metrics', '/api/v2/status'), 'Unsupported isolated source query')
    return native_request(cluster, 'alertmanager-primary-0', path)


def native_reload_state(cluster):
    original = json.loads(source_get(cluster, '/api/v2/status'))['config']['original']
    raw = source_get(cluster, '/metrics')
    values = []
    for name in ('alertmanager_config_last_reload_successful',
                 'alertmanager_config_last_reload_success_timestamp_seconds'):
        rows = [line for line in raw.splitlines() if line.startswith(name + ' ')]
        require(len(rows) == 1 and len(rows[0].split()) == 2, 'Native reload metric unavailable')
        value = float(rows[0].split()[1])
        require(math.isfinite(value), 'Invalid native reload metric')
        values.append(value)
    require(values[0] in (0, 1) and values[1] > 0, 'Invalid native reload state')
    return {'original': original, 'successful': values[0] == 1, 'timestamp': values[1]}


def native_reloaded(cluster, expected, previous, identity):
    source_unchanged(get('Pod', 'alertmanager-primary-0', cluster.namespace), identity)
    state = native_reload_state(cluster)
    source_unchanged(get('Pod', 'alertmanager-primary-0', cluster.namespace), identity)
    return state['original'] == expected and state['successful'] and state['timestamp'] > previous


def verify_snapshots(cluster, source, identity):
    boundary, baseline, _ = snapshot_metadata(cluster.namespace, source)
    errors = maintenance_errors(cluster)
    generations = Generations(boundary, baseline)

    def completed():
        require_source_denied(cluster)
        source_unchanged(get('pod', source, cluster.namespace), identity)
        require(maintenance_errors(cluster) == errors, 'Native maintenance failed')
        return generations.observe(snapshot_metadata(cluster.namespace, source)[1])

    wait('two complete post-quiescence snapshot generations', completed, timeout=75)
    for _ in range(3):
        source_unchanged(get('pod', source, cluster.namespace), identity)
        _, before, hashes = snapshot_metadata(cluster.namespace, source)
        raw = exec_pod(cluster.namespace, source, '/bin/sh', '-ec',
            'tar -C /alertmanager -cf - nflog silences | head -c 16777217',
            container='alertmanager', reject_warnings=True)
        _, after, after_hashes = snapshot_metadata(cluster.namespace, source)
        if before == after and hashes == after_hashes:
            values = parse_archive(raw, hashes)
            logs = kubectl('logs', '-n', cluster.namespace, source, '-c', 'alertmanager',
                           '--since-time=' + identity['startedAt'], '--tail=-1')
            for line in logs.decode().splitlines():
                row = json.loads(line)
                require(not (row.get('component') in ('nflog', 'silences')
                             and row.get('level', '').lower() in ('error', 'warn')), 'Native state maintenance log failure')
            require(maintenance_errors(cluster) == errors, 'Native maintenance failed during capture')
            require_source_denied(cluster)
            source_unchanged(get('Pod', source, cluster.namespace), identity)
            for name, value in values.items():
                write_new(cluster.receipt.directory / name, value)
            cluster.receipt.phase('snapshot-captured', hashes=hashes,
                                  generations={k: len(v) for k, v in generations.seen.items()})
            return values, hashes
    raise RuntimeError('Snapshot generation changed during bounded capture; source retained')


def service_binding(service):
    value = service['spec']
    require(value.get('selector') and value.get('type', 'ClusterIP') != 'ExternalName',
            'Unsupported derived Endpoint Service')
    ports = [{'name': row.get('name', ''), 'port': row['port'], 'protocol': row.get('protocol', 'TCP'),
              'targetPort': row.get('targetPort', row['port']), 'appProtocol': row.get('appProtocol')}
             for row in value.get('ports', [])]
    require(ports, 'Derived Endpoint Service lacks ports')
    return {'selector': copy.deepcopy(value['selector']), 'ports': ports}


def endpoint_entries(current):
    values = set()
    for subset in current.get('subsets', []):
        ports = sorted((p.get('name', ''), p['port'], p.get('protocol', 'TCP'), p.get('appProtocol') or '')
                       for p in subset.get('ports', []))
        for address in subset.get('addresses', []) + subset.get('notReadyAddresses', []):
            reference = address.get('targetRef', {})
            values.add(digest(canonical({'reference': {key: reference.get(key) for key in ('kind', 'namespace', 'name', 'uid')},
                                        'ip': address.get('ip'), 'ports': ports})))
    return sorted(values)


def endpoint_binding(cluster, current, prior=None):
    metadata = current['metadata']
    require(current['apiVersion'] == 'v1' and current['kind'] == 'Endpoints'
            and metadata.get('namespace') == cluster.namespace and not metadata.get('ownerReferences')
            and metadata.get('labels', {}).get(LABEL) == cluster.operation
            and metadata['labels'].get('cloudlab.io/owner') == OWNER
            and metadata['labels'].get('endpoints.kubernetes.io/managed-by') == 'endpoint-controller',
            'Foreign derived Endpoints')
    writers = {row['manager'] for row in metadata.get('managedFields', [])}
    require(writers in ({'kube-controller-manager'}, {'k3s'}), 'Unknown Endpoints controller provenance')
    require(set(metadata.get('annotations', {})) <= {'endpoints.kubernetes.io/last-change-trigger-time'},
            'Unknown derived Endpoint annotation')
    service_row = cluster.row('Service', metadata['name'], cluster.namespace)
    service = cluster.current('Service', metadata['name'], cluster.namespace)
    binding = service_binding(service)
    require(binding == service_row.get('serviceBinding'), 'Receipted Service selector or ports changed')
    service_labels = service['metadata'].get('labels', {})
    require(all(metadata['labels'].get(key) == value for key, value in service_labels.items()),
            'Derived Endpoint labels differ from current Service')
    require((metadata['labels'].get('service.kubernetes.io/headless') == '' if service['spec'].get('clusterIP') == 'None'
             else 'service.kubernetes.io/headless' not in metadata['labels']),
            'Derived Endpoint headless marker changed')
    if prior:
        require(prior['uid'] == metadata['uid'] and prior['serviceUID'] == service['metadata']['uid']
                and set(prior['writers']) == writers, 'Derived Endpoint or Service replaced')
    targets = []
    for subset in current.get('subsets', []):
        addresses = subset.get('addresses', []) + subset.get('notReadyAddresses', [])
        require(addresses and subset.get('ports'), 'Incomplete derived Endpoint subset')
        actual_ports = {(p.get('name', ''), p['port'], p.get('protocol', 'TCP'), p.get('appProtocol'))
                        for p in subset['ports']}
        require(len(actual_ports) == len(subset['ports']), 'Duplicate derived Endpoint ports')
        for address in addresses:
            reference = address.get('targetRef', {})
            require(reference.get('kind') == 'Pod' and reference.get('namespace') == cluster.namespace,
                    'Endpoint target is outside the fixture')
            rows = [row for row in cluster.receipt.value['resources'] if row['kind'] == 'Pod'
                    and row.get('uid') == reference.get('uid') and row['name'] == reference.get('name')
                    and row['namespace'] == cluster.namespace]
            require(len(rows) == 1, 'Endpoint targets an unrecorded Pod')
            pod = get('Pod', reference['name'], cluster.namespace)
            require(pod and pod['metadata']['uid'] == reference['uid']
                    and all(pod['metadata'].get('labels', {}).get(key) == value for key, value in binding['selector'].items())
                    and address.get('ip') in {entry['ip'] for entry in pod.get('status', {}).get('podIPs', [])},
                    'Endpoint Pod identity, selector or IP changed')
            expected_ports = set()
            for port in binding['ports']:
                target = port['targetPort']
                if isinstance(target, str):
                    matches = {p['containerPort'] for c in pod['spec']['containers'] for p in c.get('ports', [])
                               if p.get('name') == target and p.get('protocol', 'TCP') == port['protocol']}
                    require(len(matches) == 1, 'Endpoint named target port is ambiguous')
                    target = matches.pop()
                require(type(target) is int and 1 <= target <= 65535, 'Invalid Endpoint target port')
                expected_ports.add((port['name'], target, port['protocol'], port['appProtocol']))
            require(actual_ports == expected_ports, 'Endpoint ports differ from receipted Service and Pod')
            targets.append(reference['uid'])
    return {'apiVersion': 'v1', 'kind': 'Endpoints', 'name': metadata['name'], 'namespace': cluster.namespace,
            'uid': metadata['uid'], 'observed': True, 'derivedEndpoint': True, 'serviceUID': service['metadata']['uid'],
            'writers': sorted(writers), 'targets': sorted(set(targets)), 'owners': [], 'entries': endpoint_entries(current)}


def record_generated(cluster, qualification=True):
    rows = cluster.receipt.value['resources']
    for _ in range(4):
        known = {row['uid'] for row in rows if row['uid']}
        added = False
        for kind in ('StatefulSet', 'ReplicaSet', 'Pod', 'Service', 'Secret', 'ConfigMap',
                     'ControllerRevision', 'EndpointSlice'):
            for current in get(kind, namespace=cluster.namespace)['items']:
                metadata = current['metadata']
                if kind == 'Pod' and qualification:
                    pod_enrolled(current)
                if metadata['uid'] in known:
                    continue
                owners = metadata.get('ownerReferences', [])
                if not owners or not all(owner['uid'] in known for owner in owners):
                    continue
                require(metadata.get('labels', {}).get(LABEL) == cluster.operation
                        and metadata['labels'].get('cloudlab.io/owner') == OWNER, 'Unexpected native child labels')
                row = {'apiVersion': current['apiVersion'], 'kind': kind, 'name': metadata['name'],
                       'namespace': cluster.namespace, 'uid': metadata['uid'],
                       'owners': [owner['uid'] for owner in owners], 'observed': True}
                if kind == 'Service':
                    row['serviceBinding'] = service_binding(current)
                rows.append(row)
                added = True
        if not added:
            break
    # Endpoints lack ownerRefs; validate only after the complete native Service/Pod chains are recorded.
    for current in get('Endpoints', namespace=cluster.namespace, managed_fields=True)['items']:
        metadata = current['metadata']
        prior = [row for row in rows if row['kind'] == 'Endpoints' and row['name'] == metadata['name']
                 and row['namespace'] == cluster.namespace]
        require(len(prior) <= 1, 'Ambiguous derived Endpoint receipt')
        observed = endpoint_binding(cluster, current, prior[0] if prior else None)
        if prior:
            prior[0].update(observed)
        else:
            rows.append(observed)
    cluster.receipt.save()


def storage_identity(claim, healthy=True):
    require(claim and claim.get('status', {}).get('phase') == 'Bound', 'Checkpoint claim is not bound')
    pv = get('pv', claim['spec']['volumeName'])
    require(pv['spec']['persistentVolumeReclaimPolicy'] == 'Retain'
            and pv['spec']['claimRef']['uid'] == claim['metadata']['uid']
            and pv['spec']['csi']['driver'] == 'driver.longhorn.io', 'Unqualified checkpoint PV')
    volume = get('volumes.longhorn.io', pv['spec']['csi']['volumeHandle'], 'longhorn-system')
    require(volume and (not healthy or volume['status'].get('robustness') == 'healthy')
            and volume['spec']['numberOfReplicas'] == 2, 'Checkpoint Longhorn volume unhealthy')
    return {'claim': claim['metadata']['uid'], 'pv': pv['metadata']['uid'],
            'pvName': pv['metadata']['name'], 'volume': volume['metadata']['name'],
            'volumeUID': volume['metadata']['uid'], 'handle': pv['spec']['csi']['volumeHandle']}


def verify_storage(namespace, claim_name, identity):
    require(storage_identity(get('pvc', claim_name, namespace)) == identity, 'Checkpoint storage identity changed')


def storage_class_matches(actual, desired):
    fields = ('provisioner', 'reclaimPolicy', 'volumeBindingMode', 'allowVolumeExpansion', 'parameters', 'mountOptions')
    require(actual and actual['metadata']['name'] == desired['metadata']['name']
            and actual['metadata'].get('labels', {}).get('cloudlab.io/owner') ==
                desired['metadata']['labels']['cloudlab.io/owner']
            and all(actual.get(key) == desired.get(key) for key in fields),
            'Telemetry StorageClass differs from its accepted owner declaration')


def no_restore(volume):
    spec, status_value = volume.get('spec', {}), volume.get('status', {})
    require(not any(spec.get(key) for key in ('fromBackup', 'dataSource', 'cloneMode', 'backingImage', 'Standby', 'standby'))
            and not any(status_value.get(key) for key in ('restoreRequired', 'restoreInitiated', 'lastBackup', 'lastRestoredBackup'))
            and not any(status_value.get('cloneStatus', {}).get(key) for key in ('sourceVolume', 'snapshot', 'state')),
            'Restored, cloned or backed storage cannot become synthetic deletion scope')


def storage_baseline(cluster, desired):
    storage_class_matches(get('storageclass', 'cloudlab-telemetry'), desired)
    baseline = {'boundary': datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                'storageClassUID': get('storageclass', 'cloudlab-telemetry')['metadata']['uid']}
    for key, kind, namespace in [('pvs', 'pv', None), ('volumes', 'volumes.longhorn.io', 'longhorn-system')]:
        listed = get(kind, namespace=namespace)
        require(not listed.get('metadata', {}).get('continue'), 'Incomplete storage baseline inventory')
        baseline[key] = {'uids': sorted(digest(row['metadata']['uid'].encode()) for row in listed['items']),
                         'names': sorted(digest(row['metadata']['name'].encode()) for row in listed['items'])}
    cluster.receipt.phase('pre-claim-storage-inventory', storageBaseline=baseline)
    return baseline


def fresh_storage(claim, baseline, desired_class):
    require(claim and claim.get('status', {}).get('phase') == 'Bound', 'Fresh claim is not bound')
    spec, metadata = claim['spec'], claim['metadata']
    require(not any(spec.get(key) for key in ('dataSource', 'dataSourceRef', 'selector'))
            and spec.get('storageClassName') == 'cloudlab-telemetry'
            and metadata.get('annotations', {}).get('volume.kubernetes.io/storage-provisioner') == 'driver.longhorn.io',
            'Claim is restored, selected or not dynamically provisioned')
    current_class = get('storageclass', 'cloudlab-telemetry')
    storage_class_matches(current_class, desired_class)
    require(current_class['metadata']['uid'] == baseline['storageClassUID'], 'StorageClass replaced during provisioning')
    expected = 'pvc-' + metadata['uid']
    require(spec['volumeName'] == expected, 'Dynamic PV name does not bind the exact claim UID')
    pv = get('pv', expected)
    require(pv and pv['metadata'].get('annotations', {}).get('pv.kubernetes.io/provisioned-by') == 'driver.longhorn.io'
            and pv['spec']['claimRef']['uid'] == metadata['uid']
            and pv['spec']['claimRef']['name'] == metadata['name']
            and pv['spec']['claimRef']['namespace'] == metadata['namespace']
            and pv['spec'].get('storageClassName') == 'cloudlab-telemetry'
            and pv['spec']['csi']['driver'] == 'driver.longhorn.io'
            and pv['spec']['csi']['volumeHandle'] == expected
            and pv['spec']['persistentVolumeReclaimPolicy'] == 'Retain', 'PV provisioning chain changed')
    volume = get('volumes.longhorn.io', expected, 'longhorn-system')
    require(volume and volume['metadata']['name'] == expected and volume['spec']['numberOfReplicas'] == 2,
            'Native volume does not bind this claim')
    no_restore(volume)
    boundary = datetime.fromisoformat(baseline['boundary'])
    created = datetime.fromisoformat(metadata['creationTimestamp'].replace('Z', '+00:00'))
    require(created >= boundary, 'Claim predates the complete storage baseline')
    for kind, current in [('pvs', pv), ('volumes', volume)]:
        item = current['metadata']
        require(digest(item['uid'].encode()) not in baseline[kind]['uids']
                and digest(item['name'].encode()) not in baseline[kind]['names']
                and datetime.fromisoformat(item['creationTimestamp'].replace('Z', '+00:00')) >= created,
                'Preexisting PV or Longhorn data cannot become synthetic storage')
    kubernetes = volume.get('status', {}).get('kubernetesStatus', {})
    if not kubernetes.get('pvcName') or not kubernetes.get('pvName'):
        return None
    require(kubernetes['pvcName'] == metadata['name'] and kubernetes.get('namespace') == metadata['namespace']
            and kubernetes['pvName'] == expected, 'Longhorn Kubernetes ownership linkage differs')
    identity = storage_identity(claim, healthy=False)
    return identity


def alert(name, resolved=False):
    now = datetime.now(timezone.utc)
    return {'labels': {'alertname': name, 'severity': 'critical'}, 'annotations': {'summary': 'Synthetic checkpoint'},
            'startsAt': (now - timedelta(minutes=1)).isoformat(),
            'endsAt': (now - timedelta(seconds=1) if resolved else now + timedelta(hours=1)).isoformat()}


def callbacks(namespace):
    return json.loads(request(namespace, 'http://receiver:8080/events')['text'])


def delivered(namespace, name, status_value):
    rows = callbacks(namespace)
    return all(any(row == {'integration': index, 'name': name, 'status': status_value} for row in rows)
               for index in ('0', '1'))


def populate(namespace):
    base = 'http://alertmanager-primary-0.alertmanager-operated:9093'
    records = [alert('FixtureGroupA'), alert('FixtureGroupB')]
    for value in records:
        request(namespace, base + '/api/v2/alerts', [value])
        wait('initial native fanout', lambda: delivered(namespace, value['labels']['alertname'], 'firing'))
    resolved = alert('FixtureResolved')
    request(namespace, base + '/api/v2/alerts', [resolved])
    wait('initial firing before resolve', lambda: delivered(namespace, 'FixtureResolved', 'firing'))
    resolved['endsAt'] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    request(namespace, base + '/api/v2/alerts', [resolved])
    wait('resolved fanout', lambda: delivered(namespace, 'FixtureResolved', 'resolved'))
    records.append(resolved)
    now = datetime.now(timezone.utc)
    silences = []
    for index in range(3):
        value = {'matchers': [{'name': 'alertname', 'value': 'FixtureSilenced' + str(index),
                               'isRegex': False, 'isEqual': True}],
                 'startsAt': (now - timedelta(minutes=2)).isoformat(),
                 'endsAt': (now + timedelta(hours=1)).isoformat(),
                 'createdBy': 'checkpoint-proof', 'comment': 'Synthetic retained state'}
        result = json.loads(request(namespace, base + '/api/v2/silences', value)['text'])
        if index == 2:
            request(namespace, base + '/api/v2/silence/' + result['silenceID'], method='DELETE')
        silences.append(json.loads(request(namespace, base + '/api/v2/silence/' + result['silenceID'])['text']))
    return records, silences


def native_validation(cluster, pod, records, silences, control):
    namespace = cluster.namespace
    for expected in silences:
        actual = json.loads(native_request(cluster, pod, '/api/v2/silence/' + expected['id']))
        require(all(actual[key] == expected[key] for key in ('id', 'matchers', 'startsAt', 'endsAt', 'createdBy', 'comment')),
                'Native silence state changed')
    before = callbacks(namespace)
    native_request(cluster, pod, '/api/v2/alerts', records + [alert('FixtureSilenced0')])
    time.sleep(4)
    require(callbacks(namespace) == before, 'Native checkpoint lost suppression or notification deduplication')
    native_request(cluster, pod, '/api/v2/alerts', [alert(control)])
    wait('native validator positive callback control', lambda: delivered(namespace, control, 'firing'))


def pod_dry_run(template, namespace, name):
    document = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': dict(template['metadata'], name=name,
                 namespace=namespace), 'spec': copy.deepcopy(template['spec'])}
    document['metadata'].pop('creationTimestamp', None)
    security = document['spec'].get('securityContext', {})
    require(security.get('runAsNonRoot') and security.get('seccompProfile', {}).get('type') == 'RuntimeDefault',
            'Native Pod does not satisfy Restricted security')
    for container in document['spec']['containers'] + document['spec'].get('initContainers', []):
        value = container.get('securityContext', {})
        require(value.get('allowPrivilegeEscalation') is False and 'ALL' in value.get('capabilities', {}).get('drop', [])
                and container.get('resources', {}).get('requests') and container['resources'].get('limits')
                and '@sha256:' in container['image'], 'Unbounded or unsafe native container')
    kubectl('create', '--dry-run=server', '-f', '-', body=canonical(document))
    return {'securityContext': security, 'containers': {
        c['name']: {'image': c['image'], 'securityContext': c.get('securityContext'), 'resources': c['resources']}
        for c in document['spec']['containers'] + document['spec'].get('initContainers', [])}}


def preflight(payload):
    import ipaddress
    version = json.loads(kubectl('version', '-o', 'json'))['serverVersion']['gitVersion']
    require(version.startswith('v1.36.5+k3s'), 'Unexpected K3s version')
    storage_class_matches(get('storageclass', 'cloudlab-telemetry'), payload['storageClass'])
    operator = get('deployment', 'cloudlab-prometheus-operator', 'cloudlab-observability')
    containers = operator['spec']['template']['spec']['containers']
    require(any(c['image'] == payload['images']['operator']
                and '--namespaces=cloudlab-observability,cloudlab-app-notes' in c.get('args', [])
                for c in containers), 'Production Operator isolation differs from reviewed scope')
    # Inspect installed policies, not only Git. Their admission decision is qualified by the dry runs below.
    policies = get('validatingpolicies.policies.kyverno.io')
    require(policies is not None, 'Installed admission policies unavailable')
    strict_root_policy(get('peerauthentications.security.istio.io', namespace='istio-system')['items'])
    nodes = get('nodes')['items']
    require(len(nodes) == 2 and all(any(c['type'] == 'Ready' and c['status'] == 'True'
            for c in n['status']['conditions']) for n in nodes), 'Proof requires two ready existing nodes')
    allocated = 0
    for node in nodes:
        raw = node['status']['allocatable']['memory']
        require(raw.endswith('Ki'), 'Unknown node memory unit')
        allocated += int(raw[:-2]) * 1024
    requested = 0
    for pod in json.loads(kubectl('get', 'pods', '-A', '-o', 'json'))['items']:
        if pod.get('status', {}).get('phase') in ('Succeeded', 'Failed'):
            continue
        for container in pod['spec']['containers']:
            raw = container.get('resources', {}).get('requests', {}).get('memory', '0')
            unit = {'Ki': 1024, 'Mi': 1024 ** 2, 'Gi': 1024 ** 3}
            requested += next((int(raw[:-2]) * scale for suffix, scale in unit.items() if raw.endswith(suffix)),
                              int(raw) if raw.isdigit() else allocated)
    require(allocated - requested >= 768 * 1024 ** 2, 'Insufficient unreserved memory for bounded fixture')
    longhorn_nodes = get('nodes.longhorn.io', namespace='longhorn-system')['items']
    require(len(longhorn_nodes) == 2 and all(any(
        disk.get('storageAvailable', 0) > 2 * 1024 ** 3
        and disk.get('storageMaximum', 0) - disk.get('storageScheduled', 0) > 2 * 1024 ** 3
        for disk in node.get('status', {}).get('diskStatus', {}).values()) for node in longhorn_nodes),
        'Insufficient Longhorn replica capacity')
    endpoints = get('endpoints', 'kubernetes', 'default')['subsets']
    require(len(endpoints) == 1 and len(endpoints[0]['addresses']) == 1, 'Ambiguous API endpoint')
    address = str(ipaddress.ip_address(endpoints[0]['addresses'][0]['ip']))
    service = get('service', 'kubernetes', 'default')
    service_address = str(ipaddress.ip_address(service['spec']['clusterIP']))
    require(':' not in address and ':' not in service_address, 'IPv6 API fixture is not qualified')
    port = endpoints[0]['ports'][0]['port']
    require(port in (443, 6443), 'Unexpected API port')
    return {'API_CIDR': address + '/32', 'API_SERVICE_CIDR': service_address + '/32', 'API_PORT': port}


def operator_permissions(cluster):
    subject = 'system:serviceaccount:' + cluster.namespace + ':proof-operator'
    identity = ['--as=' + subject, '--as-group=system:serviceaccounts',
                '--as-group=system:serviceaccounts:' + cluster.namespace, '--as-group=system:authenticated']
    for resource_name, verb, namespace, allowed in [
            ('alertmanagers.monitoring.coreos.com', 'list', cluster.namespace, True),
            ('prometheuses.monitoring.coreos.com', 'list', cluster.namespace, False),
            ('prometheusagents.monitoring.coreos.com', 'list', cluster.namespace, False),
            ('thanosrulers.monitoring.coreos.com', 'list', cluster.namespace, False),
            ('secrets', 'get', 'cloudlab-observability', False)]:
        code, output, _ = command(['kubectl', '--request-timeout=30s', *identity, 'auth', 'can-i',
            verb, resource_name, '-n', namespace], allow_failure=True)
        require((code == 0 and output.strip() == b'yes') if allowed else
                (code == 1 and output.strip() == b'no'), 'Fixture Operator authority differs from reviewed scope')
    cluster.receipt.phase('operator-authority-qualified')


def authorization_context(cluster, ignored=('fixture-readers',)):
    namespace = cluster.current('Namespace', cluster.namespace)
    pods = {name: get('Pod', name, cluster.namespace)
            for name in ('client', 'unauthorized', 'receiver', 'alertmanager-primary-0')}
    for name, pod in pods.items():
        require(pod and pod['metadata']['uid'] == cluster.row('Pod', name, cluster.namespace)['uid'],
                'Authorization fixture Pod replaced')
        pod_enrolled(pod)
        require(all(row.get('restartCount') == 0 and row.get('state', {}).get('running')
                    for row in pod.get('status', {}).get('containerStatuses', [])), 'Authorization fixture process changed')
    approved, denied = pods['client'], pods['unauthorized']
    require(approved['spec']['nodeName'] == denied['spec']['nodeName']
            and approved['metadata']['labels'] == denied['metadata']['labels']
            and approved['spec']['serviceAccountName'] == 'proof-client'
            and denied['spec']['serviceAccountName'] == 'default'
            and approved['spec'].get('automountServiceAccountToken') is False
            and denied['spec'].get('automountServiceAccountToken') is False,
            'Authorization clients do not share the qualified network path')
    peers = get('PeerAuthentication', namespace='istio-system')['items']
    strict_root_policy(peers)
    other = get('AuthorizationPolicy', namespace='istio-system')['items'] + [
        row for row in get('AuthorizationPolicy', namespace=cluster.namespace)['items']
        if row['metadata']['name'] not in ignored]
    def policies(rows):
        return sorted([{'name': row['metadata']['name'], 'namespace': row['metadata']['namespace'],
                        'uid': row['metadata']['uid'], 'spec': row.get('spec', {})} for row in rows],
                      key=lambda row: (row['namespace'], row['name']))
    context = {'namespaceUID': namespace['metadata']['uid'],
        'pods': {name: {'uid': pod['metadata']['uid'], 'node': pod['spec']['nodeName'],
                       'labels': pod['metadata'].get('labels', {}), 'serviceAccount': pod['spec'].get('serviceAccountName'),
                       'automount': pod['spec'].get('automountServiceAccountToken'),
                       'ephemeralContainers': pod['spec'].get('ephemeralContainers', []),
                       'addresses': pod['status'].get('podIPs', []),
                       'processes': [(row['name'], row['containerID'], row['state']['running']['startedAt'])
                                     for row in pod['status']['containerStatuses']]}
                 for name, pod in pods.items()},
        'networkPolicies': policies(get('NetworkPolicy', namespace=cluster.namespace)['items']),
        'otherAuthorization': policies(other),
        'peerPolicies': policies(peers + get('PeerAuthentication', namespace=cluster.namespace)['items']),
        'services': {row['metadata']['name']: {'uid': row['metadata']['uid'], 'binding': service_binding(row)}
                     for row in get('Service', namespace=cluster.namespace)['items']}}
    return digest(canonical(context))


def principal_proof(cluster, policy):
    namespace = cluster.namespace
    urls = ['http://receiver:8080/events', 'http://alertmanager-primary-0.alertmanager-operated:9093/api/v2/status']
    baseline = authorization_context(cluster)
    for url in urls:
        request(namespace, url)
        request(namespace, url, client='unauthorized')
    created = cluster.create(policy)
    restricted = copy.deepcopy(policy['spec'])
    require(created['spec'] == restricted, 'Authorization policy changed during admission')
    policy_uid = created['metadata']['uid']

    def stable(expected):
        current = cluster.current('AuthorizationPolicy', 'fixture-readers', namespace)
        require(current['metadata']['uid'] == policy_uid and current['spec'] == expected
                and authorization_context(cluster) == baseline, 'Authorization proof environment changed')

    def restricted_check():
        stable(restricted)
        for url in urls:
            request(namespace, url)
            wait('unauthorized principal blocked by restricted policy', lambda url=url:
                 request(namespace, url, client='unauthorized', expected_denied=True).get('denied'))
            request(namespace, url)
        stable(restricted)

    restricted_check()
    path = '/spec/rules/0/from/0/source/principals'
    original = restricted['rules'][0]['from'][0]['source']['principals']
    expanded = copy.deepcopy(restricted)
    expanded['rules'][0]['from'][0]['source']['principals'] = original + ['cluster.local/ns/' + namespace + '/sa/default']
    cluster.patch('AuthorizationPolicy', 'fixture-readers', [
        {'op': 'test', 'path': '/spec', 'value': restricted},
        {'op': 'replace', 'path': path, 'value': expanded['rules'][0]['from'][0]['source']['principals']}], namespace)
    try:
        stable(expanded)
        for url in urls:
            request(namespace, url)
            # The positive control is mandatory; a setup/DNS failure never proves authorization.
            wait('temporarily allowed principal succeeds', lambda url=url: not request(
                namespace, url, client='unauthorized', expected_denied=True).get('denied'))
    finally:
        cluster.patch('AuthorizationPolicy', 'fixture-readers', [
            {'op': 'test', 'path': '/spec', 'value': expanded},
            {'op': 'replace', 'path': path, 'value': original}], namespace)
    restricted_check()
    cluster.receipt.phase('principal-authorization-qualified', principalPolicyUID=policy_uid,
                          principalContextHash=baseline, principalDifferential=True)


def readiness_window(pod):
    container = next(row for row in pod['spec']['containers'] if row['name'] == 'alertmanager')
    probe = container.get('readinessProbe', {})
    require(probe.get('httpGet', {}).get('path') == '/-/ready', 'Unknown native readiness probe')
    period, failures, timeout = (probe.get('periodSeconds', 10), probe.get('failureThreshold', 3),
                                 probe.get('timeoutSeconds', 1))
    require(all(type(value) is int and value > 0 for value in (period, failures, timeout)),
            'Invalid native readiness failure window')
    window = period * failures + timeout + 2
    require(window <= 300, 'Native readiness failure window exceeds fixture bound')
    return window


def pod_profile(spec):
    def containers(rows):
        return [{'name': row.get('name'), 'image': row.get('image'), 'command': row.get('command') or [],
                 'args': row.get('args') or [], 'ports': row.get('ports') or []} for row in rows]
    return copy.deepcopy({'containers': containers(spec.get('containers', [])), 'initContainers': containers(spec.get('initContainers', [])),
            'serviceAccountName': spec.get('serviceAccountName'),
            'automountServiceAccountToken': spec.get('automountServiceAccountToken'),
            'hostNetwork': spec.get('hostNetwork', False), 'hostPID': spec.get('hostPID', False)})


def singleton_profile(zero, current, namespace):
    expected = copy.deepcopy(zero)
    old = [row for row in expected['containers'] if row['name'] == 'alertmanager']
    new = [row for row in current['containers'] if row['name'] == 'alertmanager']
    require(len(old) == len(new) == 1, 'Native singleton container set changed')
    zero_listen = '--cluster.listen-address=[$(POD_IP)]:9094'
    singleton_listen = '--cluster.listen-address='
    maintenance = '--data.maintenance-interval=5s'
    peer = '--cluster.peer=alertmanager-primary-0.alertmanager-operated:9094'
    previous, actual = old[0]['args'], new[0]['args']
    require([arg for arg in previous if arg.startswith('--cluster.listen-address')] == [zero_listen]
            and not any(arg.startswith('--cluster.peer=') for arg in previous)
            and [arg for arg in previous if arg.startswith('--data.maintenance-interval')] == [maintenance],
            'Zero-replica native argument lineage differs')
    require([arg for arg in actual if arg.startswith('--cluster.listen-address')] == [singleton_listen]
            and [arg for arg in actual if arg.startswith('--cluster.peer=')] == [peer]
            and [arg for arg in actual if arg.startswith('--data.maintenance-interval')] == [maintenance]
            and [arg for arg in actual if arg not in (singleton_listen, peer)] ==
                [arg for arg in previous if arg != zero_listen],
            'Native singleton arguments or namespace-local peer differ')
    require(re.fullmatch(PREFIX + r'[a-f0-9]{16}', namespace), 'Native singleton peer namespace is outside proof')
    old[0]['args'] = copy.deepcopy(actual)
    require(current == expected, 'Native singleton executable profile changed beyond approved replica arguments')
    return expected


def qualify_singleton_template(cluster, pod, controls):
    namespace = cluster.namespace
    evidence = cluster.receipt.value['evidence']
    zero = evidence['zeroNativeTemplate']
    statefulset = cluster.current('StatefulSet', 'alertmanager-primary', namespace)
    manager = cluster.current('Alertmanager', 'primary', namespace)
    service = cluster.current('Service', 'alertmanager-operated', namespace)
    metadata, spec, status = statefulset['metadata'], statefulset['spec'], statefulset.get('status', {})
    require(metadata['uid'] == zero['uid'] and manager['metadata']['uid'] == zero['alertmanagerUID']
            and service['metadata']['uid'] == zero['serviceUID'] and service['spec'].get('clusterIP') == 'None'
            and metadata.get('ownerReferences') and len(metadata['ownerReferences']) == 1
            and metadata['ownerReferences'][0].get('uid') == manager['metadata']['uid']
            and metadata['ownerReferences'][0].get('kind') == 'Alertmanager'
            and metadata['ownerReferences'][0].get('name') == 'primary'
            and metadata['ownerReferences'][0].get('controller') is True,
            'Native singleton template UID, owner or peer Service changed')
    require(spec.get('replicas') == 1 and manager['spec'].get('replicas') == 1
            and manager['spec'].get('forceEnableClusterMode', False) is False
            and manager['spec'].get('additionalArgs') == [{'name': 'data.maintenance-interval', 'value': '5s'}],
            'Native singleton desired replica or maintenance settings changed')
    if status.get('observedGeneration') != metadata['generation'] or status.get('currentReplicas') != 1 or status.get('replicas') != 1:
        return None
    require(pod['metadata'].get('namespace') == namespace and pod['metadata'].get('name') == 'alertmanager-primary-0'
            and len(pod['metadata'].get('ownerReferences', [])) == 1
            and pod['metadata']['ownerReferences'][0].get('kind') == 'StatefulSet'
            and pod['metadata']['ownerReferences'][0].get('uid') == metadata['uid']
            and pod['metadata']['ownerReferences'][0].get('name') == metadata['name']
            and pod['metadata']['ownerReferences'][0].get('controller') is True
            and all(source.get('dnsPolicy', 'ClusterFirst') == 'ClusterFirst' and not source.get('dnsConfig')
                    for source in (pod['spec'], spec['template']['spec'])),
            'Native singleton Pod owner or namespace DNS binding changed')
    cluster.owned(pod)
    require(cluster.row('Pod', pod['metadata']['name'], namespace)['uid'] == pod['metadata']['uid'],
            'Native singleton Pod UID is not receipted')
    require(all(pod['metadata']['labels'].get(key) == value for key, value in service['spec'].get('selector', {}).items())
            and service['spec'].get('selector'), 'Native peer Service does not select this singleton')
    actual = pod_profile(spec['template']['spec'])
    expected = singleton_profile(evidence['zeroNativePodProfile'], actual, namespace)
    require(pod_profile(pod['spec']) == expected, 'Native singleton Pod differs from current admitted template')
    require(pod_dry_run(spec['template'], namespace, 'singleton-native-admission') == controls,
            'Native singleton security or image changed after zero admission')
    identity = source_identity(pod)
    current_pod = get('Pod', pod['metadata']['name'], namespace)
    source_unchanged(current_pod, identity)
    require(pod_profile(current_pod['spec']) == expected, 'Native singleton Pod profile changed during qualification')
    latest = cluster.current('StatefulSet', metadata['name'], namespace)
    require(latest['metadata']['uid'] == metadata['uid'] and latest['metadata']['generation'] == metadata['generation']
            and latest['metadata'].get('ownerReferences') == metadata.get('ownerReferences')
            and latest['spec'].get('replicas') == 1 and latest.get('status', {}).get('observedGeneration') == metadata['generation']
            and latest['status'].get('currentReplicas') == 1 and latest['status'].get('replicas') == 1
            and pod_profile(latest['spec']['template']['spec']) == expected,
            'Native singleton template changed during qualification')
    cluster.receipt.phase('native-singleton-template-qualified', nativePodProfile=expected,
        singletonNativeTemplate={'uid': metadata['uid'], 'generation': metadata['generation'],
            'observedGeneration': status['observedGeneration'], 'replicas': 1, 'alertmanagerUID': manager['metadata']['uid'],
            'serviceUID': service['metadata']['uid']})
    return statefulset


def pod_processes(pod):
    statuses = pod.get('status', {}).get('containerStatuses', [])
    require(len(statuses) == len(pod['spec']['containers']) and all(
        row.get('restartCount') == 0 and row.get('state', {}).get('running') for row in statuses),
        'Fixture listener process is not stable')
    return {'uid': pod['metadata']['uid'], 'profile': pod_profile(pod['spec']),
            'processes': [(row['name'], row['containerID'], row['state']['running']['startedAt']) for row in statuses]}


def namespace_listener_profile(cluster):
    # Namespace DENY is safe only for this fully enumerated synthetic executable/port set.
    record_generated(cluster)
    cleanup_inventory(cluster)
    images = cluster.receipt.value['evidence']['fixtureImages']
    code = cluster.current('ConfigMap', 'proof-code', cluster.namespace)
    require(code.get('data') == {'proof.py': Path(__file__).read_text()}, 'Fixture executable ConfigMap changed')
    pods = get('Pod', namespace=cluster.namespace)['items']
    categories, listeners = [], {}
    ambient = {15001, 15006, 15008, 15053}
    shell = "awk 'FNR>1 && $4==\"0A\" {split($2,address,\":\"); print address[2]}' /proc/net/tcp /proc/net/tcp6"
    python = ("import json,pathlib; print(json.dumps(sorted({int(row.split()[1].rsplit(':',1)[1],16) "
              "for name in ('tcp','tcp6') for row in pathlib.Path('/proc/net/'+name).read_text().splitlines()[1:] "
              "if row.split()[3]=='0A'})))")
    source_owner = r'''set -eu
test "$(readlink /proc/1/exe)" = /bin/alertmanager
listeners=$(awk 'FNR>1 && $4=="0A" && $2 ~ /:2385$/ {print $10}' /proc/net/tcp /proc/net/tcp6)
test -n "$listeners"
for inode in $listeners; do found=no; for descriptor in /proc/1/fd/*; do target=$(readlink "$descriptor" || true); if test "$target" = "socket:[$inode]"; then found=yes; fi; done; test "$found" = yes; done
printf 'native-owner\n'
'''
    for pod in pods:
        cluster.owned(pod)
        metadata, spec = pod['metadata'], pod['spec']
        rows = [row for row in cluster.receipt.value['resources'] if row['kind'] == 'Pod'
                and row.get('uid') == metadata['uid'] and row['name'] == metadata['name'] and row['namespace'] == cluster.namespace]
        require(len(rows) == 1 and not spec.get('hostNetwork') and not spec.get('hostPID')
                and not spec.get('ephemeralContainers'), 'Unrecorded fixture workload')
        name, role = metadata['name'], metadata['labels'].get('checkpoint-role')
        if name == 'alertmanager-primary-0':
            category, container, expected = 'source', 'alertmanager', ambient | {8080, 9093}
            profile = cluster.receipt.value['evidence']['nativePodProfile']
            require(role == 'manager', 'Unexpected native source role')
        elif role == 'operator' and name.startswith('proof-operator-'):
            category, container, expected = 'operator', 'operator', ambient | {8080}
            profile = cluster.row('Deployment', 'proof-operator', cluster.namespace)['podProfile']
        else:
            require(name in ('client', 'unauthorized', 'receiver', 'writer', 'validator'), 'Unknown fixture executable')
            category, container = name, name
            expected = ambient | ({8080} if name == 'receiver' else {9093} if name == 'validator' else set())
            profile = cluster.row('Pod', name, cluster.namespace)['podProfile']
            require(role == ('receiver' if name == 'receiver' else 'validator' if name == 'validator' else 'client'),
                    'Fixture executable role changed')
        require(pod_profile(spec) == profile and all(
            item['image'] in images.values() for item in spec['containers'] + spec.get('initContainers', [])),
            'Fixture executable image, command, argument or declared port changed')
        categories.append(category)
        terminal = pod.get('status', {}).get('phase') in ('Succeeded', 'Failed')
        if terminal:
            require(name == 'writer' and all(row.get('state', {}).get('terminated')
                    for row in pod['status'].get('containerStatuses', []))
                    and len(pod['status'].get('containerStatuses', [])) == len(spec['containers']),
                    'Unexpected terminal or active fixture workload')
            continue
        before = pod_processes(pod)
        if category in ('source', 'operator', 'validator'):
            raw = exec_pod(cluster.namespace, name, '/bin/sh', '-ec', shell, container=container,
                           limit=4096, timeout=20, reject_warnings=True).decode().splitlines()
            require(all(re.fullmatch(r'[a-fA-F0-9]{4}', row) for row in raw), 'Unknown native listener output')
            actual = {int(row, 16) for row in raw}
            if category in ('source', 'validator'):
                require(exec_pod(cluster.namespace, name, '/bin/sh', '-ec', source_owner, container=container,
                        limit=128, timeout=20, reject_warnings=True) == b'native-owner\n', 'Port9093 is not owned by native process1')
        else:
            actual = set(json.loads(exec_pod(cluster.namespace, name, 'python', '-c', python, container=container,
                         limit=4096, timeout=20, reject_warnings=True)))
        require(actual == expected and pod_processes(get('Pod', name, cluster.namespace)) == before,
                'Fixture active listeners or Pod process changed')
        listeners[name] = {'uid': metadata['uid'], 'ports': sorted(actual)}
    require(all(categories.count(name) == 1 for name in ('source', 'operator', 'client', 'unauthorized', 'receiver'))
            and len(categories) == len(set(categories)), 'Fixture workload set differs from exclusive namespace profile')
    source = next(pod for pod in pods if pod['metadata']['name'] == 'alertmanager-primary-0')
    services = get('Service', namespace=cluster.namespace)['items']
    require({service['metadata']['name'] for service in services} == {'receiver', 'alertmanager-operated'},
            'Fixture Service inventory differs from reviewed scope')
    source_ports = {port['name']: port['containerPort'] for container in source['spec']['containers']
                    for port in container.get('ports', []) if port.get('protocol', 'TCP') == 'TCP' and 'name' in port}
    for service in services:
        cluster.owned(service, cluster.row('Service', service['metadata']['name'], cluster.namespace))
        require(service['metadata']['name'] in ('receiver', 'alertmanager-operated'), 'Unknown fixture Service')
        binding = service_binding(service)
        if service['metadata']['name'] == 'receiver':
            require(binding['selector'] == {'checkpoint-role': 'receiver'}
                    and binding['ports'] == [{'name': 'http', 'port': 8080, 'protocol': 'TCP', 'targetPort': 8080, 'appProtocol': None}],
                    'Receiver Service scope changed')
        else:
            require(all(source['metadata']['labels'].get(key) == value for key, value in binding['selector'].items())
                    and all(pod['metadata']['name'] == source['metadata']['name'] for pod in pods
                        if all(pod['metadata']['labels'].get(key) == value for key, value in binding['selector'].items()))
                    and any(port['port'] == 9093 and port['protocol'] == 'TCP'
                            and (source_ports.get(port['targetPort']) if isinstance(port['targetPort'], str)
                                 else port['targetPort']) == 9093 for port in binding['ports']),
                    'Native Service does not exclusively select the receipted source9093')
    cluster.receipt.phase('exclusive-namespace-listeners', listenerProfileHash=digest(canonical(listeners)))
    return listeners


def source_deny_policy(cluster):
    policy = document('AuthorizationPolicy', 'source-quiescence', cluster, spec={
        'action': 'DENY', 'rules': [{'to': [{'operation': {'ports': ['9093']}}]}]})
    policy['apiVersion'] = 'security.istio.io/v1'
    return policy


def require_source_denied(cluster):
    cluster.current('Namespace', cluster.namespace)
    current = cluster.current('AuthorizationPolicy', 'source-quiescence', cluster.namespace)
    require(current['spec'] == source_deny_policy(cluster)['spec'], 'Held source DENY scope changed')
    pod = get('Pod', 'alertmanager-primary-0', cluster.namespace)
    cluster.owned(pod)
    require(pod['kind'] == 'Pod' and pod['metadata'].get('labels', {}).get('checkpoint-role') == 'manager'
            and not pod.get('spec', {}).get('ephemeralContainers'),
            'Held source DENY no longer selects the native source')


def quiesce_source(cluster, identity, maintenance_text):
    namespace = cluster.namespace
    namespace_listener_profile(cluster)
    policy = source_deny_policy(cluster)
    cluster.create(policy, dry_run=True)
    source = cluster.current('Pod', 'alertmanager-primary-0', namespace)
    source_unchanged(source, identity)
    window = readiness_window(source)
    baseline = authorization_context(cluster, ignored=('source-quiescence',))
    access = copy.deepcopy(cluster.current('NetworkPolicy', 'source-access', namespace)['spec']['ingress'])
    url = 'http://alertmanager-primary-0.alertmanager-operated:9093/api/v2/status'
    with held_source_connection(namespace) as (revoked, baseline_time):
        held_time_budget(baseline_time, 25)
        created = cluster.create(policy)
        require(created['spec'] == policy['spec'], 'Source DENY policy changed during admission')
        held_time_budget(baseline_time, 25)
        def fresh_denied():
            held_time_budget(baseline_time, 25)
            result = request(namespace, url, expected_denied=True).get('denied')
            held_time_budget(baseline_time, 25)
            return result
        while not fresh_denied():
            time.sleep(min(1, held_time_budget(baseline_time, 25)))
        revoked()
    policy_uid = created['metadata']['uid']
    def verify_policy():
        current = cluster.current('AuthorizationPolicy', 'source-quiescence', namespace)
        require(current['metadata']['uid'] == policy_uid and current['spec'] == policy['spec'],
                'Source DENY policy identity or scope changed')
    wait('fresh source connection denied by native policy', lambda: request(namespace, url, expected_denied=True).get('denied'))
    start = time.monotonic()
    while True:
        verify_policy()
        pod = pod_ready('alertmanager-primary-0', namespace)
        require(pod is not None, 'Source readiness lost under DENY policy')
        source_unchanged(pod, identity)
        require(json.loads(source_get(cluster, '/api/v2/status'))['config']['original'] == maintenance_text,
                'Source maintenance configuration changed under DENY policy')
        if time.monotonic() - start > window:
            break
        time.sleep(1)
    require(authorization_context(cluster, ignored=('source-quiescence',)) == baseline,
            'Source isolation proof environment changed')
    cluster.patch('NetworkPolicy', 'source-access', [{'op': 'replace', 'path': '/spec/ingress', 'value': []}], namespace)
    require(request(namespace, url, expected_denied=True).get('denied'), 'Isolated source accepts ordinary network clients')
    verify_policy()
    source_unchanged(get('Pod', 'alertmanager-primary-0', namespace), identity)
    require(pod_ready('alertmanager-primary-0', namespace) is not None
            and json.loads(source_get(cluster, '/api/v2/status'))['config']['original'] == maintenance_text,
            'Source health or maintenance configuration lost after network closure')
    cluster.receipt.phase('source-quiesced', quiescencePolicyUID=policy_uid, readinessWindowSeconds=window,
                          heldConnectionRevoked=True, quiescenceContextHash=baseline, heldBaselineMonotonic=baseline_time)
    return access


def document(kind, name, cluster, **values):
    return {'apiVersion': 'v1', 'kind': kind, 'metadata': {'name': name, 'namespace': cluster.namespace,
            'labels': labels(cluster.operation)}} | values


def create_service_accounts(cluster, manifests):
    accounts = [item for item in manifests if item['kind'] == 'ServiceAccount']
    expected = {'proof-operator': True, 'proof-client': False, 'proof-alertmanager': False}

    def validate(item):
        metadata = item['metadata']
        require(item.get('apiVersion') == 'v1' and item.get('kind') == 'ServiceAccount'
                and set(item) == {'apiVersion', 'kind', 'metadata', 'automountServiceAccountToken'}
                and metadata.get('name') in expected and metadata.get('namespace') == cluster.namespace
                and set(metadata) <= {'name', 'namespace', 'labels', 'uid', 'resourceVersion', 'creationTimestamp', 'managedFields'}
                and metadata.get('labels') == labels(cluster.operation)
                and not metadata.get('annotations') and not metadata.get('ownerReferences')
                and item['automountServiceAccountToken'] is expected[metadata['name']],
                'Prerequisite ServiceAccount differs from reviewed declaration')

    require(len(accounts) == len(expected) and {item['metadata']['name'] for item in accounts} == set(expected),
            'Prerequisite ServiceAccount set differs from reviewed declaration')
    for item in accounts:
        validate(item)
    # Admission needs real identities; these accounts grant no RBAC or workload by themselves.
    for item in accounts:
        validate(cluster.create(item, dry_run=True))
    for item in accounts:
        validate(cluster.create(item))


def delete_options(current):
    metadata = current['metadata']
    return {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Foreground',
            'preconditions': {'uid': metadata['uid'], 'resourceVersion': metadata['resourceVersion']}}


def certificate_hash(value):
    require(isinstance(value, str) and 0 < len(value) <= 65536, 'Invalid public root certificate bundle')
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----', value)
    require(blocks and not re.sub(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----', '', value).strip(),
            'Unexpected public root certificate content')
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=value)
    return digest(canonical(sorted(ssl.PEM_cert_to_DER_cert(block).hex() for block in blocks)))


def housekeeping_roots():
    # Select only public CA data, never the kubeconfig object or its credential fields.
    encoded = kubectl('config', 'view', '--raw', '--minify', '-o',
                      'jsonpath={.clusters[0].cluster.certificate-authority-data}', limit=131072).strip()
    require(encoded, 'Selected kubeconfig must contain public cluster CA data')
    kubernetes = certificate_hash(base64.b64decode(encoded, validate=True).decode('ascii'))
    istio = get('ConfigMap', 'istio-ca-root-cert', 'istio-system')
    require(istio and set(istio.get('data', {})) == {'root-cert.pem'} and not istio.get('binaryData'),
            'Trusted Istio public root unavailable')
    crl = get('ConfigMap', 'istio-ca-crl', 'istio-system')
    require(crl and set(crl.get('data', {})) == {'ca-crl.pem'} and not crl.get('binaryData'),
            'Trusted Istio public revocation list unavailable')
    return {'kube-root-ca.crt': kubernetes, 'istio-ca-root-cert': certificate_hash(istio['data']['root-cert.pem']),
            'istio-ca-crl': revocation_hash(crl['data']['ca-crl.pem'])}


def revocation_hash(value):
    require(isinstance(value, str) and len(value) <= 65536, 'Invalid public revocation list')
    return digest(value.encode())


def housekeeping_identity(cluster, current, roots):
    metadata, kind = current['metadata'], current['kind']
    name = metadata['name']
    ns_row = cluster.row('Namespace', cluster.namespace)
    namespace = cluster.current('Namespace', cluster.namespace)
    require(ns_row.get('createdAt') and namespace['metadata']['creationTimestamp'] == ns_row['createdAt'],
            'Housekeeping namespace creation boundary unavailable or changed')
    require(current.get('apiVersion') == 'v1' and metadata.get('namespace') == cluster.namespace
            and metadata.get('uid') and metadata.get('resourceVersion')
            and metadata.get('creationTimestamp')
            and datetime.fromisoformat(metadata['creationTimestamp'].replace('Z', '+00:00')) >=
                datetime.fromisoformat(ns_row['createdAt'].replace('Z', '+00:00'))
            and set(metadata) <= {'name', 'namespace', 'uid', 'resourceVersion', 'creationTimestamp',
                                  'managedFields', 'labels', 'annotations'}
            and not metadata.get('ownerReferences'), 'Foreign housekeeping metadata')
    writers = {row['manager'] for row in metadata.get('managedFields', [])}
    if kind == 'ServiceAccount' and name == 'default':
        require(set(current) <= {'apiVersion', 'kind', 'metadata'}
                and not metadata.get('labels') and not metadata.get('annotations')
                and writers <= {'kube-controller-manager', 'k3s'}, 'Foreign default ServiceAccount shape')
        content = digest(canonical({'kind': kind, 'name': name}))
    else:
        require(kind == 'ConfigMap' and name in roots
                and set(current) <= {'apiVersion', 'kind', 'metadata', 'data'}, 'Foreign root ConfigMap shape')
        if name == 'kube-root-ca.crt':
            managers, key = {'kube-controller-manager', 'k3s'}, 'ca.crt'
            require(not metadata.get('labels') and set(metadata.get('annotations', {})) <= {'kubernetes.io/description'},
                    'Foreign Kubernetes root metadata')
        else:
            managers = {'pilot-discovery', 'istiod'}
            key = 'ca-crl.pem' if name == 'istio-ca-crl' else 'root-cert.pem'
            require(metadata.get('labels') == {'istio.io/config': 'true'} and not metadata.get('annotations'),
                    'Foreign Istio root metadata')
        require(writers and writers <= managers and set(current.get('data', {})) == {key},
                'Foreign root ConfigMap provenance or schema')
        content = revocation_hash(current['data'][key]) if name == 'istio-ca-crl' else certificate_hash(current['data'][key])
        require(content == roots[name], 'Housekeeping CA differs from trusted public root')
    return {'kind': kind, 'name': name, 'uid': metadata['uid'], 'writers': sorted(writers),
            'createdAt': metadata['creationTimestamp'], 'contentHash': content,
            'metadataHash': digest(canonical({key: metadata.get(key) for key in ('labels', 'annotations')}))}


def record_housekeeping(cluster):
    known = cluster.receipt.value.setdefault('housekeeping', [])
    roots = housekeeping_roots()
    evidence = cluster.receipt.value['evidence']
    require(evidence.get('housekeepingRoots', roots) == roots, 'Trusted housekeeping roots changed during proof')
    evidence['housekeepingRoots'] = roots
    for kind, name in [('ServiceAccount', 'default'), ('ConfigMap', 'kube-root-ca.crt'),
                       ('ConfigMap', 'istio-ca-root-cert'), ('ConfigMap', 'istio-ca-crl')]:
        current = get(kind, name, cluster.namespace, managed_fields=True)
        if current is None:
            continue
        observed = housekeeping_identity(cluster, current, roots)
        prior = next((r for r in known if r['kind'] == kind and r['name'] == name), None)
        if prior:
            require(prior == observed, 'Housekeeping resource replaced or changed')
        else:
            known.append(observed)
    cluster.receipt.save()


def record_events(cluster):
    known = {row['uid'] for row in cluster.receipt.value['resources'] if row.get('uid')}
    known.update(v for k, v in cluster.receipt.value.get('evidence', {}).get('storage', {}).items()
                 if k in ('claim', 'pv', 'volumeUID'))
    records = cluster.receipt.value.setdefault('events', [])
    for current in get('events', namespace=cluster.namespace)['items']:
        metadata = current['metadata']
        reference = current.get('regarding', current.get('involvedObject', {})).get('uid')
        reporter = current.get('reportingController') or current.get('reportingComponent') or current.get('source', {}).get('component', '')
        require(reference in known and re.fullmatch(
            r'(default-scheduler|kubelet|statefulset-controller|deployment-controller|replicaset-controller|'
            r'attachdetach-controller|persistentvolume-controller|alertmanager-controller|'
            r'monitoring[.]coreos[.]com/alertmanager-controller|driver[.]longhorn[.]io_[A-Za-z0-9._-]+|'
            r'external-(provisioner|attacher)([./_-][A-Za-z0-9./_-]+)?)', reporter),
            'Unknown or unrelated proof Event')
        row = {'uid': metadata['uid'], 'name': metadata['name'], 'reference': reference, 'reporter': reporter}
        prior = next((r for r in records if r['uid'] == metadata['uid']), None)
        require(prior is None or prior == row, 'Event identity changed')
        if prior is None:
            records.append(row)
    cluster.receipt.save()


def namespace_inventory(namespace):
    groups = json.loads(kubectl('get', '--raw', '/apis'))['groups']
    versions = ['/api/v1'] + sorted({'/apis/' + version['groupVersion']
                                   for group in groups for version in group['versions']})
    found = {}
    for version in versions:
        discovery = json.loads(kubectl('get', '--raw', version))
        for item in discovery['resources']:
            # Projected metrics/review APIs have no stored objects or namespace-deletion semantics.
            if not item.get('namespaced') or not {'list', 'delete'} <= set(item.get('verbs', [])) or '/' in item['name']:
                continue
            path = version + '/namespaces/' + namespace + '/' + item['name']
            rows = json.loads(kubectl('get', '--raw', path + '?limit=100'))
            require(not rows.get('metadata', {}).get('continue'), 'Incomplete final namespace discovery')
            for row in rows['items']:
                require(row.get('kind', item['kind']) == item['kind'], 'Discovered resource kind changed')
                row.setdefault('kind', item['kind'])
                row.setdefault('apiVersion', discovery['groupVersion'])
                found[row['metadata']['uid']] = row
    return list(found.values())


def namespace_delete_gate(cluster, inventory, allow_owned=False, retiring=False):
    owned = {row['uid']: row for row in cluster.receipt.value['resources'] if row.get('uid')}
    housekeeping = {row['uid']: row for row in cluster.receipt.value.get('housekeeping', [])}
    events = {row['uid']: row for row in cluster.receipt.value.get('events', [])}
    for current in inventory:
        metadata, kind = current['metadata'], current['kind']
        if allow_owned and metadata['uid'] in owned:
            row = owned[metadata['uid']]
            require(kind == row['kind'] and metadata['name'] == row['name'] and metadata.get('namespace') == cluster.namespace
                    and metadata.get('labels', {}).get(LABEL) == cluster.operation
                    and metadata['labels'].get('cloudlab.io/owner') == OWNER, 'Owned cleanup object changed')
            if row.get('observed'):
                if row.get('derivedEndpoint'):
                    if retiring:
                        require(cluster.receipt.value.get('cleanup', {}).get('started')
                                and not metadata.get('ownerReferences')
                                and metadata['labels'].get('endpoints.kubernetes.io/managed-by') == 'endpoint-controller'
                                and {value['manager'] for value in metadata.get('managedFields', [])} == set(row['writers'])
                                and set(endpoint_entries(current)) <= set(row['entries']),
                                'Retiring Endpoint identity or previously verified targets changed')
                    else:
                        endpoint_binding(cluster, current, row)
                else:
                    require([owner['uid'] for owner in metadata.get('ownerReferences', [])] == row['owners'],
                            'Native cleanup owner chain changed')
        elif metadata['uid'] in housekeeping:
            row = housekeeping[metadata['uid']]
            require(housekeeping_identity(cluster, current, cluster.receipt.value['evidence']['housekeepingRoots']) == row,
                    'Housekeeping provenance, shape or content changed')
        elif metadata['uid'] in events:
            row = events[metadata['uid']]
            require(kind == 'Event' and metadata['name'] == row['name']
                    and current.get('regarding', current.get('involvedObject', {})).get('uid') == row['reference']
                    and (current.get('reportingController') or current.get('reportingComponent') or current.get('source', {}).get('component', '')) == row['reporter'],
                    'Event provenance changed')
        else:
            raise RuntimeError('Unknown resource blocks final namespace deletion')
    cluster.current('Namespace', cluster.namespace)


def inspector_identity(pod):
    require(pod is not None, 'Replica inspector is absent')
    rows = [row for row in pod.get('status', {}).get('containerStatuses', []) if row['name'] == 'longhorn-manager']
    require(len(rows) == 1 and rows[0].get('state', {}).get('running'), 'Replica inspector is not running')
    return {'uid': pod['metadata']['uid'], 'node': pod['spec']['nodeName'], 'containerID': rows[0]['containerID'],
            'startedAt': rows[0]['state']['running']['startedAt'], 'restarts': rows[0]['restartCount']}


def directory_state(manager, disk, parent, path):
    script = ('set -eu; for directory in "$1" "$2"; do test -d "$directory"; '
              'test ! -L "$directory"; test -r "$directory"; test -x "$directory"; '
              'stat -c %d:%i "$directory"; done; '
              'if test -e "$3" || test -L "$3"; then test -d "$3"; test ! -L "$3"; '
              'stat -c %d "$3"; printf "present\\n"; else printf "%s\\n%s\\n" - absent; fi')
    code, raw, _ = command(['kubectl', '--request-timeout=30s', 'exec', '-n', 'longhorn-system',
        manager, '-c', 'longhorn-manager', '--', 'sh', '-ec', script, '_', disk, parent, path], allow_failure=True)
    require(code == 0, 'Replica parent filesystem is unavailable or inaccessible')
    lines = raw.decode().splitlines()
    require(len(lines) == 4 and all(re.fullmatch(r'[0-9]+:[0-9]+', value) for value in lines[:2])
            and lines[3] in ('present', 'absent'), 'Invalid replica filesystem evidence')
    if lines[3] == 'present':
        require(lines[2].isdigit() and lines[0].split(':')[0] == lines[1].split(':')[0] == lines[2],
                'Replica parent or target crosses an unexpected device')
    else:
        require(lines[2] == '-', 'Invalid replica absence evidence')
    return {'disk': lines[0], 'parent': lines[1], 'present': lines[3] == 'present'}


def backing_absent(row):
    current = get('pod', row['manager'], 'longhorn-system')
    require(inspector_identity(current) == row['inspector'], 'Replica inspector changed during cleanup')
    state = directory_state(row['manager'], row['disk'], row['parent'], row['path'])
    require(state['disk'] == row['context']['disk'] and state['parent'] == row['context']['parent'],
            'Replica parent filesystem identity changed')
    return not state['present']


def replica_directories(identity):
    result = []
    for replica in get('replicas.longhorn.io', namespace='longhorn-system')['items']:
        spec = replica['spec']
        if spec.get('volumeName') != identity['volume']:
            continue
        directory, disk = spec.get('dataDirectoryName'), spec.get('diskPath')
        if not directory or disk != '/var/lib/longhorn' or not re.fullmatch(r'[A-Za-z0-9_-]+', directory):
            continue
        managers = [p for p in get('pods', namespace='longhorn-system')['items']
                    if p['metadata'].get('labels', {}).get('app') == 'longhorn-manager'
                    and p['spec'].get('nodeName') == spec['nodeID']]
        if len(managers) != 1:
            continue
        path = disk + '/replicas/' + directory
        manager = managers[0]
        parent = disk + '/replicas'
        context = directory_state(manager['metadata']['name'], disk, parent, path)
        if context['present']:
            result.append({'node': spec['nodeID'], 'manager': manager['metadata']['name'],
                           'managerUID': manager['metadata']['uid'], 'path': path,
                           'replicaUID': replica['metadata']['uid'], 'disk': disk, 'parent': parent,
                           'context': context, 'inspector': inspector_identity(manager)})
    return result


def cleanup_inventory(cluster):
    record_housekeeping(cluster)
    record_events(cluster)
    inventory = namespace_inventory(cluster.namespace)
    namespace_delete_gate(cluster, inventory, allow_owned=True,
                          retiring=cluster.receipt.value.get('cleanup', {}).get('started', False))


def storage_deletion_identities(identity):
    return ({'kind': 'PersistentVolume', 'name': identity['pvName'], 'namespace': None, 'uid': identity['pv']},
            {'kind': 'Volume', 'name': identity['volume'], 'namespace': 'longhorn-system', 'uid': identity['volumeUID']})


def complete_replica_evidence(rows):
    require(isinstance(rows, list) and len(rows) == 2 and len({row.get('node') for row in rows}) == 2
            and len({row.get('replicaUID') for row in rows}) == 2, 'Two independent replica records are required')
    for row in rows:
        inspector, context = row.get('inspector', {}), row.get('context', {})
        require(row.get('node') and row.get('manager') and row.get('replicaUID')
                and row.get('managerUID') == inspector.get('uid') and inspector.get('uid')
                and isinstance(row['manager'], str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', row['manager'])
                and inspector.get('node') == row['node'] and inspector.get('containerID') and inspector.get('startedAt')
                and isinstance(inspector.get('restarts'), int) and context.get('present') is True
                and all(re.fullmatch(r'[0-9]+:[0-9]+', context.get(key, '')) for key in ('disk', 'parent'))
                and context['disk'].split(':')[0] == context['parent'].split(':')[0]
                and row.get('disk') == '/var/lib/longhorn' and row.get('parent') == row['disk'] + '/replicas'
                and isinstance(row.get('path'), str) and re.fullmatch(re.escape(row['parent']) + r'/[A-Za-z0-9_-]+', row['path']),
                'Incomplete or unsafe stable replica context')


def verify_cleanup_pv(cluster, pv, identity):
    claims = [row for row in cluster.receipt.value['resources'] if row['kind'] == 'PersistentVolumeClaim'
              and row.get('uid') == identity['claim'] and row['namespace'] == cluster.namespace]
    require(pv and pv['metadata']['uid'] == identity['pv']
            and pv['metadata']['name'] == identity['pvName'] and len(claims) == 1
            and pv['spec']['claimRef']['uid'] == identity['claim']
            and pv['spec']['claimRef']['name'] == claims[0]['name']
            and pv['spec']['claimRef']['namespace'] == cluster.namespace
            and pv['spec']['csi']['volumeHandle'] == identity['handle']
            and pv['spec']['csi']['driver'] == 'driver.longhorn.io'
            and pv['spec']['storageClassName'] == 'cloudlab-telemetry'
            and pv['spec']['persistentVolumeReclaimPolicy'] == 'Retain'
            and pv['status']['phase'] == 'Released', 'Synthetic storage cleanup identity changed')


def paired_storage_intent(cluster, pv, volume, identity):
    receipt = cluster.receipt
    pv_id, volume_id = storage_deletion_identities(identity)
    require(bool(receipt.deletion(pv_id)) == bool(receipt.deletion(volume_id)),
            'Unpaired historical storage intent cannot be repaired retrospectively')
    verify_cleanup_pv(cluster, pv, identity)
    claim = next(row for row in receipt.value['resources'] if row['kind'] == 'PersistentVolumeClaim'
                 and row.get('uid') == identity['claim'])
    require(get('PersistentVolumeClaim', claim['name'], cluster.namespace) is None,
            'Live claim blocks backing storage deletion')
    require(volume and volume['metadata']['name'] == identity['volume']
            and volume['metadata']['uid'] == identity['volumeUID']
            and volume['metadata'].get('namespace') == 'longhorn-system', 'Synthetic volume replaced')
    no_restore(volume)
    kubernetes = volume.get('status', {}).get('kubernetesStatus', {})
    require(kubernetes.get('pvName') == identity['pvName']
            and identity['handle'] == identity['volume'] == identity['pvName']
            and volume['spec'].get('numberOfReplicas') == 2
            and kubernetes.get('pvStatus') == 'Released'
            and kubernetes.get('pvcName') == claim['name'] and kubernetes.get('namespace') == cluster.namespace
            and kubernetes.get('lastPVCRefAt')
            and (not kubernetes.get('workloadsStatus') or kubernetes.get('lastPodRefAt'))
            and all(any(row['kind'] == workload.get('workloadType') and row['name'] == workload.get('workloadName')
                        and row['namespace'] == cluster.namespace and row.get('uid') for row in receipt.value['resources'])
                    for workload in kubernetes.get('workloadsStatus', [])), 'Longhorn released claim linkage changed')
    # Both intents must survive a native Longhorn controller PV cascade.
    old = copy.deepcopy(receipt.value)
    scope_hash = digest(canonical(identity))
    try:
        for current in (pv, volume):
            key = object_identity(current)
            prior = receipt.deletion(key)
            require(prior is None or prior['scopeHash'] == scope_hash and not prior['complete'],
                    'Storage deletion scope changed or completed resource reappeared')
            require(prior is not None or not current['metadata'].get('deletionTimestamp'),
                    'Storage already deleting without accepted cleanup intent')
            if prior is None:
                prior = dict(key, scopeHash=scope_hash, complete=False)
                receipt.value.setdefault('deletions', []).append(prior)
            prior['resourceVersion'] = current['metadata']['resourceVersion']
        receipt.save()
    except BaseException:
        receipt.value = old
        raise


def cleanup_storage(cluster, identity):
    evidence, receipt = cluster.receipt.value['evidence'], cluster.receipt
    require(evidence.get('storageFresh') is True and evidence.get('storageBaseline'),
            'Unverified storage cannot become deletion scope')
    pv_id, volume_id = storage_deletion_identities(identity)
    scope_hash = digest(canonical(identity))
    for item in (pv_id, volume_id):
        prior = receipt.deletion(item)
        require(prior is None or prior['scopeHash'] == scope_hash, 'Storage deletion intent scope changed')
    require(bool(receipt.deletion(pv_id)) == bool(receipt.deletion(volume_id)),
            'Unpaired historical storage intent requires separate recovery')
    pv = get('pv', identity['pvName'])
    if pv:
        verify_cleanup_pv(cluster, pv, identity)
        require(receipt.deletion(pv_id) is not None or not pv['metadata'].get('deletionTimestamp'),
                'PV was already deleting without accepted cleanup intent')
    else:
        receipt.deleted(pv_id)
    volume = get('volumes.longhorn.io', identity['volume'], 'longhorn-system')
    if volume:
        require(volume['metadata']['uid'] == identity['volumeUID'], 'Synthetic volume replaced')
        require(pv is not None or receipt.deletion(pv_id) is not None
                and receipt.deletion(volume_id) is not None and volume['metadata'].get('deletionTimestamp'),
                'PV absent before protected native volume deletion')
        no_restore(volume)
        if receipt.deletion(volume_id) is None:
            require(not volume['metadata'].get('deletionTimestamp'), 'Volume was already deleting outside accepted cleanup')
            directories = replica_directories(identity)
            complete_replica_evidence(directories)
            receipt.phase('retention-verified', retainedPV=True, retainedLonghorn=True,
                          replicaDirectories=directories)
        require('replicaDirectories' in evidence, 'Pre-deletion replica evidence is missing')
        complete_replica_evidence(evidence['replicaDirectories'])
        cleanup_inventory(cluster)
        pv = get('pv', identity['pvName'])
        volume = get('volumes.longhorn.io', identity['volume'], 'longhorn-system')
        if pv is not None:
            paired_storage_intent(cluster, pv, volume, identity)
            request_delete(receipt, volume, scope_hash)
        else:
            require(receipt.deletion(pv_id) is not None and receipt.deletion(volume_id) is not None
                    and volume and volume['metadata']['uid'] == identity['volumeUID']
                    and volume['metadata'].get('deletionTimestamp'), 'Native cascade lost protected storage identity')
    else:
        receipt.deleted(volume_id)
        require('replicaDirectories' in evidence, 'Missing prior scoped replica evidence')
    wait('synthetic Longhorn volume deletion', lambda: deletion_finished(receipt, volume_id), timeout=240)
    wait('synthetic engines and replicas cascade', lambda: all(
        row['spec'].get('volumeName') != identity['volume']
        for kind in ('engines.longhorn.io', 'replicas.longhorn.io')
        for row in get(kind, namespace='longhorn-system')['items']), timeout=240)
    directories = evidence['replicaDirectories']
    complete_replica_evidence(directories)
    for row in directories:
        wait('synthetic backing directory removal', lambda row=row: backing_absent(row), timeout=180)
    current = get('pv', identity['pvName'])
    if current:
        verify_cleanup_pv(cluster, current, identity)
        cleanup_inventory(cluster)
        request_delete(receipt, current, scope_hash)
    else:
        receipt.deleted(pv_id)
    wait('synthetic PV removal', lambda: deletion_finished(receipt, pv_id))
    receipt.phase('storage-cleaned', backingFilesVerified=True, storageCleanupComplete=True)


def cleanup(cluster):
    namespace = cluster.namespace
    receipt = cluster.receipt
    ns_row = cluster.row('Namespace', namespace)
    ns_identity = {key: ns_row[key] for key in ('kind', 'name', 'namespace', 'uid')}
    current_namespace = get('Namespace', namespace)
    if current_namespace is None:
        finish_cleanup(cluster, ns_identity)
        return
    cluster.owned(current_namespace, ns_row)
    progress = receipt.value.setdefault('cleanup', {})
    if receipt.deletion(ns_identity):
        require(progress.get('finalizeReady'), 'Namespace deletion lacks completed scope checks')
        if not current_namespace['metadata'].get('deletionTimestamp'):
            record_housekeeping(cluster)
            record_events(cluster)
            namespace_delete_gate(cluster, namespace_inventory(namespace))
            cluster.delete('Namespace', namespace)
        wait('exact synthetic namespace deletion', lambda: deletion_finished(receipt, ns_identity))
        finish_cleanup(cluster, ns_identity)
        return
    if not progress.get('started'):
        record_generated(cluster, qualification=False)
        cleanup_inventory(cluster)
        progress['started'] = True
        receipt.save()
    cleanup_inventory(cluster)
    managers = [row for row in receipt.value['resources'] if row['kind'] == 'Alertmanager' and row.get('uid')]
    for manager in managers:
        cleanup_inventory(cluster)
        cluster.delete('Alertmanager', manager['name'], namespace)
        manager_identity = {key: manager[key] for key in ('kind', 'name', 'namespace', 'uid')}
        wait('synthetic Alertmanager deletion', lambda: deletion_finished(receipt, manager_identity))
        wait('synthetic native workload cascade', lambda: not get('statefulsets', namespace=namespace)['items']
             and not any(p['metadata'].get('labels', {}).get('alertmanager') == 'primary'
                         for p in get('pods', namespace=namespace)['items']), timeout=240)
    cleanup_inventory(cluster)
    for row in receipt.value['resources']:
        if row['kind'] == 'Pod' and not row.get('observed') and row.get('uid'):
            cluster.delete('Pod', row['name'], namespace)
            pod_identity = {key: row[key] for key in ('kind', 'name', 'namespace', 'uid')}
            wait('receipted Pod mount released', lambda item=pod_identity: deletion_finished(receipt, item))
    identity = receipt.value.get('evidence', {}).get('storage')
    if identity:
        require(receipt.value['evidence'].get('storageFresh') is True, 'Unverified backing data is retained')
        claims = [r for r in receipt.value['resources'] if r['kind'] == 'PersistentVolumeClaim' and r.get('uid')]
        require(len(claims) == 1, 'Ambiguous synthetic claim cleanup')
        claim_row = claims[0]
        claim_identity = {key: claim_row[key] for key in ('kind', 'name', 'namespace', 'uid')}
        claim = get('PersistentVolumeClaim', claim_row['name'], namespace)
        if claim is not None:
            cluster.owned(claim, claim_row)
            if receipt.deletion(claim_identity) is None:
                require(not claim['metadata'].get('deletionTimestamp')
                        and storage_identity(claim, healthy=False) == identity, 'Native workload removal did not retain state')
                receipt.phase('workload-retention-verified', retainedClaim=True)
            cleanup_inventory(cluster)
            cluster.delete('PersistentVolumeClaim', claim_row['name'], namespace)
        else:
            receipt.deleted(claim_identity)
        wait('synthetic PVC deletion', lambda: deletion_finished(receipt, claim_identity), timeout=240)
        def released():
            pv = get('pv', identity['pvName'])
            if pv is None:
                receipt.deleted(storage_deletion_identities(identity)[0])
                return True
            require(pv['metadata']['uid'] == identity['pv'], 'Released PV replaced')
            return pv['status']['phase'] == 'Released'
        wait('synthetic PV released', released)
        cleanup_storage(cluster, identity)
    # Driver-created resources have no implicit broad cleanup authority over descendants or peers.
    cleanup_inventory(cluster)
    for row in reversed(receipt.value['resources']):
        if row.get('observed') or row['kind'] in ('Namespace', 'Alertmanager', 'PersistentVolumeClaim', 'Pod') or not row.get('uid'):
            continue
        cluster.delete(row['kind'], row['name'], row['namespace'])
        resource_identity = {key: row[key] for key in ('kind', 'name', 'namespace', 'uid')}
        wait('receipted resource deletion', lambda item=resource_identity: deletion_finished(receipt, item))
    wait('fixture Pods finish', lambda: not get('pods', namespace=namespace)['items'])
    def cascaded():
        known = {row['uid'] for row in receipt.value['resources'] if row.get('uid')}
        remaining = False
        for row in receipt.value['resources']:
            if not row.get('observed'):
                continue
            current = get(row['kind'], row['name'], row['namespace'])
            if current:
                require(current['metadata']['uid'] in known, 'Native cascade resource replaced')
                remaining = True
        return not remaining
    wait('receipted native child cascade', cascaded)
    record_events(cluster)
    inventory = namespace_inventory(namespace)
    namespace_delete_gate(cluster, inventory)
    progress['finalizeReady'] = True
    receipt.save()
    cluster.delete('Namespace', namespace)
    wait('exact synthetic namespace deletion', lambda: deletion_finished(receipt, ns_identity))
    finish_cleanup(cluster, ns_identity)


def finish_cleanup(cluster, ns_identity):
    receipt = cluster.receipt
    require(receipt.value.get('cleanup', {}).get('finalizeReady'), 'Unexpected namespace absence before finalization')
    require(deletion_finished(receipt, ns_identity), 'Namespace cleanup is not complete')
    for row in receipt.value['resources']:
        if row['kind'] in ('ClusterRole', 'ClusterRoleBinding') and row.get('uid'):
            item = {key: row[key] for key in ('kind', 'name', 'namespace', 'uid')}
            require(deletion_finished(receipt, item), 'Cluster-scoped proof authority remains')
    identity = receipt.value['evidence'].get('storage')
    if identity:
        require(receipt.value['evidence'].get('storageCleanupComplete'), 'Storage cleanup remains incomplete')
        for item in storage_deletion_identities(identity):
            require(deletion_finished(receipt, item), 'Recorded synthetic storage remains')
    receipt.phase('cleaned')


def protected_bytes(path):
    path = Path(path)
    protected_directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and not metadata.st_mode & 0o077 and metadata.st_size <= LIMIT, 'Unsafe protected recovery input')
        raw = stream.read(LIMIT + 1)
        require(len(raw) <= LIMIT, 'Recovery input exceeds bound')
    return raw, {'sha256': digest(raw), 'uid': metadata.st_uid, 'gid': metadata.st_gid, 'mode': metadata.st_mode,
                 'inode': metadata.st_ino, 'size': metadata.st_size, 'mtime': metadata.st_mtime_ns, 'ctime': metadata.st_ctime_ns}


def recovery_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate recovery input field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def recovery_shape(current):
    result = copy.deepcopy(current)
    result.pop('status', None)
    metadata = result['metadata']
    for key in ('resourceVersion', 'managedFields', 'generation', 'creationTimestamp', 'deletionTimestamp', 'deletionGracePeriodSeconds'):
        metadata.pop(key, None)
    if current['kind'] == 'Event':
        return {'kind': 'Event', 'metadata': {key: metadata.get(key) for key in ('name', 'namespace', 'uid')},
                'reference': current.get('regarding', current.get('involvedObject', {})).get('uid'),
                'reporter': current.get('reportingController') or current.get('reportingComponent') or current.get('source', {}).get('component', '')}
    return result


def recovery_generated_name(current, resources):
    metadata = current['metadata']
    prefix = metadata['generateName']
    dns = r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*'
    require(isinstance(prefix, str) and 1 < len(prefix) <= 248 and prefix.endswith('-')
            and re.fullmatch(dns, prefix[:-1]) and len(metadata['name']) <= 253
            and metadata['name'].startswith(prefix) and re.fullmatch(r'[a-z0-9]+', metadata['name'][len(prefix):]),
            'Invalid native recovery name prefix')
    rows = {row['uid']: row for row in resources if row.get('uid')}
    row = rows.get(metadata['uid'])
    owners = metadata.get('ownerReferences', [])
    require(row and row.get('observed') and row['kind'] == current['kind'] and row['name'] == metadata['name']
            and row['namespace'] == metadata.get('namespace') and len(owners) == 1
            and row.get('owners') == [owners[0]['uid']] and owners[0].get('controller') is True,
            'Generated recovery name lacks recorded native identity')
    owner = owners[0]
    parent = rows.get(owner['uid'])
    require(current['kind'] in ('Pod', 'EndpointSlice')
            and owner.get('kind') in ({'ReplicaSet', 'StatefulSet'} if current['kind'] == 'Pod' else {'Service'})
            and parent and parent['kind'] == owner['kind'] and parent['name'] == owner.get('name')
            and parent['namespace'] == row['namespace'] and prefix == parent['name'] + '-',
            'Generated recovery name differs from native owner prefix')
    seen = {row['uid']}
    while parent.get('observed'):
        require(parent['uid'] not in seen and len(parent.get('owners', [])) == 1, 'Invalid recorded native owner lineage')
        seen.add(parent['uid'])
        parent = rows.get(parent['owners'][0])
        require(parent and parent['namespace'] == row['namespace'], 'Incomplete recorded native owner lineage')


def recovery_stateless_shape(current, native_resources=()):
    allowed = {'Namespace', 'ResourceQuota', 'ServiceAccount', 'Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding',
               'NetworkPolicy', 'AuthorizationPolicy', 'Deployment', 'ReplicaSet', 'Pod', 'Service', 'Endpoints',
               'EndpointSlice', 'ConfigMap', 'Secret', 'Event'}
    require(current.get('kind') in allowed, 'Persistent or unsupported recovery target')
    fields = {'ServiceAccount': {'automountServiceAccountToken', 'secrets', 'imagePullSecrets'},
              'Role': {'rules'}, 'ClusterRole': {'rules'}, 'RoleBinding': {'subjects', 'roleRef'},
              'ClusterRoleBinding': {'subjects', 'roleRef'}, 'Endpoints': {'subsets'},
              'EndpointSlice': {'addressType', 'endpoints', 'ports'}, 'ConfigMap': {'data', 'binaryData', 'immutable'},
              'Secret': {'data', 'type', 'immutable'}, 'Event': {'action', 'count', 'eventTime', 'firstTimestamp',
                  'involvedObject', 'lastTimestamp', 'message', 'reason', 'regarding', 'related', 'reportingComponent',
                  'reportingController', 'reportingInstance', 'series', 'source', 'type', 'note', 'deprecatedCount',
                  'deprecatedSource', 'deprecatedFirstTimestamp', 'deprecatedLastTimestamp'}}
    generated = {'generateName'} if 'generateName' in current['metadata'] else set()
    if generated:
        recovery_generated_name(current, native_resources)
    require(set(current) <= {'apiVersion', 'kind', 'metadata', 'status'} | fields.get(current['kind'], {'spec'})
            and set(current['metadata']) <= {'name', 'namespace', 'uid', 'resourceVersion', 'generation', 'creationTimestamp',
                'managedFields', 'labels', 'annotations', 'ownerReferences', 'finalizers', 'deletionTimestamp', 'deletionGracePeriodSeconds'} | generated,
            'Unknown recovery object field')
    if current['kind'] == 'ServiceAccount':
        require(not current.get('secrets') and not current.get('imagePullSecrets'), 'Credential-bearing recovery account')
    spec = current.get('spec', {})
    if current['kind'] in ('Deployment', 'ReplicaSet'):
        spec = spec['template']['spec']
    if current['kind'] in ('Pod', 'Deployment', 'ReplicaSet'):
        require(not any(spec.get(key) for key in ('hostNetwork', 'hostPID', 'hostIPC', 'ephemeralContainers'))
                and all(set(volume) <= {'name', 'emptyDir', 'configMap', 'secret', 'projected', 'downwardAPI'}
                        for volume in spec.get('volumes', []))
                and not any(row.get('securityContext', {}).get('privileged') for key in ('containers', 'initContainers')
                            for row in spec.get(key, [])), 'Persistent or privileged recovery workload')


def recovery_storage_absent(predecessor):
    identity = predecessor.receipt.value['evidence']['storage']
    claims = [row for row in predecessor.receipt.value['resources'] if row['kind'] == 'PersistentVolumeClaim'
              and row.get('uid') == identity['claim']]
    require(len(claims) == 1 and get('PersistentVolumeClaim', claims[0]['name'], predecessor.namespace) is None
            and get('pv', identity['pvName']) is None
            and get('volumes.longhorn.io', identity['volume'], 'longhorn-system') is None,
            'Original or replacement storage blocks stateless recovery')
    aliases = {identity['pvName'], identity['volume'], identity['handle']}
    live_claims = json.loads(kubectl('get', '--raw', '/api/v1/persistentvolumeclaims?limit=100'))
    require(not live_claims.get('metadata', {}).get('continue') and all(
        row['metadata']['uid'] != identity['claim'] and row.get('spec', {}).get('volumeName') not in aliases
        and not (row['metadata']['name'] == claims[0]['name'] and row['metadata'].get('namespace') == predecessor.namespace)
        for row in live_claims['items']), 'Live or aliased cluster claim blocks stateless recovery')
    for kind, namespace in [('pv', None), ('volumes.longhorn.io', 'longhorn-system'),
                            ('engines.longhorn.io', 'longhorn-system'), ('replicas.longhorn.io', 'longhorn-system'),
                            ('volumeattachments.longhorn.io', 'longhorn-system'), ('snapshots.longhorn.io', 'longhorn-system'),
                            ('volumeattachments.storage.k8s.io', None)]:
        listed = get(kind, namespace=namespace)
        require(not listed.get('metadata', {}).get('continue'), 'Incomplete recovery storage discovery')
        for row in listed['items']:
            spec, status_value = row.get('spec', {}), row.get('status', {})
            kubernetes = status_value.get('kubernetesStatus', {})
            require(row['metadata']['name'] not in aliases
                    and row['metadata']['uid'] not in (identity['claim'], identity['pv'], identity['volumeUID'])
                    and not any(spec.get(key) in aliases for key in ('volumeName', 'volume', 'volumeHandle'))
                    and spec.get('csi', {}).get('volumeHandle') not in aliases
                    and spec.get('source', {}).get('persistentVolumeName') not in aliases
                    and spec.get('claimRef', {}).get('uid') != identity['claim']
                    and not (spec.get('claimRef', {}).get('name') == claims[0]['name']
                             and spec['claimRef'].get('namespace') == predecessor.namespace)
                    and kubernetes.get('pvName') not in aliases
                    and not (kubernetes.get('pvcName') == claims[0]['name'] and kubernetes.get('namespace') == predecessor.namespace),
                    'Storage alias or dependent blocks stateless recovery')
    groups = json.loads(kubectl('get', '--raw', '/apis'))['groups']
    if any(row['name'] == 'snapshot.storage.k8s.io' for row in groups):
        snapshots = get('volumesnapshotcontents.snapshot.storage.k8s.io')
        require(not snapshots.get('metadata', {}).get('continue') and all(
            row.get('spec', {}).get('source', {}).get('volumeHandle') not in aliases
            and not any(alias in row.get('spec', {}).get('source', {}).get('snapshotHandle', '') for alias in aliases)
            and row.get('spec', {}).get('volumeSnapshotRef', {}).get('namespace') != predecessor.namespace
            for row in snapshots['items']), 'CSI snapshot blocks stateless recovery')
    directories = predecessor.receipt.value['evidence'].get('replicaDirectories', [])
    complete_replica_evidence(directories)
    require(all(backing_absent(row) for row in directories), 'Stable backing absence is not established')


def recovery_operator_pods(predecessor, targets, payload):
    pods = [item for item in targets if item['kind'] == 'Pod']
    if not pods:
        return {}
    declarations = [item for item in payload['manifests'] if item['kind'] == 'Deployment']
    require(len(declarations) == 1 and declarations[0]['metadata']['name'] == 'proof-operator', 'Unsupported recovery Pod controller declaration')
    images = payload['images']
    require(all(isinstance(images.get(key), str) and re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', images[key])
                for key in ('operator', 'reloader')), 'Unpinned recovery operator profile')
    declared = substitute(declarations[0], {'NAMESPACE': predecessor.namespace, 'OPERATION': predecessor.operation,
        'OPERATOR_IMAGE': images['operator'], 'RELOADER_IMAGE': images['reloader']})
    deployments = [item for item in targets if item['kind'] == 'Deployment'
                   and item['metadata']['name'] == declared['metadata']['name']]
    require(len(deployments) == 1, 'Frozen operator Deployment is missing or ambiguous')
    deployment = deployments[0]
    old = predecessor.row('Deployment', declared['metadata']['name'], predecessor.namespace)
    predecessor.owned(deployment, old)
    require(not old.get('observed') and not deployment['metadata'].get('ownerReferences')
            and deployment['apiVersion'] == declared['apiVersion'] and deployment['spec'].get('replicas') == 1
            and deployment['spec'].get('selector') == declared['spec']['selector'], 'Frozen operator Deployment scope changed')
    expected = declared['spec']['template']['spec']
    require([row['name'] for row in expected['containers']] == ['operator'] and not expected.get('initContainers'),
            'Unsupported operator container declaration')
    def profile(spec):
        return {'executable': pod_profile(spec), 'securityContext': spec.get('securityContext'),
                'containers': [{key: row.get(key) for key in ('name', 'securityContext', 'resources')}
                               for row in spec.get('containers', [])]}
    require(profile(deployment['spec']['template']['spec']) == profile(expected), 'Frozen operator template profile changed')
    rows = {row['uid']: row for row in predecessor.receipt.value['resources'] if row.get('uid')}
    namespace = predecessor.row('Namespace', predecessor.namespace)
    result = {}
    for pod in pods:
        metadata = pod['metadata']
        row = rows.get(metadata['uid'])
        owners = metadata.get('ownerReferences', [])
        require(row and row.get('observed') and row['kind'] == 'Pod' and row['name'] == metadata['name']
                and row['namespace'] == predecessor.namespace and metadata.get('namespace') == predecessor.namespace
                and len(owners) == 1 and owners[0].get('kind') == 'ReplicaSet' and owners[0].get('controller') is True
                and row.get('owners') == [owners[0]['uid']], 'Unsupported frozen recovery Pod lineage')
        replica = rows.get(owners[0]['uid'])
        require(replica and replica.get('observed') and replica['kind'] == 'ReplicaSet'
                and replica['name'] == owners[0].get('name') and replica['namespace'] == predecessor.namespace
                and replica.get('owners') == [deployment['metadata']['uid']]
                and profile(pod['spec']) == profile(expected)
                and all(metadata.get('labels', {}).get(key) == value
                        for key, value in declared['spec']['template']['metadata']['labels'].items())
                and isinstance(pod['spec'].get('nodeName'), str) and 0 < len(pod['spec']['nodeName']) <= 253,
                'Unsupported frozen operator Pod profile')
        recovery_stateless_shape(pod, predecessor.receipt.value['resources'])
        result[metadata['uid']] = {'podUID': metadata['uid'], 'podName': metadata['name'], 'namespace': predecessor.namespace,
            'node': pod['spec']['nodeName'], 'container': 'operator', 'namespaceUID': namespace['uid'],
            'namespaceCreatedAt': namespace['createdAt'], 'deployment': object_identity(deployment),
            'deploymentScopeHash': digest(canonical(recovery_shape(deployment)))}
    return result


def recovery_event_time(value, lower):
    require(isinstance(value, str) and len(value) <= 40, 'Invalid recovery Event time')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None and parsed >= lower, 'Recovery Event predates its namespace or interval')
    return parsed.astimezone(timezone.utc).isoformat()


def recovery_event_observation(event, profiles):
    recovery_stateless_shape(event)
    metadata = event['metadata']
    require(event['kind'] == 'Event' and event['apiVersion'] in ('v1', 'events.k8s.io/v1')
            and not any(key in metadata for key in ('ownerReferences', 'finalizers'))
            and not metadata.get('labels') and not metadata.get('annotations')
            and event.get('type') == 'Normal' and event.get('reason') == 'Killing'
            and event.get('action') in (None, '') and event.get('related') is None and event.get('eventTime') is None,
            'Unsupported termination Event schema')
    def alias(*keys):
        values = [event[key] for key in keys if key in event]
        require(values and all(value == values[0] for value in values), 'Missing or conflicting Event aliases')
        return values[0]
    reference = alias('involvedObject', 'regarding')
    require(isinstance(reference, dict) and set(reference) <= {'apiVersion', 'kind', 'name', 'namespace', 'uid', 'fieldPath', 'resourceVersion'}
            and reference.get('uid') in profiles, 'Unknown termination Event reference')
    scope = profiles[reference['uid']]
    require(reference.get('apiVersion') == 'v1' and reference.get('kind') == 'Pod'
            and reference.get('name') == scope['podName'] and reference.get('namespace') == scope['namespace']
            and reference.get('fieldPath') == 'spec.containers{' + scope['container'] + '}'
            and metadata.get('namespace') == scope['namespace']
            and alias('source', 'deprecatedSource') == {'component': 'kubelet', 'host': scope['node']}
            and alias('reportingComponent', 'reportingController') == 'kubelet'
            and event.get('reportingInstance') == scope['node']
            and alias('message', 'note') == 'Stopping container ' + scope['container']
            and isinstance(metadata.get('uid'), str) and re.fullmatch(r'[A-Za-z0-9-]{1,128}', metadata['uid'])
            and isinstance(metadata.get('name'), str) and len(metadata['name']) <= 253
            and re.fullmatch(re.escape(scope['podName']) + r'\.[0-9a-f]{1,16}', metadata['name']),
            'Termination Event identity or native provenance changed')
    if 'resourceVersion' in reference:
        require(isinstance(reference['resourceVersion'], str) and re.fullmatch(r'[0-9]{1,32}', reference['resourceVersion']), 'Invalid Event reference version')
    lower = datetime.fromisoformat(scope['namespaceCreatedAt'].replace('Z', '+00:00'))
    require(lower.tzinfo is not None, 'Namespace creation boundary is missing')
    first = recovery_event_time(alias('firstTimestamp', 'deprecatedFirstTimestamp'), lower)
    last = recovery_event_time(alias('lastTimestamp', 'deprecatedLastTimestamp'), datetime.fromisoformat(first))
    created = recovery_event_time(metadata.get('creationTimestamp'), lower)
    count = alias('count', 'deprecatedCount')
    series = event.get('series')
    require(type(count) is int and 1 <= count <= 1024
            and (series is None or isinstance(series, dict) and set(series) == {'count', 'lastObservedTime'}
                 and type(series['count']) is int and 1 <= series['count'] <= 1024), 'Unbounded Event count or series')
    series_last = recovery_event_time(series['lastObservedTime'], datetime.fromisoformat(first)) if series else None
    identity = {'uid': metadata['uid'], 'name': metadata['name'], 'namespace': scope['namespace'], 'namespaceUID': scope['namespaceUID'],
        'podUID': scope['podUID'], 'podName': scope['podName'], 'node': scope['node'], 'container': scope['container'],
        'deploymentUID': scope['deployment']['uid'], 'reporter': 'kubelet', 'reason': 'Killing', 'type': 'Normal',
        'message': 'Stopping container ' + scope['container'], 'createdAt': created, 'firstAt': first}
    return {'identity': identity, 'provenanceHash': digest(canonical(identity)), 'count': count,
            'lastAt': last, 'seriesCount': series['count'] if series else 0, 'seriesLastAt': series_last}


def recovery_events(predecessor, targets, payload, inventory, receipt):
    # This establishes consistency, not authenticated authorship or DELETE causality.
    profiles = recovery_operator_pods(predecessor, targets, payload)
    saved = receipt.value.get('recoveryEvents', []) if receipt else []
    require(isinstance(saved, list) and len(saved) <= len(profiles), 'Unbounded termination Event observations')
    def accepted(scope):
        require(receipt is not None, 'Termination Event before recovery authority')
        intent = receipt.deletion(scope['deployment'])
        durable = recovery_json(protected_bytes(receipt.path)[0])
        rows = [row for row in durable.get('deletions', []) if all(row.get(key) == value for key, value in scope['deployment'].items())]
        require(intent and intent.get('accepted') is True and intent.get('scopeHash') == scope['deploymentScopeHash']
                and isinstance(intent.get('resourceVersion'), str) and intent['resourceVersion']
                and len(rows) == 1 and rows[0] == intent, 'Termination Event lacks durable accepted operator DELETE')
    known = set()
    pod_keys = set()
    for row in saved:
        require(set(row) == {'identity', 'provenanceHash', 'count', 'lastAt', 'seriesCount', 'seriesLastAt'}
                and row['provenanceHash'] == digest(canonical(row['identity'])), 'Saved Event provenance changed')
        identity = row['identity']
        scope = profiles.get(identity.get('podUID'))
        require(set(identity) == {'uid', 'name', 'namespace', 'namespaceUID', 'podUID', 'podName', 'node', 'container',
                    'deploymentUID', 'reporter', 'reason', 'type', 'message', 'createdAt', 'firstAt'}
                and scope and all(identity.get(key) == scope[key] for key in ('podName', 'namespace', 'node', 'container', 'namespaceUID'))
                and identity.get('deploymentUID') == scope['deployment']['uid'] and identity.get('reporter') == 'kubelet'
                and identity.get('reason') == 'Killing' and identity.get('type') == 'Normal'
                and identity.get('message') == 'Stopping container ' + scope['container']
                and identity.get('uid') not in known and identity['podUID'] not in pod_keys
                and isinstance(identity.get('uid'), str) and re.fullmatch(r'[A-Za-z0-9-]{1,128}', identity['uid'])
                and isinstance(identity.get('name'), str) and len(identity['name']) <= 253
                and re.fullmatch(re.escape(scope['podName']) + r'\.[0-9a-f]{1,16}', identity['name']), 'Saved termination Event scope changed')
        lower = datetime.fromisoformat(scope['namespaceCreatedAt'].replace('Z', '+00:00'))
        first = recovery_event_time(identity['firstAt'], lower)
        recovery_event_time(identity['createdAt'], lower)
        recovery_event_time(row['lastAt'], datetime.fromisoformat(first))
        require(type(row['count']) is int and 1 <= row['count'] <= 1024
                and type(row['seriesCount']) is int and 0 <= row['seriesCount'] <= 1024
                and (row['seriesLastAt'] is None) == (row['seriesCount'] == 0), 'Saved Event update exceeds bound')
        if row['seriesCount'] > 0:
            recovery_event_time(row['seriesLastAt'], datetime.fromisoformat(first))
        accepted(scope)
        known.add(identity['uid'])
        pod_keys.add(identity['podUID'])
    frozen = {item['metadata']['uid'] for item in targets}
    observed = []
    for event in inventory:
        if event['kind'] != 'Event' or event['metadata']['uid'] in frozen:
            continue
        require(not any(row['uid'] == event['metadata']['uid'] for row in predecessor.receipt.value.get('events', [])),
                'Previously recorded Event is outside the frozen target set')
        row = recovery_event_observation(event, profiles)
        accepted(profiles[row['identity']['podUID']])
        prior = next((item for item in saved if item['identity']['uid'] == row['identity']['uid']), None)
        if prior:
            require(prior['identity'] == row['identity'] and row['count'] >= prior['count'] and row['lastAt'] >= prior['lastAt']
                    and row['seriesCount'] >= prior['seriesCount']
                    and (prior['seriesLastAt'] is None or row['seriesLastAt'] is not None and row['seriesLastAt'] >= prior['seriesLastAt']),
                    'Termination Event provenance or update regressed')
            prior.update(row)
        else:
            require(len(saved) < len(profiles) and not any(item['identity']['podUID'] == row['identity']['podUID'] for item in saved),
                    'Additional termination Event exceeds frozen Pod scope')
            saved.append(row)
        receipt.value['recoveryEvents'] = saved
        receipt.save()
        observed.append(event['metadata']['uid'])
    return [item for item in inventory if item['metadata']['uid'] not in observed]


def recovery_inventory(predecessor, targets, payload, receipt=None, initial=False):
    recovery_storage_absent(predecessor)
    inventory = namespace_inventory(predecessor.namespace)
    inventory = recovery_events(predecessor, targets, payload, inventory, receipt)
    namespace_delete_gate(predecessor, inventory, allow_owned=True, retiring=True)
    namespace = predecessor.current('Namespace', predecessor.namespace)
    current = inventory + [namespace]
    manifests = substitute([row for row in payload['manifests']
                            if row['kind'] in ('Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding')],
                           {'NAMESPACE': predecessor.namespace, 'OPERATION': predecessor.operation})
    for item in inventory:
        if item['kind'] in ('Role', 'RoleBinding'):
            declarations = [row for row in manifests if row['kind'] == item['kind'] and row['metadata']['name'] == item['metadata']['name']]
            require(len(declarations) == 1 and all(item.get(key) == value for key, value in declarations[0].items() if key != 'metadata'),
                    'Recovery namespace authority or subjects changed')
    for kind in ('ClusterRole', 'ClusterRoleBinding'):
        row = predecessor.row(kind, 'checkpoint-' + predecessor.operation)
        actual = get(kind, row['name'])
        if actual is not None:
            predecessor.owned(actual, row)
            expected = next(item for item in manifests if item['kind'] == kind)
            require(all(actual.get(key) == value for key, value in expected.items() if key != 'metadata'),
                    'Recovery cluster authority or subjects changed')
            current.append(actual)
    expected = {row['metadata']['uid']: row for row in targets}
    require(len(expected) == len(targets), 'Duplicate recovery target UID')
    cascade = {row['uid'] for row in receipt.value.get('deletions', [])} if receipt else set()
    while True:
        children = {uid for uid, item in expected.items() if any(
            owner['uid'] in cascade for owner in item['metadata'].get('ownerReferences', []))
            or item['kind'] == 'Endpoints' and receipt and any(row['kind'] == 'Service' and row['name'] == item['metadata']['name']
                for row in receipt.value.get('deletions', []))}
        if children <= cascade:
            break
        cascade.update(children)
    actual_uids = set()
    for item in current:
        uid = item['metadata']['uid']
        require(uid in expected and recovery_shape(item) == recovery_shape(expected[uid]), 'Unknown or changed recovery object')
        recovery_stateless_shape(item, predecessor.receipt.value['resources'])
        old = next((row for row in predecessor.receipt.value['resources'] if row.get('uid') == uid), None)
        if old is not None and not old.get('observed'):
            require(not item['metadata'].get('ownerReferences'), 'Driver-created recovery target gained a foreign owner')
        if initial:
            require(not item['metadata'].get('deletionTimestamp')
                    and item['metadata']['resourceVersion'] == expected[uid]['metadata']['resourceVersion'], 'Reviewed recovery resource changed')
        elif receipt:
            intent = receipt.deletion(object_identity(item))
            require((intent is None or not intent['complete'])
                    and (not item['metadata'].get('deletionTimestamp') or uid in cascade), 'Unprotected or completed recovery target deletion')
        actual_uids.add(uid)
    if initial:
        require(actual_uids == set(expected), 'Reviewed recovery inventory is not complete')
    elif receipt:
        for uid in set(expected) - actual_uids:
            item = expected[uid]
            direct = receipt.deletion(object_identity(item))
            require(direct is not None or uid in cascade, 'Unexplained recovery target disappearance')
            if direct is None:
                recorded = receipt.value.setdefault('recoveryCascade', [])
                if uid not in recorded:
                    recorded.append(uid)
                    receipt.save()
    return current


def delete_recovery_target(cluster, target, native_resources=()):
    recovery_stateless_shape(target, native_resources)
    metadata = target['metadata']
    row = cluster.row(target['kind'], metadata['name'], metadata.get('namespace'))
    api = target['apiVersion']
    require(api == 'v1' or re.fullmatch(r'[a-z0-9][a-z0-9.-]*/v[0-9]+(?:(?:alpha|beta)[0-9]+)?', api),
            'Invalid frozen recovery API version')
    resource_type = target['kind'] if api == 'v1' else api_path(target).rsplit('/', 2)[1] + '.' + '.'.join(reversed(api.split('/')))
    current = get(resource_type, metadata['name'], metadata.get('namespace'))
    if current is None:
        cluster.receipt.deleted(object_identity(target))
        return
    cluster.owned(current, row)
    require(recovery_shape(current) == recovery_shape(target), 'Recovery target changed before delete')
    recovery_stateless_shape(current, native_resources)
    if current['metadata'].get('deletionTimestamp'):
        prior = cluster.receipt.deletion(object_identity(current))
        require(prior and prior.get('accepted') is True, 'Recovery target deletion was not accepted by this operation')
        return
    request_delete(cluster.receipt, current, row['specHash'])


def recover_stateless(predecessor_directory, directory, operation, plan_path):
    global DIAGNOSTIC_DIRECTORY
    predecessor_directory = protected_directory(predecessor_directory)
    directory = Path(directory)
    require(directory.is_absolute() and directory != predecessor_directory
            and predecessor_directory.parent not in directory.parents and directory not in predecessor_directory.parents,
            'Recovery must use a separate protected operation path')
    plan_raw, _ = protected_bytes(plan_path)
    plan = recovery_json(plan_raw)
    require(set(plan) == {'predecessor', 'recoveryDriverSHA256', 'targets'}
            and set(plan['predecessor']) == {'receiptSHA256', 'driverSHA256', 'inputSHA256', 'inputCanonicalSHA256'}
            and all(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value)
                    for value in [*plan['predecessor'].values(), plan['recoveryDriverSHA256']])
            and plan['recoveryDriverSHA256'] == digest(Path(__file__).read_bytes())
            and isinstance(plan['targets'], list) and 0 < len(plan['targets']) <= 100, 'Invalid reviewed recovery input')
    predecessor_receipt = object.__new__(Receipt)
    predecessor_receipt.directory, predecessor_receipt.path = predecessor_directory, predecessor_directory / 'receipt.json'
    def immutable():
        raise RuntimeError('Immutable predecessor cannot be saved')
    predecessor_receipt.save = immutable
    artifacts = {}
    paths = {'receipt': predecessor_directory / 'receipt.json', 'driver': predecessor_directory.parent / 'proof.py',
             'input': predecessor_directory.parent / 'input.json', **{name: predecessor_directory / name for name in FILES}}
    for name, path in paths.items():
        raw, artifacts[name] = protected_bytes(path)
        if name in ('receipt', 'driver', 'input'):
            require(digest(raw) == plan['predecessor'][name + 'SHA256'], 'Immutable predecessor artifact hash differs')
        if name == 'receipt':
            predecessor_receipt.value = recovery_json(raw)
            snapshot_hashes = predecessor_receipt.value.get('evidence', {}).get('hashes', {})
            require(isinstance(snapshot_hashes, dict) and set(snapshot_hashes) == set(FILES)
                    and all(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value)
                            for value in snapshot_hashes.values()), 'Approved native snapshot hashes are missing or invalid')
        if name in FILES:
            require(digest(raw) == snapshot_hashes[name], 'Approved native snapshot content changed')
        if name == 'input':
            payload = recovery_json(raw)
            require(digest(canonical(payload)) == plan['predecessor']['inputCanonicalSHA256'], 'Predecessor input provenance differs')
    require(re.fullmatch(r'[a-f0-9]{16}', operation) and predecessor_receipt.value['operation'] == operation
            and predecessor_receipt.value['namespace'] == PREFIX + operation, 'Recovery predecessor operation differs')
    predecessor = Cluster(predecessor_receipt)
    require(predecessor.receipt.value.get('provenance') == {'driver': plan['predecessor']['driverSHA256'],
                'input': plan['predecessor']['inputCanonicalSHA256']}
            and predecessor.receipt.value.get('cleanup', {}).get('started') is True
            and predecessor.receipt.value['evidence'].get('storageFresh') is True,
            'Predecessor is not the reviewed incomplete storage operation')
    targets = plan['targets']
    old = {row['uid']: row for row in predecessor.receipt.value['resources'] if row.get('uid')}
    resources = []
    for item in targets:
        if item['metadata']['uid'] in old:
            row = copy.deepcopy(old[item['metadata']['uid']])
            row['specHash'] = digest(canonical(recovery_shape(item)))
            resources.append(row)
    def unchanged():
        require(digest(protected_bytes(plan_path)[0]) == digest(plan_raw), 'Frozen recovery input changed')
        for name, path in paths.items():
            raw, metadata = protected_bytes(path)
            require(digest(raw) == artifacts[name]['sha256'] and metadata == artifacts[name], 'Frozen recovery artifact changed')
    def gate(receipt=None, initial=False):
        unchanged()
        return recovery_inventory(predecessor, targets, payload, receipt, initial)
    if directory.exists():
        receipt = Receipt.load(directory, operation)
        require(receipt.value.get('recovery') == {'predecessor': plan['predecessor'], 'planHash': digest(plan_raw),
                    'artifacts': artifacts, 'driver': plan['recoveryDriverSHA256']}, 'Recovery context changed')
        require(receipt.value['resources'] == resources
                and receipt.value.get('housekeeping') == predecessor.receipt.value.get('housekeeping', [])
                and receipt.value.get('events') == predecessor.receipt.value.get('events', [])
                and receipt.value.get('recoveryPodProfiles') == recovery_operator_pods(predecessor, targets, payload), 'Frozen recovery targets changed')
    else:
        gate(initial=True)
        receipt = Receipt(directory, operation)
        receipt.value['recovery'] = {'predecessor': plan['predecessor'], 'planHash': digest(plan_raw),
                                   'artifacts': artifacts, 'driver': plan['recoveryDriverSHA256']}
        receipt.value['resources'] = resources
        receipt.value['housekeeping'] = copy.deepcopy(predecessor.receipt.value.get('housekeeping', []))
        receipt.value['events'] = copy.deepcopy(predecessor.receipt.value.get('events', []))
        receipt.value['recoveryPodProfiles'] = recovery_operator_pods(predecessor, targets, payload)
        receipt.value['evidence']['housekeepingRoots'] = predecessor.receipt.value['evidence']['housekeepingRoots']
        receipt.value['recoveryMissing'] = sorted(set(old) - {item['metadata']['uid'] for item in targets})
        receipt.phase('stateless-recovery')
    cluster = Cluster(receipt)
    DIAGNOSTIC_DIRECTORY = receipt.directory
    recovery_events(predecessor, targets, payload, [], receipt)
    expected = {item['metadata']['uid']: item for item in targets}
    ns_id = object_identity(next(item for item in targets if item['kind'] == 'Namespace'))
    if get('Namespace', predecessor.namespace) is not None:
        gate(receipt)
        priority = {'Deployment': 0, 'Pod': 0, 'RoleBinding': 2, 'ClusterRoleBinding': 2,
                    'Role': 3, 'ClusterRole': 3, 'ServiceAccount': 4}
        direct = [row for row in receipt.value['resources'] if not row.get('observed') and row['kind'] != 'Namespace']
        for row in sorted(direct, key=lambda row: priority.get(row['kind'], 1)):
            gate(receipt)
            delete_recovery_target(cluster, expected[row['uid']], predecessor.receipt.value['resources'])
            key = {name: row[name] for name in ('kind', 'name', 'namespace', 'uid')}
            wait('exact stateless recovery deletion', lambda key=key: deletion_finished(receipt, key))
        def ready():
            current = gate(receipt)
            remaining = [item for item in current if item['kind'] not in ('Namespace', 'Event')
                         and item['metadata']['uid'] not in {row['uid'] for row in receipt.value.get('housekeeping', [])}]
            return not remaining
        wait('exact stateless native recovery cascade', ready)
        namespace_delete_gate(cluster, recovery_events(predecessor, targets, payload, namespace_inventory(cluster.namespace), receipt))
        receipt.value.setdefault('cleanup', {})['finalizeReady'] = True
        receipt.save()
        gate(receipt)
        delete_recovery_target(cluster, expected[ns_id['uid']], predecessor.receipt.value['resources'])
    require(receipt.value.get('cleanup', {}).get('finalizeReady'), 'Unexpected recovery namespace absence')
    wait('exact stateless recovery namespace deletion', lambda: deletion_finished(receipt, ns_id))
    for row in receipt.value['resources']:
        if row['kind'] in ('ClusterRole', 'ClusterRoleBinding'):
            require(deletion_finished(receipt, row), 'Recovery cluster authority remains')
    for row in predecessor.receipt.value['resources']:
        if row['kind'] in ('ClusterRole', 'ClusterRoleBinding'):
            require(get(row['kind'], row['name']) is None, 'Old authority name was replaced during recovery')
    recovery_storage_absent(predecessor)
    unchanged()
    receipt.phase('stateless-remnants-cleaned', statelessRemnantsCleaned=True, predecessorQualification='incomplete')
    return {'statelessRemnantsCleaned': True, 'predecessorQualification': 'incomplete'}


def promote_storage(cluster, storage, source, identity):
    require(cluster.receipt.value['phase'] == 'persistent-validated', 'Source replacement before persistent validation')
    source_unchanged(get('pod', source, cluster.namespace), identity)
    require_source_denied(cluster)
    cluster.patch('Alertmanager', 'primary', [{'op': 'add', 'path': '/spec/storage', 'value': storage}], cluster.namespace)


def retained_replacement(cluster, source, original, target, claim_name, storage):
    receipt, namespace = cluster.receipt, cluster.namespace
    require(source == 'alertmanager-primary-0' and receipt.value['phase'] == 'persistent-validated'
            and receipt.value['evidence'].get('storageFresh') is True
            and receipt.value['evidence'].get('storage') == storage, 'Replacement wait before qualified persistent storage')
    cluster.current('Namespace', namespace)
    manager = cluster.current('Alertmanager', 'primary', namespace)
    require(manager['spec'].get('storage') == target and manager['spec'].get('replicas') == 1
            and manager['spec'].get('persistentVolumeClaimRetentionPolicy') == {'whenDeleted': 'Retain', 'whenScaled': 'Retain'},
            'Replacement desired storage or retention changed')
    deny = cluster.current('AuthorizationPolicy', 'source-quiescence', namespace)
    require(deny['spec'] == source_deny_policy(cluster)['spec'], 'Replacement source DENY changed')
    claim = cluster.current('PersistentVolumeClaim', claim_name, namespace)
    require(storage_identity(claim, healthy=False) == storage, 'Replacement recorded CSI identity changed')
    old_rows = [row for row in receipt.value['resources'] if row['kind'] == 'Pod' and row['name'] == source
                and row['namespace'] == namespace and row.get('uid') == original['uid']]
    require(len(old_rows) == 1 and old_rows[0].get('observed') and len(old_rows[0].get('owners', [])) == 1,
            'Original Pod transition identity is not receipted')
    old_owner = old_rows[0]['owners'][0]
    parents = [row for row in receipt.value['resources'] if row['kind'] == 'StatefulSet'
               and row['name'] == 'alertmanager-primary' and row['namespace'] == namespace
               and row.get('uid') == old_owner and row.get('owners') == [manager['metadata']['uid']]]
    require(len(parents) == 1, 'Original Pod native lineage is not receipted')
    pod = get('Pod', source, namespace)
    if pod is None:
        return None
    cluster.owned(pod)
    require(pod['kind'] == 'Pod' and pod['metadata']['name'] == source
            and all(pod['metadata']['labels'].get(key) == value for key, value in labels(cluster.operation, 'manager').items())
            and not pod['spec'].get('ephemeralContainers'), 'Replacement Pod scope changed')
    owners = pod['metadata'].get('ownerReferences', [])
    require(len(owners) == 1 and owners[0].get('kind') == 'StatefulSet' and owners[0].get('name') == 'alertmanager-primary'
            and owners[0].get('controller') is True, 'Replacement Pod native owner changed')
    statefulset = get('StatefulSet', 'alertmanager-primary', namespace)
    if statefulset is not None:
        cluster.owned(statefulset)
        parent = statefulset['metadata'].get('ownerReferences', [])
        require(len(parent) == 1 and parent[0].get('kind') == 'Alertmanager' and parent[0].get('name') == 'primary'
                and parent[0].get('uid') == manager['metadata']['uid'] and parent[0].get('controller') is True,
                'Replacement StatefulSet has a foreign native owner')
    if pod['metadata']['uid'] == original['uid']:
        cluster.owned(pod, old_rows[0])
        require(old_owner == owners[0]['uid']
                and pod_profile(pod['spec']) == receipt.value['evidence']['nativePodProfile'],
                'Known old Pod identity or executable profile changed')
        return None
    require(not pod['metadata'].get('deletionTimestamp') and pod.get('status', {}).get('phase') not in ('Failed', 'Succeeded')
            and all(row.get('restartCount', 0) == 0 and not row.get('state', {}).get('terminated')
                    for row in pod.get('status', {}).get('containerStatuses', [])),
            'New replacement Pod failed or restarted')
    require(statefulset is not None and statefulset['metadata']['uid'] != old_owner
            and statefulset['metadata']['name'] == 'alertmanager-primary' and owners[0]['uid'] == statefulset['metadata']['uid']
            and statefulset['spec'].get('replicas') == 1
            and statefulset['spec'].get('persistentVolumeClaimRetentionPolicy') == {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}
            and pod_profile(statefulset['spec']['template']['spec']) == receipt.value['evidence']['nativePodProfile']
            and pod_profile(pod['spec']) == receipt.value['evidence']['nativePodProfile'],
            'New replacement differs from intended native controller template')
    volume = 'alertmanager-primary-db'
    templates = statefulset['spec'].get('volumeClaimTemplates', [])
    require(len(templates) == 1 and templates[0]['metadata'].get('name') == volume
            and claim_name == volume + '-alertmanager-primary-0', 'Replacement native claim naming changed')
    template_spec = copy.deepcopy(templates[0]['spec'])
    if template_spec.get('volumeMode') == 'Filesystem':
        template_spec.pop('volumeMode')
    require(template_spec == target['volumeClaimTemplate']['spec']
            and all(claim['spec'].get(key) == value for key, value in template_spec.items())
            and claim['spec'].get('volumeName') == storage['pvName'] and claim['metadata']['uid'] == storage['claim'],
            'Replacement claim template or bound claim changed')
    main = [row for row in pod['spec']['containers'] if row['name'] == 'alertmanager']
    mounts = [row for row in main[0].get('volumeMounts', []) if row.get('mountPath') == '/alertmanager'] if len(main) == 1 else []
    require(mounts == [{'name': volume, 'mountPath': '/alertmanager', 'subPath': 'alertmanager-db'}]
            and [row for row in pod['spec'].get('volumes', []) if row.get('name') == volume] == [
                {'name': volume, 'persistentVolumeClaim': {'claimName': claim_name}}]
            and all(not any(key in row for key in ('hostPath', 'ephemeral'))
                    and ('persistentVolumeClaim' not in row or row.get('name') == volume)
                    for row in pod['spec'].get('volumes', [])), 'Replacement native PVC mount or subPath changed')
    if statefulset.get('status', {}).get('observedGeneration') != statefulset['metadata']['generation']:
        return None
    ready = pod_ready(source, namespace)
    if ready is None:
        return None
    require(ready['metadata']['uid'] == pod['metadata']['uid'] and pod_profile(ready['spec']) == pod_profile(pod['spec'])
            and ready['metadata'].get('ownerReferences') == owners, 'Replacement Pod changed during readiness check')
    source_identity(ready)
    pod_processes(ready)
    verify_storage(namespace, claim_name, storage)
    return ready


def run(payload, directory, operation):
    global DIAGNOSTIC_DIRECTORY
    source_storage = approved_source_storage(payload.get('sourceStorage'))
    require(payload.get('storage') == approved_retained_storage(payload.get('storage'))
            and payload.get('retention') == {'whenDeleted': 'Retain', 'whenScaled': 'Retain'},
            'Fixture requires canonical retained target and retention policy before creation')
    receipt = Receipt(directory, operation)
    receipt.value['provenance'] = {'driver': digest(Path(__file__).read_bytes()), 'input': digest(canonical(payload))}
    receipt.save()
    DIAGNOSTIC_DIRECTORY = receipt.directory
    cluster = Cluster(receipt)
    receipt.phase('prepared', fixtureImages=payload['images'])
    bindings = {'NAMESPACE': cluster.namespace, 'OPERATION': operation,
                'OPERATOR_IMAGE': payload['images']['operator'], 'RELOADER_IMAGE': payload['images']['reloader']}
    bindings.update(preflight(payload))
    manifests = substitute(payload['manifests'], bindings)
    for item in manifests:
        item['metadata'].setdefault('labels', {}).update(labels(operation))
    namespace = cluster.namespace
    require(manifests[0]['kind'] == 'Namespace', 'Fixture declaration order changed')
    cluster.create(manifests[0], dry_run=True)
    cluster.create(manifests[0])
    record_housekeeping(cluster)
    create_service_accounts(cluster, manifests)
    # Admission sees every fixed Pod template before any associated workload is persisted.
    for item in manifests[1:]:
        if item['kind'] == 'ServiceAccount':
            continue
        if item['kind'] == 'Deployment':
            pod_dry_run(item['spec']['template'], namespace, 'operator-admission')
        cluster.create(item, dry_run=True)
    for item in manifests[1:]:
        if item['kind'] in ('AuthorizationPolicy', 'ServiceAccount'):
            continue
        if item['kind'] == 'Deployment':
            operator_permissions(cluster)
        cluster.create(item)
    code = document('ConfigMap', 'proof-code', cluster, data={'proof.py': Path(__file__).read_text()})
    cluster.create(code, dry_run=True)
    cluster.create(code)
    code_volume = [{'name': 'code', 'configMap': {'name': 'proof-code'}}]
    code_mount = [{'name': 'code', 'mountPath': '/proof', 'readOnly': True}]
    for name, arguments, role in [('receiver', ['python', '/proof/proof.py', '--serve'], 'receiver'),
                                 ('client', ['python', '-c', 'import time; time.sleep(7200)'], 'client'),
                                 ('unauthorized', ['python', '-c', 'import time; time.sleep(7200)'], 'client')]:
        pod = pod_document(name, namespace, operation, payload['images']['python'], arguments,
                           code_volume, code_mount, role=role,
                           service_account='default' if name == 'unauthorized' else 'proof-client')
        if name == 'unauthorized':
            pod['spec']['nodeName'] = get('Pod', 'client', namespace)['spec']['nodeName']
        cluster.create(pod, dry_run=True)
        cluster.create(pod)
        wait(name + ' ready', lambda name=name: pod_ready(name, namespace))
    for name, selector, port in [('receiver', {'checkpoint-role': 'receiver'}, 8080)]:
        cluster.create(document('Service', name, cluster, spec={'selector': selector,
            'ports': [{'name': 'http', 'port': port, 'targetPort': port}]}))
    config = {'route': {'receiver': 'proof', 'group_by': ['alertname'], 'group_wait': '0s',
                        'group_interval': '1s', 'repeat_interval': '1h'},
              'receivers': [{'name': 'proof', 'webhook_configs': [
                  {'url': 'http://receiver:8080/alerts/' + index, 'send_resolved': True} for index in ('0', '1')]}]}
    initial = document('Secret', 'source-config', cluster,
                       data={'alertmanager.yaml': base64.b64encode(canonical(config)).decode()})
    original = document('ConfigMap', 'validator-config', cluster, data={'alertmanager.yaml': canonical(config).decode()})
    cluster.create(initial)
    cluster.create(original)
    manager = {'apiVersion': 'monitoring.coreos.com/v1', 'kind': 'Alertmanager',
        'metadata': {'name': 'primary', 'namespace': namespace, 'labels': labels(operation),
                     'annotations': {'operator.prometheus.io/controller-id': operation}},
        'spec': {'replicas': 0, 'image': payload['images']['alertmanager'], 'version': '0.34.1',
                 'configSecret': 'source-config', 'serviceAccountName': 'proof-alertmanager',
                 'storage': source_storage,
                 'automountServiceAccountToken': False, 'forceEnableClusterMode': False,
                 'additionalArgs': [{'name': 'data.maintenance-interval', 'value': '5s'}],
                 'logLevel': 'debug', 'logFormat': 'json', 'resources': copy.deepcopy(RESOURCES),
                 'securityContext': payload['securityContext'],
                 'podMetadata': {'labels': labels(operation, 'manager')},
                 'persistentVolumeClaimRetentionPolicy': payload['retention']}}
    create_source_manager(cluster, manager)
    statefulset = wait('native zero-replica template', lambda: get('statefulset', 'alertmanager-primary', namespace))
    controls = pod_dry_run(statefulset['spec']['template'], namespace, 'native-admission')
    source_volume(statefulset['spec']['template']['spec'], statefulset['spec'].get('volumeClaimTemplates'))
    record_generated(cluster)
    zero = cluster.current('StatefulSet', 'alertmanager-primary', namespace)
    require(zero['metadata']['uid'] == statefulset['metadata']['uid'] and zero['spec'].get('replicas') == 0
            and pod_profile(zero['spec']['template']['spec']) == pod_profile(statefulset['spec']['template']['spec']),
            'Native zero-replica template changed before scale')
    calibrate_retained_storage(cluster, payload['storage'])
    receipt.phase('native-zero-template-qualified', zeroNativePodProfile=pod_profile(zero['spec']['template']['spec']),
        zeroNativeTemplate={'uid': zero['metadata']['uid'], 'generation': zero['metadata']['generation'], 'replicas': 0,
            'alertmanagerUID': cluster.row('Alertmanager', 'primary', namespace)['uid'],
            'serviceUID': cluster.current('Service', 'alertmanager-operated', namespace)['metadata']['uid']})
    cluster.patch('Alertmanager', 'primary', [{'op': 'replace', 'path': '/spec/replicas', 'value': 1}], namespace)
    source = 'alertmanager-primary-0'
    pod = wait('synthetic native primary ready', lambda: pod_ready(source, namespace))
    source_volume(pod['spec'])
    actual_controls = pod_dry_run({'metadata': {'labels': labels(operation)}, 'spec': pod['spec']},
                                 namespace, 'final-native-admission')
    require(actual_controls == controls, 'Native security or image changed after admission qualification')
    record_generated(cluster)
    wait('current native singleton template qualification', lambda: qualify_singleton_template(cluster, pod, controls), timeout=60)
    identity = source_identity(pod)
    record_housekeeping(cluster)
    record_events(cluster)
    principal_proof(cluster, next(item for item in manifests if item['kind'] == 'AuthorizationPolicy'))
    records, silences = populate(namespace)
    # Missing/old/in-flight generations never qualify a complete checkpoint.
    before_reload = native_reload_state(cluster)
    require(before_reload['successful'], 'Source last configuration reload failed')
    original_text = before_reload['original']
    maintenance_text = native_maintenance_text(original_text)
    source_unchanged(get('Pod', source, namespace), identity)
    maintenance = maintenance_config(config)
    cluster.patch('Secret', 'source-config', [{'op': 'replace', 'path': '/data/alertmanager.yaml',
                  'value': base64.b64encode(canonical(maintenance)).decode()}], namespace)
    wait('integration-free native configuration reload', lambda: native_reloaded(
        cluster, maintenance_text, before_reload['timestamp'], identity))
    access = quiesce_source(cluster, identity, maintenance_text)
    require(native_reloaded(cluster, maintenance_text, before_reload['timestamp'], identity),
            'Isolated source lost its maintenance configuration')
    source_unchanged(get('pod', source, namespace), identity)
    counts = callbacks(namespace)
    values, hashes = verify_snapshots(cluster, source, identity)
    require(callbacks(namespace) == counts, 'Notification pipeline was not quiesced')
    record_generated(cluster)
    statefulset = get('statefulset', 'alertmanager-primary', namespace)
    claim = final_claim(statefulset, pod, payload['storage'], namespace, operation)
    cluster.create(claim, dry_run=True)
    baseline = storage_baseline(cluster, payload['storageClass'])
    cluster.create(claim)
    wait('fresh checkpoint claim bound', lambda: get('pvc', claim['metadata']['name'], namespace).get('status', {}).get('phase') == 'Bound')
    storage = wait('fresh dynamic own-claim storage verified', lambda: fresh_storage(
        get('pvc', claim['metadata']['name'], namespace), baseline, payload['storageClass']))
    receipt.phase('fresh-storage-verified', storage=storage, storageFresh=True)
    data_volume = [{'name': 'data', 'persistentVolumeClaim': {'claimName': claim['metadata']['name']}}]
    writer = pod_document('writer', namespace, operation, payload['images']['python'],
        ['python', '-c', 'import time; time.sleep(7200)'], code_volume + data_volume,
        code_mount + [{'name': 'data', 'mountPath': '/data'}], payload['securityContext'])
    cluster.create(writer, dry_run=True)
    cluster.create(writer)
    wait('nonroot checkpoint writer ready', lambda: pod_ready('writer', namespace))
    namespace_listener_profile(cluster)
    actual_hashes = json.loads(exec_pod(namespace, 'writer', 'python', '/proof/proof.py', '--write-checkpoint',
        body=canonical({'files': {k: base64.b64encode(v).decode() for k, v in values.items()}, 'hashes': hashes})))
    require(actual_hashes == hashes, 'Persistent checkpoint bytes differ')
    wait('two healthy native replicas', lambda: get('volumes.longhorn.io', get('pv', get('pvc',
        claim['metadata']['name'], namespace)['spec']['volumeName'])['spec']['csi']['volumeHandle'],
        'longhorn-system')['status'].get('robustness') == 'healthy', timeout=240)
    require(storage_identity(get('pvc', claim['metadata']['name'], namespace)) == storage,
            'Fresh storage identity changed during checkpoint write')
    receipt.phase('persisted', storage=storage)
    source_unchanged(get('pod', source, namespace), identity)
    cluster.delete('Pod', 'writer', namespace)
    wait('checkpoint writer mount released', lambda: get('pod', 'writer', namespace) is None)
    validator = pod_document('validator', namespace, operation, payload['images']['alertmanager'],
        ['/bin/alertmanager', '--config.file=/config/alertmanager.yaml', '--storage.path=/alertmanager',
         '--cluster.listen-address='], data_volume + [{'name': 'config', 'configMap': {'name': 'validator-config'}}],
        [{'name': 'data', 'mountPath': '/alertmanager', 'subPath': 'alertmanager-db'},
         {'name': 'config', 'mountPath': '/config', 'readOnly': True}], payload['securityContext'],
        role='validator', service_account='proof-alertmanager')
    validator['spec']['containers'][0]['readinessProbe'] = {'httpGet': {'path': '/-/ready', 'port': 9093},
                                                          'periodSeconds': 1, 'initialDelaySeconds': 1}
    cluster.create(validator, dry_run=True)
    cluster.create(validator)
    wait('native disk-only validator ready', lambda: pod_ready('validator', namespace))
    namespace_listener_profile(cluster)
    native_validation(cluster, 'validator', records, silences, 'FixtureValidatorControl')
    source_unchanged(get('pod', source, namespace), identity)
    verify_storage(namespace, claim['metadata']['name'], storage)
    receipt.phase('persistent-validated', sourcePreserved=True, silenceCount=len(silences), groups=len(records), integrations=2)
    cluster.delete('Pod', 'validator', namespace)
    wait('native validator mount released', lambda: get('pod', 'validator', namespace) is None)
    promote_storage(cluster, payload['storage'], source, identity)
    replacement = wait('native retained-state replacement', lambda: retained_replacement(
        cluster, source, identity, payload['storage'], claim['metadata']['name'], storage), timeout=300)
    verify_storage(namespace, claim['metadata']['name'], storage)
    replacement_identity = source_identity(replacement)
    record_generated(cluster)
    namespace_listener_profile(cluster)
    before_restore = native_reload_state(cluster)
    require(before_restore['successful'] and before_restore['original'] == maintenance_text,
            'Native replacement did not load exact maintenance configuration')
    source_unchanged(get('Pod', source, namespace), replacement_identity)
    cluster.patch('Secret', 'source-config', [{'op': 'replace', 'path': '/data/alertmanager.yaml',
                  'value': base64.b64encode(canonical(config)).decode()}], namespace)
    wait('native replacement restores original integrations', lambda: native_reloaded(
        cluster, original_text, before_restore['timestamp'], replacement_identity))
    native_validation(cluster, source, records, silences, 'FixtureReplacementControl')
    require_source_denied(cluster)
    deny_row = cluster.row('AuthorizationPolicy', 'source-quiescence', namespace)
    cluster.delete('AuthorizationPolicy', 'source-quiescence', namespace)
    deny_identity = {key: deny_row[key] for key in ('kind', 'name', 'namespace', 'uid')}
    wait('exact source DENY removal', lambda: deletion_finished(receipt, deny_identity))
    cluster.patch('NetworkPolicy', 'source-access', [{'op': 'replace', 'path': '/spec/ingress', 'value': access}], namespace)
    wait('persistent source ordinary client access restored', lambda: not request(namespace,
        'http://alertmanager-primary-0.alertmanager-operated:9093/api/v2/status', expected_denied=True).get('denied'))
    request(namespace, 'http://alertmanager-primary-0.alertmanager-operated:9093/api/v2/status')
    request(namespace, 'http://alertmanager-primary-0.alertmanager-operated:9093/api/v2/alerts', [alert('FixtureOrdinaryControl')])
    wait('ordinary native delivery restored', lambda: delivered(namespace, 'FixtureOrdinaryControl', 'firing'))
    require(replacement['metadata']['uid'] != identity['uid'], 'Native storage transition did not replace emptyDir Pod')
    receipt.phase('native-adoption-verified')
    record_generated(cluster)
    cleanup(cluster)
    physical = receipt.value['evidence'].get('backingFilesVerified', False)
    return {'qualified': physical, 'checkpointQualified': True, 'nativeRetentionVerified': True,
            'sourceAliveUntilValidation': True, 'sameCSIIdentity': True, 'backingFilesVerified': physical,
            'coverage': 'complete' if physical else 'partial: backing-file cleanup unverified'}


def main():
    global DIAGNOSTIC_DIRECTORY
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--run', action='store_true')
    mode.add_argument('--cleanup', action='store_true')
    mode.add_argument('--recover-stateless', action='store_true')
    mode.add_argument('--serve', action='store_true')
    mode.add_argument('--request', action='store_true')
    mode.add_argument('--held-http-probe', action='store_true')
    mode.add_argument('--write-checkpoint', action='store_true')
    mode.add_argument('--host-preflight', action='store_true')
    parser.add_argument('--directory')
    parser.add_argument('--operation')
    parser.add_argument('--input')
    parser.add_argument('--predecessor-directory')
    parser.add_argument('--driver-hash')
    parser.add_argument('--host-mode', choices=('fresh', 'cleanup'))
    args = parser.parse_args()
    if args.prepare:
        print(json.dumps(prepare()))
    elif args.serve:
        serve()
    elif args.request:
        http_request()
    elif args.held_http_probe:
        held_http_probe()
    elif args.write_checkpoint:
        write_checkpoint()
    elif args.host_preflight:
        require(os.geteuid() == 0, 'Host proof preflight requires existing server administrator')
        require(args.host_mode is not None, 'Host proof mode is required')
        host_preflight(args.directory, args.operation, args.driver_hash, args.host_mode == 'cleanup')
    else:
        require(os.geteuid() == 0, 'Cluster proof requires existing server administrator')
        if args.recover_stateless:
            print(json.dumps(recover_stateless(args.predecessor_directory, args.directory, args.operation, args.input)))
        elif args.cleanup:
            receipt = Receipt.load(args.directory, args.operation)
            DIAGNOSTIC_DIRECTORY = receipt.directory
            cleanup(Cluster(receipt))
            print(json.dumps({'cleanup': True, 'qualified': False}))
        else:
            payload = json.loads(Path(args.input).read_bytes())
            print(json.dumps(run(payload, args.directory, args.operation)))


def record_failure(error):
    if DIAGNOSTIC_DIRECTORY is None:
        return False
    try:
        directory = protected_directory(DIAGNOSTIC_DIRECTORY)
        path = directory / 'receipt.json'
        require(path.stat().st_size <= LIMIT, 'Failure receipt exceeds bound')
        phase = json.loads(path.read_bytes())['phase']
        require(re.fullmatch(r'[a-z-]{1,80}', phase), 'Invalid diagnostic phase')
        frames = []
        frame = error.__traceback__
        while frame:
            if frame.tb_frame.f_code.co_filename == __file__ and frame.tb_frame.f_code.co_name != 'require':
                frames.append({'function': frame.tb_frame.f_code.co_name, 'line': frame.tb_lineno})
            frame = frame.tb_next
        frames = frames[-4:]
        anonymous = {'<module>': 'module', '<lambda>': 'lambda', '<listcomp>': 'listcomp',
                     '<dictcomp>': 'dictcomp', '<setcomp>': 'setcomp', '<genexpr>': 'genexpr'}
        for row in frames:
            row['function'] = anonymous.get(row['function'], row['function'])
        name = type(error).__name__
        require(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,79}', name)
                and all(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,79}', row['function']) for row in frames),
                'Invalid diagnostic identity')
        raw = canonical({'exception': name, 'frames': frames, 'phase': phase})
        require(len(raw) <= 1024, 'Failure evidence exceeds bound')
        write_new(directory / ('failure-' + secrets.token_hex(8) + '.json'), raw)
        return True
    except Exception:
        # Failure reporting must never replace the original task failure.
        return False


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        record_failure(error)
        raise SystemExit(str(error) + '; protected operation retained') from None
    except Exception as error:
        record_failure(error)
        raise SystemExit('Checkpoint proof incomplete; inspect protected operation; diagnostics withheld') from None
