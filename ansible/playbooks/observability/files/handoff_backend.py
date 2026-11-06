"""Native, operation-bound Alertmanager checkpoint and phase execution.

The runner classifies YAML through a private challenge. Runtime checks bind that
classification to a fresh native process; a classification never proves DENY.
"""
import base64
import copy
from datetime import datetime, timezone
import http.client
import io as streams
import json
import math
import os
from pathlib import Path
import re
import secrets
import time

from playbooks.observability.files import checkpoint as cp, handoff as h, native_transport as transport

NAMESPACE = cp.NAMESPACE
PREFIX = '/api/v1/namespaces/' + NAMESPACE + '/'
MANAGER = '/apis/monitoring.coreos.com/v1/namespaces/' + NAMESPACE + '/alertmanagers/cloudlab'
STATEFULSET = '/apis/apps/v1/namespaces/' + NAMESPACE + '/statefulsets/alertmanager-cloudlab'
OPERATOR = '/apis/apps/v1/namespaces/' + NAMESPACE + '/deployments/cloudlab-prometheus-operator'
SOURCE = 'alertmanager-cloudlab-0'
DENY = 'cloudlab-observability-handoff-write-deny'
DENY_PATH = '/apis/security.istio.io/v1/namespaces/' + NAMESPACE + '/authorizationpolicies/' + DENY
CLAIM = 'alertmanager-cloudlab-db-alertmanager-cloudlab-0'
CONFIG_LIMIT = 1024 * 1024
PURPOSES = ('original', 'muted', 'restored')

PROBE = r'''
import http.client,json,os,socket,time
from pathlib import Path
root=Path('/tmp')
def state(value):
    target=root/'state.new';target.write_text(json.dumps(value));os.replace(target,root/'state.json')
try:
    connection=socket.create_connection(('alertmanager-cloudlab-0.alertmanager-operated.cloudlab-observability.svc',9093),timeout=5)
    def exchange():
        connection.sendall(b'GET /api/v2/status HTTP/1.1\r\nHost: alertmanager:9093\r\nConnection: keep-alive\r\n\r\n')
        response=http.client.HTTPResponse(connection);response.begin()
        if response.status!=200 or response.will_close or len(response.read(1048577))>1048576:raise RuntimeError()
        response.close()
    exchange();exchange();time.sleep(45);exchange()
    ready=time.monotonic();state({'stage':'ready','readyAt':ready,'requests':3,'idleSeconds':45,'connections':1})
    while not (root/'check').exists():
        if time.monotonic()-ready>=25:raise TimeoutError()
        time.sleep(.05)
    if time.monotonic()-ready>=25:raise TimeoutError()
    connection.settimeout(max(.001,40-(time.monotonic()-ready)))
    try:
        if connection.recv(1,socket.MSG_PEEK)!=b'':raise RuntimeError()
    except ConnectionError:pass
    if time.monotonic()-ready>=40:raise TimeoutError()
    state({'stage':'revoked','readyAt':ready,'connections':1})
except Exception:
    state({'stage':'inconclusive'})
time.sleep(14400)
'''
PROBE_READ = "import json,time;from pathlib import Path;p=Path('/tmp/state.json');v=json.loads(p.read_text()) if p.exists() else {'stage':'starting'};v['age']=time.monotonic()-v['readyAt'] if 'readyAt' in v else 0;print(json.dumps(v))"
FRESH_PROBE = r'''
import http.client,json,socket,urllib.error,urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None
try:
    with urllib.request.build_opener(NoRedirect).open('http://alertmanager-cloudlab-0.alertmanager-operated.cloudlab-observability.svc:9093/api/v2/status',timeout=5) as response:
        value={'outcome':'success' if response.status==200 and len(response.read(1048577))<=1048576 else 'inconclusive'}
except urllib.error.HTTPError as error:value={'outcome':'authorization' if error.code in (401,403) else 'inconclusive'}
except (urllib.error.URLError,TimeoutError,ConnectionError,http.client.HTTPException) as error:
    reason=error.reason if isinstance(error,urllib.error.URLError) else error
    value={'outcome':'inconclusive' if isinstance(reason,(socket.gaierror,TimeoutError)) else 'closed' if isinstance(reason,ConnectionError) else 'inconclusive'}
print(json.dumps(value))
'''
WRITER = r'''
import base64,hashlib,json,os,stat,sys
from pathlib import Path
value=json.load(sys.stdin);root=Path('/data');target=root/'alertmanager-db'
if not root.is_dir() or root.is_symlink() or set(value)!= {'files','hashes'} or set(value['files'])!={'nflog','silences'} or set(value['hashes'])!={'nflog','silences'}:raise RuntimeError('Invalid checkpoint input')
if target.exists():
    if target.is_symlink() or not target.is_dir() or set(p.name for p in target.iterdir())!={'nflog','silences'}:raise RuntimeError('Partial checkpoint retained')
else:target.mkdir(mode=0o700)
for name in ('nflog','silences'):
    raw=base64.b64decode(value['files'][name],validate=True);expected=value['hashes'][name]
    if len(raw)>8388608 or hashlib.sha256(raw).hexdigest()!=expected:raise RuntimeError('Checkpoint hash differs')
    path=target/name
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise RuntimeError('Checkpoint file differs')
    else:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
for directory in (target,root):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
print(json.dumps({name:hashlib.sha256((target/name).read_bytes()).hexdigest() for name in ('nflog','silences')}))
'''


class NativeConfigPending(RuntimeError):
    def __init__(self, purpose):
        h.require(purpose in PURPOSES, 'Unsupported native configuration purpose')
        self.purpose = purpose
        super().__init__('Private native configuration classification is pending')


def complete(value, maximum=2048):
    h.require(isinstance(value, dict) and isinstance(value.get('items'), list)
        and len(value['items']) <= maximum and not value.get('metadata', {}).get('continue'),
        'Native discovery is incomplete or excessive')
    return value['items']


def parse_native_http(raw):
    h.require(isinstance(raw, bytes) and len(raw) <= 2 * CONFIG_LIMIT, 'Native HTTP response exceeds bound')
    split = raw.find(b'\r\n\r\n')
    h.require(0 < split <= 32768, 'Native HTTP headers missing or excessive')
    lines, body = raw[:split].split(b'\r\n'), raw[split + 4:]
    h.require(re.fullmatch(rb'HTTP/1\.[01] 200(?: [\x20-\x7e]*)?', lines[0]) and len(lines) <= 101,
        'Native HTTP requires one exact200 response')
    headers = {}
    for line in lines[1:]:
        key, colon, value = line.partition(b':')
        h.require(colon and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
            and all(32 <= byte <= 126 or byte == 9 for byte in value), 'Malformed native HTTP header')
        headers.setdefault(key.lower(), []).append(value.strip().lower())
    length, transfer, encoding = (headers.get(key, []) for key in
        (b'content-length', b'transfer-encoding', b'content-encoding'))
    h.require(len(length) <= 1 and len(transfer) <= 1 and len(encoding) <= 1
        and not (length and transfer) and encoding in ([], [b'identity']), 'Ambiguous native HTTP framing')
    if length:
        h.require(re.fullmatch(rb'[0-9]{1,10}', length[0]) and int(length[0]) == len(body),
            'Truncated or trailing native HTTP response')
    else:
        h.require(transfer == [b'chunked'], 'Unsupported native HTTP framing')
        cursor, total, chunks = 0, 0, 0
        while True:
            end = body.find(b'\r\n', cursor)
            h.require(end >= cursor and re.fullmatch(rb'[0-9a-fA-F]{1,16}', body[cursor:end]), 'Invalid native chunk')
            size, cursor = int(body[cursor:end], 16), end + 2
            chunks += 1
            h.require(chunks <= 65536, 'Excessive native HTTP chunks')
            if not size:
                h.require(body[cursor:] == b'\r\n', 'Unexpected native HTTP trailer')
                break
            total += size
            h.require(total <= CONFIG_LIMIT and body[cursor + size:cursor + size + 2] == b'\r\n',
                'Native chunk truncated or excessive')
            cursor += size + 2
    class Socket:
        def makefile(self, *_args, **_kwargs):
            return streams.BytesIO(raw)
    response = http.client.HTTPResponse(Socket())
    try:
        response.begin()
        result = response.read(CONFIG_LIMIT + 1)
    except (http.client.HTTPException, ValueError):
        raise RuntimeError('Malformed native HTTP response') from None
    finally:
        response.close()
    h.require(len(result) <= CONFIG_LIMIT, 'Native HTTP body exceeds bound')
    return result


def reload_metrics(raw):
    names = ('alertmanager_config_last_reload_successful',
        'alertmanager_config_last_reload_success_timestamp_seconds',
        'alertmanager_nflog_maintenance_errors_total', 'alertmanager_silences_maintenance_errors_total')
    result = {}
    for name in names:
        rows = [line.split() for line in raw.decode('ascii').splitlines() if line.startswith(name + ' ')]
        h.require(len(rows) == 1 and len(rows[0]) == 2, 'Native reload or maintenance metric unavailable')
        value = float(rows[0][1])
        h.require(math.isfinite(value) and value >= 0, 'Invalid native metric')
        result[name] = value
    h.require(result[names[0]] == 1 and result[names[1]] > 0, 'Native configuration reload unsuccessful')
    return {'timestamp': result[names[1]], 'errors': {name: result[name] for name in names[2:]}}


def operator_scope(arguments, namespaces):
    """Conservative union, never an interpretation of label-selector equality."""
    h.require(isinstance(arguments, list) and all(isinstance(arg, str) and '$' not in arg for arg in arguments),
        'Unsupported Operator argument expansion')
    options = {}
    scope_keys = {'namespaces', 'deny-namespaces', 'alertmanager-instance-namespaces',
        'alertmanager-instance-selector', 'alertmanager-config-namespaces', 'secret-field-selector'}
    harmless = {'kubelet-service', 'kubelet-endpoints', 'kubelet-endpointslice', 'localhost', 'log-level',
        'log-format', 'prometheus-config-reloader', 'config-reloader-cpu-request', 'config-reloader-cpu-limit',
        'config-reloader-memory-request', 'config-reloader-memory-limit', 'labels', 'web.listen-address',
        'web.enable-tls', 'web.cert-file', 'web.key-file', 'web.client-ca-file', 'web.tls-min-version',
        'web.tls-cipher-suites', 'web.tls-reload-interval', 'prometheus-instance-selector',
        'thanos-ruler-instance-selector', 'controller-id', 'secret-watch-labels', 'kubelet-node-address-priority'}
    for arg in arguments:
        match = re.fullmatch(r'--([a-z][a-z0-9.-]*)(?:=(.*))?', arg)
        h.require(match and match[1] in scope_keys | harmless and match[1] not in options,
            'Unsupported or repeated Operator argument')
        options[match[1]] = match[2] if match[2] is not None else 'true'
    def named(key, fallback):
        if key not in options or options[key] == '': return set(fallback)
        rows = options[key].split(',')
        h.require(len(rows) == len(set(rows)) and all(re.fullmatch(r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?', row)
            and row in namespaces for row in rows), 'Operator watch namespace is unresolved')
        return set(rows)
    general = named('namespaces', namespaces)
    instances = named('alertmanager-instance-namespaces', general)
    configuration = named('alertmanager-config-namespaces', general)
    denied = named('deny-namespaces', set())
    # A selector can only narrow this union. Requiring zero configuration objects
    # throughout the superset avoids a second selector evaluator.
    h.require(not options.get('secret-field-selector'), 'Filtered Operator Secret discovery is unsupported')
    result = (general | instances | configuration) - denied
    h.require(NAMESPACE in result, 'Operator does not watch the singleton namespace')
    return sorted(result)


def private_bytes(path, raw):
    h.require(isinstance(raw, bytes) and len(raw) <= h.PRIVATE_LIMIT, 'Private native artifact exceeds bound')
    if h.private_path(path, missing=True) is not None:
        h.require(h.read_private(path, h.PRIVATE_LIMIT) == raw, 'Private native artifact changed')
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


class Backend:
    def __init__(self, io, directory, intent, journal=None, persist=None, sync_resources=None):
        self.io, self.directory, self.intent = io, Path(directory), intent
        self.journal, self.persist, self.sync_resources = journal, persist, sync_resources
        self.operation, self.phase = intent['operationId'], intent['phase']
        self.path = self.directory / 'backend.json'
        binding = {'operationId': self.operation, 'bundleSHA256': intent['prepared']['bundleSHA256'],
            'baselineSHA256': h.digest(h.canonical(intent['baseline']))}
        if h.private_path(self.path, missing=True) is None:
            self.state = binding | {'mutations': {}, 'classifications': {}}
            self.save()
        else:
            self.state = h.phase_json(self.path)
            h.require(all(self.state.get(key) == value for key, value in binding.items()), 'Backend operation authority changed')
        pins = intent['qualifications']['references']['checkpoint']['imagePins'].values()
        self.pins = {name: next((value for value in pins if value.startswith(prefix)), '') for name, prefix in
            (('operator', 'quay.io/prometheus-operator/prometheus-operator:'),
             ('alertmanager', 'quay.io/prometheus/alertmanager:'))}
        cp.approved_pins(self.pins)

    def save(self):
        h.atomic_private(self.path, self.state, h.PRIVATE_LIMIT)

    def get(self, path):
        value = self.io.request(path)
        h.require(value is not None, 'Required native object is unavailable')
        return value

    def list(self, resource, namespace=None):
        args = ['get', resource, '--show-managed-fields=true', '-o', 'json', '--chunk-size=0']
        args += ['-n', namespace] if namespace else ['--all-namespaces']
        return complete(h.strict_json(self.io.command(args), h.PRIVATE_LIMIT))

    def source(self):
        pod = self.get(PREFIX + 'pods/' + SOURCE)
        actual = cp.source_identity(pod)
        expected = self.state.get('replacementSource', self.state.get('source'))
        if expected is not None: h.require(actual == expected, 'Native source process changed')
        h.require(any(row.get('type') == 'Ready' and row.get('status') == 'True'
            for row in pod.get('status', {}).get('conditions', [])), 'Native source is not Ready')
        return pod

    def native(self, path, pod=None, container='alertmanager'):
        h.require(path in ('/api/v2/status', '/metrics', '/api/v2/silences', '/-/ready'), 'Unsupported native read')
        pod = self.source() if pod is None else pod
        before = process_identity(pod, container)
        payload = ('GET ' + path + ' HTTP/1.1\r\nHost: 127.0.0.1:9093\r\nConnection: close\r\n'
            'Accept-Encoding: identity\r\nContent-Length: 0\r\n\r\n').encode()
        raw = self.io.command(['exec', '-i', '-n', NAMESPACE, pod['metadata']['name'], '-c', container,
            '--', '/bin/nc', '-n', '-w', '8', '127.0.0.1', '9093'], body=payload,
            limit=2 * CONFIG_LIMIT, timeout=20)
        after = self.get(PREFIX + 'pods/' + pod['metadata']['name'])
        h.require(process_identity(after, container) == before, 'Native read process changed')
        return parse_native_http(raw)

    def native_state(self):
        pod = self.source()
        raw = self.native('/api/v2/status', pod)
        status = h.strict_json(raw, CONFIG_LIMIT)
        original = status.get('config', {}).get('original')
        h.require(isinstance(original, str) and 0 < len(original.encode()) <= CONFIG_LIMIT, 'Loaded native configuration absent')
        metrics = reload_metrics(self.native('/metrics', pod))
        h.require(cp.source_identity(self.source()) == cp.source_identity(pod), 'Native configuration source changed')
        return {'source': cp.source_identity(pod), 'configSHA256': h.digest(original.encode()),
            'reloadTimestamp': metrics['timestamp'], 'errors': metrics['errors']}, raw

    def operator(self):
        deployment = self.get(OPERATOR)
        h.require(deployment['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') ==
            'cloudlab-prometheus:apps/Deployment:' + NAMESPACE + '/cloudlab-prometheus-operator', 'Operator owner changed')
        containers = deployment['spec']['template']['spec'].get('containers', [])
        h.require(len(containers) == 1 and containers[0].get('image') == self.pins['operator']
            and containers[0].get('command', []) in ([], ['/bin/operator'])
            and not containers[0].get('env') and not containers[0].get('envFrom'), 'Operator executable profile unsupported')
        pods = [row for row in self.list('pods', NAMESPACE)
            if all(row['metadata'].get('labels', {}).get(key) == value
                for key, value in deployment['spec']['selector']['matchLabels'].items())]
        h.require(len(pods) == 1, 'Operator process discovery is ambiguous')
        pod = pods[0]
        references = pod['metadata'].get('ownerReferences', [])
        h.require(len(references) == 1 and references[0].get('kind') == 'ReplicaSet' and references[0].get('controller') is True,
            'Operator Pod lineage is unsupported')
        replica = self.get('/apis/apps/v1/namespaces/' + NAMESPACE + '/replicasets/' + references[0]['name'])
        h.require(replica['metadata']['uid'] == references[0]['uid'] and replica['metadata'].get('ownerReferences') == [{
            'apiVersion': 'apps/v1', 'kind': 'Deployment', 'name': deployment['metadata']['name'],
            'uid': deployment['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}], 'Operator controller lineage changed')
        actual = pod['spec']['containers']
        h.require(len(actual) == 1 and all(actual[0].get(key, []) == containers[0].get(key, [])
            for key in ('image', 'command', 'args', 'env', 'envFrom')), 'Operator Pod differs from owned Deployment')
        identity = process_identity(pod, containers[0]['name'])
        namespaces = {row['metadata']['name'] for row in complete(self.get('/api/v1/namespaces'))}
        scope = operator_scope(containers[0].get('args', []), namespaces)
        configurations = self.list('alertmanagerconfigs.monitoring.coreos.com')
        h.require(not [row for row in configurations if row['metadata'].get('namespace') in scope],
            'Operator scope contains AlertmanagerConfig resources')
        result = {'deployment': cp.identity(deployment), 'specSHA256': h.digest(h.canonical(deployment['spec'])),
            'process': identity, 'scope': scope}
        if 'operator' in self.state: h.require(result == self.state['operator'], 'Operator process or watch scope changed')
        return result

    def create(self, key, path, document):
        h.require(self.journal is not None, 'Backend creation requires protected execution authority')
        target = path + '/' + document['metadata']['name']
        rows = self.state['mutations']
        row = rows.get(key)
        if row is not None:
            h.require(row['path'] == target and row['document'] == document, 'Owned creation intent changed')
            h.require(row.get('uid'), 'Creation acknowledgement is unknown; object retained')
            current = self.get(target)
            h.require(current['metadata']['uid'] == row['uid'], 'Owned object UID changed')
            return current
        h.require(self.io.request(target) is None, 'Existing object cannot be adopted by a handoff')
        rows[key] = {'path': target, 'document': document, 'uid': None, 'deleted': False}
        self.save()
        current = self.io.request(path, 'POST', document)
        h.require(current is not None and current['metadata'].get('name') == document['metadata']['name']
            and current['metadata'].get('namespace') == document['metadata'].get('namespace')
            and current.get('spec', current.get('data')) is not None, 'Owned creation acknowledgement differs')
        cp.identity(current)
        rows[key]['uid'] = current['metadata']['uid']
        rows[key]['acknowledgementSHA256'] = h.digest(h.canonical(current))
        self.save()
        return current

    def remove(self, key):
        row = self.state['mutations'].get(key)
        h.require(row and row.get('uid'), 'Cleanup has no acknowledged identity')
        current = self.io.request(row['path'])
        if current is None:
            h.require(row.get('deletion'), 'Unrequested disappearance of an owned object')
            row['deleted'] = True; self.save(); return
        h.require(not row['deleted'] and current['metadata']['uid'] == row['uid'], 'Cleanup target UID changed')
        if not row.get('deletion'):
            row['deletion'] = {key: current['metadata'][key] for key in ('uid', 'resourceVersion')}
            self.save()
            self.io.request(row['path'], 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                'preconditions': row['deletion'], 'propagationPolicy': 'Foreground'})
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            remaining = self.io.request(row['path'])
            if remaining is None:
                row['deleted'] = True; self.save(); return
            h.require(remaining['metadata']['uid'] == row['uid'], 'Cleanup target was replaced')
            time.sleep(2)
        raise RuntimeError('Owned temporary object cleanup did not complete')

    def pod(self, role, image, command, volumes=None, mounts=None, security=None):
        names = {'probe': 'cloudlab-handoff-probe-', 'writer': 'cloudlab-checkpoint-writer-',
            'validator': 'cloudlab-checkpoint-'}
        h.require(role in names, 'Unknown backend Pod role')
        return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': names[role] + self.operation,
            'namespace': NAMESPACE, 'labels': {'cloudlab.io/observability-handoff': self.operation,
                'cloudlab.io/handoff-role': role}}, 'spec': {
            'automountServiceAccountToken': False, 'serviceAccountName': 'default', 'restartPolicy': 'Never',
            'securityContext': security or {'runAsNonRoot': True, 'runAsUser': 65534, 'runAsGroup': 65534,
                'fsGroup': 65534, 'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': role, 'image': image, 'command': command,
                'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                    'capabilities': {'drop': ['ALL']}},
                'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '128Mi'}},
                'volumeMounts': mounts or []}], 'volumes': volumes or []}}

    def owned_pod(self, key, container):
        row = self.state['mutations'][key]
        pod = self.get(row['path'])
        h.require(pod['metadata']['uid'] == row['uid'] and not pod['metadata'].get('ownerReferences')
            and not pod['spec'].get('ephemeralContainers') and not pod['spec'].get('hostNetwork')
            and pod['spec'].get('automountServiceAccountToken') is False, 'Owned Pod identity or isolation changed')
        expected = row['document']['spec']
        actual = pod['spec']
        h.require(not actual.get('initContainers') and not actual.get('hostPID') and not actual.get('hostIPC')
            and actual.get('serviceAccountName', 'default') == expected.get('serviceAccountName', 'default')
            and actual.get('restartPolicy') == expected.get('restartPolicy')
            and actual.get('securityContext') == expected.get('securityContext')
            and len(actual.get('containers', [])) == len(expected['containers']) == 1
            and all(actual['containers'][0].get(field) == value for field, value in expected['containers'][0].items())
            and set(actual['containers'][0]) <= set(expected['containers'][0]) |
                {'imagePullPolicy', 'terminationMessagePath', 'terminationMessagePolicy'}
            and actual['containers'][0].get('imagePullPolicy') in ('IfNotPresent', 'Always')
            and len(actual.get('volumes', [])) == len(expected.get('volumes', [])), 'Owned Pod executable profile changed')
        for observed, desired in zip(actual.get('volumes', []), expected.get('volumes', [])):
            h.require(set(observed) == set(desired) and all(observed.get(field) == value
                if not isinstance(value, dict) else all(observed[field].get(k) == v for k, v in value.items())
                and set(observed[field]) <= set(value) | ({'defaultMode'} if field == 'configMap' else set())
                for field, value in desired.items()), 'Owned Pod volume profile changed')
        process_identity(pod, container)
        return pod

    def exec_owned(self, key, container, arguments, body=None, limit=CONFIG_LIMIT, timeout=30):
        pod = self.owned_pod(key, container)
        before = process_identity(pod, container)
        raw = self.io.command(['exec', '-i', '-n', NAMESPACE, pod['metadata']['name'], '-c', container,
            '--', *arguments], body=body, limit=limit, timeout=timeout)
        h.require(process_identity(self.owned_pod(key, container), container) == before, 'Owned exec process changed')
        return raw

    def wait_owned(self, key, container):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            pod = self.get(self.state['mutations'][key]['path'])
            h.require(pod['metadata']['uid'] == self.state['mutations'][key]['uid']
                and pod.get('status', {}).get('phase') not in ('Failed', 'Succeeded'), 'Owned Pod exited or changed')
            statuses = pod.get('status', {}).get('containerStatuses', [])
            if any(row.get('name') == container and row.get('state', {}).get('running') for row in statuses):
                return self.owned_pod(key, container)
            time.sleep(2)
        raise RuntimeError('Owned Pod startup exceeded its bound')

    def authorization_context(self):
        pod = self.source()
        probe = self.owned_pod('probe', 'probe')
        namespace = self.get('/api/v1/namespaces/' + NAMESPACE)
        h.require(namespace['metadata'].get('labels', {}).get('istio.io/dataplane-mode') == 'ambient'
            and 'sidecar.istio.io/status' not in pod['metadata'].get('annotations', {})
            and pod['spec'].get('hostNetwork', False) is False, 'Source ambient enrollment is unsupported')
        services = self.list('services', NAMESPACE)
        target = [row for row in services if row['metadata']['name'] == 'alertmanager-operated']
        h.require(len(target) == 1 and target[0]['spec'].get('clusterIP') == 'None', 'Native headless Service changed')
        service = target[0]
        for row in services:
            selector = row['spec'].get('selector')
            h.require(not selector or not all(probe['metadata'].get('labels', {}).get(key) == value
                for key, value in selector.items()), 'Probe unexpectedly matches a Service selector')
        selector = service['spec'].get('selector', {})
        h.require(selector and all(pod['metadata'].get('labels', {}).get(key) == value for key, value in selector.items())
            and any(port.get('port') == 9093 and port.get('targetPort') in (9093, 'http-web')
                for port in service['spec'].get('ports', [])), 'Source Service binding changed')
        endpoints = self.get(PREFIX + 'endpoints/alertmanager-operated')
        addresses = [address for subset in endpoints.get('subsets', [])
            for address in subset.get('addresses', []) + subset.get('notReadyAddresses', [])]
        h.require(len(addresses) == 1 and addresses[0].get('targetRef', {}).get('uid') == pod['metadata']['uid']
            and addresses[0].get('targetRef', {}).get('name') == SOURCE
            and addresses[0].get('ip') in {row['ip'] for row in pod['status'].get('podIPs', [])},
            'Native endpoint does not identify the singleton')
        def policies(resource):
            return sorted([{'namespace': row['metadata'].get('namespace'), 'name': row['metadata']['name'],
                'uid': row['metadata']['uid'], 'spec': row.get('spec', {})}
                for row in self.list(resource)
                if not (resource == 'authorizationpolicies.security.istio.io'
                    and row['metadata'].get('namespace') == NAMESPACE and row['metadata']['name'] == DENY)],
                key=lambda row: (row['namespace'] or '', row['name']))
        peers = policies('peerauthentications.security.istio.io')
        h.require(any(row['namespace'] == 'istio-system' and row['spec'].get('mtls', {}).get('mode') == 'STRICT'
            and not row['spec'].get('selector') for row in peers), 'Root STRICT mesh policy is unavailable')
        value = {'namespace': cp.identity(namespace), 'labels': namespace['metadata'].get('labels', {}),
            'source': cp.source_identity(pod), 'sourceSpec': pod['spec'],
            'probe': process_identity(probe, 'probe'), 'probeSpec': probe['spec'],
            'service': cp.identity(service), 'serviceSpec': service['spec'],
            'endpoint': cp.identity(endpoints), 'addresses': addresses,
            'peers': peers, 'authorization': policies('authorizationpolicies.security.istio.io'),
            'network': policies('networkpolicies.networking.k8s.io')}
        self.context_value = value
        return h.digest(h.canonical(value))

    def fresh_probe(self):
        result = h.strict_json(self.exec_owned('probe', 'probe', ['python', '-c', FRESH_PROBE], limit=4096), 4096)
        h.require(isinstance(result, dict) and set(result) == {'outcome'}
            and result['outcome'] in ('success', 'authorization', 'closed', 'inconclusive'), 'Invalid probe response')
        return result['outcome']

    def deny_transition(self, sync_configuration):
        if self.state.get('denied'):
            h.require(self.authorization_context() == self.state['authorizationContext']
                and self.fresh_probe() in ('authorization', 'closed'), 'Native writer isolation no longer holds')
            return
        h.require(self.io.request(DENY_PATH) is None, 'Existing DENY cannot become handoff authority')
        pod = self.pod('probe', transport.PYTHON_IMAGE, ['python', '-u', '-c', PROBE],
            [{'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '4Mi'}}],
            [{'name': 'tmp', 'mountPath': '/tmp'}])
        self.create('probe', PREFIX + 'pods', pod)
        self.wait_owned('probe', 'probe')
        h.require(self.fresh_probe() == 'success', 'Pre-DENY native HTTP200 control failed')
        context = self.authorization_context()
        deadline = time.monotonic() + 80
        while time.monotonic() < deadline:
            start = time.monotonic()
            state = h.strict_json(self.exec_owned('probe', 'probe', ['python', '-c', PROBE_READ], limit=4096), 4096)
            if state.get('stage') == 'ready':
                h.require(state.get('requests') == 3 and state.get('connections') == 1 and state.get('idleSeconds') == 45
                    and type(state.get('age')) in (int, float) and math.isfinite(state['age']) and 0 <= state['age'] < 25,
                    'Held connection positive controls differ')
                control = start + 25 - state['age']
                revoke = start + 40 - state['age']
                break
            h.require(state.get('stage') == 'starting', 'Held connection positive controls failed')
            time.sleep(.1)
        else:
            raise RuntimeError('Held connection positive controls exceeded bound')
        h.require(time.monotonic() < control, 'Held control deadline expired')
        with self.io.bounded(control):
            h.require(self.authorization_context() == context, 'Authorization context changed before DENY')
            sync_configuration(control)
            self.exec_owned('probe', 'probe', ['python', '-c', "from pathlib import Path;Path('/tmp/check').write_text('check')"])
        with self.io.bounded(revoke):
            while time.monotonic() < revoke:
                result = h.strict_json(self.exec_owned('probe', 'probe', ['python', '-c', PROBE_READ], limit=4096), 4096)
                if result.get('stage') == 'revoked': break
                h.require(result.get('stage') == 'ready', 'Held connection revocation is inconclusive')
                time.sleep(.1)
            else:
                raise RuntimeError('Held connection was not revoked within its original deadline')
            h.require(self.fresh_probe() in ('authorization', 'closed')
                and self.authorization_context() == context, 'Fresh DENY control failed or context changed')
        source = self.source()
        container = next(row for row in source['spec']['containers'] if row['name'] == 'alertmanager')
        readiness = container.get('readinessProbe', {})
        h.require(readiness.get('httpGet', {}).get('path') == '/-/ready', 'Unknown native readiness profile')
        period, failures, timeout = (readiness.get('periodSeconds', 10), readiness.get('failureThreshold', 3),
            readiness.get('timeoutSeconds', 1))
        h.require(all(type(value) is int and value > 0 for value in (period, failures, timeout)), 'Invalid readiness window')
        window = period * failures + timeout + 2
        h.require(window <= 300, 'Native readiness window exceeds supported bound')
        end = time.monotonic() + window
        while time.monotonic() < end:
            self.source()
            h.require(self.authorization_context() == context and self.fresh_probe() in ('authorization', 'closed'),
                'Source readiness or writer isolation changed')
            time.sleep(min(2, max(0, end - time.monotonic())))
        self.state['denied'], self.state['authorizationContext'] = True, context
        self.state['authorizationContextValue'] = self.context_value
        self.save()

    def quiescent(self):
        h.require(self.state.get('denied') is True and self.authorization_context() == self.state['authorizationContext']
            and self.fresh_probe() in ('authorization', 'closed'), 'Native source is not isolated')
        self.operator()
        native = self.classify('muted')
        if 'maintenanceErrors' in self.state:
            h.require(native['errors'] == self.state['maintenanceErrors'], 'Native maintenance errors advanced')
        return True

    def inventory(self, application, phase=None):
        phase = self.phase if phase is None else phase
        packet = h.phase_json(h.phase_file(self.directory, phase, 'resources'))
        record = h.phase_json(h.phase_file(self.directory, phase, 'record'))
        h.require(record['payloadSHA256'] == h.digest(h.canonical(packet))
            and packet['custody']['objectsSHA256'] == h.digest(h.canonical(packet['objects'])),
            'Backend inventory is not the authenticated phase record')
        return packet['objects'][application]

    def resource(self, application, kind, name, phase=None):
        rows = [row for row in self.inventory(application, phase) if row['kind'] == kind
            and row['metadata']['name'] == name and row['metadata'].get('namespace', '') in ('', NAMESPACE)]
        h.require(len(rows) == 1, 'Backend resource is absent or ambiguous in the authenticated inventory')
        return rows[0]

    def sync(self, application, resources, *, prune=False, deadline=None):
        h.require(callable(self.sync_resources) and self.journal is not None, 'Backend Sync requires execution authority')
        return self.sync_resources(self.io, self.directory, self.phase, self.journal,
            application, resources, prune=prune, deadline=deadline)

    def wait_reload(self, previous):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            current, _ = self.native_state()
            if current['reloadTimestamp'] > previous: return current
            time.sleep(2)
        raise RuntimeError('Native successful configuration reload did not advance')

    def reload_after_secret_sync(self, previous):
        """One fixed, empty localhost POST; never a caller-controlled HTTP writer."""
        h.require(self.phase in ('maintenance', 'persistent-normal') and self.journal is not None
            and self.journal.get('authorization', {}).get('operationId') == self.operation
            and self.state.get('denied') is True, 'Native reload requires fenced isolated execution')
        owned = self.journal.get('steps', {}).get('owned-deny')
        deny = self.get(DENY_PATH)
        h.require(owned and transport.identity(deny) == owned['identity'] and deny['spec'] == owned['spec'],
            'Native reload lost its exact owned DENY')
        secret = self.resource('cloudlab-prometheus', 'Secret', 'alertmanager-cloudlab')
        selectors = [{'kind': 'Secret', 'namespace': NAMESPACE, 'name': 'alertmanager-cloudlab'}]
        key = self.phase + ':sync:cloudlab-prometheus:' + h.digest(h.canonical(selectors))
        sync = self.journal['steps'].get(key)
        h.require(sync and sync.get('complete') is True
            and sync['intent']['operation']['sync']['resources'] == selectors,
            'Native reload must follow the exact authenticated Secret Sync')
        current, _ = self.native_state()
        if current['reloadTimestamp'] > previous:
            return current
        key = self.phase + ':native-reload'
        row = self.state['mutations'].get(key)
        if row is None:
            row = {'source': current['source'], 'previousTimestamp': previous,
                'secretSHA256': h.digest(h.canonical(secret)), 'acknowledged': False}
            self.state['mutations'][key] = row
            self.save()
        h.require(row['source'] == current['source'] and row['previousTimestamp'] == previous
            and row['secretSHA256'] == h.digest(h.canonical(secret)), 'Native reload source intent changed')
        if not row['acknowledged']:
            h.require(not row.get('requested'), 'Native reload acknowledgement is unknown; fresh native evidence required')
            row['requested'] = True
            self.save()
            pod = self.source()
            identity = cp.source_identity(pod)
            payload = (b'POST /-/reload HTTP/1.1\r\nHost: 127.0.0.1:9093\r\nConnection: close\r\n'
                b'Accept-Encoding: identity\r\nContent-Length: 0\r\n\r\n')
            raw = self.io.command(['exec', '-i', '-n', NAMESPACE, SOURCE, '-c', 'alertmanager', '--',
                '/bin/nc', '-n', '-w', '8', '127.0.0.1', '9093'], body=payload,
                limit=2 * CONFIG_LIMIT, timeout=20)
            h.require(cp.source_identity(self.source()) == identity, 'Native reload source process changed')
            h.require(parse_native_http(raw) == b'', 'Native reload response differs from the pinned empty response')
            row['acknowledged'] = True
            self.save()
        return self.wait_reload(previous)

    def storage_objects(self):
        claim = self.get(PREFIX + 'persistentvolumeclaims/' + CLAIM)
        handle = claim['spec'].get('volumeName')
        h.require(isinstance(handle, str) and re.fullmatch(r'pvc-' + cp.UID.pattern, handle), 'Native claim handle differs')
        pv = self.get('/api/v1/persistentvolumes/' + handle)
        volume = self.get('/apis/longhorn.io/v1beta2/namespaces/longhorn-system/volumes/' + handle)
        return claim, pv, volume

    def storage_identity_binding(self):
        claim, pv, volume = self.storage_objects()
        desired = self.resource('cloudlab-observability', 'StorageClass', 'cloudlab-telemetry', 'baseline')
        current = self.get('/apis/storage.k8s.io/v1/storageclasses/cloudlab-telemetry')
        binding = cp.fresh_storage_identity(claim, pv, volume, current, self.state['storageBaseline'],
            self.state['claimDocument'], desired)
        if 'storage' in self.state: h.require(binding == self.state['storage'], 'Retained storage identities changed')
        return binding, volume

    def storage_binding(self, usage='mounted', consumer='source'):
        binding, volume = self.storage_identity_binding()
        # A detached claim must have no Pod consumer before any mount/fsGroup
        # operation. A mounted claim may belong only to the exact recorded actor.
        pods = [pod for pod in self.list('pods', NAMESPACE) if any(
            row.get('persistentVolumeClaim', {}).get('claimName') == CLAIM for row in pod.get('spec', {}).get('volumes', []))]
        if usage == 'unmounted':
            h.require(not pods, 'Unexpected Pod references the unmounted checkpoint claim')
        else:
            h.require(usage == 'mounted' and consumer in ('writer', 'validator', 'source'), 'Unsupported checkpoint consumer')
            expected = (self.state.get('replacementSource') if consumer == 'source'
                else self.state['mutations'].get(consumer))
            h.require(expected and len(pods) == 1 and pods[0]['metadata'].get('uid') == expected.get('uid')
                and not pods[0]['metadata'].get('deletionTimestamp'), 'Checkpoint claim has an unexpected or ambiguous consumer')
            node = pods[0]['spec'].get('nodeName')
            h.require(isinstance(node, str) and node, 'Checkpoint consumer has no assigned node')
            if volume.get('status', {}).get('state') == 'attached':
                h.require(volume['spec'].get('nodeID') == volume['status'].get('currentNodeID') == node,
                    'Checkpoint backing storage is attached to another node')
        cp.storage_usage(volume, usage)
        return binding

    def wait_storage(self, usage, consumer='source', timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                return self.storage_binding(usage, consumer)
            except cp.StorageUsageNotReady:
                # Only attachment/replica convergence is transient. Every poll
                # repeats complete freshness and ownership validation first.
                time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise RuntimeError('Checkpoint storage consumer state did not converge')

    def mount_consumer(self, key, document):
        h.require(key in ('writer', 'validator'), 'Unsupported temporary checkpoint consumer')
        if key not in self.state['mutations']:
            self.wait_storage('unmounted')
        self.create(key, PREFIX + 'pods', document)
        self.wait_owned(key, key)
        self.wait_storage('mounted', key)

    def write_checkpoint(self, values, writer):
        if self.state['mutations'].get('writer', {}).get('deleted'):
            h.require(self.state.get('checkpointWritten') is True, 'Checkpoint writer completion is absent')
            self.storage_identity_binding()
            if not (self.state['mutations'].get('validator') and not self.state['mutations']['validator'].get('deleted')):
                self.wait_storage('unmounted')
            return
        self.mount_consumer('writer', writer)
        self.quiescent()
        self.wait_storage('mounted', 'writer')
        body = h.canonical({'files': {name: base64.b64encode(raw).decode() for name, raw in values.items()},
            'hashes': self.state['checkpoint']})
        result = h.strict_json(self.exec_owned('writer', 'writer', ['python', '-c', WRITER], body=body,
            limit=4096), 4096)
        h.require(result == self.state['checkpoint'], 'Native checkpoint writer hashes differ')
        self.state['checkpointWritten'] = True
        self.save()
        self.remove('writer')
        self.wait_storage('unmounted')

    def snapshot_metadata(self):
        self.source()
        raw = self.io.command(['exec', '-n', NAMESPACE, SOURCE, '-c', 'alertmanager', '--',
            '/bin/sh', '-c', cp.SNAPSHOT_SCRIPT], limit=4096, timeout=20)
        self.source()
        return cp.snapshot_metadata(raw)

    def checkpoint_values(self):
        if self.state.get('checkpoint'):
            payload = self.directory / 'checkpoint'
            result = {name: h.read_private(payload / name, cp.LIMIT // 2) for name in cp.FILES}
            h.require({name: h.digest(raw) for name, raw in result.items()} == self.state['checkpoint'],
                'Protected checkpoint bytes changed')
            self.quiescent()
            return result
        self.quiescent()
        observation = self.state.get('generations')
        if observation is None:
            boundary, baseline, _ = self.snapshot_metadata()
            observation = {'boundary': boundary, 'baseline': baseline, 'seen': {name: [] for name in cp.FILES},
                'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'deadlineMonotonic': time.monotonic() + 2040}
            self.state['generations'] = observation
            self.save()
        h.require(observation['bootID'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'Checkpoint wait crossed a host restart')
        generations = cp.Generations(observation['boundary'], observation['baseline'])
        generations.seen = {name: {tuple(row) for row in observation['seen'][name]} for name in cp.FILES}
        while time.monotonic() < observation['deadlineMonotonic']:
            self.quiescent()
            _, metadata, _ = self.snapshot_metadata()
            ready = generations.observe(metadata)
            observation['seen'] = {name: [list(row) for row in sorted(generations.seen[name])] for name in cp.FILES}
            self.save()
            if ready: break
            time.sleep(min(15, max(0, observation['deadlineMonotonic'] - time.monotonic())))
        else:
            raise RuntimeError('Two post-quiescence native generations did not complete')
        def archive():
            return self.io.command(['exec', '-n', NAMESPACE, SOURCE, '-c', 'alertmanager', '--',
                '/bin/tar', '-C', '/alertmanager', '-cf', '-', 'nflog', 'silences'], limit=cp.LIMIT, timeout=30)
        values = cp.capture(self.source, self.snapshot_metadata, archive, self.quiescent, self.state['source'], generations)
        payload = self.directory / 'checkpoint'
        if not payload.exists(): payload.mkdir(mode=0o700)
        hashes = cp.write_payloads(payload, values)
        self.state['checkpoint'] = hashes
        self.save()
        return values

    def checkpoint_and_validate(self):
        if self.state.get('checkpointValidated'):
            self.wait_storage('mounted' if self.state.get('replacementSource') else 'unmounted')
            self.quiescent()
            return
        values = self.checkpoint_values()
        if 'storageBaseline' not in self.state:
            h.require(self.io.request(PREFIX + 'persistentvolumeclaims/' + CLAIM) is None,
                'Existing retained claim cannot become a fresh checkpoint')
            storage_class = self.get('/apis/storage.k8s.io/v1/storageclasses/cloudlab-telemetry')
            pvs = complete(self.get('/api/v1/persistentvolumes'))
            volumes = complete(self.get('/apis/longhorn.io/v1beta2/namespaces/longhorn-system/volumes'))
            def observed(rows):
                return {field: sorted(h.digest(row['metadata'][key].encode()) for row in rows)
                    for field, key in (('uids', 'uid'), ('names', 'name'))}
            self.state['storageBaseline'] = {'complete': True,
                'boundary': datetime.now(timezone.utc).isoformat(), 'storageClassUID': storage_class['metadata']['uid'],
                'pvs': observed(pvs), 'volumes': observed(volumes)}
            manager = self.resource('cloudlab-prometheus', 'Alertmanager', 'cloudlab')
            self.state['claimDocument'] = cp.final_claim(self.get(STATEFULSET), self.source(),
                manager['spec']['storage'], self.operation, self.pins)
            self.save()
        self.create('claim', PREFIX + 'persistentvolumeclaims', self.state['claimDocument'])
        if 'storage' not in self.state:
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                claim = self.get(PREFIX + 'persistentvolumeclaims/' + CLAIM)
                if claim.get('status', {}).get('phase') == 'Bound':
                    binding = self.wait_storage('unmounted')
                    break
                time.sleep(2)
            else:
                raise RuntimeError('Fresh retained claim did not become Bound')
            self.state['storage'] = binding; self.save()
        else:
            self.storage_identity_binding()
        source = self.source()
        main = next(row for row in source['spec']['containers'] if row['name'] == 'alertmanager')
        security = source['spec'].get('securityContext', {})
        native_security = {key: main.get('securityContext', {}).get(key, security.get(key)) for key in ('runAsUser', 'runAsGroup')}
        h.require(all(type(value) is int and value > 0 for value in native_security.values())
            and type(security.get('fsGroup')) is int and security['fsGroup'] > 0, 'Unsupported native state UID/group')
        native_security.update({'runAsNonRoot': True, 'fsGroup': security['fsGroup'], 'seccompProfile': {'type': 'RuntimeDefault'}})
        writer = self.pod('writer', transport.PYTHON_IMAGE, ['python', '-c', 'import time;time.sleep(3600)'],
            [{'name': 'data', 'persistentVolumeClaim': {'claimName': CLAIM}}],
            [{'name': 'data', 'mountPath': '/data'}], native_security)
        self.write_checkpoint(values, writer)
        h.require(self.state.get('checkpointWritten') is True, 'Checkpoint writer completion is absent')
        plan = cp.validation_plan(source, self.get(PREFIX + 'persistentvolumeclaims/' + CLAIM),
            'cloudlab-checkpoint-' + self.operation, self.pins)
        name = plan['pod']['metadata']['name']
        configuration = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': name, 'namespace': NAMESPACE},
            'data': {'alertmanager.yaml': h.canonical(plan['configuration']).decode()}}
        if self.state.get('nativeDiskValidated'):
            self.remove('validator'); self.remove('validation-config')
            self.wait_storage('unmounted'); self.quiescent()
            self.state['checkpointValidated'] = True; self.save(); return
        self.create('validation-config', PREFIX + 'configmaps', configuration)
        self.mount_consumer('validator', plan['pod'])
        silences = silence_state(h.strict_json(self.native('/api/v2/silences'), CONFIG_LIMIT))
        def validate():
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                pod = self.owned_pod('validator', 'validator')
                try:
                    self.native('/-/ready', pod, 'validator')
                    break
                except RuntimeError:
                    self.owned_pod('validator', 'validator')
                time.sleep(2)
            else:
                raise RuntimeError('Native checkpoint validator did not become ready')
            self.quiescent(); self.wait_storage('mounted', 'validator')
            pod = self.owned_pod('validator', 'validator')
            loaded = h.strict_json(self.native('/api/v2/silences', pod, 'validator'), CONFIG_LIMIT)
            h.require(silence_state(loaded) == silences, 'Native checkpoint silence contents differ')
            reload_metrics(self.native('/metrics', pod, 'validator'))
            logs = self.io.command(['logs', '-n', NAMESPACE, name, '-c', 'validator', '--limit-bytes=1048576'],
                limit=CONFIG_LIMIT)
            h.require(not re.search(rb'(?i)(?:level[=:]["\x27]?(?:warn|error)|corrupt|failed to (?:load|read))', logs),
                'Native checkpoint validator reports a loading error')
            self.quiescent()
        cp.with_preserved_source(validate, self.source, self.state['source'])
        self.state['validatedSilencesSHA256'] = h.digest(h.canonical(silences))
        self.state['nativeDiskValidated'] = True
        self.save()
        self.remove('validator'); self.remove('validation-config')
        self.wait_storage('unmounted'); self.quiescent()
        self.state['checkpointValidated'] = True
        self.save()

    def replacement(self):
        h.require(self.state.get('checkpointValidated') is True, 'Storage replacement precedes native disk validation')
        expected_manager = self.resource('cloudlab-prometheus', 'Alertmanager', 'cloudlab')
        manager = self.get(MANAGER)
        h.require(manager['metadata']['uid'] == self.state['binding']['objects']['manager']['uid']
            and all(manager['spec'].get(key) == value for key, value in expected_manager['spec'].items()),
            'Replacement Alertmanager desired state changed')
        deny = self.get(DENY_PATH)
        owned = self.journal['steps']['owned-deny']
        h.require(transport.identity(deny) == owned['identity'] and deny['spec'] == owned['spec'], 'Replacement DENY changed')
        statefulset = self.get(STATEFULSET)
        cp.owner(statefulset, manager)
        h.require(statefulset['metadata']['uid'] != self.state['binding']['objects']['statefulset']['uid']
            and statefulset['spec'].get('replicas') == 1
            and statefulset['spec'].get('persistentVolumeClaimRetentionPolicy') == cp.RETENTION,
            'Replacement native StatefulSet has not converged')
        templates = statefulset['spec'].get('volumeClaimTemplates', [])
        h.require(len(templates) == 1 and templates[0]['metadata'].get('name') == 'alertmanager-cloudlab-db'
            and all(templates[0]['spec'].get(key) == value for key, value in cp.CLAIM_SPEC.items()),
            'Replacement native claim template differs')
        def without_state_volume(template):
            result = copy.deepcopy(template)
            result['spec']['volumes'] = [row for row in result['spec'].get('volumes', [])
                if row['name'] != 'alertmanager-cloudlab-db']
            return result
        h.require(without_state_volume(statefulset['spec']['template']) == without_state_volume(self.state['sourceTemplate']),
            'Replacement changes an unrelated native executable template')
        pod = self.get(PREFIX + 'pods/' + SOURCE)
        cp.owner(pod, statefulset)
        h.require(pod['metadata']['uid'] != self.state['source']['uid']
            and not pod['metadata'].get('deletionTimestamp') and not pod['spec'].get('ephemeralContainers')
            and pod.get('status', {}).get('phase') == 'Running', 'Replacement source process has not converged')
        _, mount = cp.state_mount(pod, self.pins)
        h.require(mount['name'] == 'alertmanager-cloudlab-db'
            and [row for row in pod['spec'].get('volumes', []) if row['name'] == mount['name']] == [
                {'name': mount['name'], 'persistentVolumeClaim': {'claimName': CLAIM}}]
            and statefulset.get('status', {}).get('observedGeneration') == statefulset['metadata']['generation'],
            'Replacement does not mount the exact final claim')
        for container in pod['spec']['containers']:
            expected = [row for row in statefulset['spec']['template']['spec']['containers'] if row['name'] == container['name']]
            h.require(len(expected) == 1 and all(container.get(key) == expected[0].get(key)
                for key in ('image', 'command', 'args', 'securityContext', 'resources', 'ports')),
                'Replacement Pod executable differs from its authenticated native template')
        identity = cp.source_identity(pod)
        h.require(any(row.get('type') == 'Ready' and row.get('status') == 'True'
            for row in pod.get('status', {}).get('conditions', [])), 'Replacement source is not Ready')
        if 'replacementSource' in self.state:
            h.require(self.state['replacementSource'] == identity, 'Replacement source process changed')
        else:
            self.state['replacementSource'] = identity
            self.save()
        self.wait_storage('mounted')
        # Only the authenticated source transition can replace these context fields.
        self.authorization_context()
        wanted = copy.deepcopy(self.state['authorizationContextValue'])
        for key in ('source', 'sourceSpec', 'addresses'):
            wanted[key] = self.context_value[key]
        h.require(wanted == self.context_value, 'Unrelated authorization context changed during storage conversion')
        self.state['authorizationContextValue'] = wanted
        self.state['authorizationContext'] = h.digest(h.canonical(wanted))
        self.save()
        self.quiescent()
        silences = silence_state(h.strict_json(self.native('/api/v2/silences'), CONFIG_LIMIT))
        h.require(h.digest(h.canonical(silences)) == self.state['validatedSilencesSHA256'],
            'Retained replacement changed native silence contents')

    def verify_restored(self):
        self.operator(); self.storage_binding()
        restored = self.classify('restored')
        h.require(restored['configSHA256'] == self.state['classifications']['original']['configSHA256'],
            'Restored native configuration bytes differ')
        deny = self.io.request(DENY_PATH)
        if deny is not None:
            original = self.resource('cloudlab-observability', 'AuthorizationPolicy', DENY, 'maintenance')
            self.sync('cloudlab-observability', [original], prune=True)
        h.require(self.io.request(DENY_PATH) is None, 'Owned DENY is not absent after restoration')
        h.require(self.authorization_context() == self.state['authorizationContext']
            and self.fresh_probe() == 'success', 'Restored native network positive control failed')
        self.state['restored'] = True
        self.save()

    def preflight(self):
        h.require(self.phase == 'baseline' and self.journal is None, 'Preflight must precede production execution')
        application = self.get(transport.APPS + cp.APPLICATION)
        pod, manager, statefulset, operator = self.source(), self.get(MANAGER), self.get(STATEFULSET), self.get(OPERATOR)
        # The executor verifies original_baseline_export custody before this read.
        original = h.phase_json(h.phase_file(self.directory, 'baseline', 'draft-payload'))['baseline']['cloudlab-prometheus']
        for actual, kind, name in ((manager, 'Alertmanager', 'cloudlab'),
                (operator, 'Deployment', 'cloudlab-prometheus-operator')):
            expected = [row for row in original if row['kind'] == kind and row['metadata']['name'] == name
                and row['metadata'].get('namespace') == NAMESPACE]
            h.require(len(expected) == 1 and all(actual['spec'].get(key) == value for key, value in expected[0]['spec'].items()),
                'Original native object differs from the accepted inventory')
        reloader_pins = {value for value in self.intent['qualifications']['references']['lifecycle']['imagePins'].values()
            if value.startswith('quay.io/prometheus-operator/prometheus-config-reloader:')}
        h.require(len(reloader_pins) == 1
            and {row['name'] for row in pod['spec']['containers']} == {'alertmanager', 'config-reloader'}
            and {row['name'] for row in pod['spec'].get('initContainers', [])} <= {'init-config-reloader'}
            and all(row.get('image') in reloader_pins for row in
                pod['spec']['containers'] + pod['spec'].get('initContainers', []) if row['name'] != 'alertmanager')
            and not pod['spec'].get('ephemeralContainers'), 'Original native listener or reloader profile is unsupported')
        binding = cp.bind_source(application, manager, statefulset, pod, operator,
            self.intent['applicationBindings'][cp.APPLICATION]['spec'], self.pins)
        h.require(self.io.request(DENY_PATH) is None, 'Preflight cannot adopt an existing writer DENY')
        watch = self.operator()
        if 'source' in self.state:
            h.require(self.state['source'] == binding['source'] and self.state['binding'] == binding,
                'Production source changed before authorization')
        else:
            self.state.update({'source': binding['source'], 'binding': binding, 'operator': watch,
                'sourceTemplate': copy.deepcopy(statefulset['spec']['template'])})
            self.save()
        self.classify('original')
        h.require(cp.bind_source(self.get(transport.APPS + cp.APPLICATION), self.get(MANAGER), self.get(STATEFULSET),
            self.source(), self.get(OPERATOR), self.intent['applicationBindings'][cp.APPLICATION]['spec'], self.pins) == binding,
            'Production source changed during preflight')
        self.operator()

    def run(self):
        h.require(self.journal is not None and callable(self.persist) and callable(self.sync_resources),
            'Backend phase requires protected execution authority')
        if self.phase == 'baseline':
            original = h.phase_json(h.phase_file(self.directory, 'baseline', 'draft-payload'))['baseline']['cloudlab-observability']
            quotas = [row for row in self.inventory('cloudlab-observability') if row['kind'] == 'ResourceQuota'
                and row['metadata']['name'] == 'telemetry-budget']
            h.require(len(quotas) == 1, 'Native telemetry quota is absent or ambiguous')
            old = [row for row in original if row['kind'] == 'ResourceQuota' and row['metadata']['name'] == 'telemetry-budget']
            h.require(len(old) == 1, 'Original telemetry quota is absent or ambiguous')
            if old[0] != quotas[0]: self.sync('cloudlab-observability', quotas)
            self.source(); self.classify('original'); self.operator()
        elif self.phase == 'maintenance':
            self.deny_transition(lambda deadline: self.sync('cloudlab-observability',
                [self.resource('cloudlab-observability', 'AuthorizationPolicy', DENY)], deadline=deadline))
            if 'maintenanceReloadBefore' not in self.state:
                self.state['maintenanceReloadBefore'] = self.native_state()[0]['reloadTimestamp']; self.save()
            self.sync('cloudlab-prometheus', [self.resource('cloudlab-prometheus', 'Secret', 'alertmanager-cloudlab')])
            self.reload_after_secret_sync(self.state['maintenanceReloadBefore'])
            current = self.classify('muted')
            self.state['maintenanceErrors'] = current['errors']; self.save()
            self.quiescent()
        elif self.phase == 'persistent-maintenance':
            if not self.state.get('storageSyncComplete'):
                self.checkpoint_and_validate()
                self.quiescent()
                self.sync('cloudlab-prometheus', [self.resource('cloudlab-prometheus', 'Alertmanager', 'cloudlab')])
                self.state['storageSyncComplete'] = True; self.save()
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                current = self.io.request(PREFIX + 'pods/' + SOURCE)
                if (current is not None and current['metadata']['uid'] != self.state['source']['uid']
                        and any(row.get('type') == 'Ready' and row.get('status') == 'True'
                            for row in current.get('status', {}).get('conditions', []))):
                    self.replacement(); break
                time.sleep(2)
            else:
                raise RuntimeError('Native retained replacement did not become Ready')
        elif self.phase == 'persistent-normal':
            if 'restoredReloadBefore' not in self.state:
                self.quiescent()
                self.state['restoredReloadBefore'] = self.native_state()[0]['reloadTimestamp']; self.save()
            self.sync('cloudlab-prometheus', [self.resource('cloudlab-prometheus', 'Secret', 'alertmanager-cloudlab')])
            self.reload_after_secret_sync(self.state['restoredReloadBefore'])
            self.verify_restored()
        elif self.phase == 'native-paused':
            h.require(self.state.get('restored') is True and self.io.request(DENY_PATH) is None,
                'Canonical paused adoption precedes normal delivery restoration')
            self.storage_binding(); self.operator(); self.classify('restored')
            if not self.state['mutations']['probe']['deleted']:
                h.require(self.fresh_probe() == 'success', 'Final native network control failed')
                self.remove('probe')
        else:
            raise RuntimeError('Backend cannot activate native reconciliation')

    def classify(self, purpose):
        h.require(purpose in PURPOSES, 'Unknown native classification purpose')
        current, raw = self.native_state()
        original = self.state.get('classifications', {}).get('original')
        if purpose != 'original':
            h.require(original is not None, 'Original native configuration classification is absent')
            h.require(current['reloadTimestamp'] > original['reloadTimestamp'], 'Native reload timestamp did not advance')
        accepted = self.state['classifications'].get(purpose)
        if accepted is not None:
            same = all(accepted.get(key) == current[key] for key in ('source', 'configSHA256', 'reloadTimestamp'))
            if same: return current
            h.require(purpose == 'muted' and self.phase == 'persistent-maintenance'
                and self.state.get('replacementSource') == current['source']
                and accepted['source'] == self.state['source'] and accepted['configSHA256'] == current['configSHA256'],
                'Classified native configuration or process changed')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        pending = self.state.get('pendingClassification')
        if pending is None or pending['challenge']['bootID'] != boot or time.monotonic() >= pending['challenge']['deadlineMonotonic']:
            nonce = secrets.token_hex(16)
            challenge = {'operationId': self.operation, 'phase': self.phase, 'purpose': purpose,
                'bundleSHA256': self.intent['prepared']['bundleSHA256'], 'intentSHA256': h.digest(h.canonical(self.intent)),
                'previousPhaseSHA256': self.intent['previousPhaseSHA256'], **current,
                'nonce': nonce, 'bootID': boot, 'deadlineMonotonic': time.monotonic() + 180}
            # Maintenance error counters are runtime guards, not classification authority.
            challenge.pop('errors')
            private_bytes(self.directory / ('native-' + nonce + '.status.json'), raw)
            h.write_once(self.directory / ('native-' + nonce + '.challenge.json'), challenge)
            self.state['pendingClassification'] = {'purpose': purpose, 'challenge': challenge}
            self.save()
        challenge = self.state['pendingClassification']['challenge']
        result_path = self.directory / ('native-' + challenge['nonce'] + '.classification.json')
        h.require(challenge['bootID'] == boot and time.monotonic() < challenge['deadlineMonotonic']
            and all(challenge.get(key) == current[key] for key in ('source', 'configSHA256', 'reloadTimestamp'))
            and self.state['pendingClassification']['purpose'] == purpose and challenge['purpose'] == purpose
            and challenge['operationId'] == self.operation and challenge['phase'] == self.phase
            and challenge['intentSHA256'] == h.digest(h.canonical(self.intent)), 'Native classification challenge expired or changed')
        if h.private_path(result_path, missing=True) is None:
            raise NativeConfigPending(purpose)
        result = h.phase_json(result_path)
        h.require(set(result) == {'version', 'challengeSHA256', 'challenge', 'classification',
            'originalConfigSHA256', 'configSHA256'} and result['version'] == 'cloudlab-native-config-classification/v1'
            and result['challenge'] == challenge and result['challengeSHA256'] == h.digest(h.canonical(challenge))
            and result['classification'] == purpose and result['configSHA256'] == current['configSHA256']
            and result['originalConfigSHA256'] == (current['configSHA256'] if original is None else original['configSHA256']),
            'Native classification result differs from the protected challenge')
        again, _ = self.native_state()
        h.require(again == current, 'Native configuration changed before consuming classification')
        if accepted is not None:
            self.state.setdefault('classificationHistory', []).append({'purpose': purpose, **accepted})
        self.state['classifications'][purpose] = current | {'challengeSHA256': result['challengeSHA256']}
        self.state['classifications'][purpose]['nonce'] = challenge['nonce']
        del self.state['pendingClassification']
        self.save()
        return current


def silence_state(values):
    h.require(isinstance(values, list) and len(values) <= 4096, 'Native silence inventory exceeds bound')
    keys = ('id', 'matchers', 'startsAt', 'endsAt', 'createdBy', 'comment')
    result = []
    for value in values:
        h.require(isinstance(value, dict) and all(key in value for key in keys)
            and isinstance(value['id'], str) and cp.UID.fullmatch(value['id']), 'Native silence identity is invalid')
        result.append({key: value[key] for key in keys})
    h.require(len({row['id'] for row in result}) == len(result), 'Duplicate native silence identity')
    return sorted(result, key=lambda row: row['id'])


def production_preflight(io, directory, intent):
    return Backend(io, directory, intent).preflight()


def backend_phase(io, directory, phase, journal, persist, sync_resources):
    intent = h.phase_json(h.phase_file(directory, phase, 'intent'))
    return Backend(io, directory, intent, journal, persist, sync_resources).run()



def process_identity(pod, container):
    cp.identity(pod)
    rows = [row for row in pod.get('status', {}).get('containerStatuses', []) if row.get('name') == container]
    h.require(len(rows) == 1 and rows[0].get('restartCount') == 0 and rows[0].get('state', {}).get('running')
        and isinstance(rows[0].get('containerID'), str), 'Native process is absent or restarted')
    return cp.identity(pod) | {'containerID': rows[0]['containerID'], 'startedAt': rows[0]['state']['running']['startedAt']}


def native_config_export(directory, source_export):
    directory = Path(directory)
    state = h.phase_json(directory / 'backend.json')
    pending = state.get('pendingClassification')
    h.require(isinstance(pending, dict) and set(pending) == {'purpose', 'challenge'}, 'Native classification is not pending')
    purpose, challenge = pending['purpose'], pending['challenge']
    h.require(purpose in PURPOSES and re.fullmatch('[a-f0-9]{32}', challenge['nonce']), 'Invalid pending classification')
    original = state['classifications'].get('original')
    return {'version': 'cloudlab-native-config-challenge/v1', 'challenge': challenge,
        'rawStatus': base64.b64encode(h.read_private(directory / ('native-' + challenge['nonce'] + '.status.json'), CONFIG_LIMIT)).decode(),
        'originalStatus': None if purpose == 'original' else base64.b64encode(h.read_private(
            directory / ('native-' + original['nonce'] + '.status.json'), CONFIG_LIMIT)).decode(),
        'sourcePhase': source_export(purpose, challenge['phase'])}


def stage_native_classification(directory, proposal_path, expected_sha256):
    raw = h.read_private(proposal_path)
    result = h.strict_json(raw)
    h.require(h.digest(h.canonical(result)) == expected_sha256, 'Native classification proposal changed')
    purpose = result.get('classification')
    state = h.phase_json(Path(directory) / 'backend.json')
    challenge = state.get('pendingClassification', {}).get('challenge')
    h.require(purpose in PURPOSES and result.get('challenge') == challenge
        and isinstance(challenge, dict) and re.fullmatch('[a-f0-9]{32}', challenge['nonce']), 'Native classification challenge changed')
    h.write_once(Path(directory) / ('native-' + challenge['nonce'] + '.classification.json'), result)
    return {'stage': 'native-config-staged', 'purpose': purpose, 'ready': False}
