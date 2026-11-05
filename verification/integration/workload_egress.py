"""Explicit egress checks in disposable existing-cluster namespaces.

Run through the existing Compose lab Python entrypoint. Receipts live under
/recovery/workload-egress. --resume finishes interrupted cleanup; start a fresh
run afterwards. --cleanup only cleans the exact recorded run and target.
--application-ports runs only the candidate catalog authorization lifecycle.
"""
import argparse
import base64
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import struct
import sys
import time
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ansible'))
sys.path.insert(0, str(ROOT / 'ansible/playbooks/tailscale/files'))
from verify_access import ssh_channel
from playbooks.istio.files import fixtures
from playbooks.services.files.gitops import resources

MARKER = 'cloudlab.io/egress-proof'
OWNER = 'cloudlab-egress-verify'
LIMIT = 2 * 1024 * 1024
ROLES = ('source', 'plain', 'wrong', 'ambient')
CHILD = r'(?:v1/(?:Pod|Service|ServiceAccount)|networking[.]k8s[.]io/v1/NetworkPolicy|security[.]istio[.]io/v1/(?:PeerAuthentication|AuthorizationPolicy))/[a-z0-9][a-z0-9.-]{0,252}'
REMOTE = ('import subprocess,sys;data=sys.stdin.buffer.readline(1048577);'
          'assert len(data)<=1048576;'
          'r=subprocess.run(sys.argv[1:],input=data if data.strip() else None,timeout=45);'
          'sys.exit(r.returncode)')


class ProofFailure(RuntimeError):
    pass


class RunFailure(RuntimeError):
    def __init__(self, run, stage, verification, cleanup, evidence=None):
        self.result = {'run': run, 'stage': stage, 'verification': verification, 'cleanup': cleanup,
                       'recovery': '--cleanup ' + run}
        if evidence: self.result['captured_dns_observations'] = evidence
        super().__init__(json.dumps(self.result, sort_keys=True))


def fail(message):
    raise ProofFailure(message)


def safe_reason(error):
    reasons = {
        'Fixture probe failed unexpectedly': 'unexpected-probe-outcome',
        'Fixture returned unexpected application content': 'unexpected-application-content',
        'Egress traffic differs from its declared allowance': 'allowance-did-not-converge',
        'Denied egress became reachable again': 'denied-egress-became-reachable',
        'Foreign or persistent fixture resource blocks cleanup; receipt retained': 'foreign-or-persistent-resource',
        'Persistent data refers to proof namespace; receipt retained': 'persistent-data-reference',
        'Fixture namespace ownership changed; receipt retained': 'namespace-identity-mismatch',
        'Fixture child identity changed; receipt retained': 'child-identity-mismatch',
        'Proof source changed; use exact receipt cleanup': 'source-changed',
        'Proof receipt differs from its target': 'receipt-target-mismatch',
        'Namespace discovery is incomplete': 'incomplete-discovery',
        'Namespace discovery changed during cleanup': 'discovery-changed',
        'Fixture cleanup deadline exceeded; receipt retained': 'cleanup-deadline',
        'Egress verification deadline exceeded': 'verification-deadline',
        'Captured DNS forwarding remained reachable after withdrawal': 'captured-forwarding-remained-reachable',
        'Captured DNS positive control failed; proof unqualified': 'captured-positive-control-failed',
        'Unexpected NXDOMAIN; name propagation is not denial': 'unexpected-nxdomain',
        'SRV control did not propagate; proof unqualified': 'srv-control-propagation-failed',
        'SRV control failed after source probe; proof unqualified': 'srv-control-failed',
        'Source IP reused; fresh-flow proof unqualified': 'source-ip-reused',
        'Intended ambient DNS capture cannot be established': 'dns-capture-unqualified',
        'Intended fixture resolver cannot be established': 'fixture-resolver-unqualified',
        'Known Service A local-resolution control failed; capture unqualified': 'local-resolution-control-failed',
    }
    if isinstance(error, ProofFailure): return reasons.get(str(error), 'verification-condition-failed')
    if isinstance(error, NotReady): return 'fixture-not-ready'
    if isinstance(error, KeyboardInterrupt): return 'interrupted'
    if isinstance(error, json.JSONDecodeError): return 'invalid-json-response'
    return 'operation-failed; private diagnostics withheld'


def dns_evidence(rpc):
    value = getattr(rpc, 'evidence', None)
    if not isinstance(value, dict): return {}
    permitted = {'A': {'not-run', 'source-positive-controls-healthy'},
                 'B': {'not-run', 'source-success-after-withdrawal', 'three-candidate-failures-controls-healthy'},
                 'A_restore': {'not-run', 'same-client-positive-controls-healthy', 'failed-or-unqualified'},
                 'controls': {'not-qualified', 'healthy-before-and-after-every-source-attempt'},
                 'classification': {'unqualified', 'observed-policy-correlated-captured-forwarding-failure'},
                 'upstream_wire_protocol': {'not-inferred'}}
    result = {}
    for key in ('captured_dns_client_udp', 'captured_dns_client_tcp'):
        row = value.get(key)
        if (not isinstance(row, dict) or set(row) - (set(permitted) | {'known_service_a_after_withdrawal'}) or
                any(not isinstance(row.get(field), str) or row[field] not in options for field, options in permitted.items()) or
                ('known_service_a_after_withdrawal' in row and type(row['known_service_a_after_withdrawal']) is not bool)):
            continue
        result[key] = dict(row)
    return result


def digest(paths):
    value = hashlib.sha256()
    for path in sorted(paths):
        value.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes())
    return value.hexdigest()


def hashes():
    return {'source': digest([Path(__file__), ROOT / 'ansible/playbooks/istio/files/fixtures.py',
                             ROOT / 'ansible/playbooks/tailscale/files/ssh_channel.py',
                             ROOT / 'ansible/playbooks/tailscale/files/verify_access.py',
                             ROOT / 'ansible/playbooks/services/files/gitops.py',
                             ROOT / 'ansible/playbooks/services/files/contract.py',
                             ROOT / 'ansible/group_vars/all/verification.yml',
                             ROOT / 'platform/connectivity/istio/cni/values.json',
                             ROOT / 'platform/connectivity/istio/ztunnel/values.json',
                             *[p for p in (ROOT / 'charts/service').rglob('*') if p.is_file()]]),
            'chart': digest([p for p in (ROOT / 'platform/delivery/services').rglob('*') if p.is_file()])}


def native(name, rules, publication='ready'):
    definition = yaml.safe_load((ROOT / 'charts/service/values.yaml').read_text())
    definition['name'] = name
    approved = {'name': name, 'namespace': 'cloudlab-app-' + name,
                'repository': 'https://github.com/example/fixture.git', 'revision': 'a' * 40,
                'valuesPath': 'apps/proof.yaml', 'secretReferences': [], 'configMaps': [], 'egress': rules}
    rows = resources(definition, approved, 'https://github.com/example/platform.git', 'a' * 40,
                     publication=publication)
    namespace = [r for r in rows if r['kind'] == 'Namespace']
    policy = [r for r in rows if r['kind'] == 'NetworkPolicy' and r['metadata']['name'] == 'platform-egress']
    if len(namespace) != 1 or len(policy) != 1:
        fail('Native namespace/egress extraction is ambiguous')
    return namespace[0], policy[0]


def profiles(run):
    name = 'egress-' + run[:12]
    source, _ = native(name, [])
    result = {'source': source}
    for role in ROLES[1:]:
        result[role] = fixtures.namespace('cloudlab-egress-' + role + '-' + run[:12], ambient=role == 'ambient')
    for row in result.values():
        row['metadata']['labels'].update({MARKER: run, 'app.kubernetes.io/managed-by': OWNER})
    return result


class Receipt:
    def __init__(self, directory, run=None):
        self.run = run or uuid.uuid4().hex
        if not re.fullmatch('[a-f0-9]{32}', self.run): fail('Invalid egress proof run ID')
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = (self.directory / '.lock').open('a')
        try: fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.lock.close()
            raise
        self.path = self.directory / (self.run + '.json')
        self.value = None

    def save(self):
        temporary = self.path.with_suffix('.pending')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(self.value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)

    def start(self, target):
        if self.path.exists(): fail('Proof receipt already exists')
        self.value = {'version': 2, 'run': self.run, 'target': target, 'hashes': hashes(), 'complete': False,
                      'proof': {'client': None, 'service': None, 'preflight': None},
                      'namespaces': {role: {'profile': row, 'phase': 'planned', 'uid': None, 'objects': {}}
                                     for role, row in profiles(self.run).items()}}
        self.save()

    def load(self, target):
        if self.path.is_symlink() or self.path.stat().st_size > 262144: fail('Invalid proof receipt')
        self.value = json.loads(self.path.read_text())
        version = self.value.get('version')
        fields = {'version', 'run', 'target', 'hashes', 'complete', 'namespaces'} | ({'proof'} if version == 2 else set())
        if (set(self.value) != fields or version not in (1, 2) or
                self.value['run'] != self.run or self.value['target'] != target or
                set(self.value['namespaces']) != set(ROLES)):
            fail('Proof receipt differs from its target')
        for role, expected in profiles(self.run).items():
            row = self.value['namespaces'][role]
            if (set(row) != {'profile', 'phase', 'uid', 'objects'} or row['profile'] != expected or
                    row['phase'] not in ('planned', 'create-pending', 'created', 'delete-pending', 'cleaned') or
                    (row['uid'] is not None and not re.fullmatch('[a-f0-9-]{36}', row['uid'])) or
                    not isinstance(row['objects'], dict) or len(row['objects']) > 32 or
                    any(not re.fullmatch(CHILD, key) or (uid is not None and not re.fullmatch('[a-f0-9-]{36}', uid))
                        for key, uid in row['objects'].items())):
                fail('Proof receipt has an invalid namespace identity')
        if version == 2: validate_history(self.value)

    def close(self):
        self.lock.close()


class RPC:
    def __init__(self, host, deadline):
        self.host, self.deadline = host, deadline
        self.pods = {}
        self.pod_ips = {}
        self.evidence = {}

    def call(self, arguments, document=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: fail('Egress verification deadline exceeded')
        argv = ['/usr/local/bin/k3s', 'kubectl', '--request-timeout=20s', *arguments]
        command = shlex.join(['python3', '-c', REMOTE, *argv])
        raw = json.dumps(document, separators=(',', ':')).encode() if document is not None else b'{}'
        if len(raw) > 1048576: fail('Fixture input exceeds its bound')
        with ssh_channel('VM', self.host, command, deadline=min(self.deadline, time.monotonic() + 50),
                         frame_limit=LIMIT, output_limit=LIMIT) as channel:
            if document is not None: channel.write_frame(raw)
            channel.close_input()
            result = channel.read_output()
        return result.decode('utf-8')

    def get(self, kind, name=None, namespace=None):
        args = ['get', kind]
        if name: args.append(name)
        if namespace: args += ['-n', namespace]
        raw = self.call([*args, '--ignore-not-found', '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    def write(self, verb, document):
        return json.loads(self.call([verb, '-f', '-', '-o', 'json'], document))

    def exec(self, namespace, pod, script):
        ready(self, namespace, pod)
        raw = self.call(['exec', '-n', namespace, pod, '--', 'sh', '-c', script])
        try: value = json.loads(raw)
        except (ValueError, UnicodeError): fail('Malformed fixture probe result')
        if not isinstance(value, dict): fail('Malformed fixture probe result')
        return value


def identity(current, row, run):
    meta = (current or {}).get('metadata', {})
    expected = row['profile']['metadata']
    if (meta.get('name') != expected['name'] or meta.get('labels', {}).get(MARKER) != run or
            any(meta.get('labels', {}).get(k) != v for k, v in expected['labels'].items()) or
            any(meta.get('annotations', {}).get(k) != v for k, v in expected.get('annotations', {}).items()) or
            meta.get('ownerReferences') or set((current or {}).get('spec', {}).get('finalizers', [])) - {'kubernetes'} or
            not re.fullmatch('[a-f0-9-]{36}', meta.get('uid', '')) or
            (row['uid'] is not None and meta['uid'] != row['uid'])):
        fail('Fixture namespace ownership changed; receipt retained')
    return meta['uid']


def create_namespace(rpc, receipt, role):
    row = receipt.value['namespaces'][role]
    name = row['profile']['metadata']['name']
    existing = rpc.get('namespace', name)
    if row['phase'] == 'planned':
        if existing is not None: fail('Fixture namespace name collision')
        row['phase'] = 'create-pending'
        receipt.save()
        existing = rpc.write('create', row['profile'])
    elif existing is None:
        if row['phase'] != 'create-pending': fail('Recorded fixture namespace disappeared')
        existing = rpc.write('create', row['profile'])
    row['uid'] = identity(existing, row, receipt.run)
    row['phase'] = 'created'
    receipt.save()


def object_key(row):
    return row['apiVersion'] + '/' + row['kind'] + '/' + row['metadata']['name']


def record(rpc, receipt, role, objects):
    row = receipt.value['namespaces'][role]
    namespace = row['profile']['metadata']['name']
    identity(rpc.get('namespace', namespace), row, receipt.run)
    for obj in objects:
        obj = copy.deepcopy(obj)
        if obj['metadata']['namespace'] != namespace: fail('Fixture object escaped its namespace')
        obj['metadata'].setdefault('labels', {})[MARKER] = receipt.run
        key = object_key(obj)
        if not re.fullmatch(CHILD, key): fail('Unsupported fixture object')
        current = rpc.get(obj['kind'], obj['metadata']['name'], namespace)
        if current is not None:
            expected = row['objects'].get(key)
            if (not expected or current['metadata'].get('uid') != expected or
                    current['metadata'].get('labels', {}).get(MARKER) != receipt.run):
                fail('Fixture object collided with another owner')
            obj['metadata'].update(uid=expected, resourceVersion=current['metadata']['resourceVersion'])
        # Record intent before an ambiguous object-create response; inventory recovery
        # admits only this exact key with our unpredictable run marker.
        row['objects'].setdefault(key, None)
        receipt.save()
        current = rpc.write('replace' if current is not None else 'create', obj)
        if current['metadata'].get('labels', {}).get(MARKER) != receipt.run: fail('Fixture object marker changed')
        row['objects'][key] = current['metadata']['uid']
        if obj['kind'] == 'Pod':
            rpc.pods[(namespace, obj['metadata']['name'])] = (current['metadata']['uid'], receipt.run)
        receipt.save()


class NotReady(RuntimeError):
    pass


def ready(rpc, namespace, pod):
    row = rpc.get('pod', pod, namespace) or {}
    expected = getattr(rpc, 'pods', None)
    if isinstance(expected, dict):
        target = expected.get((namespace, pod))
        if not target or (row.get('metadata', {}).get('uid'), row.get('metadata', {}).get('labels', {}).get(MARKER)) != target:
            fail('Probe pod differs from its recorded fixture UID')
    addresses = getattr(rpc, 'pod_ips', None)
    if isinstance(addresses, dict) and (namespace, pod) in addresses and row.get('status', {}).get('podIP') != addresses[(namespace, pod)]:
        fail('Fixture IP changed during proof; freshness unqualified')
    if (row.get('metadata', {}).get('deletionTimestamp') or row.get('status', {}).get('phase') != 'Running' or
            not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in row.get('status', {}).get('conditions', []))):
        raise NotReady('Fixture is not ready; denial is unproved')
    return row


def wait_ready(rpc, namespace, pod):
    deadline = min(rpc.deadline, time.monotonic() + 180)
    while True:
        try: return ready(rpc, namespace, pod)
        except NotReady:
            if time.monotonic() >= deadline: raise
            time.sleep(2)


def probe_result(value, nonce):
    if set(value) != {'code', 'body', 'error'} or type(value['code']) is not int:
        fail('Invalid HTTP probe result')
    try:
        body = base64.b64decode(value['body'], validate=True).decode('ascii')
        error = base64.b64decode(value['error'], validate=True).decode('ascii')
    except (ValueError, UnicodeError, TypeError): fail('Invalid HTTP probe encoding')
    if value['code'] == 0:
        if body != nonce: fail('Fixture returned unexpected application content')
        return True
    if (value['code'] != 1 or body or not any(text in error.lower() for text in
            ('timed out', 'connection refused', 'connection reset by peer', 'network is unreachable', 'no route to host')) or
            'server returned error' in error.lower()):
        fail('Fixture probe failed unexpectedly')
    return False


def http(rpc, namespace, pod, address, port, nonce):
    ipaddress.IPv4Address(address)
    # Controlled BusyBox backends return one nonce. The outer shell always exits
    # successfully so kubectl failure cannot be confused with connection failure.
    command = 'wget -O /work/body -T 3 http://' + address + ':' + str(port) + '/'
    script = (': >/work/body && : >/work/error || exit 70; ' + command + ' 2>/work/error; code=$?; '
              'printf \'{"code":%s,"body":"%s","error":"%s"}\\n\' "$code" '
              '"$(base64 /work/body | tr -d \'\\n\')" "$(base64 /work/error | tr -d \'\\n\')"')
    return probe_result(rpc.exec(namespace, pod, script), nonce)


def expect_connection(probe, allowed, timeout=60):
    deadline = time.monotonic() + timeout
    while probe() is not allowed:
        if time.monotonic() >= deadline: fail('Egress traffic differs from its declared allowance')
        time.sleep(2)
    # First wait for asynchronous dataplane convergence, then require repeated
    # fresh denials. Probe exceptions remain errors, not convergence retries.
    if not allowed and any(probe() for _ in range(3)):
        fail('Denied egress became reachable again')


def hold_connection(rpc, namespace, address, pod='allowed'):
    remote = ipaddress.IPv4Address(address).packed[::-1].hex().upper() + ':1F90'
    script = ('rm -f /work/held-in /work/held-out; mkfifo /work/held-in; '
              '(sleep 20) >/work/held-in 2>/dev/null & writer=$!; '
              'nc -w 15 ' + address + ' 8080 </work/held-in >/work/held-out 2>/work/held-error & client=$!; '
              'printf "%s %s" "$writer" "$client" >/work/held-pids; established=false; '
              'for attempt in 1 2 3 4 5 6 7 8 9 10; do '
              'if awk \'$3=="' + remote + '" && $4=="01" {found=1} END {exit !found}\' /proc/net/tcp; '
              'then established=true; break; fi; sleep .1; done; '
              'printf \'{"established":%s}\\n\' "$established"')
    result = rpc.exec(namespace, pod, script)
    if set(result) != {'established'} or type(result['established']) is not bool:
        fail('Malformed held-connection observation')
    return result['established']


def release_connection(rpc, namespace, established, nonce, pod='allowed'):
    script = ('read writer client </work/held-pids; '
              'timeout 2 sh -c \'printf "GET / HTTP/1.0\\r\\n\\r\\n" >/work/held-in\' >/dev/null 2>&1; '
              'sleep 2; kill "$writer" "$client" >/dev/null 2>&1 || true; '
              'printf \'{"data":"%s"}\\n\' "$(base64 /work/held-out | tr -d \'\\n\')"; '
              'rm -f /work/held-in /work/held-pids')
    result = rpc.exec(namespace, pod, script)
    if set(result) != {'data'}: fail('Malformed held-connection observation')
    try: data = base64.b64decode(result['data'], validate=True)
    except (ValueError, TypeError): fail('Malformed held-connection encoding')
    if data and data.split(b'\r\n\r\n', 1)[-1] != nonce.encode():
        fail('Held connection returned unexpected application content')
    return {'established_before_withdrawal': established,
            'response_after_withdrawal': bool(data) if established else None,
            'limit': 'No response is not attributed to policy; no immediate revocation claim'}


def question(name, transaction=0x6A31, qtype=1):
    labels = name.rstrip('.').split('.')
    if qtype not in (1, 33) or any(not re.fullmatch(r'_?[a-z0-9-]{1,62}|[a-z0-9-]{63}', label) for label in labels):
        fail('Invalid fixture DNS name')
    encoded = b''.join(bytes([len(label)]) + label.encode() for label in labels) + b'\0'
    return struct.pack('!6H', transaction, 0x100, 1, 0, 0, 0) + encoded + struct.pack('!HH', qtype, 1)


def dns_name(raw, offset, seen=None):
    seen = set() if seen is None else seen
    labels, end = [], None
    for _ in range(128):
        if offset >= len(raw) or offset in seen: fail('Malformed DNS response')
        seen.add(offset)
        size = raw[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(raw): fail('Malformed DNS response')
            pointer = ((size & 63) << 8) | raw[offset + 1]
            suffix, _ = dns_name(raw, pointer, seen)
            return '.'.join(labels + [suffix]), end or offset + 2
        if size & 0xC0 or size > 63: fail('Malformed DNS response')
        offset += 1
        if not size: return '.'.join(labels), end or offset
        if offset + size > len(raw): fail('Malformed DNS response')
        try: labels.append(raw[offset:offset + size].decode('ascii'))
        except UnicodeError: fail('Malformed DNS response')
        offset += size
    fail('Malformed DNS response')


def dns_response(raw, query, expected, port=None):
    if len(raw) < 14 or len(raw) != int.from_bytes(raw[:2], 'big') + 2: fail('Invalid TCP DNS response length')
    data = raw[2:]
    tx, flags, count, answers, authority, additional = struct.unpack('!6H', data[:12])
    expected_name, end = dns_name(query, 12)
    name, offset = dns_name(data, 12)
    qtype = int.from_bytes(query[end:end + 2], 'big')
    code = flags & 0xF
    if (tx != int.from_bytes(query[:2], 'big') or flags & 0x8000 == 0 or flags & 0x7800 or flags & 0x200 or
            count != 1 or name != expected_name or data[offset:offset + 4] != query[end:end + 4]):
        fail('Invalid TCP DNS response')
    if code == 3: fail('Unexpected NXDOMAIN; name propagation is not denial')
    if code not in (0, 2) or (code == 2 and answers): fail('Unexpected DNS response code; proof unqualified')
    if answers + authority + additional > 512: fail('DNS response exceeds record bound')
    offset += 4
    found = 0
    for index in range(answers + authority + additional):
        owner, offset = dns_name(data, offset)
        if offset + 10 > len(data): fail('Malformed DNS answer')
        kind, family, _, length = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        if offset + length > len(data): fail('Malformed DNS answer')
        if index < answers and kind == qtype and family == 1:
            if owner.lower() != expected_name.lower(): fail('Unexpected DNS answer owner')
            if qtype == 1:
                if length != 4 or str(ipaddress.IPv4Address(data[offset:offset + 4])) != expected:
                    fail('DNS response has wrong fixture address')
            else:
                if length < 7: fail('Malformed SRV answer')
                _, _, actual_port = struct.unpack('!HHH', data[offset:offset + 6])
                target, target_end = dns_name(data, offset + 6)
                if target_end != offset + length or target.lower().rstrip('.') != expected.lower().rstrip('.') or actual_port != port:
                    fail('DNS response has wrong SRV target or port')
            found += 1
        offset += length
    if offset != len(data): fail('Malformed DNS trailing data')
    if code == 2: return 'candidate'
    if found != 1: fail('DNS response lacks exact fixture answer')
    return 'success'


def dns_answer(raw, query, address):
    if dns_response(raw, query, address) != 'success': fail('Known Service A answer is unavailable')
    return True


def inventory(rpc, namespace):
    types = rpc.call(['api-resources', '--namespaced=true', '--verbs=list,delete', '--cached=false', '-o', 'name']).splitlines()
    if (not types or len(types) > 512 or len(set(types)) != len(types) or
            any(not re.fullmatch('[a-z][a-z0-9.-]{0,252}', name) for name in types)):
        fail('Namespace discovery is incomplete')
    # Only metadata crosses SSH, including for Secret types. Do not export object
    # data or kubectl's last-applied annotations into receipts or diagnostics.
    expression = ('{range .items[*]}{.apiVersion}{"\\t"}{.kind}{"\\t"}{.metadata.name}{"\\t"}'
                  '{.metadata.uid}{"\\t"}{.metadata.labels.cloudlab\\.io/egress-proof}{"\\t"}'
                  '{.involvedObject.uid}{.regarding.uid}{"\\t"}'
                  '{.metadata.ownerReferences}{"\\t"}'
                  '{.metadata.labels.endpoints\\.kubernetes\\.io/managed-by}{"\\t"}'
                  '{.metadata.labels.kubernetes\\.io/service-name}{"\\t"}'
                  '{.metadata.labels.endpointslice\\.kubernetes\\.io/managed-by}{"\\t"}'
                  '{.metadata.labels.istio\\.io/config}{"\\t"}'
                  '{.metadata.labels.app\\.kubernetes\\.io/managed-by}{"\\n"}{end}')
    raw = rpc.call(['get', ','.join(types), '-n', namespace, '-o', 'jsonpath=' + expression])
    again = rpc.call(['api-resources', '--namespaced=true', '--verbs=list,delete', '--cached=false', '-o', 'name']).splitlines()
    if again != types: fail('Namespace discovery changed during cleanup')
    rows = []
    for line in raw.splitlines():
        fields = line.split('\t')
        if len(fields) != 12: fail('Malformed namespace metadata inventory')
        (version, kind, name, uid, marker, related, owners, endpoints_controller, service_name,
         slices_controller, istio_config, manager) = fields
        if (not re.fullmatch('[A-Za-z0-9./-]{1,253}', version) or
                not re.fullmatch('[A-Za-z][A-Za-z0-9]{0,63}', kind) or
                not re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', name) or
                not re.fullmatch('[a-f0-9-]{36}', uid)):
            fail('Malformed namespace metadata identity')
        try: owners = json.loads(owners) if owners else []
        except ValueError: fail('Malformed namespace owner metadata')
        if not isinstance(owners, list) or len(owners) > 32 or any(not isinstance(owner, dict) for owner in owners):
            fail('Malformed namespace owner metadata')
        rows.append((version + '/' + kind + '/' + name, uid, marker, related,
                     {'owners': owners, 'endpoints_controller': endpoints_controller,
                      'service_name': service_name, 'slices_controller': slices_controller,
                      'istio_config': istio_config, 'manager': manager}))
    return rows


def service_child(key, marker, metadata, rows, recorded, run):
    """Recognize only this run's backend Service controller children."""
    service_key = 'v1/Service/backend'
    service_uid = recorded.get(service_key)
    if (not service_uid or marker != run or
            not any(row[0] == service_key and row[1] == service_uid and row[2] == run for row in rows)):
        return False
    owners = metadata.get('owners')
    if key == 'v1/Endpoints/backend':
        return owners == [] and metadata.get('endpoints_controller') == 'endpoint-controller'
    if not re.fullmatch(r'discovery[.]k8s[.]io/v1/EndpointSlice/backend-[a-z0-9]{5}', key):
        return False
    return (metadata.get('service_name') == 'backend' and
            metadata.get('slices_controller') == 'endpointslice-controller.k8s.io' and
            isinstance(owners, list) and len(owners) == 1 and
            owners[0].get('apiVersion') == 'v1' and owners[0].get('kind') == 'Service' and
            owners[0].get('name') == 'backend' and owners[0].get('uid') == service_uid and
            owners[0].get('controller') is True)


def mesh_or_policy_child(key, marker, metadata, rows, recorded, run):
    """Allow canonical public trust copies or reports owned by recorded pods."""
    if marker not in ('', run): return False
    owners = metadata.get('owners')
    if key in ('v1/ConfigMap/istio-ca-crl', 'v1/ConfigMap/istio-ca-root-cert'):
        return metadata.get('istio_config') == 'true' and owners == []
    if (not re.fullmatch(r'wgpolicyk8s[.]io/v1alpha2/PolicyReport/[a-z0-9][a-z0-9.-]{0,252}', key) or
            metadata.get('manager') != 'kyverno' or not isinstance(owners, list) or len(owners) != 1):
        return False
    owner = owners[0]
    if (owner.get('apiVersion') != 'v1' or owner.get('kind') != 'Pod' or 'controller' in owner or
            not isinstance(owner.get('name'), str)):
        return False
    parent = 'v1/Pod/' + owner['name']
    if not recorded.get(parent) or owner.get('uid') != recorded[parent]: return False
    current = [row for row in rows if row[0] == parent]
    return not current or (len(current) == 1 and current[0][1] == recorded[parent] and current[0][2] == run)


def cleanup(rpc, receipt):
    for row in receipt.value['namespaces'].values():
        name = row['profile']['metadata']['name']
        current = rpc.get('namespace', name)
        if current is None:
            row['phase'] = 'cleaned'
            receipt.save()
            continue
        if row['phase'] == 'planned': fail('Uncreated proof namespace unexpectedly exists')
        uid = identity(current, row, receipt.run)
        if row['uid'] is None:
            row['uid'] = uid
            receipt.save()
        if not current['metadata'].get('deletionTimestamp'):
            rows = inventory(rpc, name)
            for key, actual_uid, marker, _, _ in rows:
                if key in row['objects'] and row['objects'][key] is None and marker == receipt.run:
                    row['objects'][key] = actual_uid
            receipt.save()
            known = {uid, *[value for value in row['objects'].values() if value]}
            for key, actual_uid, marker, related, metadata in rows:
                if key in ('v1/ServiceAccount/default', 'v1/ConfigMap/kube-root-ca.crt'): continue
                if key.startswith(('v1/Event/', 'events.k8s.io/v1/Event/')) and related in known: continue
                if service_child(key, marker, metadata, rows, row['objects'], receipt.run): continue
                if mesh_or_policy_child(key, marker, metadata, rows, row['objects'], receipt.run): continue
                if key not in row['objects'] or marker != receipt.run:
                    fail('Foreign or persistent fixture resource blocks cleanup; receipt retained')
                if row['objects'][key] is not None and row['objects'][key] != actual_uid:
                    fail('Fixture child identity changed; receipt retained')
            # A retained PV can still refer to a removed PVC in this namespace.
            pv = rpc.call(['get', 'persistentvolumes', '-o',
                           'jsonpath={range .items[?(@.spec.claimRef.namespace=="' + name + '")]}{.metadata.uid}{"\\n"}{end}'])
            if pv.strip(): fail('Persistent data refers to proof namespace; receipt retained')
            row['phase'] = 'delete-pending'
            receipt.save()
        if not current['metadata'].get('deletionTimestamp'):
            rpc.call(['delete', '--raw', '/api/v1/namespaces/' + name, '-f', '-'],
                     {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid},
                      'propagationPolicy': 'Background'})
        while True:
            current = rpc.get('namespace', name)
            if current is None: break
            identity(current, row, receipt.run)
            if time.monotonic() >= rpc.deadline: fail('Fixture cleanup deadline exceeded; receipt retained')
            time.sleep(2)
        row['phase'] = 'cleaned'
        receipt.save()
    receipt.value['complete'] = True
    receipt.save()


def placed_pod(namespace, name, image, account, node, nonce, *, server=False, label='backend'):
    row = fixtures.pod(namespace, name, image, account, server=server)
    row['metadata']['labels']['app'] = label if server else 'client'
    row['spec']['nodeSelector'] = {'kubernetes.io/hostname': node}
    row['spec'].setdefault('volumes', []).append({'name': 'work', 'emptyDir': {'sizeLimit': '1Mi'}})
    row['spec']['containers'][0].setdefault('volumeMounts', []).append({'name': 'work', 'mountPath': '/work'})
    if server:
        row['spec']['containers'][0]['command'] = ['sh', '-ec',
            'mkdir -p /www; printf %s ' + shlex.quote(nonce) + ' > /www/index.html; '
            'httpd -p 8081 -h /www; exec httpd -f -p 8080 -h /www']
        row['spec']['containers'][0]['readinessProbe']['exec']['command'] = ['sh', '-ec',
            'wget -qO- -T 2 http://127.0.0.1:8080/ >/dev/null; wget -qO- -T 2 http://127.0.0.1:8081/ >/dev/null']
    return row


def validate_history(value):
    proof = value['proof']
    if not isinstance(proof, dict) or set(proof) != {'client', 'service', 'preflight'}:
        fail('Invalid proof history')
    client = proof['client']
    if client is not None:
        if (set(client) != {'active', 'seen_ips', 'retirements'} or
                not re.fullmatch(r'allowed(?:-[a-f0-9]{12})?', client['active']) or
                not isinstance(client['seen_ips'], list) or len(client['seen_ips']) > 32 or
                len(set(client['seen_ips'])) != len(client['seen_ips']) or
                not isinstance(client['retirements'], list) or len(client['retirements']) > 20):
            fail('Invalid source client history')
        for address in client['seen_ips']: ipaddress.IPv4Address(address)
        for item in client['retirements']:
            if (set(item) != {'old', 'uid', 'ip', 'new', 'phase', 'new_uid', 'new_ip'} or
                    not re.fullmatch(r'allowed(?:-[a-f0-9]{12})?', item['old']) or
                    not re.fullmatch(r'allowed-[a-f0-9]{12}', item['new']) or
                    item['phase'] not in ('retire-pending', 'create-pending', 'complete') or
                    value['namespaces']['source']['objects'].get('v1/Pod/' + item['old']) != item['uid']):
                fail('Invalid source retirement history')
            ipaddress.IPv4Address(item['ip'])
            if item['new_uid'] is not None and value['namespaces']['source']['objects'].get('v1/Pod/' + item['new']) != item['new_uid']:
                fail('Invalid source replacement identity')
            if item['new_ip'] is not None: ipaddress.IPv4Address(item['new_ip'])
    service = proof['service']
    if service is not None:
        if (set(service) != {'uid', 'spec_hash', 'intended', 'names'} or
                service['uid'] != value['namespaces']['plain']['objects'].get('v1/Service/backend') or
                not re.fullmatch('[a-f0-9]{64}', service['spec_hash']) or
                not re.fullmatch(r'http|h-[a-f0-9]{12}', service['intended']) or
                len(service['names']) > 64 or len(set(service['names'])) != len(service['names']) or
                any(not re.fullmatch(r'h-[a-f0-9]{12}', name) for name in service['names'])):
            fail('Invalid named-port history')
    if proof['preflight'] is not None and len(json.dumps(proof['preflight'])) > 4096:
        fail('Invalid preflight interpretation')


def current_client(receipt):
    return receipt.value['proof']['client']['active']


def fresh_client(rpc, receipt, image, node):
    row = receipt.value['namespaces']['source']
    namespace = row['profile']['metadata']['name']
    identity(rpc.get('namespace', namespace), row, receipt.run)
    history = receipt.value['proof']['client']
    if len(history['retirements']) >= 20: fail('Fresh-client budget exhausted; proof unqualified')
    old = current_client(receipt)
    pod = ready(rpc, namespace, old)
    new = 'allowed-' + uuid.uuid4().hex[:12]
    if 'v1/Pod/' + new in row['objects']: fail('Source replacement name reused')
    transition = {'old': old, 'uid': pod['metadata']['uid'], 'ip': pod['status']['podIP'],
                  'new': new, 'phase': 'retire-pending', 'new_uid': None, 'new_ip': None}
    history['retirements'].append(transition)
    receipt.save()
    rpc.call(['delete', '--raw', '/api/v1/namespaces/' + namespace + '/pods/' + old, '-f', '-'],
             {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': transition['uid']},
              'gracePeriodSeconds': 1})
    deadline = min(rpc.deadline, time.monotonic() + 60)
    while True:
        remaining = rpc.get('pod', old, namespace)
        if remaining is None: break
        if remaining['metadata'].get('uid') != transition['uid']: fail('Retiring source UID changed')
        if time.monotonic() >= deadline: fail('Source retirement did not complete')
        time.sleep(1)
    transition['phase'] = 'create-pending'
    row['objects']['v1/Pod/' + new] = None
    receipt.save()
    record(rpc, receipt, 'source', [placed_pod(namespace, new, image, 'allowed', node['hostname'], receipt.run)])
    transition['new_uid'] = row['objects']['v1/Pod/' + new]
    receipt.save()
    if transition['new_uid'] in [uid for key, uid in row['objects'].items() if key.startswith('v1/Pod/') and key != 'v1/Pod/' + new]:
        fail('Source UID reused; fresh-flow proof unqualified')
    replacement = wait_ready(rpc, namespace, new)
    address = replacement['status']['podIP']
    ipaddress.IPv4Address(address)
    transition['new_ip'] = address
    receipt.save()
    annotations = replacement['metadata'].get('annotations', {})
    if (replacement['spec'].get('nodeName') != node['name'] or
            replacement['spec'].get('serviceAccountName') != 'allowed' or
            replacement['spec'].get('automountServiceAccountToken') is not False or
            replacement['spec'].get('dnsPolicy') != 'ClusterFirst' or replacement['spec'].get('dnsConfig') or
            annotations.get('ambient.istio.io/redirection') != 'enabled' or
            annotations.get('ambient.istio.io/dns-capture') not in (None, 'true')):
        fail('Fresh client placement or capture differs')
    if address in history['seen_ips']: fail('Source IP reused; fresh-flow proof unqualified')
    history['seen_ips'].append(address)
    rpc.pod_ips[(namespace, new)] = address
    history['active'] = new
    transition['phase'] = 'complete'
    receipt.save()
    return new


def node_targets(nodes):
    if len(nodes) != 2 or any(not any(c.get('type') == 'Ready' and c.get('status') == 'True'
                                     for c in n.get('status', {}).get('conditions', [])) for n in nodes):
        fail('Proof requires exactly two existing Ready nodes')
    rows = [{'hostname': n['metadata']['labels']['kubernetes.io/hostname'],
             'name': n['metadata']['name'], 'uid': n['metadata']['uid']} for n in nodes]
    if any(len({row[key] for row in rows}) != 2 for key in ('hostname', 'name', 'uid')):
        fail('Cross-node proof requires distinct node identities and hostname labels')
    if any(not re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', row['name']) or
           not re.fullmatch('[a-z0-9][a-z0-9.-]{0,62}', row['hostname']) or
           not re.fullmatch('[a-f0-9-]{36}', row['uid']) for row in rows):
        fail('Invalid node scheduling identity')
    if any(not n.get('spec', {}).get('podCIDRs') or any(ipaddress.ip_network(cidr).version != 4
           for cidr in n['spec']['podCIDRs']) for n in nodes):
        fail('This verifier only qualifies configured IPv4 pod networks')
    return sorted(rows, key=lambda row: row['hostname'])


def setup(rpc, receipt, image, nodes):
    for role in ROLES: create_namespace(rpc, receipt, role)
    names = {role: row['profile']['metadata']['name'] for role, row in receipt.value['namespaces'].items()}
    for role in ROLES:
        ns = names[role]
        objects = []
        if role == 'source':
            for account in ('allowed', 'denied'):
                objects += [fixtures.account(ns, account),
                            placed_pod(ns, account, image, account, nodes[1]['hostname'], receipt.run)]
        else:
            objects = [fixtures.account(ns, 'backend'), fixtures.service(ns),
                       placed_pod(ns, 'backend', image, 'backend', nodes[0]['hostname'], receipt.run, server=True)]
            if role == 'plain':
                objects.append(placed_pod(ns, 'other', image, 'backend', nodes[0]['hostname'], receipt.run, server=True, label='other'))
        record(rpc, receipt, role, objects)
    pods = {role: ('allowed', 'denied') if role == 'source' else ('backend', 'other') if role == 'plain' else ('backend',)
            for role in ROLES}
    observed = {}
    for role, names_in_role in pods.items():
        for pod in names_in_role:
            row = wait_ready(rpc, names[role], pod)
            expected = receipt.value['namespaces'][role]['objects']['v1/Pod/' + pod]
            node = nodes[1 if role == 'source' else 0]
            if (row['metadata']['uid'] != expected or row['spec'].get('nodeName') != node['name'] or
                    row['spec'].get('nodeSelector') != {'kubernetes.io/hostname': node['hostname']}):
                fail('Fixture pod identity or placement differs')
            if role in ('source', 'ambient') and row['metadata'].get('annotations', {}).get('ambient.istio.io/redirection') != 'enabled':
                fail('Fixture pod is not captured by ambient')
            ipaddress.IPv4Address(row['status']['podIP'])
            observed[(role, pod)] = row['status']['podIP']
            rpc.pod_ips[(names[role], pod)] = row['status']['podIP']
    if node_targets(rpc.get('nodes')['items']) != nodes: fail('Node identities changed during fixture placement')
    receipt.value['proof']['client'] = {'active': 'allowed', 'seen_ips': sorted(set(observed.values())), 'retirements': []}
    if len(receipt.value['proof']['client']['seen_ips']) != len(observed): fail('Fixture Pod IPs are not distinct')
    receipt.save()
    return names, observed


def peer(namespace, label='backend', ports=(8080,)):
    return {'namespace': namespace, 'podSelector': {'matchLabels': {'app': label}},
            'ports': [{'port': port, 'protocol': 'TCP'} for port in ports]}


def apply_policy(rpc, receipt, rules, publication='ready', *, extra=False):
    name = receipt.value['namespaces']['source']['profile']['metadata']['name'].removeprefix('cloudlab-app-')
    _, policy = native(name, rules, publication)
    if extra: policy['metadata']['name'] = 'proof-additive'
    record(rpc, receipt, 'source', [policy])


def rename_service_port(rpc, receipt, name):
    if not re.fullmatch(r'http|h-[a-f0-9]{12}', name): fail('Invalid fixture named port')
    row = receipt.value['namespaces']['plain']
    namespace = row['profile']['metadata']['name']
    identity(rpc.get('namespace', namespace), row, receipt.run)
    service = rpc.get('service', 'backend', namespace) or {}
    meta, spec = service.get('metadata', {}), service.get('spec', {})
    if (meta.get('uid') != row['objects'].get('v1/Service/backend') or
            meta.get('labels', {}).get(MARKER) != receipt.run or not meta.get('resourceVersion') or
            len(spec.get('ports', [])) != 1 or spec.get('selector') != {'app': 'backend'}):
        fail('Fixture Service identity or selector changed')
    port = spec['ports'][0]
    if (port.get('port') != 8080 or port.get('targetPort') != 8080 or port.get('protocol') != 'TCP' or
            not re.fullmatch(r'http|h-[a-f0-9]{12}', port.get('name', ''))):
        fail('Fixture Service port changed')
    normalized = copy.deepcopy(spec)
    normalized['ports'][0]['name'] = 'http'
    spec_hash = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    state = receipt.value['proof']['service']
    if state is None:
        if port['name'] != 'http': fail('Initial fixture named port differs')
        state = {'uid': meta['uid'], 'spec_hash': spec_hash, 'intended': 'http', 'names': []}
        receipt.value['proof']['service'] = state
    if state['uid'] != meta['uid'] or state['spec_hash'] != spec_hash:
        fail('Fixture Service immutable fields changed')
    if name != 'http':
        if name in state['names'] or len(state['names']) >= 64: fail('SRV question name reused or budget exhausted')
        state['names'].append(name)
    state['intended'] = name
    receipt.save()
    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': meta['uid']},
             {'op': 'test', 'path': '/metadata/resourceVersion', 'value': meta['resourceVersion']},
             {'op': 'test', 'path': '/spec', 'value': spec},
             {'op': 'replace', 'path': '/spec/ports/0/name', 'value': name}]
    raw = rpc.call(['patch', 'service', 'backend', '-n', namespace, '--type=json', '--patch-file=/dev/stdin', '-o', 'json'], patch)
    changed = json.loads(raw)
    expected = copy.deepcopy(spec)
    expected['ports'][0]['name'] = name
    if changed.get('metadata', {}).get('uid') != meta['uid'] or changed.get('spec') != expected:
        fail('Named-port update changed unrelated Service fields')
    return '_' + name + '._tcp.backend.' + namespace + '.svc.cluster.local'


def dns_probe(rpc, namespace, pod, resolver, name, answer, tcp):
    ipaddress.IPv4Address(resolver)
    query = question(name)
    if tcp:
        encoded = base64.b64encode(struct.pack('!H', len(query)) + query).decode()
        script = ('printf %s ' + shlex.quote(encoded) + ' | base64 -d | nc -w 4 ' + resolver +
                  ' 53 > /work/dns 2>/work/error; code=$?; printf \'{"code":%s,"data":"%s"}\\n\' '
                  '"$code" "$(base64 /work/dns | tr -d \'\\n\')"')
    else:
        script = ('timeout 8 nslookup -type=A ' + shlex.quote(name) + ' ' + resolver + ' > /work/dns 2>&1; '
                  'code=$?; printf \'{"code":%s,"data":"%s"}\\n\' "$code" '
                  '"$(base64 /work/dns | tr -d \'\\n\')"')
    value = rpc.exec(namespace, pod, script)
    if set(value) != {'code', 'data'} or type(value['code']) is not int: fail('Invalid DNS probe result')
    try: data = base64.b64decode(value['data'], validate=True)
    except (ValueError, TypeError): fail('Invalid DNS probe encoding')
    if tcp:
        if data: return dns_answer(data, query, answer)
        if value['code'] not in (0, 1): fail('TCP DNS applet failed')
        return False
    try: text = data.decode('ascii')
    except UnicodeError: fail('Invalid UDP DNS response')
    if value['code'] == 0:
        if name not in text or not re.search(r'(?m)^Address(?: [0-9]+)?:\s*' + re.escape(answer) + r'(?:\s|$)', text):
            fail('UDP DNS response lacks expected answer')
        return True
    if value['code'] in (124, 143) and not any(error in text.upper() for error in ('NXDOMAIN', 'SERVFAIL', 'REFUSED')):
        return False
    if value['code'] != 1 or not any(word in text.lower() for word in ('timed out', 'no servers could be reached')):
        fail('UDP DNS failed unexpectedly')
    return False


def srv_text(code, data, name, target, port):
    try: text = data.decode('ascii')
    except UnicodeError: fail('Malformed client UDP DNS response')
    if code not in (0, 1, 124, 143): fail('DNS applet failed; proof unqualified')
    if 'NXDOMAIN' in text.upper(): fail('Unexpected NXDOMAIN; name propagation is not denial')
    matches = re.findall(r'(?im)^\s*(\S+)\s+service\s*=\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$', text)
    if matches:
        if (code != 0 or len(matches) != 1 or matches[0][0].lower().rstrip('.') != name.lower().rstrip('.') or
                matches[0][4].lower().rstrip('.') != target.lower().rstrip('.') or int(matches[0][3]) != port or
                any(int(value) > 65535 for value in matches[0][1:4])):
            fail('DNS response has wrong SRV target or port')
        return 'success'
    if (not text.strip() or 'SERVFAIL' in text.upper() or 'timed out' in text.lower() or
            'no servers could be reached' in text.lower()):
        return 'candidate'
    if code in (124, 143) and not any(token in text.lower() for token in ('usage:', 'not found', 'invalid option')):
        return 'candidate'
    fail('Malformed client UDP SRV response')


def srv_probe(rpc, namespace, pod, resolver, name, target, tcp):
    ipaddress.IPv4Address(resolver)
    query = question(name, uuid.uuid4().int & 65535, 33)
    if tcp:
        encoded = base64.b64encode(struct.pack('!H', len(query)) + query).decode()
        command = ('printf %s ' + shlex.quote(encoded) + ' | base64 -d | nc -w 4 ' + resolver + ' 53')
    else:
        command = 'timeout 8 nslookup -type=SRV ' + shlex.quote(name) + ' ' + resolver
    script = (': >/work/dns && : >/work/error || exit 70; ' + command + ' >/work/dns 2>/work/error; code=$?; '
              'printf \'{"code":%s,"data":"%s","error":"%s"}\\n\' "$code" '
              '"$(base64 /work/dns | tr -d \'\\n\')" "$(base64 /work/error | tr -d \'\\n\')"')
    value = rpc.exec(namespace, pod, script)
    if set(value) != {'code', 'data', 'error'} or type(value['code']) is not int:
        fail('Malformed SRV probe result')
    try:
        data = base64.b64decode(value['data'], validate=True)
        error = base64.b64decode(value['error'], validate=True)
    except (ValueError, TypeError): fail('Malformed SRV probe encoding')
    if len(data) > 65537 or len(error) > 8192: fail('SRV response exceeds bound')
    if tcp:
        if value['code'] not in (0, 1): fail('TCP DNS applet failed; proof unqualified')
        if data: return dns_response(data, query, target, 8080)
        if error and not any(token in error.lower() for token in (b'timed out', b'connection refused', b'no route to host')):
            fail('TCP DNS probe failed unexpectedly')
        return 'candidate'
    return srv_text(value['code'], data + error, name, target, 8080)


def fresh_srv_attempt(rpc, receipt, names, resolver, tcp):
    qname = rename_service_port(rpc, receipt, 'h-' + uuid.uuid4().hex[:12])
    target = 'backend.' + names['plain'] + '.svc.cluster.local'
    def control():
        return srv_probe(rpc, names['plain'], 'backend', resolver, qname, target, tcp)
    deadline = min(rpc.deadline, time.monotonic() + 30)
    # A newly named port may not have reached CoreDNS yet. Propagation, including
    # NXDOMAIN, is a prerequisite problem and never the source's denial outcome.
    while True:
        try: outcome = control()
        except ProofFailure as error:
            if str(error) != 'Unexpected NXDOMAIN; name propagation is not denial': raise
            outcome = 'propagating'
        if outcome == 'success': break
        if time.monotonic() >= deadline: fail('SRV control did not propagate; proof unqualified')
        time.sleep(1)
    source = srv_probe(rpc, names['source'], current_client(receipt), resolver, qname, target, tcp)
    if control() != 'success': fail('SRV control failed after source probe; proof unqualified')
    return source


def positive_srv(rpc, receipt, names, resolver, tcp):
    deadline = min(rpc.deadline, time.monotonic() + 60)
    while fresh_srv_attempt(rpc, receipt, names, resolver, tcp) != 'success':
        if time.monotonic() >= deadline: fail('Captured DNS positive control failed; proof unqualified')
        time.sleep(1)


def captured_dns(rpc, receipt, names, resolver, image, node, allow, dns_rule, tcp, cluster_ip):
    transport = 'tcp' if tcp else 'udp'
    key = 'captured_dns_client_' + transport
    evidence = {'A': 'not-run', 'B': 'not-run', 'A_restore': 'not-run', 'controls': 'not-qualified',
                'classification': 'unqualified', 'upstream_wire_protocol': 'not-inferred'}
    rpc.evidence[key] = evidence
    outer_deadline = rpc.deadline
    if outer_deadline - time.monotonic() < 180: fail('DNS restoration budget unavailable; proof unqualified')
    original_error = None
    failure_stage = None
    b_client = None
    try:
        rpc.stage = 'dns-allow-' + transport
        apply_policy(rpc, receipt, allow + [dns_rule])
        positive_srv(rpc, receipt, names, resolver, tcp)
        evidence['A'] = 'source-positive-controls-healthy'
        rpc.stage = 'dns-withdrawal-' + transport
        apply_policy(rpc, receipt, allow)
        # Reserve time for A restoration; cleanup has its own independent budget.
        rpc.deadline = outer_deadline - 90
        b_client = fresh_client(rpc, receipt, image, node)
        for _ in range(3):
            if fresh_srv_attempt(rpc, receipt, names, resolver, tcp) != 'candidate':
                evidence['B'] = 'source-success-after-withdrawal'
                fail('Captured DNS forwarding remained reachable after withdrawal')
        evidence['B'] = 'three-candidate-failures-controls-healthy'
        evidence['known_service_a_after_withdrawal'] = dns_probe(
            rpc, names['source'], b_client, resolver, 'backend.' + names['plain'] + '.svc.cluster.local', cluster_ip, tcp)
        # Local resolution controls the capture classification, not upstream access.
        if evidence['known_service_a_after_withdrawal'] is not True:
            fail('Known Service A local-resolution control failed; capture unqualified')
    except BaseException as error:
        original_error = error
        failure_stage = rpc.stage
    finally:
        rpc.deadline = outer_deadline
        rpc.stage = 'dns-restoration-' + transport
        try:
            apply_policy(rpc, receipt, allow + [dns_rule])
            if b_client is None or current_client(receipt) != b_client:
                fail('DNS restoration lacks the same fresh B client')
            positive_srv(rpc, receipt, names, resolver, tcp)
            evidence['A_restore'] = 'same-client-positive-controls-healthy'
        except BaseException as error:
            evidence['A_restore'] = 'failed-or-unqualified'
            if original_error is None: original_error, failure_stage = error, rpc.stage
        try: rename_service_port(rpc, receipt, 'http')
        except BaseException as error:
            if original_error is None: original_error, failure_stage = error, rpc.stage
    if original_error is not None:
        rpc.stage = failure_stage
        raise original_error
    evidence['controls'] = 'healthy-before-and-after-every-source-attempt'
    evidence['classification'] = 'observed-policy-correlated-captured-forwarding-failure'
    return evidence


def cni_dns_settings(container, data):
    """Validate configured settings, not a running process's environment."""
    flags = ('AMBIENT_ENABLED', 'AMBIENT_DNS_CAPTURE')
    if (not isinstance(container, dict) or
            container.get('envFrom') != [{'configMapRef': {'name': 'istio-cni-config'}}]):
        fail('CNI DNS capture configuration source differs')
    if not isinstance(data, dict) or any(data.get(name) != 'true' for name in flags):
        fail('Intended ambient DNS capture cannot be established')
    entries = container.get('env', [])
    if not isinstance(entries, list): fail('CNI direct environment shape is unsupported')
    seen = set()
    for entry in entries:
        if (not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or not entry['name'] or
                set(entry) - {'name', 'value', 'valueFrom'} or
                ('value' in entry and not isinstance(entry['value'], str)) or
                ('valueFrom' in entry and (not isinstance(entry['valueFrom'], dict) or
                 len(entry['valueFrom']) != 1 or entry.get('value', '') != ''))):
            fail('CNI direct environment shape is unsupported')
        name = entry['name']
        if name not in flags: continue
        if name in seen or set(entry) != {'name', 'value'} or entry['value'] != 'true':
            fail('Intended ambient DNS capture cannot be established')
        seen.add(name)
    return {'ambient_enabled': True, 'ambient_dns_capture': True}


def dns_preflight(rpc, receipt, names, resolver):
    interpretation = {}
    cni_container = None
    for component, daemon in (('ztunnel', 'ztunnel'), ('cni', 'istio-cni-node')):
        values = json.loads((ROOT / 'platform/connectivity/istio' / component / 'values.json').read_text())
        expected = values[component]['image']
        image_name = 'ztunnel' if component == 'ztunnel' else 'install-cni'
        if not re.fullmatch('docker.io/istio/' + image_name + r':1[.]31[.]1@sha256:[a-f0-9]{64}', expected):
            fail('Reviewed ambient DNS source pin differs; proof unqualified')
        obj = rpc.get('daemonset', daemon, 'istio-system') or {}
        spec, status = obj.get('spec', {}).get('template', {}).get('spec', {}), obj.get('status', {})
        containers = spec.get('containers', [])
        if (len(containers) != 1 or containers[0].get('image') != expected or
                status.get('observedGeneration', 0) < obj.get('metadata', {}).get('generation', 1) or
                any(status.get(key) != 2 for key in ('desiredNumberScheduled', 'updatedNumberScheduled', 'numberReady'))):
            fail('Pinned ambient data plane is not ready; DNS unqualified')
        if component == 'cni': cni_container = containers[0]
        interpretation[component + '_pin_matches'] = True
    config = rpc.get('configmap', 'istio-cni-config', 'istio-system') or {}
    cni_dns_settings(cni_container, config.get('data'))
    pod = ready(rpc, names['source'], current_client(receipt))
    capture = pod['metadata'].get('annotations', {}).get('ambient.istio.io/dns-capture')
    if (capture not in (None, 'true') or pod.get('spec', {}).get('dnsPolicy') != 'ClusterFirst' or
            pod['spec'].get('hostNetwork', False) or pod['spec'].get('dnsConfig')):
        fail('Fixture resolver or capture profile differs')
    result = rpc.exec(names['source'], current_client(receipt),
                      'printf \'{"resolv":"%s"}\\n\' "$(head -c 4097 /etc/resolv.conf | base64 | tr -d \'\\n\')"')
    if set(result) != {'resolv'}: fail('Resolver evidence malformed')
    try: raw = base64.b64decode(result['resolv'], validate=True).decode('ascii')
    except (ValueError, TypeError, UnicodeError): fail('Resolver evidence malformed')
    if len(raw) > 4096: fail('Resolver evidence exceeds bound')
    servers = re.findall(r'(?m)^nameserver\s+(\S+)\s*$', raw)
    if servers != [resolver]: fail('Intended fixture resolver cannot be established')
    interpretation.update(configured_dns_capture_enabled=True, source_dns_policy='ClusterFirst',
                          resolver_matches_cluster_dns=True, source_capture_override='default' if capture is None else 'true')
    receipt.value['proof']['preflight'] = interpretation
    receipt.save()
    return interpretation


def traffic(rpc, receipt, image, nodes):
    rpc.stage = 'fixture-setup'
    names, pods = setup(rpc, receipt, image, nodes)
    source = names['source']
    def connection(role, pod='backend', port=8080, *, address=None, client=None):
        # Verify the actual listener before and after the policy probe, not merely
        # stale Ready status or an unrelated listener in the same pod.
        if not http(rpc, names[role], pod, '127.0.0.1', port, receipt.run): fail('Backend listener unhealthy')
        value = http(rpc, source, client or current_client(receipt), address or pods[(role, pod)], port, receipt.run)
        if not http(rpc, names[role], pod, '127.0.0.1', port, receipt.run): fail('Backend listener became unhealthy')
        return value
    targets = [('plain', 'backend', 8080), ('plain', 'other', 8080), ('wrong', 'backend', 8080),
               ('ambient', 'backend', 8080), ('ambient', 'backend', 8081), ('plain', 'backend', 8081)]
    rpc.stage = 'reachable-baselines'
    for role, pod, port in targets: expect_connection(lambda r=role, p=pod, n=port: connection(r, p, n), True)
    cluster_ip = rpc.get('service', 'backend', names['plain'])['spec']['clusterIP']
    expect_connection(lambda: connection('plain', address=cluster_ip), True)
    dns_service = rpc.get('service', 'kube-dns', 'kube-system') or {}
    resolver = dns_service.get('spec', {}).get('clusterIP', '')
    dns_pods = rpc.get('pods', namespace='kube-system')['items']
    if not any(p['metadata'].get('labels', {}).get('k8s-app') == 'kube-dns' and
               any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in p.get('status', {}).get('conditions', []))
               for p in dns_pods): fail('Accepted DNS resolver is not ready')
    rpc.stage = 'dns-preflight'
    preflight = dns_preflight(rpc, receipt, names, resolver)
    dns_name_value = 'backend.' + names['plain'] + '.svc.cluster.local'
    known_a = {('client_tcp' if tcp else 'client_udp'): dns_probe(
        rpc, source, current_client(receipt), resolver, dns_name_value, cluster_ip, tcp) for tcp in (False, True)}
    held_client = current_client(receipt)
    held = hold_connection(rpc, source, pods[('plain', 'backend')], held_client)
    rpc.stage = 'empty-egress'
    apply_policy(rpc, receipt, [])
    established_observation = release_connection(rpc, source, held, receipt.run, held_client)
    fresh_client(rpc, receipt, image, nodes[1])
    expect_connection(lambda: connection('plain'), False)
    expect_connection(lambda: connection('plain', address=cluster_ip), False)
    expect_connection(lambda: connection('ambient'), False)
    allow = [peer(names['plain'])]
    rpc.stage = 'exact-peer'
    apply_policy(rpc, receipt, allow)
    fresh_client(rpc, receipt, image, nodes[1])
    expect_connection(lambda: connection('plain'), True)
    expect_connection(lambda: connection('ambient'), False)
    for role, pod, port in (('wrong', 'backend', 8080), ('plain', 'other', 8080), ('plain', 'backend', 8081)):
        expect_connection(lambda r=role, p=pod, n=port: connection(r, p, n), False)
    dns_rule = {'namespace': 'kube-system', 'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}},
                'ports': [{'port': 53, 'protocol': 'UDP'}, {'port': 53, 'protocol': 'TCP'}]}
    dns_outcomes = {}
    for tcp in (False, True):
        dns_outcomes['captured_dns_client_' + ('tcp' if tcp else 'udp')] = captured_dns(
            rpc, receipt, names, resolver, image, nodes[1], allow, dns_rule, tcp, cluster_ip)
    apply_policy(rpc, receipt, [])
    fresh_client(rpc, receipt, image, nodes[1])
    expect_connection(lambda: connection('plain'), False)
    rpc.stage = 'additive-policy'
    apply_policy(rpc, receipt, allow, extra=True)
    expect_connection(lambda: connection('plain'), True)
    extra_key = 'networking.k8s.io/v1/NetworkPolicy/proof-additive'
    extra = rpc.get('networkpolicy', 'proof-additive', source)
    extra_uid = receipt.value['namespaces']['source']['objects'][extra_key]
    if (not extra or extra['metadata'].get('uid') != extra_uid or
            extra['metadata'].get('labels', {}).get(MARKER) != receipt.run):
        fail('Additive fixture policy identity changed')
    rpc.call(['delete', '--raw', '/apis/networking.k8s.io/v1/namespaces/' + source + '/networkpolicies/proof-additive', '-f', '-'],
             {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': extra_uid}})
    if rpc.get('networkpolicy', 'proof-additive', source) is not None: fail('Additive policy removal is incomplete')
    receipt.value['namespaces']['source']['objects'].pop(extra_key)
    receipt.save()
    expect_connection(lambda: connection('plain'), False)
    apply_policy(rpc, receipt, allow)
    expect_connection(lambda: connection('plain'), True)
    rpc.stage = 'retirement'
    apply_policy(rpc, receipt, allow, 'retired')
    fresh_client(rpc, receipt, image, nodes[1])
    expect_connection(lambda: connection('plain'), False)
    observations = {}
    rpc.stage = 'ambient-transport'
    for port in (8080, 15008):
        apply_policy(rpc, receipt, [peer(names['ambient'], ports=(port,))])
        fresh_client(rpc, receipt, image, nodes[1])
        observations[str(port)] = connection('ambient')
    # Mesh identity/inner-port checks need a usable observed transport path.
    usable = next((int(port) for port, value in observations.items() if value), None)
    if usable is None: fail('No declared ambient transport path worked; mesh qualification incomplete')
    apply_policy(rpc, receipt, [peer(names['ambient'], ports=(usable, 8081))])
    fresh_client(rpc, receipt, image, nodes[1])
    principal = 'cluster.local/ns/' + source + '/sa/allowed'
    rpc.stage = 'ambient-authorization'
    expect_connection(lambda: connection('ambient', client='denied'), True)
    record(rpc, receipt, 'ambient', fixtures.identity_policy(names['ambient'], [principal]))
    expect_connection(lambda: connection('ambient'), True)
    expect_connection(lambda: connection('ambient', client='denied'), False)
    expect_connection(lambda: connection('ambient', port=8081), False)
    expect_connection(lambda: connection('ambient'), True)
    return {'fresh_ipv4_egress': 'passed', **dns_outcomes,
            'known_service_a_resolution_observation': known_a, 'dns_capture_preflight': preflight,
            'removal_retirement_additive': 'passed',
            'ambient_transport_observations': observations, 'ambient_identity_inner_port': 'passed',
            'established_connections': established_observation,
            'dual_stack': 'not configured; not qualified', 'node_api_external': 'not qualified'}


def application_policy(name, publication='ready'):
    definition = yaml.safe_load((ROOT / 'charts/service/values.yaml').read_text())
    definition['name'] = 'allowed'
    approved = {'name': name, 'namespace': 'cloudlab-app-' + name,
                'repository': 'https://github.com/example/fixture.git', 'revision': 'a' * 40,
                'valuesPath': 'apps/proof.yaml', 'secretReferences': [], 'configMaps': [], 'egress': []}
    rows = resources(definition, approved, 'https://github.com/example/platform.git', 'a' * 40,
                     publication=publication)
    selected = [row for row in rows if row['kind'] == 'AuthorizationPolicy']
    if len(selected) != 1 or selected[0]['metadata']['name'] != 'platform-workloads':
        fail('Candidate application authorization is ambiguous')
    return selected[0]


def application_policies(rpc, namespace):
    """An empty inventory requires a successful, complete typed API collection."""
    if not isinstance(namespace, str) or not re.fullmatch(r'cloudlab-app-egress-[a-f0-9]{12}', namespace):
        fail('Application authorization inventory escaped its fixture namespace')
    raw = rpc.call(['get', '--raw', '/apis/security.istio.io/v1/namespaces/' + namespace + '/authorizationpolicies'])
    if not isinstance(raw, str) or len(raw.encode()) > LIMIT:
        fail('Application authorization inventory exceeds its bound')
    try: collection = json.loads(raw)
    except (ValueError, TypeError): fail('Application authorization inventory is malformed')
    if (not isinstance(collection, dict) or collection.get('apiVersion') != 'security.istio.io/v1' or
            collection.get('kind') != 'AuthorizationPolicyList' or
            not isinstance(collection.get('metadata'), dict) or
            not isinstance(collection['metadata'].get('resourceVersion'), str) or
            not collection['metadata']['resourceVersion'] or
            ('continue' in collection['metadata'] and collection['metadata']['continue'] != '') or
            ('remainingItemCount' in collection['metadata'] and
             (type(collection['metadata']['remainingItemCount']) is not int or collection['metadata']['remainingItemCount'] != 0)) or
            not isinstance(collection.get('items'), list) or len(collection['items']) > 128):
        fail('Application authorization inventory is incomplete')
    names, uids = set(), set()
    for row in collection['items']:
        meta = row.get('metadata') if isinstance(row, dict) else None
        if (not isinstance(meta, dict) or row.get('apiVersion') != 'security.istio.io/v1' or
                row.get('kind') != 'AuthorizationPolicy' or meta.get('namespace') != namespace or
                not isinstance(meta.get('name'), str) or not re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', meta['name']) or
                not isinstance(meta.get('uid'), str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', meta['uid']) or
                not isinstance(meta.get('resourceVersion'), str) or not meta['resourceVersion'] or
                meta.get('deletionTimestamp') or not isinstance(row.get('spec'), dict) or
                meta['name'] in names or meta['uid'] in uids):
            fail('Application authorization inventory has an invalid object')
        names.add(meta['name'])
        uids.add(meta['uid'])
    return collection['items']


def application_ports(rpc, receipt, image, nodes):
    """Exercise unchanged native policy documents; L4 permissions never withdraw."""
    rpc.stage = 'application-setup'
    create_namespace(rpc, receipt, 'source')
    namespace = receipt.value['namespaces']['source']['profile']['metadata']['name']
    name = namespace.removeprefix('cloudlab-app-')
    for account in ('allowed', 'denied'):
        record(rpc, receipt, 'source', [fixtures.account(namespace, account),
            placed_pod(namespace, account, image, account, nodes[1]['hostname'], receipt.run)])
    backend = placed_pod(namespace, 'backend', image, 'allowed', nodes[0]['hostname'], receipt.run, server=True)
    backend['metadata']['labels'].update({'cloudlab.io/owner': 'platform', 'app.kubernetes.io/name': 'allowed'})
    record(rpc, receipt, 'source', [backend, fixtures.identity_policy(namespace, [])[0]])
    pods = {}
    for pod in ('allowed', 'denied', 'backend'):
        row = wait_ready(rpc, namespace, pod)
        expected_node = nodes[0 if pod == 'backend' else 1]
        if (row['spec'].get('nodeName') != expected_node['name'] or
                row['metadata'].get('annotations', {}).get('ambient.istio.io/redirection') != 'enabled'):
            fail('Fixture application capture or placement differs')
        pods[pod] = (row['metadata']['uid'], row['status']['podIP'])
        rpc.pod_ips[(namespace, pod)] = row['status']['podIP']
    apply_policy(rpc, receipt, [peer(namespace, ports=(8080, 8081, 15008))])
    l4 = rpc.get('networkpolicy', 'platform-egress', namespace)
    frozen_l4 = (l4['metadata']['uid'], copy.deepcopy(l4['spec']))
    active, retired = application_policy(name), application_policy(name, 'retired')
    if active['metadata'] != retired['metadata'] or retired['spec'].get('rules') != []:
        fail('Candidate retirement did not preserve its denying policy identity')
    fingerprint = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    receipt.value['proof']['preflight'] = {'application_policy_sha256': fingerprint(active),
        'retired_policy_sha256': fingerprint(retired), 'l4_spec_sha256': fingerprint(frozen_l4[1]),
        'pod_uids': {pod: value[0] for pod, value in pods.items()}}
    receipt.save()
    def stable():
        for pod, (uid, address) in pods.items():
            row = ready(rpc, namespace, pod)
            if (row['metadata']['uid'], row['status']['podIP']) != (uid, address):
                fail('Application fixture identity changed')
        current = rpc.get('networkpolicy', 'platform-egress', namespace)
        if (current['metadata']['uid'], current['spec']) != frozen_l4:
            fail('Application fixture L4 control changed')
    def connection(account='allowed', port=8080):
        stable()
        if not http(rpc, namespace, 'backend', '127.0.0.1', port, receipt.run):
            fail('Backend listener unhealthy')
        result = http(rpc, namespace, account, pods['backend'][1], port, receipt.run)
        if not http(rpc, namespace, 'backend', '127.0.0.1', port, receipt.run):
            fail('Backend listener became unhealthy')
        return result
    def install(document):
        record(rpc, receipt, 'source', [document])
        expected_uid = receipt.value['namespaces']['source']['objects'][object_key(document)]
        policies = application_policies(rpc, namespace)
        if (len(policies) != 1 or policies[0]['metadata']['name'] != document['metadata']['name'] or
                policies[0]['metadata']['uid'] != expected_uid or policies[0]['spec'] != document['spec'] or
                policies[0]['metadata'].get('labels', {}).get(MARKER) != receipt.run):
            fail('Candidate application policy differs from its exact fixture owner')
    rpc.stage = 'application-baselines'
    if application_policies(rpc, namespace):
        fail('Application fixture already has an authorization policy')
    for account, port in (('allowed', 8080), ('allowed', 8081), ('denied', 8080)):
        expect_connection(lambda a=account, p=port: connection(a, p), True)
    rpc.stage = 'application-authorization'
    install(active)
    expect_connection(lambda: connection(), True)
    expect_connection(lambda: connection(port=8081), False)
    expect_connection(lambda: connection('denied'), False)
    expect_connection(lambda: connection(), True)
    rpc.stage = 'application-retirement'
    install(retired)
    expect_connection(lambda: connection(), False)
    rpc.stage = 'application-restoration'
    install(active)
    expect_connection(lambda: connection(), True)
    expect_connection(lambda: connection(port=8081), False)
    expect_connection(lambda: connection('denied'), False)
    expect_connection(lambda: connection(), True)
    stable()
    if node_targets(rpc.get('nodes')['items']) != nodes: fail('Node identities changed during application proof')
    if receipt.value['hashes'] != hashes(): fail('Proof source changed; use exact receipt cleanup')
    return {'candidate_application_ports': 'passed', 'candidate_retirement_restoration': 'passed',
            'stable_pods_and_l4_controls': True,
            'gateway_other_additive_root_udp_ipv6_external_existing_streams': 'not qualified'}


def execute(args, rpc, target, image, nodes):
    receipt = Receipt(args.receipts, args.resume or args.cleanup)
    stage = 'receipt'
    try:
        if args.resume or args.cleanup: receipt.load(target)
        else: receipt.start(target)
        if receipt.value['complete']: return {'run': receipt.run, 'cleanup': 'complete'}
        if args.cleanup:
            stage = 'cleanup'
            cleanup(RPC(rpc.host, time.monotonic() + 300), receipt)
            return {'run': receipt.run, 'cleanup': 'complete'}
        stage = 'source-check'
        if receipt.value['hashes'] != hashes(): fail('Proof source changed; use exact receipt cleanup')
        if args.resume:
            # Resume means safely finish interrupted cleanup, then start a fresh
            # experiment. Never continue a traffic matrix with unknown old flows.
            stage = 'cleanup'
            cleanup(RPC(rpc.host, time.monotonic() + 300), receipt)
            return {'run': receipt.run, 'cleanup': 'complete', 'verification': 'interrupted; run a fresh proof'}
        stage = 'traffic'
        verification_error = cleanup_error = None
        try:
            result = (application_ports if getattr(args, 'application_ports', False) else traffic)(
                rpc, receipt, image, nodes)
        except BaseException as error:
            verification_error = error
        try:
            cleanup(RPC(rpc.host, time.monotonic() + 300), receipt)
        except BaseException as error:
            cleanup_error = error
        if verification_error is not None or cleanup_error is not None:
            known_stages = {'fixture-setup', 'reachable-baselines', 'empty-egress', 'exact-peer', 'dns-allow',
                            'dns-allow-udp', 'dns-allow-tcp', 'dns-withdrawal', 'dns-withdrawal-udp',
                            'dns-withdrawal-tcp', 'dns-restoration-udp', 'dns-restoration-tcp', 'dns-preflight',
                            'additive-policy', 'retirement', 'ambient-transport', 'ambient-authorization',
                            'application-setup', 'application-baselines', 'application-authorization',
                            'application-retirement', 'application-restoration'}
            stage = rpc.stage if getattr(rpc, 'stage', None) in known_stages else 'traffic'
            raise RunFailure(receipt.run, stage,
                             safe_reason(verification_error) if verification_error is not None else 'passed',
                             safe_reason(cleanup_error) if cleanup_error is not None else 'complete', dns_evidence(rpc)) from None
        return dict(result, run=receipt.run, cleanup='complete')
    except RunFailure:
        raise
    except Exception as error:
        raise RunFailure(receipt.run, stage,
                         'not-requested' if stage == 'cleanup' else safe_reason(error),
                         safe_reason(error) if stage == 'cleanup' else 'not-attempted') from None
    finally:
        receipt.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument('--resume')
    choice.add_argument('--cleanup')
    parser.add_argument('--application-ports', action='store_true')
    parser.add_argument('--receipts', default='/recovery/workload-egress')
    args = parser.parse_args()
    from dotenv import dotenv_values
    values = dotenv_values(ROOT / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'VM_PORT'):
        os.environ[key] = values.get(key) or ('root' if key == 'VM_USER' else '22' if key == 'VM_PORT' else '')
    if not os.environ['VM_HOST'] or not os.environ['VM_PASSWORD']: fail('VM inspection credentials unavailable')
    rpc = RPC(os.environ['VM_HOST'], time.monotonic() + 1800)
    cluster = rpc.get('namespace', 'kube-system') or {}
    cluster_uid = cluster.get('metadata', {}).get('uid')
    if not cluster_uid: fail('Target cluster identity unavailable')
    target = hashlib.sha256(json.dumps([os.environ['VM_HOST'], os.environ['VM_PORT'], cluster_uid]).encode()).hexdigest()
    # Recovery must remain available when a node is unhealthy or image pins have
    # advanced. Only a new traffic experiment needs those prerequisites.
    image, nodes = None, []
    if not (args.resume or args.cleanup):
        nodes = node_targets(rpc.get('nodes')['items'])
        image = yaml.safe_load((ROOT / 'ansible/group_vars/all/verification.yml').read_text())['smoke_image']
        if not re.fullmatch(r'docker.io/library/busybox:1[.]37[.]0@sha256:[a-f0-9]{64}', image): fail('Fixture image pin changed')
    print(json.dumps(execute(args, rpc, target, image, nodes), sort_keys=True))


if __name__ == '__main__':
    try: main()
    except RunFailure as error:
        print(json.dumps(error.result, sort_keys=True), file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        raise SystemExit('Egress verification failed; receipts retained for explicit recovery; private diagnostics withheld')
