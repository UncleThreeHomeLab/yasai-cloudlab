"""Bounded native Argo reads for an authenticated observability handoff caller.

The caller owns source authentication, protected journal persistence and host
credentials. Supplied source objects alone grant no authority. Argo Secret
reads and raw repo/Redis forwarding are broader than project-scoped reads.
CNI enforcement and controller-dependent credential expiry require qualification.
"""
import argparse
import base64
from contextlib import contextmanager
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

LIMIT = 1024 * 1024
DOWNSTREAM_LIMIT = 32 * LIMIT
DOWNSTREAM = ('cloudlab-observability', 'cloudlab-prometheus', 'cloudlab-kiali')
PARENT = 'cloudlab-observability-gitops'
CHILDREN = ('cloudlab-observability', 'cloudlab-prometheus', 'cloudlab-loki', 'cloudlab-tempo', 'cloudlab-alloy', 'cloudlab-kiali')
ARGO = 'argocd'
OWNER = 'observability-native-transport'
JOB = 'native-manifests'
LABEL = 'cloudlab.io/native-transport'
UID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
SHA = re.compile(r'[a-f0-9]{64}')
REPOSITORY = re.compile(r'https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[.]git')
ARGO_IMAGE = 'quay.io/argoproj/argocd:v3.5.3@sha256:dd3f47d5a5e4da563a7a398506e892481b358a7cec50abdf320c71aa55904bfa'
PYTHON_IMAGE = 'python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed'
REDIS_IMAGE = 'docker.io/library/redis:8.6.4-alpine@sha256:2cc044fc5a07c9b701f8f1255a309ae9ad7856e694ac03513bf3648c01e40763'
BINARY_SHA = 'e557da422ff52a729989e3d631bcc171b3f6e925631c157306c1724228e8f8f9'
MANIFEST_PATH = '/api/v1/applications/cloudlab-observability-gitops/manifests?appNamespace=argocd&project=cloudlab-observability-gitops'
GENERATE_PATH = '/api/v1/applicationsets/generate'
DOWNSTREAM_PATHS = {name: '/api/v1/applications/' + name + '/manifests?appNamespace=argocd&project=cloudlab-observability' for name in DOWNSTREAM}
APPS = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/'
SETS = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applicationsets/'
RESULT = Path('/result/manifest.json')
TOKEN = Path('/var/run/secrets/cloudlab/token')
CA = Path('/var/run/secrets/cloudlab/ca.crt')
COLLECT = ['/usr/local/bin/python', '/assets/native_transport.py', '--collect']
SECURITY = {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(obj):
    metadata = obj.get('metadata', {})
    require(isinstance(metadata.get('uid'), str) and UID.fullmatch(metadata['uid'])
        and isinstance(metadata.get('resourceVersion'), str) and metadata['resourceVersion']
        and not metadata.get('deletionTimestamp'), 'Native object identity is absent, changed or deleting')
    return {key: metadata.get(key) for key in ('name', 'namespace', 'uid')}


def namespace(operation):
    require(isinstance(operation, str) and re.fullmatch('[a-f0-9]{16}', operation), 'Invalid transport operation')
    return 'cloudlab-obs-native-' + operation


def profile_limit(profile, baseline_inventory=False):
    require(profile in ('parent', 'phase-parent', 'downstream') and type(baseline_inventory) is bool
        and (not baseline_inventory or profile == 'phase-parent'), 'Unsupported native manifest profile')
    return DOWNSTREAM_LIMIT if profile == 'downstream' or baseline_inventory else LIMIT


def initial_baseline(value):
    return value.get('profile') == 'phase-parent' and value['source']['phaseContext']['phase'] == 'baseline'


def input_limit(value):
    return profile_limit(value.get('profile', 'parent'), initial_baseline(value))


def strict_json(raw, limit=LIMIT):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate fixture JSON field')
            result[key] = value
        return result
    require(isinstance(raw, (bytes, str)) and len(raw) <= limit and limit in (LIMIT, DOWNSTREAM_LIMIT), 'Fixture JSON exceeds bound')
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('Nonfinite fixture JSON')))

def decode_response(raw, limit=LIMIT):
    require(limit in (LIMIT, DOWNSTREAM_LIMIT), 'Unsupported response bound')
    require(isinstance(raw, bytes) and 0 < len(raw) <= limit, 'Dashboard response exceeded total byte bound')
    header, separator, body = raw.partition(b'\r\n\r\n')
    require(separator and len(header) <= 32768, 'Dashboard HTTP header framing differs')
    lines = header.split(b'\r\n')
    require(re.fullmatch(rb'HTTP/1[.][01] 200(?: [\x20-\x7e]*)?', lines[0]) and len(lines) <= 101,
            'Dashboard requires exact HTTP 200')
    headers = {}
    for line in lines[1:]:
        key, colon, value = line.partition(b':')
        require(colon and re.fullmatch(rb'[A-Za-z0-9-]+', key) and all(32 <= byte <= 126 or byte == 9 for byte in value),
                'Dashboard HTTP header differs')
        headers.setdefault(key.lower(), []).append(value.strip().lower())
    length, transfer, encoding = (headers.get(key, []) for key in (b'content-length', b'transfer-encoding', b'content-encoding'))
    require(len(length) <= 1 and len(transfer) <= 1 and not (length and transfer)
            and encoding in ([], [b'identity']) and headers.get(b'location') is None, 'Ambiguous dashboard HTTP framing')
    if length:
        require(re.fullmatch(rb'[0-9]{1,10}', length[0]) and int(length[0]) == len(body), 'Dashboard body length differs')
        return body
    require(transfer == [b'chunked'], 'Unsupported dashboard HTTP body framing')
    result, cursor, chunks = bytearray(), 0, 0
    while True:
        end = body.find(b'\r\n', cursor)
        require(end >= cursor and re.fullmatch(rb'[a-fA-F0-9]{1,16}', body[cursor:end]), 'Dashboard chunk length differs')
        size, cursor = int(body[cursor:end], 16), end + 2
        chunks += 1
        require(chunks <= 65536 and size <= limit, 'Dashboard chunk bound exceeded')
        if not size:
            require(body[cursor:] == b'\r\n', 'Dashboard trailers or trailing bytes refused')
            return bytes(result)
        require(body[cursor + size:cursor + size + 2] == b'\r\n', 'Dashboard chunk truncated')
        result.extend(body[cursor:cursor + size])
        require(len(result) <= limit, 'Dashboard body exceeds bound')
        cursor += size + 2

def owned_listener(process, arguments, port):
    require(os.getpgid(process.pid) == process.pid
            and Path('/proc/' + str(process.pid) + '/cmdline').read_bytes().split(b'\0')[:-1] == [arg.encode() for arg in arguments]
            and Path('/proc/' + str(process.pid) + '/exe').resolve() == Path(arguments[0]).resolve(),
            'Dashboard process identity differs')
    members = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal(): continue
        try: fields = (entry / 'stat').read_text().rsplit(') ', 1)[1].split()
        except FileNotFoundError: continue
        if int(fields[2]) == process.pid: members.append(int(entry.name))
    require(members == [process.pid], 'Unexpected dashboard process group member')
    descriptors = set()
    for path in (Path('/proc') / str(process.pid) / 'fd').iterdir():
        try: target = os.readlink(path)
        except FileNotFoundError: continue
        match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
        if match: descriptors.add(match[1])
    listeners = []
    for table in ('tcp', 'tcp6'):
        for line in Path('/proc/net/' + table).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A' and fields[9] in descriptors:
                address, encoded_port = fields[1].split(':')
                require((table == 'tcp' and address == '0100007F') or
                        (table == 'tcp6' and address == '00000000000000000000000001000000'),
                        'Dashboard listener is not loopback-only')
                listeners.append((table, int(encoded_port, 16)))
    return ('tcp', port) in listeners

def stop_core(process):
    # The leader is never polled/reaped before killing its process group.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        stop = time.monotonic() + 1
        while time.monotonic() < stop:
            if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None:
                break
            time.sleep(0.02)
    finally:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait(timeout=5)
        if process.stdout is not None: process.stdout.close()

def core_binary(deadline):
    binary = Path('/cli/argocd')
    checksum = hashlib.sha256()
    with binary.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            require(time.monotonic() < deadline, 'Dashboard binary verification deadline expired')
            checksum.update(chunk)
    require(checksum.hexdigest() == BINARY_SHA, 'Dashboard CLI differs from the pinned fixture image')
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Dashboard CLI verification deadline expired')
    version = subprocess.run([str(binary), 'version', '--client', '--short'], capture_output=True, timeout=min(5, remaining))
    require(version.returncode == 0 and version.stdout.startswith(b'argocd: v3.5.3'), 'Dashboard CLI version differs')
    return str(binary)

def core_request(port, operation, generate_body, deadline, budget, guard, profile='parent', baseline_inventory=False):
    limit = profile_limit(profile, baseline_inventory)
    require(operation in (('generate', 'manifests', *DOWNSTREAM) if profile == 'downstream' or baseline_inventory else ('generate', 'manifests')) and type(port) is int and 0 < port < 65536,
            'Unsupported Core request')
    method, path, body = ('POST', GENERATE_PATH, generate_body) if operation == 'generate' else ('GET', DOWNSTREAM_PATHS.get(operation, MANIFEST_PATH), b'')
    require(isinstance(body, bytes) and len(body) <= LIMIT and 0 < budget[0] <= limit,
            'Core request body or cumulative response budget differs')
    guard()
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Native Core total deadline expired')
    with socket.create_connection(('127.0.0.1', port), timeout=remaining) as connection:
        request = (method + ' ' + path + ' HTTP/1.1\r\nHost: 127.0.0.1:' + str(port) +
            '\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)) +
            '\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n').encode() + body
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Native Core total deadline expired')
        connection.settimeout(remaining)
        connection.sendall(request)
        raw = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'Native Core total deadline expired')
            connection.settimeout(remaining)
            chunk = connection.recv(min(65536, budget[0] + 1 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
            require(len(raw) <= budget[0], 'Native Core cumulative response byte bound exceeded')
        budget[0] -= len(raw)
    guard()
    return decode_response(bytes(raw), limit)

def initialized_state(read, profile='parent'):
    """Observe initialized settings only; this preflight never writes or generates secrets."""
    secret = read('/api/v1/namespaces/argocd/secrets/argocd-secret')
    project = read('/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/default')
    settings = read('/api/v1/namespaces/argocd/configmaps/argocd-cm')
    require(secret.get('kind') == 'Secret' and secret.get('apiVersion') == 'v1'
        and secret.get('type') == 'Opaque' and secret['metadata'].get('name') == 'argocd-secret'
        and secret['metadata'].get('namespace') == 'argocd' and not secret['metadata'].get('ownerReferences')
        and not secret['metadata'].get('finalizers') and isinstance(secret.get('data'), dict)
        and isinstance(secret['data'].get('server.secretkey'), str)
        and 32 <= len(base64.b64decode(secret['data']['server.secretkey'], validate=True)) <= 1024,
        'Core requires an already initialized fixture signing Secret')
    require(project.get('kind') == 'AppProject' and project.get('apiVersion') == 'argoproj.io/v1alpha1'
        and project['metadata'].get('name') == 'default' and project['metadata'].get('namespace') == 'argocd'
        and settings.get('kind') == 'ConfigMap' and settings.get('apiVersion') == 'v1'
        and settings['metadata'].get('name') == 'argocd-cm' and settings['metadata'].get('namespace') == 'argocd'
        and settings.get('data', {}).get('admin.enabled') == 'false', 'Core settings or default Project are uninitialized')
    if profile in ('phase-parent', 'downstream'):
        require(settings['data'].get('application.resourceTrackingMethod') == 'annotation'
            and settings['data'].get('installationID', '') == '', 'Phase transport requires annotation tracking without installation ID')
    result = {}
    for name, obj, payload in [('secret', secret, secret['data']), ('project', project, project.get('spec', {})),
                               ('settings', settings, settings['data'])]:
        metadata = obj['metadata']
        require(isinstance(metadata.get('uid'), str) and metadata['uid']
            and isinstance(metadata.get('resourceVersion'), str) and metadata['resourceVersion']
            and not metadata.get('deletionTimestamp'), 'Core prerequisite identity differs')
        result[name] = {'uid': metadata['uid'], 'resourceVersion': metadata['resourceVersion'],
            'payloadSHA256': hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    return result

def generated_parent(raw, installed):
    value = strict_json(raw)
    require(isinstance(value, dict) and set(value) == {'applications'}
            and isinstance(value['applications'], list) and len(value['applications']) == 1,
            'Native Generate must return exactly one parent')
    generated = value['applications'][0]
    require(isinstance(generated, dict) and generated.get('kind', 'Application') == 'Application'
        and generated.get('apiVersion', 'argoproj.io/v1alpha1') == 'argoproj.io/v1alpha1'
        and generated.get('metadata', {}).get('name') == PARENT
        and generated['metadata'].get('namespace') == 'argocd'
        and not generated['metadata'].get('uid') and not generated['metadata'].get('resourceVersion')
        and generated.get('spec') == installed['spec']
        and generated['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'observability-platform'
        and generated['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') == 'true'
        and len(generated['spec'].get('sources', [])) == 2
        and all(re.fullmatch('[a-f0-9]{40}', source.get('targetRevision', '')) for source in generated['spec']['sources'])
        and generated['spec'].get('project') == PARENT
        and generated['spec'].get('destination') == {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
        and generated['spec'].get('syncPolicy', {}).get('automated') == {
            'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False},
        'Generated parent differs from installed immutable paused authority')
    return generated


def api_targets(service, endpoints):
    require(service.get('apiVersion') == endpoints.get('apiVersion') == 'v1'
        and service.get('kind') == 'Service' and endpoints.get('kind') == 'Endpoints'
        and all(obj['metadata'].get('name') == 'kubernetes' and obj['metadata'].get('namespace') == 'default'
                for obj in (service, endpoints)), 'API boundary is not the native Kubernetes service')
    identity(service); identity(endpoints)
    spec = service['spec']
    require(spec.get('type', 'ClusterIP') == 'ClusterIP' and not spec.get('externalName')
        and not spec.get('externalIPs') and len(spec.get('ports', [])) == 1, 'Unsupported API Service profile')
    service_port = spec['ports'][0]
    address = ipaddress.ip_address(spec['clusterIP'])
    require(not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified), 'Unsafe API Service IP')
    ports, addresses = set(), set()
    for subset in endpoints.get('subsets', []):
        require(not subset.get('notReadyAddresses') and len(subset.get('ports', [])) == 1, 'Incomplete API endpoint discovery')
        port = subset['ports'][0]
        require(port.get('protocol', 'TCP') == 'TCP' and port.get('name') == service_port.get('name') == 'https'
            and type(port.get('port')) is int and 0 < port['port'] < 65536, 'API endpoint port differs')
        ports.add(port['port'])
        for row in subset.get('addresses', []):
            peer = ipaddress.ip_address(row['ip'])
            require(peer.version == address.version and not (peer.is_loopback or peer.is_link_local or peer.is_multicast or peer.is_unspecified),
                    'Unsafe API endpoint IP')
            addresses.add(str(peer))
    require(len(ports) == 1 and 0 < len(addresses) <= 4 and service_port.get('protocol', 'TCP') == 'TCP'
        and type(service_port.get('port')) is int and 0 < service_port['port'] < 65536
        and service_port.get('targetPort') == next(iter(ports)), 'API endpoint mapping is ambiguous')
    return {'serviceIP': str(address), 'servicePort': service_port['port'], 'endpointIPs': sorted(addresses),
        'endpointPort': next(iter(ports)), 'serviceUID': service['metadata']['uid'], 'serviceRV': service['metadata']['resourceVersion'],
        'endpointsUID': endpoints['metadata']['uid'], 'endpointsRV': endpoints['metadata']['resourceVersion'],
        'serviceSHA256': digest(canonical(spec)), 'endpointsSHA256': digest(canonical(endpoints['subsets']))}


def validate_source(source, profile='parent'):
    fields = {'expectedSet', 'set', 'parent', 'pods'}
    if profile == 'downstream': fields |= {'downstream', 'phaseApplications', 'phaseContext'}
    if profile == 'phase-parent':
        fields.add('phaseContext')
        if source.get('phaseContext', {}).get('phase') == 'baseline': fields.add('originalBaselineApps')
    require(isinstance(source, dict) and set(source) == fields, 'Incomplete native source context')
    expected, observed, parent = (source[key] for key in ('expectedSet', 'set', 'parent'))
    for obj, kind in ((expected, 'ApplicationSet'), (observed, 'ApplicationSet'), (parent, 'Application')):
        require(obj.get('apiVersion') == 'argoproj.io/v1alpha1' and obj.get('kind') == kind
            and obj.get('metadata', {}).get('name') == PARENT and obj['metadata'].get('namespace') == ARGO,
            'Native source identity escaped observability')
    identity(observed); identity(parent)
    require(observed['spec'] == expected['spec'] and not observed['metadata'].get('ownerReferences')
        and parent['metadata'].get('ownerReferences') == [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
            'name': PARENT, 'uid': observed['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}]
        and parent.get('operation') is None
        and parent.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'),
        'Native parent is not idle under the exact accepted Set')
    generate_payload(expected)
    require(parent['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') == 'true'
        and len(parent['spec'].get('sources', [])) == 2, 'Native parent is not paused')
    template = copy.deepcopy(expected['spec']['template']['spec'])
    pin = parent['spec']['sources'][1].get('targetRevision')
    require(isinstance(pin, str) and re.fullmatch('[a-f0-9]{40}', pin), 'Private source is not immutable')
    template['sources'][1]['targetRevision'] = pin
    require(parent['spec'] == template, 'Installed parent differs from accepted source authority')
    require(set(source['pods']) == {'repo', 'redis'}, 'Native forward targets are incomplete')
    for component, image, name in (('repo', ARGO_IMAGE, 'repo-server'), ('redis', REDIS_IMAGE, 'redis')):
        pod = source['pods'][component]
        identity(pod)
        require(pod.get('kind') == 'Pod' and pod.get('apiVersion') == 'v1'
            and pod['metadata'].get('namespace') == ARGO
            and re.fullmatch('argocd-' + ('repo-server' if component == 'repo' else 'redis') + r'-[a-z0-9]+-[a-z0-9]+', pod['metadata']['name'])
            and pod['metadata'].get('labels', {}).get('app.kubernetes.io/component') == ('repo-server' if component == 'repo' else 'redis')
            and len(pod.get('spec', {}).get('containers', [])) == 1
            and pod['spec']['containers'][0].get('name') == name and pod['spec']['containers'][0].get('image') == image
            and pod.get('status', {}).get('phase') == 'Running'
            and any(row.get('type') == 'Ready' and row.get('status') == 'True' for row in pod['status'].get('conditions', [])),
            'Native forward target is not the current pinned ready Pod')

    if profile == 'downstream': validate_downstream(source)
    if profile == 'phase-parent':
        phase_context(source)
        if source['phaseContext']['phase'] == 'baseline': validate_original_baseline(source)


def validate_original_baseline(source, current=None):
    entries = source['originalBaselineApps']
    require(isinstance(entries, dict) and set(entries) == set(DOWNSTREAM), 'Original baseline needs all three native inventories')
    public = source['parent']['spec']['sources'][0]
    for name in DOWNSTREAM:
        entry = entries[name]
        require(isinstance(entry, dict) and set(entry) == {'accepted', 'observed'}, 'Original baseline binding is incomplete')
        accepted, frozen = entry['accepted'], entry['observed']
        actual = frozen if current is None else current[name]
        identity(frozen); identity(actual)
        metadata, spec = accepted.get('metadata', {}), accepted.get('spec', {})
        child = spec.get('source', {})
        helm = child.get('helm', {})
        path = 'platform/observability' + ('' if name == 'cloudlab-observability' else '/' + name.removeprefix('cloudlab-'))
        def owned(obj):
            return {kind: {key: val for key, val in obj.get('metadata', {}).get(kind, {}).items()
                if key.startswith(('cloudlab.io/', 'argocd.argoproj.io/'))} for kind in ('annotations', 'labels')}
        require(set(accepted) == {'apiVersion', 'kind', 'metadata', 'spec'}
            and accepted['apiVersion'] == 'argoproj.io/v1alpha1' and accepted['kind'] == 'Application'
            and set(metadata) <= {'name', 'namespace', 'labels', 'annotations'}
            and metadata.get('name') == name and metadata.get('namespace') == ARGO
            and metadata.get('labels') == {'cloudlab.io/owner': 'observability-platform'}
            and set(spec) == {'project', 'source', 'destination', 'revisionHistoryLimit', 'syncPolicy'}
            and spec['project'] == 'cloudlab-observability'
            and spec['destination'] == {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-observability'}
            and spec['revisionHistoryLimit'] == (0 if name == 'cloudlab-prometheus' else 10)
            and set(child) == {'repoURL', 'targetRevision', 'path', 'helm'}
            and (child['repoURL'], child['targetRevision'], child['path']) ==
                (public['repoURL'], source['phaseContext']['baselineRevision'], path)
            and set(helm) <= {'releaseName', 'valueFiles', 'valuesObject'} and helm.get('releaseName') == name
            and isinstance(helm.get('valuesObject'), dict) and 'ownershipHandoffInternal' not in helm['valuesObject']
            and helm.get('valueFiles', []) == ([] if name == 'cloudlab-observability' else ['values.json'])
            and identity(actual) == identity(frozen) and actual['metadata']['resourceVersion'] == frozen['metadata']['resourceVersion']
            and actual.get('kind') == accepted['kind'] and actual.get('apiVersion') == accepted['apiVersion']
            and actual['metadata'].get('name') == name and actual['metadata'].get('namespace') == ARGO
            and not actual['metadata'].get('ownerReferences') and not actual['metadata'].get('finalizers')
            and frozen.get('spec') == spec and actual.get('spec') == spec and owned(actual) == owned(accepted)
            and actual.get('operation') is None
            and actual.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'),
            'Original baseline moved, is active, or differs from exact accepted pre-hold source')


def phase_context(source):
    """Context must come from the protected authenticated producer, never a response receipt."""
    context = source['phaseContext']
    require(isinstance(context, dict) and set(context) == {'version', 'operationId', 'phase', 'baselineDigest',
        'baselineRevision', 'privateRevision', 'qualificationsSHA256', 'approvedStorageTarget'}
        and context['version'] == 'cloudlab-observability-handoff/v1'
        and isinstance(context['operationId'], str) and re.fullmatch('[a-f0-9]{16}', context['operationId'])
        and context['phase'] in ('baseline', 'maintenance', 'persistent-maintenance', 'persistent-normal', 'native-paused')
        and all(isinstance(context[key], str) and SHA.fullmatch(context[key]) for key in ('baselineDigest', 'qualificationsSHA256'))
        and isinstance(context['baselineRevision'], str) and re.fullmatch('[a-f0-9]{40}', context['baselineRevision'])
        and context['privateRevision'] == source['parent']['spec']['sources'][1]['targetRevision']
        and context['approvedStorageTarget'] == 'alertmanager-retained-1gi-v1', 'Incomplete authenticated phase context')
    return context


def phase_applications(source, objects=None):
    context = phase_context(source)
    apps = source['phaseApplications'] if objects is None else {obj.get('metadata', {}).get('name'): obj for obj in objects}
    require(isinstance(apps, dict) and set(apps) == set(CHILDREN)
        and (objects is None or len(objects) == 6), 'Phase must declare exactly six Applications')
    public = source['parent']['spec']['sources'][0]
    phase = context['phase']
    native = phase in ('native-paused', 'native')
    provenance = {'cloudlab.io/observability-handoff-operation': context['operationId'],
        'cloudlab.io/observability-handoff-phase': phase,
        'cloudlab.io/observability-handoff-baseline': context['baselineDigest']}
    target_annotation = 'cloudlab.io/observability-handoff-target-cluster-uid'
    targets = set()
    for name in CHILDREN:
        obj = apps[name]
        metadata, spec = obj.get('metadata', {}), obj.get('spec', {})
        annotations = metadata.get('annotations', {})
        target = annotations.get(target_annotation)
        require(isinstance(target, str) and UID.fullmatch(target)
            and target != '00000000-0000-0000-0000-000000000000', 'Native handoff target cluster annotation is invalid')
        targets.add(target)
        child = spec.get('source', {})
        helm = child.get('helm', {})
        current = native or name == 'cloudlab-observability' or (name == 'cloudlab-prometheus' and phase in
            ('maintenance', 'persistent-maintenance', 'persistent-normal'))
        path = 'platform/observability' + ('' if name == 'cloudlab-observability' else '/' + name.removeprefix('cloudlab-'))
        options = spec.get('syncPolicy', {}).get('syncOptions')
        legacy_options = ['FailOnSharedResource=true', 'ServerSideApply=true', 'DisableClientSideApplyMigration=true']
        canonical_options = legacy_options + ['PruneLast=true']
        require(options in ([canonical_options] if native else [legacy_options, canonical_options]),
            'Phase sync options differ from exact legacy or native ownership policy')
        require(set(obj) == {'apiVersion', 'kind', 'metadata', 'spec'}
            and obj['apiVersion'] == 'argoproj.io/v1alpha1' and obj['kind'] == 'Application'
            and set(metadata) == {'name', 'namespace', 'labels', 'annotations'}
            and metadata['name'] == name and metadata['namespace'] == ARGO
            and metadata['labels'] == {'cloudlab.io/owner': 'observability-platform'}
            and set(annotations) <= {'argocd.argoproj.io/skip-reconcile', 'cloudlab.io/observability-input-digest',
                'cloudlab.io/observability-health', 'argocd.argoproj.io/sync-wave', 'cloudlab.io/notification-delivery',
                'argocd.argoproj.io/tracking-id', target_annotation, *provenance}
            and annotations.get('argocd.argoproj.io/tracking-id') == PARENT + ':argoproj.io/Application:argocd/' + name
            and all(annotations.get(key) == val for key, val in provenance.items())
            and annotations.get('argocd.argoproj.io/skip-reconcile') == ('true' if phase == 'native-paused' else 'false')
            and set(spec) == {'project', 'source', 'destination', 'revisionHistoryLimit', 'syncPolicy'}
            and spec['project'] == 'cloudlab-observability'
            and spec['destination'] == {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-observability'}
            and spec['revisionHistoryLimit'] == (0 if name == 'cloudlab-prometheus' else 10)
            and set(child) == {'repoURL', 'targetRevision', 'path', 'helm'}
            and (child['repoURL'], child['targetRevision'], child['path']) ==
                (public['repoURL'], public['targetRevision'] if current else context['baselineRevision'], path)
            and set(helm) <= {'releaseName', 'valueFiles', 'valuesObject'} and helm.get('releaseName') == name
            and (isinstance(helm.get('valuesObject'), dict) or
                (not native and name in ('cloudlab-loki', 'cloudlab-tempo', 'cloudlab-alloy') and 'valuesObject' not in helm))
            and helm.get('valueFiles', []) == ([] if name == 'cloudlab-observability' else ['values.json'])
            and spec['syncPolicy'] == {'automated': {'enabled': phase == 'native', 'prune': phase == 'native',
                'selfHeal': phase == 'native', 'allowEmpty': False},
                'syncOptions': options,
                'retry': {'limit': 5, 'backoff': {'duration': '10s', 'factor': 2, 'maxDuration': '1m'}}},
            'Authenticated phase Application source, provenance or execution differs')
        control = helm.get('valuesObject', {}).get('ownershipHandoffInternal')
        if name == 'cloudlab-observability' and not native:
            require(isinstance(control, dict) and set(control) in ({'version', 'phase', 'operationId', 'baselineDigest'},
                {'version', 'phase', 'operationId', 'baselineDigest', 'quotaIncrease'})
                and all(control.get(key) == context[key] for key in ('version', 'phase', 'operationId', 'baselineDigest')),
                'Configuration phase control differs from protected context')
            if 'quotaIncrease' in control:
                quota = control['quotaIncrease']
                require(isinstance(quota, dict) and set(quota) == {'requestsStorageGiB', 'persistentVolumeClaims'}
                    and type(quota['requestsStorageGiB']) is int and quota['requestsStorageGiB'] in (72, 73)
                    and type(quota['persistentVolumeClaims']) is int and quota['persistentVolumeClaims'] == 6,
                    'Configuration quota phase escaped its fixed bounds')
        else:
            require(control is None, 'Unexpected phase adapter control')
    require(len(targets) == 1, 'Native handoff target cluster annotations differ')
    return [apps[name] for name in CHILDREN]


def phase_manifests(raw, source):
    value = strict_json(raw)
    require(isinstance(value, dict) and isinstance(value.get('manifests'), list) and len(value['manifests']) == 6,
        'Native phase response must contain six Applications')
    objects = [strict_json(item) for item in value['manifests']]
    phase_applications(source, objects)
    if 'phaseApplications' in source:
        require({obj['metadata']['name']: obj for obj in objects} == source['phaseApplications'],
            'Native phase response differs from complete authenticated declarations')
    return objects


def validate_downstream(source, parents=None):
    phase_applications(source)
    entries = source['downstream']
    expected_native = source['phaseApplications']
    require(isinstance(entries, dict) and set(entries) == set(DOWNSTREAM), 'Downstream phase closure differs')
    for name in DOWNSTREAM:
        entry = entries[name]
        require(isinstance(entry, dict) and set(entry) == {'accepted', 'observed'}
            and entry['accepted'] == source['phaseApplications'][name], 'Downstream declaration is not the accepted six-Application phase')
        expected, observed = expected_native[name], entry['observed']
        identity(observed)
        def owned(obj):
            return {kind: {key: val for key, val in obj.get('metadata', {}).get(kind, {}).items()
                if key.startswith(('cloudlab.io/', 'argocd.argoproj.io/'))} for kind in ('annotations', 'labels')}
        require(observed.get('apiVersion') == expected['apiVersion'] and observed.get('kind') == expected['kind']
            and observed['metadata'].get('name') == name and observed['metadata'].get('namespace') == ARGO
            and observed.get('spec') == expected['spec'] and owned(observed) == owned(expected)
            and observed.get('operation') is None
            and observed.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'),
            'Installed downstream Application differs from accepted idle phase')
    if parents is not None:
        require(len(parents) == 6 and {obj['metadata']['name']: obj for obj in parents} == expected_native,
            'Downstream parent closure differs from exact native phase declarations')


def resource_manifests(raw):
    value = strict_json(raw, DOWNSTREAM_LIMIT)
    require(isinstance(value, dict) and isinstance(value.get('manifests'), list) and value['manifests'],
        'Downstream native resource inventory is empty or invalid')
    objects = [strict_json(item, DOWNSTREAM_LIMIT) for item in value['manifests']]
    seen = set()
    for obj in objects:
        require(isinstance(obj, dict) and isinstance(obj.get('apiVersion'), str) and obj['apiVersion']
            and isinstance(obj.get('kind'), str) and obj['kind'] and isinstance(obj.get('metadata'), dict)
            and isinstance(obj['metadata'].get('name'), str) and obj['metadata']['name'], 'Invalid native resource identity')
        key = (obj['apiVersion'], obj['kind'], obj['metadata'].get('namespace', ''), obj['metadata']['name'])
        require(key not in seen, 'Duplicate native resource identity')
        seen.add(key)
    return objects


def generate_payload(expected):
    require(set(expected) == {'apiVersion', 'kind', 'metadata', 'spec'}
        and expected['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'observability-platform', 'Unexpected Set declaration')
    spec = expected['spec']
    require(set(spec) == {'goTemplate', 'goTemplateOptions', 'generators', 'syncPolicy', 'template'}
        and spec['goTemplate'] is True and spec['goTemplateOptions'] == ['missingkey=error']
        and spec['syncPolicy'] == {'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True}, 'Unsupported Set authority')
    template = spec['template']
    require(set(template) == {'metadata', 'spec'} and template['metadata']['name'] == PARENT
        and template['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') == 'true', 'Set template is not paused')
    parent = template['spec']
    require(set(parent) == {'project', 'sources', 'destination', 'syncPolicy'}
        and parent['project'] == PARENT and parent['destination'] == {'server': 'https://kubernetes.default.svc', 'namespace': ARGO}
        and parent['syncPolicy'] == {'automated': {'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False},
            'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}
        and len(parent['sources']) == 2, 'Set target authority differs')
    public, private = parent['sources']
    require(set(public) == {'repoURL', 'targetRevision', 'path', 'helm'}
        and REPOSITORY.fullmatch(public['repoURL']) and re.fullmatch('[a-f0-9]{40}', public['targetRevision'])
        and public['path'] == 'platform/observability/gitops'
        and set(private) == {'repoURL', 'targetRevision', 'ref'} and REPOSITORY.fullmatch(private['repoURL'])
        and private['repoURL'] != public['repoURL'] and private['ref'] == 'values'
        and isinstance(private['targetRevision'], str) and 'Consumer source acceptance refused' in private['targetRevision'],
        'Set sources are not the accepted public and gated private bindings')
    helm = public['helm']
    native_source = {'repository': public['repoURL'], 'revision': public['targetRevision'],
        'valuesRepository': private['repoURL'], 'paused': True}
    provided = helm.get('valuesObject', {}).get('nativeSource', {})
    require(isinstance(provided, dict) and 'activationQualification' in provided,
        'Authenticated Root activation qualification is required')
    pointer = provided['activationQualification']
    require(isinstance(pointer, str) and (pointer == '' or re.fullmatch('[a-f0-9]{64}', pointer))
        and pointer != '0' * 64, 'Invalid authenticated activation qualification pointer')
    native_source['activationQualification'] = pointer
    require(set(helm) == {'releaseName', 'valueFiles', 'valuesObject'} and helm['releaseName'] == PARENT
        and len(helm['valueFiles']) == 2 and re.fullmatch(r'\$values/services/catalog(-[a-z0-9]+(-[a-z0-9]+)*)?[.](json|yaml)', helm['valueFiles'][0])
        and helm['valueFiles'][1] == '$values/platform/observability.yaml'
        and helm['valuesObject'] == {'nativeSource': native_source}
        and spec['generators'] == [{'merge': {'mergeKeys': ['consumer'], 'generators': [
            {'list': {'elements': [{'consumer': 'observability'}]}}, {'git': {'repoURL': private['repoURL'], 'revision': 'main',
                'files': [{'path': 'platform/acceptance/observability.yaml'}]}}]}}], 'Set merge or Helm source overrides differ')
    raw = canonical({'applicationSet': expected})
    require(len(raw) <= LIMIT, 'Native Generate body exceeds bound')
    return raw


def validate_input(value):
    require(isinstance(value, dict) and set(value) in ({'version', 'operation', 'codeSHA256', 'source', 'api'},
        {'version', 'operation', 'codeSHA256', 'source', 'api', 'profile'})
        and type(value['version']) is int and value['version'] == 1, 'Unexpected native input fields')
    namespace(value['operation'])
    require(value['codeSHA256'] == digest(Path(__file__).read_bytes()), 'Native transport code provenance changed')
    input_limit(value)
    validate_source(value['source'], value.get('profile', 'parent'))
    if value.get('profile') in ('phase-parent', 'downstream'):
        require(value['source']['phaseContext']['operationId'] == value['operation'], 'Phase belongs to another operation')
    api = value['api']
    require(set(api) == {'serviceIP', 'servicePort', 'endpointIPs', 'endpointPort', 'serviceUID', 'serviceRV',
        'endpointsUID', 'endpointsRV', 'serviceSHA256', 'endpointsSHA256'}
        and all(isinstance(api[key], str) and UID.fullmatch(api[key]) for key in ('serviceUID', 'endpointsUID'))
        and all(isinstance(api[key], str) and SHA.fullmatch(api[key]) for key in ('serviceSHA256', 'endpointsSHA256'))
        and all(type(api[key]) is int and 0 < api[key] < 65536 for key in ('servicePort', 'endpointPort'))
        and isinstance(api['endpointIPs'], list) and 0 < len(api['endpointIPs']) <= 4, 'Incomplete native API boundary')
    for raw in [api['serviceIP'], *api['endpointIPs']]:
        parsed = ipaddress.ip_address(raw)
        require(str(parsed) == raw and not (parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified or parsed.is_link_local), 'Unsafe API address')
    require(all(isinstance(api[key], str) and api[key] for key in ('serviceRV', 'endpointsRV'))
        and len(set(api['endpointIPs'])) == len(api['endpointIPs'])
        and all(ipaddress.ip_address(peer).version == ipaddress.ip_address(api['serviceIP']).version for peer in api['endpointIPs']),
        'Native API identity or address family differs')
    require(len(canonical(value)) <= LIMIT // 2, 'Native input exceeds bound')
    return value


def manifests(raw, source):
    value = strict_json(raw)
    require(isinstance(value, dict) and isinstance(value.get('manifests'), list) and len(value['manifests']) == 6,
            'Native response does not contain six Applications')
    objects = [strict_json(item) for item in value['manifests']]
    require(len({obj.get('metadata', {}).get('name') for obj in objects}) == 6
        and {obj.get('metadata', {}).get('name') for obj in objects} == set(CHILDREN), 'Unexpected native child closure')
    public = source['parent']['spec']['sources'][0]
    hashes = set()
    for obj in objects:
        metadata, spec = obj.get('metadata', {}), obj.get('spec', {})
        name = metadata['name']
        path = 'platform/observability' + ('' if name == 'cloudlab-observability' else '/' + name.removeprefix('cloudlab-'))
        annotations = metadata.get('annotations', {})
        child = spec.get('source', {})
        helm = child.get('helm', {})
        marker = annotations.get('cloudlab.io/observability-input-digest', '')
        require(set(obj) == {'apiVersion', 'kind', 'metadata', 'spec'} and obj['apiVersion'] == 'argoproj.io/v1alpha1'
            and obj['kind'] == 'Application' and metadata.get('namespace') == ARGO
            and metadata.get('labels', {}).get('cloudlab.io/owner') == 'observability-platform'
            and not any(metadata.get(key) for key in ('ownerReferences', 'finalizers', 'uid', 'resourceVersion', 'deletionTimestamp'))
            and annotations.get('argocd.argoproj.io/skip-reconcile') == 'true'
            and annotations.get('cloudlab.io/observability-health') == 'required' and SHA.fullmatch(marker)
            and set(spec) == {'project', 'source', 'destination', 'revisionHistoryLimit', 'syncPolicy'}
            and spec['revisionHistoryLimit'] == (0 if name == 'cloudlab-prometheus' else 10)
            and spec['project'] == 'cloudlab-observability'
            and spec['destination'] == {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-observability'}
            and set(child) == {'repoURL', 'targetRevision', 'path', 'helm'}
            and (child['repoURL'], child['targetRevision'], child['path']) == (public['repoURL'], public['targetRevision'], path)
            and set(helm) <= {'releaseName', 'valueFiles', 'valuesObject'} and helm.get('releaseName') == name
            and helm.get('valueFiles', []) == ([] if name == 'cloudlab-observability' else ['values.json'])
            and helm.get('valuesObject', {}).get('nativeInputDigest') == marker
            and spec['syncPolicy'] == {'automated': {'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'ServerSideApply=true', 'DisableClientSideApplyMigration=true', 'PruneLast=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '10s', 'factor': 2, 'maxDuration': '1m'}}},
            'Native child source, execution or pause differs')
        hashes.add(marker)
    require(len(hashes) == 1, 'Native children have different input digests')
    return objects


def declarations(value, job_uid=None):
    validate_input(value)
    operation, boundary = value['operation'], value['api']
    ns, labels = namespace(operation), {'cloudlab.io/owner': OWNER, LABEL: operation}
    metadata = lambda name, namespace=ns: {'name': name, 'namespace': namespace, 'labels': copy.deepcopy(labels)}
    reference = [] if job_uid is None else [{'apiVersion': 'batch/v1', 'kind': 'Job', 'name': JOB,
        'uid': job_uid, 'controller': True, 'blockOwnerDeletion': True}]
    if job_uid is not None: require(UID.fullmatch(job_uid), 'Invalid native Job owner UID')
    owner_metadata = lambda name: metadata(name) | ({'ownerReferences': reference} if reference else {})
    code = Path(__file__).read_bytes()
    cm = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': owner_metadata(JOB), 'immutable': True,
        'data': {'native_transport.py': code.decode(), 'input.json': canonical(value).decode()}}
    account = {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': owner_metadata(JOB), 'automountServiceAccountToken': False}
    main_mounts = [{'name': 'assets', 'mountPath': '/assets', 'readOnly': True},
        {'name': 'cli', 'mountPath': '/cli', 'readOnly': True}, {'name': 'work', 'mountPath': '/work'},
        {'name': 'result', 'mountPath': '/result'}, {'name': 'token', 'mountPath': '/var/run/secrets/cloudlab', 'readOnly': True}]
    template = {'metadata': {'labels': labels, 'annotations': {'cloudlab.io/native-input-sha256': digest(canonical(value)),
        'cloudlab.io/native-code-sha256': value['codeSHA256']}}, 'spec': {
        'serviceAccountName': JOB, 'automountServiceAccountToken': False, 'restartPolicy': 'Never',
        'enableServiceLinks': False, 'terminationGracePeriodSeconds': 2,
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 999, 'runAsGroup': 999, 'fsGroup': 999,
                            'seccompProfile': {'type': 'RuntimeDefault'}},
        'initContainers': [{'name': 'cli-copy', 'image': ARGO_IMAGE, 'command': ['/bin/sh', '-ec'],
            'args': ['umask 077; test ! -e /cli/argocd; cp /usr/local/bin/argocd /cli/argocd; chmod 0500 /cli/argocd'],
            'securityContext': SECURITY, 'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'},
                'limits': {'cpu': '200m', 'memory': '128Mi'}}, 'volumeMounts': [{'name': 'cli', 'mountPath': '/cli'}]}],
        'containers': [{'name': 'transport', 'image': PYTHON_IMAGE, 'command': ['/usr/local/bin/python', '/assets/native_transport.py', '--pod'],
            'securityContext': SECURITY, 'resources': {'requests': {'cpu': '100m', 'memory': '512Mi' if input_limit(value) == DOWNSTREAM_LIMIT else '128Mi'},
                'limits': {'cpu': '1', 'memory': '768Mi'}}, 'volumeMounts': main_mounts,
            'env': [{'name': 'PYTHONDONTWRITEBYTECODE', 'value': '1'}, {'name': 'HOME', 'value': '/work'},
                {'name': 'CLOUDLAB_POD_UID', 'valueFrom': {'fieldRef': {'fieldPath': 'metadata.uid'}}}]}],
        'volumes': [{'name': 'assets', 'configMap': {'name': JOB, 'defaultMode': 292}},
            {'name': 'cli', 'emptyDir': {'sizeLimit': '512Mi'}},
            {'name': 'work', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '64Mi'}},
            {'name': 'result', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '40Mi' if input_limit(value) == DOWNSTREAM_LIMIT else '2Mi'}},
            {'name': 'token', 'projected': {'defaultMode': 288, 'sources': [
                {'serviceAccountToken': {'path': 'token', 'expirationSeconds': 600}},
                {'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}}]}}]}}
    job = {'apiVersion': 'batch/v1', 'kind': 'Job', 'metadata': metadata(JOB), 'spec': {
        'suspend': True, 'parallelism': 1, 'completions': 1, 'manualSelector': False, 'completionMode': 'NonIndexed',
        'podReplacementPolicy': 'Failed', 'activeDeadlineSeconds': 180, 'backoffLimit': 0, 'ttlSecondsAfterFinished': 60,
        'template': template}}
    role_name = ns
    role = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': metadata(role_name, ARGO), 'rules': [
        {'apiGroups': ['argoproj.io'], 'resources': ['applications', 'applicationsets', 'appprojects'], 'verbs': ['get', 'list', 'watch']},
        {'apiGroups': [''], 'resources': ['configmaps', 'secrets'], 'verbs': ['get', 'list', 'watch']},
        {'apiGroups': [''], 'resources': ['pods', 'services'], 'verbs': ['get', 'list']},
        {'apiGroups': [''], 'resources': ['pods/portforward'], 'resourceNames': sorted(
            pod['metadata']['name'] for pod in value['source']['pods'].values()), 'verbs': ['create']}]}
    binding = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': metadata(role_name, ARGO),
        'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': role_name},
        'subjects': [{'kind': 'ServiceAccount', 'name': JOB, 'namespace': ns}]}
    cidr = lambda raw: raw + '/' + str(ipaddress.ip_address(raw).max_prefixlen)
    network = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': metadata(JOB), 'spec': {
        'podSelector': {'matchLabels': labels}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': [
            {'to': [{'ipBlock': {'cidr': cidr(boundary['serviceIP'])}}], 'ports': [{'protocol': 'TCP', 'port': boundary['servicePort']}]},
            {'to': [{'ipBlock': {'cidr': cidr(raw)}} for raw in boundary['endpointIPs']],
             'ports': [{'protocol': 'TCP', 'port': boundary['endpointPort']}]}]}}
    realm = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns, 'labels': labels | {
        'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
        'istio-injection': 'disabled'}}}
    return {'namespace': realm, 'network': network, 'job': job, 'assets': cm, 'account': account, 'role': role, 'binding': binding}


class NativeClient:
    def __init__(self, value, deadline):
        self.value, self.deadline = value, deadline
        address = value['api']['serviceIP']
        self.server = 'https://' + ('[' + address + ']' if ':' in address else address) + ':' + str(value['api']['servicePort'])
        self.context = ssl.create_default_context(cafile=str(CA))
        self.paths = {APPS + PARENT, SETS + PARENT,
            '/api/v1/namespaces/argocd/secrets/argocd-secret', '/api/v1/namespaces/argocd/configmaps/argocd-cm',
            '/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/default'} | {
                '/api/v1/namespaces/argocd/pods/' + pod['metadata']['name'] for pod in value['source']['pods'].values()}
        if value.get('profile') == 'downstream' or initial_baseline(value): self.paths.update(APPS + name for name in DOWNSTREAM)

    def read(self, path):
        require(path in self.paths, 'Native API request escaped the fixed read profile')
        token = TOKEN.read_text().strip()
        require(0 < len(token) <= 8192 and re.fullmatch(r'[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+', token),
                'Bound projected token is absent or invalid')
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'Native Pod client deadline expired')
        address, port = self.value['api']['serviceIP'], self.value['api']['servicePort']
        with socket.create_connection((address, port), timeout=remaining) as plain:
            plain.settimeout(max(0.001, self.deadline - time.monotonic()))
            with self.context.wrap_socket(plain, server_hostname=address) as connection:
                connection.settimeout(max(0.001, self.deadline - time.monotonic()))
                request = ('GET ' + path + ' HTTP/1.1\r\nHost: kubernetes.default.svc\r\nAuthorization: Bearer ' + token +
                    '\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n').encode()
                connection.sendall(request)
                raw = bytearray()
                while True:
                    remaining = self.deadline - time.monotonic()
                    require(remaining > 0, 'Native Pod client deadline expired')
                    connection.settimeout(remaining)
                    chunk = connection.recv(min(65536, LIMIT + 1 - len(raw)))
                    if not chunk: break
                    raw.extend(chunk)
                    require(len(raw) <= LIMIT, 'Native API response exceeded bound')
        require(time.monotonic() < self.deadline, 'Native Pod client deadline expired')
        return strict_json(decode_response(bytes(raw)))


@contextmanager
def dashboard(directory, client, deadline):
    binary = core_binary(deadline)
    config = directory / 'kubeconfig'
    value = {'apiVersion': 'v1', 'kind': 'Config', 'clusters': [{'name': 'native', 'cluster': {
        'server': client.server, 'certificate-authority': str(CA)}}], 'users': [{'name': 'native', 'user': {'tokenFile': str(TOKEN)}}],
        'contexts': [{'name': 'native', 'context': {'cluster': 'native', 'user': 'native', 'namespace': ARGO}}], 'current-context': 'native'}
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream: stream.write(canonical(value))
    with socket.socket() as selected:
        selected.bind(('127.0.0.1', 0)); port = selected.getsockname()[1]
    arguments = [binary, 'admin', 'dashboard', '--address', '127.0.0.1', '--port', str(port), '--namespace', ARGO,
        '--kubeconfig', str(config), '--request-timeout', '10s', '--config', str(directory / 'argo-config'), '--loglevel', 'error']
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True, env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(directory), 'TMPDIR': str(directory), 'KUBECONFIG': str(config)})
    diagnostics = bytearray()
    def drain():
        while True:
            try: chunk = os.read(process.stdout.fileno(), 8192)
            except BlockingIOError: break
            if not chunk: break
            diagnostics.extend(chunk)
            require(len(diagnostics) <= 65536, 'Private Core diagnostics exceeded bound')
    def guard():
        drain()
        require(owned_listener(process, arguments, port), 'Owned Core listener changed')
    try:
        os.set_blocking(process.stdout.fileno(), False)
        while time.monotonic() < deadline:
            drain()
            require(os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None, 'Native Core exited during startup')
            ready = ('Argo CD UI is available at http://127.0.0.1:' + str(port)).encode()
            if ready in [line.removesuffix(b'\r') for line in diagnostics.split(b'\n')[:-1]]:
                guard()
                break
            time.sleep(0.1)
        else: raise RuntimeError('Native Core startup deadline expired')
        yield port, guard
    finally:
        stop_core(process)
        with socket.socket() as probe:
            probe.settimeout(1)
            require(probe.connect_ex(('127.0.0.1', port)) != 0, 'Native Core listener remains after cleanup')


def native_read(value, directory, client):
    source = value['source']
    profile = value.get('profile', 'parent')
    baseline = initial_baseline(value)
    limit = input_limit(value)
    deadline = min(client.deadline, time.monotonic() + 60)
    body = generate_payload(source['expectedSet'])
    def read(path):
        require(time.monotonic() < deadline, 'Native Core total deadline expired')
        previous = client.deadline
        client.deadline = min(previous, deadline)
        try:
            return client.read(path)
        finally:
            client.deadline = previous
    def unchanged(actual, expected):
        require(identity(actual) == identity(expected)
            and actual['metadata']['resourceVersion'] == expected['metadata']['resourceVersion']
            and actual.get('spec') == expected.get('spec'), 'Native source changed during Core read')
    def originals():
        if baseline:
            validate_original_baseline(source, {name: read(APPS + name) for name in DOWNSTREAM})
    def native_request(port, operation, body, budget, guard):
        originals()
        raw = core_request(port, operation, body, deadline, budget, guard, profile,
            baseline_inventory=True) if baseline else core_request(port, operation, body, deadline, budget, guard, profile)
        originals()
        return raw
    originals()
    unchanged(read(SETS + PARENT), source['set'])
    unchanged(read(APPS + PARENT), source['parent'])
    for pod in source['pods'].values():
        unchanged(read('/api/v1/namespaces/argocd/pods/' + pod['metadata']['name']), pod)
    if profile == 'downstream':
        validate_downstream(source)
        for name in DOWNSTREAM: unchanged(read(APPS + name), source['downstream'][name]['observed'])
    settings = initialized_state(read, profile)
    try:
        with dashboard(directory, client, deadline) as (port, guard):
            budget = [limit]
            generated_parent(native_request(port, 'generate', body, budget, guard), source['parent'])
            unchanged(read(SETS + PARENT), source['set']); unchanged(read(APPS + PARENT), source['parent'])
            response = native_request(port, 'manifests', b'', budget, guard)
            objects = phase_manifests(response, source) if profile in ('phase-parent', 'downstream') else manifests(response, source)
            if profile == 'downstream':
                validate_downstream(source, objects)
                objects = {'parent': objects}
                for name in DOWNSTREAM:
                    unchanged(read(APPS + name), source['downstream'][name]['observed'])
                    objects[name] = resource_manifests(native_request(port, name, b'', budget, guard))
                for name in DOWNSTREAM: unchanged(read(APPS + name), source['downstream'][name]['observed'])
            if baseline:
                objects = {'parent': objects, 'baseline': {}}
                for name in DOWNSTREAM:
                    objects['baseline'][name] = resource_manifests(native_request(port, name, b'', budget, guard))
            originals()
            unchanged(read(SETS + PARENT), source['set']); unchanged(read(APPS + PARENT), source['parent'])
            for pod in source['pods'].values():
                unchanged(read('/api/v1/namespaces/argocd/pods/' + pod['metadata']['name']), pod)
            require(time.monotonic() < deadline, 'Native Core total deadline expired')
    finally:
        require(initialized_state(read, profile) == settings, 'Native Core changed initialized settings')
        originals()
    return objects


def collect_file(value=None):
    limit = input_limit(value) if value is not None else LIMIT
    fd = os.open(RESULT, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= limit, 'Unsafe native result custody')
        raw = stream.read(limit + 1)
    value = strict_json(raw, limit)
    require(len(raw) == info.st_size and type(value.get('expires')) in (int, float)
        and time.monotonic() < value['expires'], 'Native result collection window expired')
    return raw


def pod_main():
    started = time.monotonic()
    raw = Path('/assets/input.json').read_bytes()
    require(len(raw) <= LIMIT // 2, 'Native Pod input exceeded bound')
    value = validate_input(strict_json(raw))
    pod_uid = os.environ.get('CLOUDLAB_POD_UID', '')
    require(UID.fullmatch(pod_uid), 'Native Pod UID is absent')
    home = Path('/work/private')
    home.mkdir(mode=0o700)
    client = NativeClient(value, started + 90)
    objects = native_read(value, home, client)
    # Core is stopped before any result becomes collectible.
    result = canonical({'version': 1, 'operation': value['operation'], 'podUID': pod_uid,
        'inputSHA256': digest(raw), 'expires': time.monotonic() + 30, 'manifests': objects})
    limit = input_limit(value)
    require(len(result) <= limit, 'Native result exceeds custody bound')
    fd = os.open(RESULT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream: stream.write(result); stream.flush(); os.fsync(stream.fileno())
        print(json.dumps({'status': 'ready', 'sha256': digest(result), 'bytes': len(result)}), flush=True)
        stop = strict_json(result, limit)['expires']
        while time.monotonic() < stop:
            remaining = min(0.2, stop - time.monotonic())
            if remaining > 0: time.sleep(remaining)
    finally:
        RESULT.unlink(missing_ok=True)


def path_for(obj):
    kind, version, metadata = obj['kind'], obj['apiVersion'], obj['metadata']
    names = {'Namespace': 'namespaces', 'NetworkPolicy': 'networkpolicies', 'Job': 'jobs', 'ConfigMap': 'configmaps',
             'ServiceAccount': 'serviceaccounts', 'Role': 'roles', 'RoleBinding': 'rolebindings', 'Pod': 'pods'}
    require(kind in names, 'Unsupported native transport resource')
    prefix = '/api/v1' if version == 'v1' else '/apis/' + version
    if kind != 'Namespace': prefix += '/namespaces/' + metadata['namespace']
    return prefix + '/' + names[kind] + '/' + metadata['name']


def fingerprint(obj):
    return digest(canonical({key: item for key, item in obj.items() if key not in ('metadata', 'status')}))


def pod_source(actual, expected):
    actual, expected = copy.deepcopy(actual), copy.deepcopy(expected)
    actual.pop('nodeName', None)
    for key, default in {'dnsPolicy': 'ClusterFirst', 'schedulerName': 'default-scheduler', 'priority': 0,
                         'preemptionPolicy': 'PreemptLowerPriority'}.items():
        if key not in expected and actual.get(key) == default: actual.pop(key)
    if 'serviceAccount' in actual and 'serviceAccount' not in expected:
        require(actual.pop('serviceAccount') == expected.get('serviceAccountName'), 'Native ServiceAccount alias changed')
    tolerations = [{'key': 'node.kubernetes.io/' + key, 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300}
                  for key in ('not-ready', 'unreachable')]
    if actual.get('tolerations') == tolerations and 'tolerations' not in expected: actual.pop('tolerations')
    for group in ('containers', 'initContainers'):
        require(len(actual.get(group, [])) == len(expected.get(group, [])), 'Native executable count changed')
        for left, right in zip(actual.get(group, []), expected.get(group, [])):
            for key, default in {'imagePullPolicy': 'IfNotPresent', 'terminationMessagePath': '/dev/termination-log',
                                 'terminationMessagePolicy': 'File'}.items():
                if key not in right and left.get(key) == default: left.pop(key)
            for entry in left.get('env', []):
                ref = entry.get('valueFrom', {}).get('fieldRef', {})
                if ref.get('apiVersion') == 'v1': ref.pop('apiVersion')
    require(actual == expected, 'Native transport executable or authority changed')


def declared(current, desired):
    identity(current)
    require(current.get('apiVersion') == desired['apiVersion'] and current.get('kind') == desired['kind']
        and current['metadata'].get('name') == desired['metadata']['name']
        and current['metadata'].get('namespace') == desired['metadata'].get('namespace')
        and all(current['metadata'].get('labels', {}).get(key) == item for key, item in desired['metadata'].get('labels', {}).items())
        and current['metadata'].get('ownerReferences', []) == desired['metadata'].get('ownerReferences', [])
        and not current['metadata'].get('finalizers'), 'Native transport resource ownership changed')
    if desired['kind'] == 'Job':
        a, b = copy.deepcopy(current['spec']), copy.deepcopy(desired['spec'])
        uid, name = current['metadata']['uid'], current['metadata']['name']
        selector = a.pop('selector', None)
        require(selector in (None, {'matchLabels': {'batch.kubernetes.io/controller-uid': uid}},
                {'matchLabels': {'controller-uid': uid}}), 'Native Job selector escaped owner UID')
        if a.get('managedBy') == 'kubernetes.io/job-controller': a.pop('managedBy')
        if a['template']['metadata'].get('creationTimestamp') is None:
            a['template']['metadata'].pop('creationTimestamp', None)
        labels = a['template']['metadata'].get('labels', {})
        for key, item in {'batch.kubernetes.io/controller-uid': uid, 'controller-uid': uid,
                          'batch.kubernetes.io/job-name': name, 'job-name': name}.items():
            if key in labels: require(labels.pop(key) == item, 'Native Job controller label changed')
        pod_source(a['template']['spec'], b['template']['spec'])
        a['template']['spec'] = b['template']['spec']
        require(a == b, 'Native Job lifecycle or template changed')
    else:
        for key, item in desired.items():
            if key not in ('metadata', 'apiVersion', 'kind'): require(current.get(key) == item, 'Native transport resource content changed')
    if desired['kind'] == 'ServiceAccount':
        require(not current.get('secrets') and not current.get('imagePullSecrets'), 'Native ServiceAccount carries other credentials')
    if desired['kind'] == 'Namespace':
        labels = current['metadata'].get('labels', {})
        require(labels.get('istio.io/dataplane-mode') != 'ambient' and 'cloudlab.io/service-secrets' not in labels,
                'Native transport realm inherited application delivery or ambient enrollment')


def prepare(request, record, persist, value):
    """Host-only: request GET returns None only for acknowledged 404; persist must be durable/protected."""
    validate_input(value)
    context = {'operation': value['operation'], 'inputSHA256': digest(canonical(value)), 'codeSHA256': value['codeSHA256']}
    if not record:
        record.update(context=context, objects={}, pending={}, cleanupStarted=False, unsuspended=False)
        persist()
    require(record.get('context') == context and not record.get('cleanupStarted'), 'Native journal context changed or cleanup started')
    def ensure(key, desired):
        path = path_for(desired)
        current = request(path)
        previous = record['objects'].get(key)
        if previous:
            require(current is not None and identity(current) == previous['identity'], 'Recorded transport resource disappeared or changed')
            declared(current, desired)
            require(fingerprint(current) == previous['fingerprint'], 'Recorded transport resource content changed')
            return current
        require(current is None, 'Unacknowledged native transport resource cannot be adopted')
        checksum = digest(canonical(desired))
        require(record['pending'].get(key, checksum) == checksum, 'Pending native resource declaration changed')
        record['pending'][key] = checksum
        persist()
        current = request(path.rsplit('/', 1)[0], 'POST', desired)
        declared(current, desired)
        record['objects'][key] = {'path': path, 'identity': identity(current), 'fingerprint': fingerprint(current)}
        record['pending'].pop(key)
        persist()
        return current
    docs = declarations(value)
    ensure('namespace', docs['namespace']); ensure('network', docs['network'])
    if record.get('unsuspended') or record.get('unsuspendIntent'):
        job = request(path_for(docs['job']))
        require(job is not None and identity(job) == record['objects']['job']['identity'], 'Native Job identity changed')
        if record.get('unsuspendIntent') and fingerprint(job) == record['unsuspendIntent']['after']:
            record['objects']['job']['fingerprint'] = fingerprint(job)
            record['unsuspended'] = True
            record.pop('unsuspendIntent'); persist()
        docs['job']['spec']['suspend'] = not record.get('unsuspended', False)
    job = ensure('job', docs['job'])
    docs = declarations(value, job['metadata']['uid'])
    for key in ('assets', 'account', 'role', 'binding'): ensure(key, docs[key])
    # Reject stale API endpoints and source targets before any projected token can exist.
    boundary = api_targets(request('/api/v1/namespaces/default/services/kubernetes'), request('/api/v1/namespaces/default/endpoints/kubernetes'))
    require(boundary == value['api'], 'Native API boundary changed before unsuspension')
    extra = [entry['observed'] for entry in value['source']['originalBaselineApps'].values()] if initial_baseline(value) else []
    for expected in (value['source']['set'], value['source']['parent'], *value['source']['pods'].values(), *extra):
        path = (SETS + PARENT if expected['kind'] == 'ApplicationSet' else APPS + expected['metadata']['name'] if expected['kind'] == 'Application'
                else '/api/v1/namespaces/argocd/pods/' + expected['metadata']['name'])
        actual = request(path)
        require(actual is not None and identity(actual) == identity(expected)
            and actual['metadata']['resourceVersion'] == expected['metadata']['resourceVersion'] and actual['spec'] == expected['spec'],
            'Native source changed before unsuspension')
    if record.get('unsuspended'): return job
    after = copy.deepcopy(job)
    after['spec']['suspend'] = False
    record['unsuspendIntent'] = {'before': fingerprint(job), 'after': fingerprint(after)}
    persist()
    returned = request(path_for(job), 'PATCH', [
        {'op': 'test', 'path': '/metadata/uid', 'value': job['metadata']['uid']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': job['metadata']['resourceVersion']},
        {'op': 'replace', 'path': '/spec/suspend', 'value': False}], 'application/json-patch+json')
    require(identity(returned) == identity(job) and fingerprint(returned) == record['unsuspendIntent']['after'],
            'Native Job unsuspension acknowledgement differs')
    record['objects']['job']['fingerprint'] = fingerprint(returned)
    record['unsuspended'] = True
    record.pop('unsuspendIntent'); persist()
    return returned


def transport_pod(pod, value, job_uid):
    identity(pod)
    require(pod.get('kind') == 'Pod' and pod.get('apiVersion') == 'v1'
        and pod['metadata'].get('namespace') == namespace(value['operation'])
        and pod['metadata'].get('ownerReferences') == [{'apiVersion': 'batch/v1', 'kind': 'Job', 'name': JOB,
            'uid': job_uid, 'controller': True, 'blockOwnerDeletion': True}]
        and set(pod['metadata'].get('finalizers', [])) <= {'batch.kubernetes.io/job-tracking'}, 'Native collector Pod owner differs')
    pod_source(pod['spec'], declarations(value, job_uid)['job']['spec']['template']['spec'])
    statuses = [row for row in pod.get('status', {}).get('containerStatuses', []) if row.get('name') == 'transport']
    require(len(statuses) == 1 and statuses[0].get('state', {}).get('running')
        and type(statuses[0].get('restartCount')) is int and statuses[0]['restartCount'] == 0 and re.fullmatch(r'containerd://[a-f0-9]{64}', statuses[0].get('containerID', '')),
        'Native collector process is not the original running container')
    return identity(pod) | {'containerID': statuses[0]['containerID']}


def collect(request, execute, record, persist, value, pod, status):
    """Trusted host must capture execute output privately/no_log; Job Role intentionally has no exec permission."""
    limit = input_limit(value)
    require(record.get('context') == {'operation': value['operation'], 'inputSHA256': digest(canonical(value)), 'codeSHA256': value['codeSHA256']}
        and record.get('unsuspended') and not record.get('cleanupStarted')
        and isinstance(status, dict) and set(status) == {'status', 'sha256', 'bytes'} and status['status'] == 'ready'
        and isinstance(status['sha256'], str) and SHA.fullmatch(status['sha256'])
        and type(status['bytes']) is int and 0 < status['bytes'] <= limit, 'Native result status or journal differs')
    job_uid = record['objects']['job']['identity']['uid']
    require(pod.get('kind') == 'Pod' and pod.get('apiVersion') == 'v1'
        and pod.get('metadata', {}).get('namespace') == namespace(value['operation'])
        and re.fullmatch(JOB + '-[a-z0-9]+', pod['metadata'].get('name', '')), 'Collector target escaped its Job namespace')
    docs = declarations(value, job_uid)
    def custody():
        for key in ('assets', 'account', 'role', 'binding'):
            expected = record['objects'][key]
            actual = request(expected['path'])
            require(actual is not None and identity(actual) == expected['identity']
                and fingerprint(actual) == expected['fingerprint'], 'Native result custody or authority changed')
            declared(actual, docs[key])
    custody()
    path = path_for(pod)
    before = transport_pod(request(path), value, job_uid)
    require(before['uid'] == pod['metadata']['uid'], 'Native result Pod changed before collection')
    raw = execute(namespace(value['operation']), pod['metadata']['name'], 'transport', list(COLLECT))
    require(isinstance(raw, bytes) and len(raw) == status['bytes'] and digest(raw) == status['sha256'], 'Native result bytes or hash differ')
    result = strict_json(raw, limit)
    require(set(result) == {'version', 'operation', 'podUID', 'inputSHA256', 'expires', 'manifests'} and result['version'] == 1
        and type(result['version']) is int and result['operation'] == value['operation'] and result['podUID'] == before['uid']
        and result['inputSHA256'] == digest(canonical(value)), 'Native result source binding differs')
    if value.get('profile') == 'downstream':
        objects = result['manifests']
        require(isinstance(objects, dict) and set(objects) == {'parent', *DOWNSTREAM}, 'Downstream result inventory differs')
        parents = phase_manifests(canonical({'manifests': [canonical(obj).decode() for obj in objects['parent']]}), value['source'])
        validate_downstream(value['source'], parents)
        for name in DOWNSTREAM:
            resource_manifests(canonical({'manifests': [canonical(obj).decode() for obj in objects[name]]}))
    elif value.get('profile') == 'phase-parent':
        objects = result['manifests']
        parents = objects
        if initial_baseline(value):
            require(isinstance(objects, dict) and set(objects) == {'parent', 'baseline'}
                and isinstance(objects['baseline'], dict) and set(objects['baseline']) == set(DOWNSTREAM),
                'Original baseline result must preserve all three native inventories')
            parents = objects['parent']
            for name in DOWNSTREAM:
                resource_manifests(canonical({'manifests': [canonical(obj).decode() for obj in objects['baseline'][name]]}))
        phase_manifests(canonical({'manifests': [canonical(obj).decode() for obj in parents]}), value['source'])
    else:
        objects = manifests(canonical({'manifests': [canonical(obj).decode() for obj in result['manifests']]}), value['source'])
    require(transport_pod(request(path), value, job_uid) == before, 'Native result Pod or container changed during collection')
    custody()
    record['collected'] = {'sha256': status['sha256'], 'bytes': status['bytes'], 'podUID': before['uid']}
    persist()
    return objects


def cleanup(request, record, persist):
    """Request Job deletion, then revoke Binding without waiting; resumption revokes first."""
    require(isinstance(record, dict) and 'context' in record and 'objects' in record, 'Missing native cleanup journal')
    namespace(record['context']['operation'])
    resumed = record.get('cleanupStarted') is True
    record['cleanupStarted'] = True
    persist()
    def remove(key):
        target = record['objects'].get(key)
        if not target: return
        ns = namespace(record['context']['operation'])
        scope = {'job': ('/apis/batch/v1/namespaces/' + ns + '/jobs/' + JOB, JOB, ns),
            'binding': ('/apis/rbac.authorization.k8s.io/v1/namespaces/argocd/rolebindings/' + ns, ns, ARGO),
            'role': ('/apis/rbac.authorization.k8s.io/v1/namespaces/argocd/roles/' + ns, ns, ARGO)}
        expected_path, expected_name, expected_namespace = scope[key]
        require(target['path'] == expected_path and target['identity']['name'] == expected_name
            and target['identity']['namespace'] == expected_namespace, 'Cleanup journal escaped the exact transport scope')
        current = request(target['path'])
        if current is None:
            record.setdefault('deletions', {})[key] = {'absent': True}; persist(); return
        require(identity(current) == target['identity'] and fingerprint(current) == target['fingerprint']
            and current['metadata'].get('labels', {}).get('cloudlab.io/owner') == OWNER
            and current['metadata']['labels'].get(LABEL) == record['context']['operation']
            and not current['metadata'].get('finalizers'), 'Unknown transport cleanup identity or content retained')
        intent = {'uid': current['metadata']['uid'], 'resourceVersion': current['metadata']['resourceVersion'], 'accepted': False}
        record.setdefault('deletions', {})[key] = intent; persist()
        request(target['path'], 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions',
            'preconditions': {field: intent[field] for field in ('uid', 'resourceVersion')}, 'propagationPolicy': 'Foreground'})
        intent['accepted'] = True; persist()
    if resumed:
        remove('binding')
        remove('job')
    else:
        try: remove('job')
        finally: remove('binding')
    remove('role')
    return {'bindingRevocationRequested': True, 'jobDeletionRequested': True,
            'namespaceCleanup': 'pending native Job/Pod/SA garbage collection and caller inventory'}


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        mode = parser.add_mutually_exclusive_group(required=True)
        mode.add_argument('--pod', action='store_true')
        mode.add_argument('--collect', action='store_true')
        selected = parser.parse_args()
        if selected.collect:
            sys.stdout.buffer.write(collect_file(validate_input(strict_json(Path('/assets/input.json').read_bytes()))))
            sys.stdout.buffer.flush()
        else:
            pod_main()
    except Exception:
        print(json.dumps({'status': 'failed'}), flush=True)
        raise SystemExit(1) from None
