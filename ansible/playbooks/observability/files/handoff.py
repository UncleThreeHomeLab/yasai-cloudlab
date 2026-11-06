"""Finite stdlib host boundary for explicit telemetry handoff inspection.

Ansible's existing become and known-host channel establishes initial custody.
The protected bundle and source documents freeze that custody on repeat calls.
This module never releases writers or reports workload readiness.
"""
from contextlib import contextmanager
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import subprocess

LIMIT = 1024 * 1024
PRIVATE_LIMIT = 32 * 1024 * 1024
PHASES = ('baseline', 'maintenance', 'persistent-maintenance', 'persistent-normal', 'native-paused')
PHASE_VERSION = 'cloudlab-observability-phase-source/v1'
QUALIFICATIONS = ('checkpoint', 'lifecycle', 'storage', 'source', 'transport', 'handoff')
HANDOFF_EVIDENCE = 'handoff-evidence.json'
CLUSTER_UID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
TRANSFER_KINDS = {('monitoring.coreos.com/v1', 'PodMonitor'): 'podmonitors',
    ('monitoring.coreos.com/v1', 'ServiceMonitor'): 'servicemonitors',
    ('monitoring.coreos.com/v1', 'PrometheusRule'): 'prometheusrules',
    ('gateway.networking.k8s.io/v1', 'HTTPRoute'): 'httproutes'}
BUNDLE_VERSION = 'cloudlab-observability-handoff-bundle/v1'
SOURCE_VERSION = 'cloudlab-observability-handoff-source/v1'
HOST_FILES = ('playbooks/observability/files/handoff.py', 'playbooks/observability/files/handoff_execute.py',
    'playbooks/observability/files/handoff_backend.py', 'playbooks/observability/files/checkpoint.py',
    'playbooks/observability/files/native_transport.py', 'playbooks/observability/files/writer_guard.py',
    'playbooks/istio/files/kube.py', 'playbooks/argocd/files/source_revision.py')
PACKAGE_INITS = tuple(name + '/__init__.py' for name in ('playbooks', 'playbooks/observability',
    'playbooks/observability/files', 'playbooks/istio', 'playbooks/istio/files', 'playbooks/argocd', 'playbooks/argocd/files'))
RUNNER_FILES = ('playbooks/observability/files/handoff_source.py', 'playbooks/observability/handoff.yml')
IDENTITY_RECEIPT = Path('/var/lib/cloudlab/gitops/identity-values-binding.json')
IDENTITY_OBJECTS = {'root_uid': ('application.argoproj.io', 'cloudlab-public-root'),
    'controller_uid': ('statefulset', 'argocd-application-controller'),
    'project_uid': ('appproject.argoproj.io', 'cloudlab-root')}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_path(path, *, missing=False):
    """Authority files cannot inherit writable directories or follow symlinks."""
    path = Path(path)
    require(path.is_absolute(), 'Handoff authority path must be absolute')
    for current in (*reversed(path.parents), path):
        try:
            info = current.lstat()
        except FileNotFoundError:
            if current == path and missing:
                return None
            raise RuntimeError('Handoff authority path is unavailable') from None
        require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode), 'Unsafe handoff authority owner')
        if current == path:
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_nlink == 1, 'Handoff authority file must be private and unlinked')
        else:
            require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022,
                    'Unsafe handoff authority directory')
    return info


def read_private(path, limit=LIMIT):
    private_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'Handoff authority file changed')
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'Handoff authority file exceeds bound')
    return raw


def strict_json(raw, limit=LIMIT):
    require(isinstance(raw, (str, bytes)) and len(raw) <= limit, 'Handoff JSON exceeds bound')
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate handoff journal field')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('Nonfinite handoff journal value')))
    except (ValueError, UnicodeError):
        raise RuntimeError('Invalid handoff journal') from None


def operation_directory(operation):
    require(isinstance(operation, str) and re.fullmatch('[a-f0-9]{16}', operation), 'Invalid handoff operation')
    return Path('/var/lib/cloudlab/observability/handoff-' + operation)


def inventory_apps():
    from playbooks.observability.files.native_transport import DOWNSTREAM
    require(DOWNSTREAM == ('cloudlab-observability', 'cloudlab-prometheus', 'cloudlab-kiali'),
        'Qualified configuration, Prometheus and Kiali inventories are required')
    return DOWNSTREAM


def artifact_key(name):
    require(isinstance(name, str) and len(name) <= 160 and not name.startswith('/')
        and all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', part)
            and part not in ('.', '..') for part in name.split('/')), 'Unsafe qualification artifact key')
    return name


def phase_order(phase, previous, operation):
    """Structure only; callers must read previous records from protected custody."""
    require(phase in PHASES, 'C2 cannot prepare native activation')
    if previous is None:
        require(phase == PHASES[0], 'Handoff phase must begin at baseline')
        return
    require(isinstance(previous, dict) and set(previous) == {'record', 'intent'}, 'Invalid previous phase packet')
    record, intent = previous['record'], previous['intent']
    require(isinstance(record, dict) and record.get('version') == PHASE_VERSION
        and record.get('stage') == 'phase-recorded' and record.get('operationId') == operation
        and record.get('intentSHA256') == digest(canonical(intent))
        and record.get('phase') in PHASES and PHASES.index(record['phase']) + 1 < len(PHASES)
        and PHASES[PHASES.index(record['phase']) + 1] == phase, 'Handoff phase order or predecessor differs')


def frozen_phase(current, previous):
    for field in ('operationId', 'baseline', 'qualifications', 'resourcePolicySHA256'):
        require(current[field] == previous[field], 'Frozen handoff phase input changed')
    if previous.get('targetClusterUID') is not None:
        require(current.get('targetClusterUID') == previous['targetClusterUID'], 'Frozen target cluster identity changed')
    elif current.get('targetClusterUID') is not None:
        require(previous.get('phase') == 'baseline' and current.get('phase') == 'maintenance'
            and valid_cluster_uid(current['targetClusterUID']), 'Initial native target binding changed')
    for field in ('bundleSHA256', 'publicSource', 'privateBinding', 'sourceBindingSHA256', 'publicIntentSHA256',
                  'rootCodeSHA256', 'identityUIDs', 'nativeFilesSHA256', 'profilesSHA256', 'profiles'):
        require(current['prepared'][field] == previous['prepared'][field], 'Frozen source, code or qualification changed')
    for field in ('version', 'operationId', 'baselineDigest', 'baselineRevision', 'qualificationsSHA256', 'approvedStorageTarget'):
        require(current['phaseContext'][field] == previous['phaseContext'][field], 'Frozen phase context changed')
    require(current['phaseContext']['privateRevision'] != previous['phaseContext']['privateRevision']
        and current['prepared']['publicRevision'] != previous['prepared']['publicRevision'],
        'Next phase requires a newly approved public and consumer revision')
    require({name: obj['metadata']['uid'] for name, obj in current['applicationBindings'].items()} ==
        {name: obj['metadata']['uid'] for name, obj in previous['applicationBindings'].items()},
        'Handoff Application identity changed')


def phase_file(directory, phase, suffix):
    require(phase in PHASES and suffix in ('proposal', 'input', 'intent', 'draft', 'draft-payload',
        'transport', 'downstream-input', 'downstream-transport', 'resources', 'record', 'patch-intent', 'final-proposal'), 'Invalid phase artifact')
    return Path(directory) / 'private' / ('%d-%s.%s.json' % (PHASES.index(phase), phase, suffix))


def phase_json(path):
    return strict_json(read_private(path, PRIVATE_LIMIT), PRIVATE_LIMIT)


def write_once(path, value, limit=PRIVATE_LIMIT):
    if private_path(path, missing=True) is None:
        atomic_private(path, value, limit)
        return True
    require(strict_json(read_private(path, limit), limit) == value, 'Protected phase artifact changed')
    return False


def phase_head(directory):
    path = Path(directory) / 'phase-head.json'
    if private_path(path, missing=True) is None:
        return None
    head = strict_json(read_private(path))
    require(isinstance(head, dict) and set(head) == {'phase', 'sha256'}, 'Invalid phase head')
    require(head['phase'] in PHASES, 'Invalid protected phase head')
    previous = None
    for phase in PHASES[:PHASES.index(head['phase']) + 1]:
        record = strict_json(read_private(phase_file(directory, phase, 'record')))
        intent = phase_json(phase_file(directory, phase, 'intent'))
        require(record.get('version') == PHASE_VERSION and record.get('stage') == 'phase-recorded'
            and record.get('phase') == phase and record['intentSHA256'] == digest(canonical(intent))
            and record['operationId'] == intent['operationId']
            and record['previousPhaseSHA256'] == intent['previousPhaseSHA256'] ==
                (None if previous is None else digest(canonical(previous['record']))), 'Protected phase chain was changed')
        if previous is not None: frozen_phase(intent, previous['intent'])
        payload = read_private(phase_file(directory, phase, 'resources'), PRIVATE_LIMIT)
        require(digest(payload) == record['payloadSHA256'], 'Protected phase payload changed')
        previous = {'record': record, 'intent': intent}
    require(digest(canonical(record)) == head['sha256'], 'Protected phase head hash changed')
    return {'record': record, 'intent': intent}


def stage_phase(directory, proposal_path, expected_sha256):
    with writer_locks():
        return _stage_phase_locked(directory, proposal_path, expected_sha256)


def _stage_phase_locked(directory, proposal_path, expected_sha256):
    """Trusted Ansible stages proposals; no proposal authorizes an executor write."""
    directory = Path(directory)
    manifest = verify_bundle(directory / 'runtime', directory / 'bundle.json')
    proposal = strict_json(read_private(proposal_path, PRIVATE_LIMIT), PRIVATE_LIMIT)
    require(isinstance(proposal, dict) and set(proposal) == {'intent', 'transportInput'}
        and digest(canonical(proposal)) == expected_sha256, 'Runner phase proposal changed')
    intent, value = proposal['intent'], proposal['transportInput']
    phase, operation = intent['phase'], manifest['operationId']
    require(intent['version'] == PHASE_VERSION and intent['operationId'] == operation
        and value['operation'] == operation and value['profile'] == 'phase-parent'
        and 'phaseApplications' not in value['source'] and value['source']['phaseContext'] == intent['phaseContext']
        and value['source']['expectedSet'] == intent['prepared']['expectedSet']
        and intent['prepared']['bundleSHA256'] == digest(canonical(manifest))
        and value['codeSHA256'] == manifest['moduleDigests']['playbooks/observability/files/native_transport.py'],
        'Phase proposal source or code binding differs')
    from playbooks.observability.files import native_transport
    native_transport.validate_input(value)
    from playbooks.observability.files import handoff_execute
    handoff_execute.advance_allowed(directory, phase)
    previous = phase_head(directory)
    phase_order(phase, previous, operation)
    require(intent['previousPhaseSHA256'] == (None if previous is None else digest(canonical(previous['record']))),
        'Phase proposal does not extend the protected head')
    if previous is not None: frozen_phase(intent, previous['intent'])
    else:
        initial = strict_json(read_private(directory / 'source.json'))
        for field in ('bundleSHA256', 'publicSource', 'privateBinding', 'sourceBindingSHA256', 'publicIntentSHA256',
                      'rootCodeSHA256', 'identityUIDs', 'nativeFilesSHA256', 'profilesSHA256', 'profiles'):
            require(intent['prepared'][field] == initial[field], 'Initial source pins or qualification changed')
    qualification_files(directory, intent)
    private = directory / 'private'
    if not private.exists(): private.mkdir(mode=0o700)
    write_once(phase_file(directory, phase, 'intent'), intent)
    changed = write_once(phase_file(directory, phase, 'input'), value)
    return {'stage': 'phase-prepared', 'phase': phase, 'sha256': digest(canonical(proposal)), 'changed': changed, 'ready': False}


def collect_phase(directory, phase, request, execute, pod, status, *, downstream=False):
    with writer_locks():
        return _collect_phase_locked(directory, phase, request, execute, pod, status, downstream=downstream)


def _collect_phase_locked(directory, phase, request, execute, pod, status, *, downstream=False):
    """Only actual transport.collect can create source custody; no raw receipt input."""
    require(callable(request) and callable(execute), 'Native collection requires bounded callable adapters, not caller receipts')
    from playbooks.observability.files import native_transport as transport
    directory = Path(directory)
    manifest = verify_bundle(directory / 'runtime', directory / 'bundle.json')
    intent = phase_json(phase_file(directory, phase, 'intent'))
    value = phase_json(phase_file(directory, phase, 'downstream-input' if downstream else 'input'))
    record_path = phase_file(directory, phase, 'downstream-transport' if downstream else 'transport')
    record = strict_json(read_private(record_path))
    qualification_files(directory, intent)
    require(intent['prepared']['bundleSHA256'] == digest(canonical(manifest))
        and value['codeSHA256'] == manifest['moduleDigests']['playbooks/observability/files/native_transport.py']
        and record.get('context') == {'operation': manifest['operationId'], 'codeSHA256': value['codeSHA256'],
            'inputSHA256': digest(canonical(value))}, 'Native collector record source changed')
    previous = phase_head(directory)
    phase_order(phase, previous, manifest['operationId'])
    require(intent['previousPhaseSHA256'] == (None if previous is None else digest(canonical(previous['record']))),
        'Native collection no longer extends the protected head')
    objects = transport.collect(request, execute, record, lambda: atomic_private(record_path, record), value, pod, status)
    require(isinstance(record.get('collected'), dict) and set(record['collected']) == {'sha256', 'bytes', 'podUID'},
        'Native transport did not persist actual collection custody')
    record['sourcePayloadSHA256'] = digest(canonical(objects))
    atomic_private(record_path, record)
    custody = collection_binding(record)
    if downstream:
        require(isinstance(objects, dict) and set(objects) == {'parent', *inventory_apps()},
            'Native downstream collection is incomplete')
        draft = strict_json(read_private(phase_file(directory, phase, 'draft')))
        payload = strict_json(read_private(phase_file(directory, phase, 'draft-payload'), PRIVATE_LIMIT), PRIVATE_LIMIT)
        require(draft['payloadSHA256'] == digest(canonical(payload))
            and {obj['metadata']['name']: obj for obj in objects['parent']} == payload['phaseApplications'],
            'Downstream native six-Application closure changed')
        write_once(phase_file(directory, phase, 'resources'), {'custody': custody, 'objects': objects})
        return {'stage': 'phase-resources-collected', 'phase': phase, 'ready': False}
    if phase == 'baseline':
        require(isinstance(objects, dict) and set(objects) == {'parent', 'baseline'}
            and isinstance(objects['baseline'], dict)
            and set(objects['baseline']) == set(inventory_apps()),
            'Qualified original baseline inventory is required before phase staging')
        applications, baseline = objects['parent'], objects['baseline']
        write_once(directory / 'transfer-baseline.json', transfer_observation(baseline))
    else:
        require(isinstance(objects, list), 'Native phase-parent collection framing differs')
        applications, baseline = objects, None
    mapping = {obj['metadata']['name']: obj for obj in applications}
    require(len(applications) == 6 and set(mapping) == set(transport.CHILDREN), 'Native phase closure differs')
    if intent.get('targetClusterUID') is not None:
        require(valid_cluster_uid(intent['targetClusterUID']) and all(
            obj['metadata'].get('annotations', {}).get('cloudlab.io/observability-handoff-target-cluster-uid') == intent['targetClusterUID']
            for obj in applications), 'Native phase target differs from the protected operation')
    payload = {'phaseApplications': mapping, 'baseline': baseline, 'applicationOrder': [obj['metadata']['name'] for obj in applications]}
    write_once(phase_file(directory, phase, 'draft-payload'), payload)
    draft = {'version': PHASE_VERSION, 'stage': 'phase-draft', 'operationId': manifest['operationId'],
        'phase': phase, 'intentSHA256': digest(canonical(intent)), 'payloadSHA256': digest(canonical(payload)), 'custody': custody}
    write_once(phase_file(directory, phase, 'draft'), draft)
    patches = {name: {'uid': observed['metadata']['uid'], 'resourceVersion': observed['metadata']['resourceVersion'],
        'fromSpecSHA256': digest(canonical(observed['spec'])), 'toApplicationSHA256': digest(canonical(mapping[name]))}
        for name, observed in intent['applicationBindings'].items()}
    write_once(phase_file(directory, phase, 'patch-intent'), {'version': PHASE_VERSION,
        'stage': 'mutation-not-authorized', 'draftSHA256': digest(canonical(draft)), 'applications': patches})
    return {'stage': 'phase-draft', 'phase': phase, 'sha256': digest(canonical(draft)), 'ready': False}


def downstream_input(directory, phase, observation):
    """Expected declarations come only from the actual protected collector draft."""
    from playbooks.observability.files import native_transport as transport
    intent = phase_json(phase_file(directory, phase, 'intent'))
    draft = strict_json(read_private(phase_file(directory, phase, 'draft')))
    payload = strict_json(read_private(phase_file(directory, phase, 'draft-payload'), PRIVATE_LIMIT), PRIVATE_LIMIT)
    require(draft.get('stage') == 'phase-draft' and draft['intentSHA256'] == digest(canonical(intent))
        and draft['payloadSHA256'] == digest(canonical(payload)), 'Native draft custody changed')
    collector = strict_json(read_private(phase_file(directory, phase, 'transport')))
    require(draft['custody'] == collection_binding(collector), 'Native draft has no matching actual collector record')
    value = phase_json(phase_file(directory, phase, 'input'))
    applications = [payload['phaseApplications'][name] for name in payload['applicationOrder']]
    original = {'parent': applications, 'baseline': payload['baseline']} if phase == 'baseline' else applications
    require(digest(canonical(original)) == draft['custody']['objectsSHA256'], 'Native draft objects changed after collection')
    require(isinstance(observation, dict) and set(observation) == {'set', 'parent', 'pods', 'applications', 'api'},
        'Fresh fixed native observations are required')
    for name in ('set', 'parent'):
        old, now = value['source'][name], observation[name]
        require(transport.identity(old) == transport.identity(now) and old['spec'] == now['spec'], 'Frozen native source identity or intent changed')
        value['source'][name] = now
    require(set(observation['pods']) == set(value['source']['pods']), 'Native forward target closure changed')
    for name, old in value['source']['pods'].items():
        now = observation['pods'][name]
        require(transport.identity(old) == transport.identity(now) and old['spec'] == now['spec'], 'Native forward source changed')
    value['source']['pods'] = observation['pods']
    require({key: item for key, item in value['api'].items() if key not in ('serviceRV', 'endpointsRV')} ==
        {key: item for key, item in observation['api'].items() if key not in ('serviceRV', 'endpointsRV')}, 'Native API boundary changed')
    value['api'] = observation['api']
    value['profile'] = 'downstream'
    value['source'].pop('originalBaselineApps', None)
    value['source']['phaseApplications'] = payload['phaseApplications']
    require(set(observation['applications']) == set(transport.CHILDREN), 'Downstream observed Application set differs')
    for name, now in observation['applications'].items():
        expected = payload['phaseApplications'][name]
        require(transport.identity(now) == transport.identity(intent['applicationBindings'][name])
            and now.get('apiVersion') == expected['apiVersion'] and now.get('kind') == expected['kind']
            and now.get('spec') == expected['spec'] and now.get('operation') is None
            and now.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'),
            'Downstream Application identity or exact drafted intent changed')
    value['source']['downstream'] = {name: {'accepted': payload['phaseApplications'][name], 'observed': observation['applications'][name]}
        for name in transport.DOWNSTREAM}
    transport.validate_input(value)
    write_once(phase_file(directory, phase, 'downstream-input'), value)
    return {'stage': 'downstream-prepared', 'sha256': digest(canonical(value)), 'ready': False}


def collection_binding(record):
    require(isinstance(record, dict) and isinstance(record.get('context'), dict)
        and isinstance(record.get('collected'), dict) and isinstance(record.get('objects'), dict)
        and isinstance(record['objects'].get('job'), dict) and isinstance(record.get('sourcePayloadSHA256'), str)
        and re.fullmatch('[a-f0-9]{64}', record['sourcePayloadSHA256']), 'Missing actual native collector binding')
    return {'context': record['context'], 'collector': record['collected'], 'job': record['objects']['job']['identity'],
        'objectsSHA256': record['sourcePayloadSHA256']}


def qualification_files(directory, intent):
    references = intent['prepared']['profiles']['acceptedArtifacts']
    require(set(references) == set(QUALIFICATIONS) and intent['qualifications']['references'] == references,
        'Reviewed qualification registry is incomplete or changed')
    if 'scope' in references['handoff']:
        manifest = verify_bundle(Path(directory) / 'runtime', Path(directory) / 'bundle.json')
        modules = references['handoff'].get('moduleDigests', {})
        require(all(manifest['runnerModuleDigests'][name] == modules.get('ansible/' + name) for name in RUNNER_FILES)
            and all(manifest['moduleDigests'][name] == modules.get('ansible/' + name) for name in HOST_FILES),
            'Handoff runtime or runner provenance differs from trusted qualification')
    result, total = {}, 0
    for profile, reference in references.items():
        require(isinstance(reference.get('artifactDigests'), dict) and reference['artifactDigests'], 'Empty qualification artifacts')
        result[profile] = {}
        for key, expected in reference['artifactDigests'].items():
            raw = read_private(Path(directory) / 'qualifications' / profile / artifact_key(key))
            total += len(raw)
            require(raw and total <= 8 * LIMIT and digest(raw) == expected, 'Protected qualification artifact changed')
            result[profile][key] = base64.b64encode(raw).decode()
    return result


def valid_cluster_uid(value):
    return isinstance(value, str) and CLUSTER_UID.fullmatch(value) is not None and value != '00000000-0000-0000-0000-000000000000'


def handoff_scope(intent, evidence):
    """The reviewed registry and artifact define scope; private intent names the target."""
    references = intent['prepared']['profiles']['acceptedArtifacts']
    require(set(references) == set(QUALIFICATIONS) and intent['qualifications']['references'] == references,
        'Handoff qualification references changed')
    scope = references['handoff'].get('scope')
    require(isinstance(scope, dict) and scope.get('kind') in ('mechanism-rehearsal', 'full-entrypoint-integration'),
        'Unknown handoff qualification scope')
    if scope['kind'] == 'mechanism-rehearsal':
        require(set(scope) == {'kind', 'targetClusterUIDSHA256'}
            and isinstance(scope['targetClusterUIDSHA256'], str)
            and re.fullmatch('[a-f0-9]{64}', scope['targetClusterUIDSHA256']), 'Invalid mechanism cluster commitment')
    else:
        require(set(scope) == {'kind'}, 'Invalid full handoff qualification scope')
    require(isinstance(evidence, dict) and set(evidence) == {'version', 'scope', 'observedClusterUID',
        'componentReferencesSHA256', 'coverage'}
        and evidence['version'] == 'cloudlab-observability-handoff-evidence/v1' and evidence['scope'] == scope
        and valid_cluster_uid(evidence['observedClusterUID']), 'Handoff evidence scope or cluster identity differs')
    require(evidence['componentReferencesSHA256'] == {name: digest(canonical(references[name]))
        for name in QUALIFICATIONS if name != 'handoff'}
        and isinstance(evidence['coverage'], dict)
        and evidence['coverage'].get('codeRevision') == references['handoff'].get('codeRevision')
        and isinstance(references['handoff'].get('codeRevision'), str)
        and re.fullmatch('[a-f0-9]{40}', references['handoff']['codeRevision']),
        'Handoff evidence component or code provenance changed')
    if scope['kind'] == 'mechanism-rehearsal':
        require(digest(evidence['observedClusterUID'].encode('ascii')) == scope['targetClusterUIDSHA256'],
            'Mechanism evidence differs from its reviewed cluster commitment')
    return copy.deepcopy(scope)


def read_native(path):
    from playbooks.observability.files import native_transport as transport
    allowed = {transport.SETS + transport.PARENT, transport.APPS + transport.PARENT,
        '/api/v1/namespaces/default/services/kubernetes', '/api/v1/namespaces/default/endpoints/kubernetes'}
    allowed |= {transport.APPS + name for name in transport.CHILDREN}
    allowed |= {'/api/v1/namespaces/argocd/pods?labelSelector=app.kubernetes.io%2Fcomponent%3D' + name
        for name in ('repo-server', 'redis')}
    require(path in allowed, 'Phase observation escaped fixed native reads')
    return native_request(path)


def native_request(path):
    response = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=10s', 'get', '--raw', path],
        capture_output=True, timeout=20)
    require(response.returncode == 0, 'Phase native observation unavailable')
    return strict_json(response.stdout)


def transfer_candidates(inventory):
    require(isinstance(inventory, dict) and set(inventory) == set(inventory_apps()), 'Original transfer inventory is incomplete')
    result = {}
    for obj in inventory['cloudlab-observability']:
        kind = (obj.get('apiVersion'), obj.get('kind'))
        if kind not in TRANSFER_KINDS: continue
        metadata = obj.get('metadata', {})
        namespace, name = metadata.get('namespace', ''), metadata.get('name', '')
        require(re.fullmatch('[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?', namespace)
            and re.fullmatch('[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?', name), 'Invalid authenticated transfer identity')
        key = '|'.join((*kind, namespace, name))
        require(key not in result, 'Duplicate original transfer identity')
        result[key] = obj
    return result


def transfer_observation(inventory):
    result = {}
    for key, expected in transfer_candidates(inventory).items():
        version, kind, namespace, name = key.split('|')
        obj = native_request('/apis/' + version + '/namespaces/' + namespace + '/' + TRANSFER_KINDS[(version, kind)] + '/' + name)
        require(obj.get('apiVersion') == version and obj.get('kind') == kind
            and obj.get('metadata', {}).get('name') == name and obj['metadata'].get('namespace') == namespace
            and obj['metadata'].get('uid') and obj['metadata'].get('resourceVersion')
            and not obj['metadata'].get('deletionTimestamp'), 'Transfer resource identity is absent or deleting')
        result[key] = obj
    return result


def phase_observation(directory, phase):
    from playbooks.observability.files import native_transport as transport, writer_guard
    directory = Path(directory)
    manifest = verify_bundle(directory / 'runtime', directory / 'bundle.json')
    prepared = strict_json(read_private(directory / 'source.json'))
    from playbooks.observability.files import handoff_execute
    handoff_execute.advance_allowed(directory, phase)
    previous = phase_head(directory)
    phase_order(phase, previous, manifest['operationId'])
    observed = {name: read_native(transport.APPS + name) for name in transport.CHILDREN}
    baseline_path = directory / 'baseline.json'
    if private_path(baseline_path, missing=True) is None:
        require(phase == 'baseline', 'Protected original baseline is unavailable')
        baseline = {}
        for name, obj in observed.items():
            writer_guard.check_child(obj, name, prepared['publicSource']['repository'])
            transport.identity(obj)
            baseline[name] = {key: copy.deepcopy(obj[key]) for key in ('apiVersion', 'kind', 'spec')}
            baseline[name]['metadata'] = {key: copy.deepcopy(obj['metadata'][key]) for key in ('name', 'namespace', 'labels')}
            if 'annotations' in obj['metadata']:
                baseline[name]['metadata']['annotations'] = copy.deepcopy(obj['metadata']['annotations'])
        write_once(baseline_path, {'stage': 'baseline-witness', 'applications': baseline, 'bindings': observed})
    witness = strict_json(read_private(baseline_path))
    pods = {}
    for component, name in (('repo', 'repo-server'), ('redis', 'redis')):
        rows = read_native('/api/v1/namespaces/argocd/pods?labelSelector=app.kubernetes.io%2Fcomponent%3D' + name)
        require(isinstance(rows, dict) and not rows.get('metadata', {}).get('continue')
            and len(rows.get('items', [])) == 1, 'Native forward target discovery is incomplete or ambiguous')
        pods[component] = rows['items'][0]
    current = {'set': read_native(transport.SETS + transport.PARENT), 'parent': read_native(transport.APPS + transport.PARENT),
        'pods': pods, 'applications': observed,
        'api': transport.api_targets(read_native('/api/v1/namespaces/default/services/kubernetes'),
            read_native('/api/v1/namespaces/default/endpoints/kubernetes'))}
    artifact_intent = {'prepared': prepared, 'qualifications': {'references': prepared['profiles']['acceptedArtifacts']}}
    return {'observation': {'version': 1, 'operationId': manifest['operationId'],
        'bundleSHA256': digest(canonical(manifest)), 'identity': observe_identity()},
        'baseline': witness['applications'], 'previous': previous,
        'artifacts': qualification_files(directory, artifact_intent), 'native': current}


def phase_export(directory, phase):
    """Export only owned collector outputs, never a supplied inventory or receipt."""
    directory = Path(directory)
    intent = phase_json(phase_file(directory, phase, 'intent'))
    draft = strict_json(read_private(phase_file(directory, phase, 'draft')))
    payload = strict_json(read_private(phase_file(directory, phase, 'draft-payload'), PRIVATE_LIMIT), PRIVATE_LIMIT)
    resources = strict_json(read_private(phase_file(directory, phase, 'resources'), PRIVATE_LIMIT), PRIVATE_LIMIT)
    baseline_draft = strict_json(read_private(phase_file(directory, 'baseline', 'draft')))
    baseline_payload = strict_json(read_private(phase_file(directory, 'baseline', 'draft-payload'), PRIVATE_LIMIT), PRIVATE_LIMIT)
    require(draft['intentSHA256'] == digest(canonical(intent)) and draft['payloadSHA256'] == digest(canonical(payload))
        and baseline_draft['payloadSHA256'] == digest(canonical(baseline_payload))
        and isinstance(baseline_payload.get('baseline'), dict), 'Actual original baseline collection is unavailable or changed')
    for selected, metadata in ((phase, draft), ('baseline', baseline_draft)):
        collector = strict_json(read_private(phase_file(directory, selected, 'transport')))
        require(metadata['custody'] == collection_binding(collector), 'Phase source collector custody changed')
        selected_payload = payload if selected == phase else baseline_payload
        objects = [selected_payload['phaseApplications'][name] for name in selected_payload['applicationOrder']]
        actual = {'parent': objects, 'baseline': selected_payload['baseline']} if selected == 'baseline' else objects
        require(digest(canonical(actual)) == metadata['custody']['objectsSHA256'], 'Phase native objects changed after collection')
    downstream_record = strict_json(read_private(phase_file(directory, phase, 'downstream-transport')))
    require(resources['custody'] == collection_binding(downstream_record), 'Downstream collector custody changed')
    require(digest(canonical(resources['objects'])) == resources['custody']['objectsSHA256'],
        'Downstream native objects changed after collection')
    return {'intent': intent, 'draft': draft, 'draftPayload': payload, 'resources': resources,
        'baseline': baseline_payload['baseline'], 'baselineApplications': baseline_payload['phaseApplications'],
        'transferBindings': {'baseline': strict_json(read_private(directory / 'transfer-baseline.json')),
            'current': transfer_observation(baseline_payload['baseline'])}}


def commit_phase(directory, phase, proposal_path, expected_sha256):
    with writer_locks():
        return _commit_phase_locked(directory, phase, proposal_path, expected_sha256)


def _commit_phase_locked(directory, phase, proposal_path, expected_sha256):
    """Commit validated source metadata only; no Sync, write gate or readiness."""
    directory = Path(directory)
    proposal = strict_json(read_private(proposal_path))
    require(digest(canonical(proposal)) == expected_sha256 and proposal.get('version') == PHASE_VERSION
        and proposal.get('stage') == 'phase-recorded' and proposal.get('phase') == phase
        and proposal.get('execution') == 'not-authorized' and proposal.get('ready') is False,
        'Runner phase validation metadata changed')
    packet = phase_export(directory, phase)
    intent = packet['intent']
    require(proposal['operationId'] == intent['operationId']
        and proposal['intentSHA256'] == digest(canonical(intent))
        and proposal['draftSHA256'] == digest(canonical(packet['draft']))
        and proposal['payloadSHA256'] == digest(canonical(packet['resources']))
        and proposal['baselineSHA256'] == digest(canonical(packet['baseline']))
        and proposal['transferBindingsSHA256'] == digest(canonical(packet['transferBindings']))
        and proposal['previousPhaseSHA256'] == intent['previousPhaseSHA256'], 'Phase validation consumed different protected inputs')
    previous = phase_head(directory)
    if previous is not None and previous['record']['phase'] == phase:
        require(previous['record'] == proposal, 'Existing phase record changed')
        return {'stage': 'phase-recorded', 'phase': phase, 'changed': False, 'ready': False}
    phase_order(phase, previous, intent['operationId'])
    require(intent['previousPhaseSHA256'] == (None if previous is None else digest(canonical(previous['record']))),
        'Phase validation no longer extends the protected head')
    qualification_files(directory, intent)
    write_once(phase_file(directory, phase, 'record'), proposal)
    atomic_private(directory / 'phase-head.json', {'phase': phase, 'sha256': expected_sha256})
    return {'stage': 'phase-recorded', 'phase': phase, 'changed': True, 'ready': False}


def stage_preflight(operation):
    """Check ancestry before trusted Ansible creates only this operation's files."""
    directory = operation_directory(operation)
    targets = [directory / 'runtime' / name for name in HOST_FILES + PACKAGE_INITS]
    targets += [directory / name for name in ('bundle.json', 'source.json', 'journal.json')]
    staging_targets(targets)
    return {'stage': 'staging-checked', 'ready': False}


def staging_targets(targets):
    for target in targets:
        for current in (*reversed(target.parents), target):
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode), 'Unsafe handoff staging owner')
            if current == target:
                require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                        'Unsafe existing handoff staging file')
            else:
                require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022, 'Unsafe handoff staging ancestry')


def artifact_preflight(directory):
    prepared = strict_json(read_private(Path(directory) / 'source.json'))
    references = prepared['profiles']['acceptedArtifacts']
    require(set(references) == set(QUALIFICATIONS), 'Registered qualification artifacts are required')
    targets = []
    for profile, reference in references.items():
        require(isinstance(reference.get('artifactDigests'), dict) and 1 <= len(reference['artifactDigests']) <= 32,
            'Invalid qualification artifact set')
        targets.extend(Path(directory) / 'qualifications' / profile / artifact_key(key) for key in reference['artifactDigests'])
    targets.extend(phase_file(directory, phase, suffix) for phase in PHASES for suffix in ('proposal', 'final-proposal'))
    staging_targets(targets)
    return {'stage': 'artifact-staging-checked', 'ready': False}


def verify_bundle(root, manifest_path):
    """A manifest attests integrity after trusted staging; it grants no authority."""
    root = Path(root)
    manifest = strict_json(read_private(manifest_path))
    require(isinstance(manifest, dict) and set(manifest) == {'version', 'operationId', 'moduleDigests', 'runnerModuleDigests'}
            and manifest['version'] == BUNDLE_VERSION, 'Invalid handoff bundle manifest')
    operation_directory(manifest['operationId'])
    require(isinstance(manifest['moduleDigests'], dict)
            and set(manifest['moduleDigests']) == set(HOST_FILES + PACKAGE_INITS), 'Handoff bundle file set changed')
    require(isinstance(manifest['runnerModuleDigests'], dict) and set(manifest['runnerModuleDigests']) == set(RUNNER_FILES)
        and all(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value)
            for value in manifest['runnerModuleDigests'].values()), 'Handoff runner provenance file set changed')
    directories = {str(parent) for name in HOST_FILES + PACKAGE_INITS
        for parent in Path(name).parents if str(parent) != '.'}
    for path in root.rglob('*'):
        relative, info = path.relative_to(root).as_posix(), path.lstat()
        require(not stat.S_ISLNK(info.st_mode)
                and ((stat.S_ISREG(info.st_mode) and relative in manifest['moduleDigests'])
                    or (stat.S_ISDIR(info.st_mode) and relative in directories)),
                'Handoff bundle contains unreviewed files or directories')
    for name, expected in manifest['moduleDigests'].items():
        require(isinstance(expected, str) and re.fullmatch('[a-f0-9]{64}', expected)
                and digest(read_private(root / name)) == expected, 'Handoff bundle integrity changed')
        if name in PACKAGE_INITS:
            require(expected == digest(b''), 'Handoff package initializer is not empty')
    return manifest


def observe_identity():
    """Read only the exact native identity receipt and its three live owners."""
    receipt = strict_json(read_private(IDENTITY_RECEIPT))
    objects = {}
    for key, (kind, name) in IDENTITY_OBJECTS.items():
        response = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=10s',
            'get', kind, name, '-n', 'argocd', '-o', 'json'], capture_output=True, timeout=20)
        require(response.returncode == 0, 'Handoff identity owner observation unavailable')
        obj = strict_json(response.stdout)
        require(isinstance(obj, dict) and obj.get('metadata', {}).get('name') == name
                and obj['metadata'].get('namespace') == 'argocd', 'Handoff identity observation escaped its owner')
        objects[key] = obj
    return {'version': 1, 'receipt': receipt, 'objects': objects}


def atomic_private(path, value, limit=LIMIT):
    path = Path(path)
    private_path(path, missing=True)
    raw = canonical(value)
    require(len(raw) <= limit, 'Handoff journal exceeds bound')
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextmanager
def writer_locks():
    """Match both retained writers' lock order; never wait behind a writer."""
    from playbooks.observability.files import writer_guard
    descriptors = []
    try:
        for name in (writer_guard.MAIN_LOCK, writer_guard.HISTORY_LOCK):
            path = Path(name)
            for current in (*reversed(path.parent.parents), path.parent):
                info = current.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                        and (not info.st_mode & 0o022 or bool(info.st_mode & stat.S_ISVTX)),
                        'Unsafe handoff lock directory')
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            descriptors.append(descriptor)
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o022, 'Unsafe handoff lock file')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def observe_bundle(package_root, manifest_path, expected_bundle):
    manifest = verify_bundle(package_root, manifest_path)
    require(digest(canonical(manifest)) == expected_bundle, 'Runner and host handoff bundles differ')
    return {'version': 1, 'operationId': manifest['operationId'], 'bundleSHA256': expected_bundle,
        'identity': observe_identity()}


def inspect_prepared(package_root, manifest_path, source_path, journal, expected_bundle, expected_source):
    """Initial source custody belongs to Ansible, not a caller-supplied boolean."""
    manifest = verify_bundle(package_root, manifest_path)
    require(digest(canonical(manifest)) == expected_bundle, 'Runner and host handoff bundles differ')
    source = strict_json(read_private(source_path))
    require(isinstance(source, dict) and source.get('version') == SOURCE_VERSION
            and source.get('operationId') == manifest['operationId'] and source.get('stage') == 'source-inspected'
            and source.get('bundleSHA256') == expected_bundle and digest(canonical(source)) == expected_source,
            'Runner and host prepared sources differ')
    from playbooks.observability.files import writer_guard
    with writer_locks():
        writer_guard.check_fence()
        require(digest(canonical(observe_identity())) == source.get('identityObservationSHA256'),
                'Native identity changed since runner source authentication')
        expected = {'version': 1, 'stage': 'source-inspected', 'bundle': manifest, 'source': source}
        changed = private_path(journal, missing=True) is None
        if not changed:
            require(strict_json(read_private(journal)) == expected,
                    'Frozen handoff source changed; explicit reviewed transition is required')
        else:
            atomic_private(journal, expected)
        return {'stage': expected['stage'], 'sourceSHA256': digest(canonical(expected)), 'ready': False, 'changed': changed}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stage-preflight', 'observe', 'inspect', 'artifact-preflight',
        'phase-observe', 'stage-phase', 'phase-export', 'commit-phase', 'authorize', 'collect',
        'apply', 'collect-resources', 'execute', 'native-config-export', 'native-config-stage', 'qualification-export'))
    parser.add_argument('--operation', required=True)
    parser.add_argument('--bundle-sha256')
    parser.add_argument('--source-sha256')
    parser.add_argument('--phase', choices=PHASES)
    arguments = parser.parse_args()
    try:
        directory = operation_directory(arguments.operation)
        if arguments.action == 'stage-preflight':
            result = stage_preflight(arguments.operation)
        else:
            package_root = Path(__file__).absolute().parents[3]
            require(package_root == directory / 'runtime', 'Handoff runtime escaped its operation directory')
            sys.path.insert(0, str(package_root))
            if arguments.action not in ('observe', 'inspect'):
                manifest = verify_bundle(package_root, directory / 'bundle.json')
                require(digest(canonical(manifest)) == arguments.bundle_sha256, 'Runner and host handoff bundles differ')
            if arguments.action == 'observe':
                result = observe_bundle(package_root, directory / 'bundle.json', arguments.bundle_sha256)
            elif arguments.action == 'inspect':
                result = inspect_prepared(package_root, directory / 'bundle.json', directory / 'source.json',
                    directory / 'journal.json', arguments.bundle_sha256, arguments.source_sha256)
            elif arguments.action == 'artifact-preflight':
                result = artifact_preflight(directory)
            else:
                require(arguments.phase is not None, 'An exact C2 source phase is required')
                if arguments.action == 'phase-observe':
                    with writer_locks(): result = phase_observation(directory, arguments.phase)
                elif arguments.action == 'stage-phase':
                    result = stage_phase(directory, phase_file(directory, arguments.phase, 'proposal'), arguments.source_sha256)
                elif arguments.action == 'phase-export':
                    with writer_locks(): result = phase_export(directory, arguments.phase)
                elif arguments.action == 'commit-phase':
                    result = commit_phase(directory, arguments.phase,
                        phase_file(directory, arguments.phase, 'final-proposal'), arguments.source_sha256)
                else:
                    from playbooks.observability.files import handoff_execute
                    if arguments.action == 'authorize':
                        require(arguments.phase == 'baseline', 'Execution authorization requires the original baseline')
                        result = handoff_execute.authorize(directory)
                    elif arguments.action in ('collect', 'collect-resources'):
                        result = handoff_execute.collect_phase(directory, arguments.phase,
                            downstream=arguments.action == 'collect-resources')
                    elif arguments.action == 'apply':
                        result = handoff_execute.apply_applications(directory, arguments.phase)
                    elif arguments.action in ('native-config-export', 'native-config-stage'):
                        if arguments.action == 'native-config-stage':
                            require(arguments.source_sha256 is not None, 'Native classification hash is required')
                        result = handoff_execute.native_classification(directory, arguments.phase,
                            expected_sha256=arguments.source_sha256 if arguments.action == 'native-config-stage' else None)
                    elif arguments.action == 'qualification-export':
                        require(arguments.phase == 'native-paused', 'Full entrypoint evidence requires native-paused')
                        result = handoff_execute.execution_evidence(directory)
                    else:
                        result = handoff_execute.execute_phase(directory, arguments.phase)
    except Exception:
        raise SystemExit('Handoff source inspection failed; protected source or runtime authority is unavailable') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
