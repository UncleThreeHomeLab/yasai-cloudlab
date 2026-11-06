"""Runner-only source authentication and finite host bundle preparation.

Host observations must arrive through the existing trusted Ansible channel.
Neither observations nor checksums independently establish that custody.
"""
import argparse
import base64
import copy
import json
import hashlib
import math
from pathlib import Path
import re
import stat
import sys
import time

import yaml

from playbooks.observability.files import handoff

ROOT = Path(__file__).resolve().parents[4]
PROFILES = ('checkpoint', 'lifecycle', 'storage', 'source', 'transport', 'handoff')
RUNNER_FILES = ('playbooks/observability/files/handoff_source.py', 'playbooks/observability/handoff.yml')
CLASSIFICATION_LIMIT = 4 * handoff.PRIVATE_LIMIT
NATIVE_CONFIG_PROFILE = {
    'image': 'quay.io/prometheus/alertmanager:v0.34.1@sha256:e9733bafb1bdef9b00e25a21f8f99dc26a22224bf16641ad754d1649f4c3357a',
    'inputSHA256': '53441667fd2dd1cff1239f34892a94efe99146cbe8bad093df1edaf9e6c7edf6',
    'nativeSHA256': '2781a6755a59dbe238c53258ca18aab542ce1ea383dbea7ebf94363d325d9eef'}


def repository_bytes(root, name):
    path = Path(root) / name
    for current in (path, *path.parents):
        if current == Path(root):
            break
        handoff.require(not stat.S_ISLNK(current.lstat().st_mode), 'Handoff package contains a symbolic link')
    handoff.require(stat.S_ISREG(path.stat().st_mode), 'Handoff package source is not a file')
    raw = path.read_bytes()
    handoff.require(len(raw) <= handoff.LIMIT, 'Handoff package source exceeds bound')
    return raw


def bundle(operation, *, root=ROOT / 'ansible'):
    handoff.operation_directory(operation)
    contents = {name: repository_bytes(root, name) for name in handoff.HOST_FILES}
    contents.update({name: b'' for name in handoff.PACKAGE_INITS})
    manifest = {'version': handoff.BUNDLE_VERSION, 'operationId': operation,
        'moduleDigests': {name: handoff.digest(raw) for name, raw in sorted(contents.items())},
        'runnerModuleDigests': {name: handoff.digest(repository_bytes(root, name)) for name in RUNNER_FILES}}
    directories = sorted({str(parent) for name in contents for parent in Path(name).parents if str(parent) != '.'})
    return {'manifest': manifest, 'bundleSHA256': handoff.digest(handoff.canonical(manifest)),
        'directories': directories,
        'files': {name: base64.b64encode(raw).decode() for name, raw in sorted(contents.items())}}


def accepted_binding(observation, expected, coordinates, revision):
    """Use the identity owner's read-only API, never redirect its globals."""
    from playbooks.argocd.files.source_transition import accepted_identity_binding
    handoff.require(isinstance(observation, dict) and set(observation) == {'version', 'receipt', 'objects'}
        and type(observation['version']) is int and observation['version'] == 1 and isinstance(observation['objects'], dict)
        and set(observation['objects']) == set(handoff.IDENTITY_OBJECTS), 'Incomplete native identity observations')
    def read(kind, name):
        keys = [key for key, target in handoff.IDENTITY_OBJECTS.items() if target == (kind, name)]
        handoff.require(len(keys) == 1, 'Identity owner requested an unsupported observation')
        return observation['objects'][keys[0]]
    try:
        binding = accepted_identity_binding(repository=coordinates['repository'], branch='main', revision=revision,
            private_repository=expected['valuesRepository'], read_receipt=lambda: observation['receipt'], read=read)
    except TypeError:
        raise RuntimeError('Identity owner remote observation API is unavailable') from None
    handoff.require(binding == expected, 'Accepted private source binding differs from protected intent')
    return binding


def prepare(operation, source_binding, observation, *, root=ROOT, deadline=None):
    from playbooks.argocd.files import source_snapshot
    from playbooks.argocd.files.private_sources import consumer_contract, acceptance_spec
    from playbooks.data.files.native import published_source, PrivateLoader, render_objects

    deadline = time.monotonic() + 120 if deadline is None else deadline
    packaged = repository_bytes(root, 'gitops/roots/public/values.yaml')
    coordinates_input = yaml.load(packaged, Loader=PrivateLoader)
    handoff.require(isinstance(coordinates_input, dict) and coordinates_input.get('revision') == 'main',
        'Packaged public coordinates are unavailable')
    coordinates = {'repository': coordinates_input.get('repository'), 'branch': 'main'}
    binding_raw = handoff.read_private(source_binding)
    expected = yaml.load(binding_raw, Loader=PrivateLoader)
    handoff.require(isinstance(expected, dict) and set(expected) == {'valuesRepository', 'valuesRevision'},
        'Protected private source binding is unavailable')
    native_bundle = bundle(operation, root=Path(root) / 'ansible')
    handoff.require(isinstance(observation, dict) and set(observation) == {'version', 'operationId', 'bundleSHA256', 'identity'}
        and type(observation['version']) is int and observation['version'] == 1 and observation['operationId'] == operation
        and observation['bundleSHA256'] == native_bundle['bundleSHA256'], 'Host observation belongs to another bundle')
    public, revision = published_source({'publicSource': coordinates}, deadline=deadline)
    files = source_snapshot.chart_files({'repository': coordinates['repository'], 'revision': revision,
        'path': 'gitops/roots/public'}, deadline=deadline)
    handoff.require(yaml.load(files['values.yaml'], Loader=PrivateLoader) == public,
        'Authenticated Root chart and public source differ')
    contract = consumer_contract(public, 'observability')
    handoff.require(contract['enabled'] and public['observability']['configuration'].get('paused') is True,
        'Handoff source preparation requires approved paused observability intent')
    binding = accepted_binding(observation['identity'], expected, coordinates, revision)
    spec = acceptance_spec(public, binding['valuesRepository'], binding['valuesRevision'], files=files, consumer='observability')
    values = copy.deepcopy(public)
    values.setdefault('identity', {}).update(enabled=True, argo=binding)
    objects = [obj for obj in render_objects(files, [values]) if obj.get('kind') == 'ApplicationSet'
        and obj.get('metadata', {}).get('name') == 'cloudlab-observability-gitops']
    handoff.require(len(objects) == 1 and objects[0]['spec'] == spec, 'Authenticated consumer Set declaration differs')
    native_files = source_snapshot.chart_files({'repository': coordinates['repository'],
        'revision': public['observability']['configuration']['revision'], 'path': 'platform/observability/gitops'}, deadline=deadline)
    handoff.require('handoff-profiles.json' in native_files, 'Authenticated handoff profile registry is unavailable')
    registry_raw = native_files['handoff-profiles.json']
    registry = handoff.strict_json(registry_raw)
    handoff.require(isinstance(registry, dict) and registry.get('version') == 'cloudlab-observability-handoff-profiles/v1'
        and registry.get('requiredProfiles') == {name: 'cloudlab-observability-qualification/v1' for name in PROFILES}
        and isinstance(registry.get('acceptedArtifacts'), dict)
        and set(registry['acceptedArtifacts']) <= set(PROFILES), 'Unsupported handoff profile registry')
    handoff.require(time.monotonic() < deadline, 'Handoff runner preparation deadline expired')
    frozen = copy.deepcopy(public)
    frozen['observability']['configuration'].pop('acceptanceCommitment', None)
    return {'version': handoff.SOURCE_VERSION, 'operationId': operation, 'stage': 'source-inspected',
        'bundleSHA256': native_bundle['bundleSHA256'], 'publicSource': coordinates, 'publicRevision': revision,
        'packageSHA256': handoff.digest(packaged), 'sourceBindingSHA256': handoff.digest(binding_raw),
        'privateBinding': binding, 'contract': contract, 'expectedSet': objects[0],
        'rootFilesSHA256': {name: handoff.digest(raw) for name, raw in sorted(files.items())},
        'nativeFilesSHA256': {name: handoff.digest(raw) for name, raw in sorted(native_files.items())},
        'profilesSHA256': handoff.digest(registry_raw), 'profiles': registry,
        'publicIntentSHA256': handoff.digest(handoff.canonical(frozen)),
        'rootCodeSHA256': {name: handoff.digest(raw) for name, raw in sorted(files.items()) if name != 'values.yaml'},
        'identityUIDs': {key: obj['metadata']['uid'] for key, obj in observation['identity']['objects'].items()},
        'identityObservationSHA256': handoff.digest(handoff.canonical(observation['identity']))}


def public_file(repository, revision, name, deadline):
    """Authenticate one fixed public contract/lock against its immutable Git blob."""
    from playbooks.argocd.files import source_snapshot
    from playbooks.argocd.files.github_setup import repository as repository_name
    handoff.require(name in ('platform/observability/contract.json', 'platform/observability/images.lock.json'),
        'Unsupported phase public document')
    obj = source_snapshot.request('repos/' + repository_name(repository) + '/contents/' + name + '?ref=' + revision, deadline)
    handoff.require(isinstance(obj, dict) and obj.get('type') == 'file' and obj.get('path') == name
        and obj.get('encoding') == 'base64' and type(obj.get('size')) is int and 0 < obj['size'] <= handoff.LIMIT,
        'Phase public document framing differs')
    raw = base64.b64decode(obj['content'].replace('\n', '').replace('\r', ''), validate=True)
    handoff.require(len(raw) == obj['size']
        and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == obj.get('sha'),
        'Phase public document Git blob differs')
    return raw


def validate_fragment(files, value, pointer):
    import jsonschema
    schema = handoff.strict_json(files['values.schema.json'])
    def local_refs(node):
        if isinstance(node, dict):
            handoff.require('$ref' not in node or node['$ref'].startswith('#/'), 'External phase schema references are unsupported')
            for child in node.values(): local_refs(child)
        elif isinstance(node, list):
            for child in node: local_refs(child)
    local_refs(schema)
    jsonschema.Draft7Validator({'$ref': pointer, '$defs': schema['$defs'], 'properties': schema['properties']}).validate(value)


def baseline_digest(files, baseline):
    """Use the authenticated owner helper; Python JSON is not Go's hash preimage."""
    from playbooks.data.files.native import render_objects
    validate_fragment(files, baseline, '#/properties/ownershipHandoff/properties/baselineApplications')
    helper = files.get('templates/_handoff.tpl')
    handoff.require(isinstance(helper, bytes) and b'observability.handoffBaselineDigest' in helper,
        'Authenticated native baseline hash helper is unavailable')
    chart = {'Chart.yaml': b'apiVersion: v2\nname: cloudlab-baseline-digest\nversion: 1.0.0\n',
        'templates/_handoff.tpl': helper,
        'templates/digest.yaml': b'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: baseline-digest}\ndata:\n  digest: {{ include "observability.handoffBaselineDigest" .Values.baseline | quote }}\n'}
    objects = render_objects(chart, [{'baseline': baseline}])
    handoff.require(len(objects) == 1 and objects[0].get('kind') == 'ConfigMap'
        and re.fullmatch('[a-f0-9]{64}', objects[0].get('data', {}).get('digest', '')),
        'Native baseline digest rendering differs')
    return objects[0]['data']['digest']


def qualification_scope(reference):
    scope = reference.get('scope')
    handoff.require(isinstance(scope, dict) and scope.get('kind') in (
        'mechanism-rehearsal', 'full-entrypoint-integration'), 'Handoff qualification scope is unavailable')
    if scope['kind'] == 'mechanism-rehearsal':
        handoff.require(set(scope) == {'kind', 'targetClusterUIDSHA256'}
            and isinstance(scope['targetClusterUIDSHA256'], str)
            and re.fullmatch('[a-f0-9]{64}', scope['targetClusterUIDSHA256'])
            and scope['targetClusterUIDSHA256'] != '0' * 64, 'Invalid mechanism target commitment')
    else:
        handoff.require(set(scope) == {'kind'}, 'Invalid full entrypoint scope')
    return scope


def cluster_uid(value):
    handoff.require(isinstance(value, str) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value)
        and value.replace('-', '') != '0' * 32, 'Invalid private qualification cluster UID')
    return value


def phase_target(applications):
    from playbooks.observability.files import native_transport
    handoff.require(isinstance(applications, dict) and set(applications) == set(native_transport.CHILDREN),
        'Private target binding requires exactly six native Applications')
    targets = {cluster_uid(obj.get('metadata', {}).get('annotations', {}).get(
        'cloudlab.io/observability-handoff-target-cluster-uid')) for obj in applications.values()}
    handoff.require(len(targets) == 1, 'Native Applications disagree on the private target cluster')
    return targets.pop()


def mechanism_reports(coverage, raw, references):
    expected = {
        'runtimeHandoff': ('lifecycle', {'runtimeHandoff': 'passed', 'parentUIDPreserved': True,
            'sixChildUIDsPreserved': True, 'pausedNativeManifests': True, 'explicitGitRelease': True,
            'driftRepair': True, 'cleanup': 'complete',
            'scope': 'disposable controller ownership only; production transport unsupported'}),
        'transport': ('transport', {'transport': 'passed', 'declaredSources': 'two distinct HTTPS URLs, full SHAs',
            'rewrite': 'read-only repo-server-only GIT_CONFIG_GLOBAL', 'externalGitHub': 'denied',
            'rootSourceApproval': 'not qualified; pinned-private fixture adaptation only'}),
        'checkpoint': ('checkpoint', {'qualified': True, 'checkpointQualified': True, 'nativeRetentionVerified': True,
            'sourceAliveUntilValidation': True, 'sameCSIIdentity': True, 'backingFilesVerified': True, 'coverage': 'complete'})}
    handoff.require(isinstance(coverage, dict) and set(coverage) == {'kind', 'codeRevision', 'reports'}
        and coverage['kind'] == 'native-component-mechanisms' and isinstance(coverage['reports'], dict)
        and set(coverage['reports']) == set(expected), 'Unsupported native mechanism report coverage')
    for name, (profile, report) in expected.items():
        key = handoff.artifact_key(coverage['reports'][name])
        handoff.require(key in raw and handoff.digest(raw[key]) in references[profile]['artifactDigests'].values()
            and not changed_fields(report, handoff.strict_json(raw[key])), 'Native mechanism owner report is absent or differs')


def full_backend_evidence(backend, operation, bundle_sha256, baseline_sha256):
    from playbooks.observability.files import checkpoint
    handoff.require(isinstance(backend, dict) and all(backend.get(key) is True for key in (
        'denied', 'checkpointWritten', 'nativeDiskValidated', 'checkpointValidated', 'storageSyncComplete', 'restored'))
        and 'pendingClassification' not in backend, 'Full entrypoint backend proof is incomplete')
    handoff.require(backend.get('operationId') == operation and backend.get('bundleSHA256') == bundle_sha256
        and backend.get('baselineSHA256') == baseline_sha256, 'Full entrypoint backend authority differs')
    hashes = backend.get('checkpoint')
    handoff.require(isinstance(hashes, dict) and set(hashes) == {'nflog', 'silences'}
        and all(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) for value in hashes.values()),
        'Full entrypoint checkpoint hashes are incomplete')
    original, replacement = backend['source'], backend['replacementSource']
    handoff.require(cluster_uid(original['uid']) != cluster_uid(replacement['uid'])
        and original['namespace'] == replacement['namespace'] == 'cloudlab-observability'
        and original['name'] == replacement['name'] == 'alertmanager-cloudlab-0', 'Native replacement process proof differs')
    classes = backend.get('classifications')
    handoff.require(isinstance(classes, dict) and set(classes) == {'original', 'muted', 'restored'},
        'Full entrypoint native configuration classifications are incomplete')
    for name, value in classes.items():
        handoff.require(value['source'] == (original if name == 'original' else replacement)
            and isinstance(value['configSHA256'], str) and re.fullmatch('[a-f0-9]{64}', value['configSHA256'])
            and isinstance(value['challengeSHA256'], str) and re.fullmatch('[a-f0-9]{64}', value['challengeSHA256'])
            and isinstance(value['nonce'], str) and re.fullmatch('[a-f0-9]{32}', value['nonce'])
            and type(value['reloadTimestamp']) in (int, float) and math.isfinite(value['reloadTimestamp'])
            and value['reloadTimestamp'] > 0, 'Full entrypoint native classification binding differs')
    handoff.require(classes['original']['reloadTimestamp'] < classes['muted']['reloadTimestamp'] < classes['restored']['reloadTimestamp']
        and classes['restored']['configSHA256'] == classes['original']['configSHA256'], 'Native restoration or reload proof differs')
    mutations = backend.get('mutations', {})
    handoff.require(all(mutations.get(key, {}).get('deleted') is True for key in (
        'writer', 'validator', 'validation-config', 'probe'))
        and mutations.get('claim', {}).get('deleted') is False
        and mutations.get('claim', {}).get('uid') == backend['storage']['claim']['uid']
        and backend['claimDocument']['spec'] == checkpoint.CLAIM_SPEC
        and backend['claimDocument']['metadata']['annotations'] == checkpoint.CLAIM_ANNOTATIONS,
        'Full entrypoint temporary cleanup or retained claim proof differs')


def full_mutation_evidence(row):
    handoff.require(isinstance(row, dict) and set(row) == {
        'intent', 'acknowledged', 'patchRequested', 'outcome', 'resultSHA256'}
        and row['acknowledged'] is True and type(row['patchRequested']) is bool
        and row['outcome'] in ('no-op', 'observed-after', 'patch-acknowledged')
        and isinstance(row['resultSHA256'], str) and re.fullmatch('[a-f0-9]{64}', row['resultSHA256']),
        'Full entrypoint mutation outcome is incomplete')
    intent = row['intent']
    handoff.require(isinstance(intent, dict) and set(intent) == {'path', 'uid', 'beforeSpecSHA256', 'afterSpecSHA256',
        'beforeMetadata', 'afterMetadata', 'annotations', 'beforeResourceVersion'}
        and isinstance(intent['beforeResourceVersion'], str) and intent['beforeResourceVersion']
        and all(isinstance(intent[key], str) and re.fullmatch('[a-f0-9]{64}', intent[key])
            for key in ('beforeSpecSHA256', 'afterSpecSHA256')), 'Full entrypoint mutation intent is incomplete')
    for name in ('beforeMetadata', 'afterMetadata'):
        metadata = intent[name]
        handoff.require(isinstance(metadata, dict) and set(metadata) == {
            'annotations', 'labels', 'ownerReferences', 'finalizers', 'deletionTimestamp'}
            and all(isinstance(metadata[key], dict) and all(isinstance(k, str) and isinstance(v, str)
                for k, v in metadata[key].items()) for key in ('annotations', 'labels'))
            and all(key.startswith(('cloudlab.io/', 'argocd.argoproj.io/')) or key == 'app.kubernetes.io/instance'
                for key in metadata['labels'])
            and isinstance(metadata['ownerReferences'], list) and isinstance(metadata['finalizers'], list)
            and all(isinstance(value, str) for value in metadata['finalizers'])
            and metadata['deletionTimestamp'] is None, 'Full entrypoint owned metadata projection differs')
    handoff.require(intent['annotations'] == intent['afterMetadata']['annotations'],
        'Full entrypoint mutation annotations differ from its after-state')
    unchanged = intent['beforeSpecSHA256'] == intent['afterSpecSHA256'] and not changed_fields(
        intent['beforeMetadata'], intent['afterMetadata'])
    handoff.require((row['outcome'] == 'no-op' and row['patchRequested'] is False and unchanged)
        or (row['outcome'] != 'no-op' and row['patchRequested'] is True and not unchanged),
        'Full entrypoint mutation outcome contradicts its durable request or state')


def full_entrypoint_evidence(coverage, raw, references, modules, observed_uid, prepared):
    from playbooks.observability.files import native_transport
    from playbooks.observability.files.handoff_execute import HOLD, VERSION
    handoff.require(set(coverage) == {'kind', 'codeRevision', 'entrypoint', 'execution', 'phases'}
        and coverage['kind'] == 'full-c2-entrypoint' and coverage['entrypoint'] == 'ansible/playbooks/observability/handoff.yml'
        and isinstance(coverage['phases'], dict) and set(coverage['phases']) == set(handoff.PHASES),
        'Full entrypoint evidence requires exactly five source phases')
    execution_key = handoff.artifact_key(coverage['execution'])
    handoff.require(execution_key in raw, 'Full entrypoint execution artifact is absent')
    entry = handoff.strict_json(raw[execution_key])
    handoff.require(isinstance(entry, dict) and set(entry) == {'version', 'codeRevision', 'operationId',
        'observedClusterUID', 'bundle', 'moduleDigests', 'imagePins', 'source', 'baseline', 'execution', 'backend', 'phaseHead'}
        and entry['version'] == 'cloudlab-observability-entrypoint-evidence/v1'
        and entry['codeRevision'] == coverage['codeRevision'] and entry['observedClusterUID'] == observed_uid,
        'Full entrypoint artifact identity differs')
    operation, bundle = entry['operationId'], entry['bundle']
    handoff.operation_directory(operation)
    required = {'ansible/' + name for name in (*handoff.HOST_FILES, *RUNNER_FILES)}
    expected_modules = {name: handoff.digest(modules[name]) for name in required if name in modules}
    handoff.require(set(expected_modules) == required and entry['moduleDigests'] == expected_modules
        and all(references['handoff']['moduleDigests'].get(name) == value for name, value in expected_modules.items()),
        'Full entrypoint current module coverage differs')
    expected_host = {name: expected_modules['ansible/' + name] for name in handoff.HOST_FILES}
    expected_host.update({name: handoff.digest(b'') for name in handoff.PACKAGE_INITS})
    handoff.require(isinstance(bundle, dict) and set(bundle) == {'version', 'operationId', 'moduleDigests', 'runnerModuleDigests'}
        and bundle['version'] == handoff.BUNDLE_VERSION and bundle['operationId'] == operation
        and bundle['moduleDigests'] == expected_host
        and bundle['runnerModuleDigests'] == {name: expected_modules['ansible/' + name] for name in RUNNER_FILES},
        'Full entrypoint protected bundle differs')
    components = {name: reference for name, reference in references.items() if name != 'handoff'}
    handoff.require(entry['imagePins'] == {name: reference['imagePins'] for name, reference in components.items()}
        and {pin for reference in components.values() for pin in reference['imagePins'].values()}
            <= set(references['handoff']['imagePins'].values()), 'Full entrypoint current image coverage differs')
    journal = entry['execution']
    handoff.require(isinstance(journal, dict) and set(journal) == {'authorization', 'steps', 'phases'}
        and set(journal['phases']) == set(handoff.PHASES), 'Full entrypoint execution journal is incomplete')
    witnesses = {}
    for name in ('source', 'baseline'):
        handoff.require(isinstance(entry[name], str) and len(entry[name]) <= 2 * handoff.LIMIT,
            'Full entrypoint authority witness exceeds bound')
        witness = base64.b64decode(entry[name], validate=True)
        witnesses[name] = (witness, handoff.strict_json(witness))
    handoff.require(witnesses['source'][1]['version'] == handoff.SOURCE_VERSION
        and witnesses['source'][1]['operationId'] == operation
        and witnesses['baseline'][1]['stage'] == 'baseline-witness', 'Full entrypoint authority witness differs')
    native_files = {name.removeprefix('platform/observability/gitops/'): handoff.digest(value)
        for name, value in modules.items() if name.startswith('platform/observability/gitops/')
            and name != 'platform/observability/gitops/handoff-profiles.json'}
    bundle_sha256, previous = handoff.digest(handoff.canonical(bundle)), None
    for phase in handoff.PHASES:
        key = handoff.artifact_key(coverage['phases'][phase])
        handoff.require(key in raw, 'Full entrypoint source phase artifact is absent')
        packet = handoff.strict_json(raw[key])
        handoff.require(isinstance(packet, dict) and set(packet) == {'intent', 'record', 'draft', 'parentCollector', 'downstreamCollector'},
            'Full entrypoint source phase framing differs')
        intent, record, draft = (packet[name] for name in ('intent', 'record', 'draft'))
        handoff.phase_order(phase, previous, operation)
        handoff.require(intent['version'] == record['version'] == draft['version'] == handoff.PHASE_VERSION
            and intent['phase'] == record['phase'] == draft['phase'] == phase
            and intent['operationId'] == record['operationId'] == draft['operationId'] == operation
            and record['targetClusterUID'] == observed_uid and intent.get('targetClusterUID', observed_uid) == observed_uid
            and record['stage'] == 'phase-recorded' and record['execution'] == 'not-authorized' and record['ready'] is False
            and draft['stage'] == 'phase-draft' and intent['prepared']['bundleSHA256'] == bundle_sha256
            and record['intentSHA256'] == draft['intentSHA256'] == handoff.digest(handoff.canonical(intent))
            and record['draftSHA256'] == handoff.digest(handoff.canonical(draft))
            and record['previousPhaseSHA256'] == intent['previousPhaseSHA256'] ==
                (None if previous is None else handoff.digest(handoff.canonical(previous['record'])))
            and journal['phases'][phase] == {'stage': 'backend-complete', 'recordSHA256': handoff.digest(handoff.canonical(record))},
            'Full entrypoint source chain or backend completion differs')
        handoff.require(intent['baseline'] == witnesses['baseline'][1]['applications']
            and intent['resourcePolicySHA256'] == handoff.digest(modules['platform/observability/contract.json'])
            and intent['prepared']['rootCodeSHA256'] == prepared['rootCodeSHA256']
            and {name: value for name, value in intent['prepared']['nativeFilesSHA256'].items()
                if name != 'handoff-profiles.json'} == native_files, 'Full entrypoint qualified Root, native chart or policy code changed')
        for field in ('bundleSHA256', 'publicSource', 'privateBinding', 'sourceBindingSHA256', 'publicIntentSHA256',
                      'rootCodeSHA256', 'identityUIDs', 'nativeFilesSHA256', 'profilesSHA256', 'profiles'):
            handoff.require(intent['prepared'][field] == witnesses['source'][1][field], 'Full entrypoint original source binding changed')
        handoff.require(intent['qualifications']['references'] == intent['prepared']['profiles']['acceptedArtifacts']
            and all(intent['qualifications']['references'][name] == reference for name, reference in components.items())
            and intent['qualifications']['references']['handoff']['codeRevision'] == coverage['codeRevision']
            and all(intent['qualifications']['references']['handoff']['moduleDigests'].get(name) == value
                for name, value in expected_modules.items()),
            'Full entrypoint component references differ')
        if previous is not None: handoff.frozen_phase(intent, previous['intent'])
        for name in ('parentCollector', 'downstreamCollector'):
            collector = packet[name]
            handoff.require(collector.get('namespaceAbsent') is True and collector.get('cleanupStarted') is True
                and collector['context']['operation'] == operation
                and collector['context']['codeSHA256'] == bundle['moduleDigests']['playbooks/observability/files/native_transport.py']
                and isinstance(collector['context']['inputSHA256'], str)
                and re.fullmatch('[a-f0-9]{64}', collector['context']['inputSHA256'])
                and handoff.collection_binding(collector), 'Full entrypoint native collector custody differs')
        handoff.require(draft['custody'] == handoff.collection_binding(packet['parentCollector']), 'Full entrypoint draft collector differs')
        handoff.require(set(intent['applicationBindings']) == set(native_transport.CHILDREN), 'Full entrypoint Application closure differs')
        for name, app in intent['applicationBindings'].items():
            held = copy.deepcopy(app['spec'])
            held['syncPolicy']['automated'] = HOLD
            for action in ('hold', 'app'):
                row = journal['steps'].get(phase + ':' + action + ':' + name, {})
                full_mutation_evidence(row)
                handoff.require(row.get('acknowledged') is True and row['intent']['uid'] == app['metadata']['uid']
                    and row['intent']['path'] == '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/' + name
                    and (action != 'app' or row['intent']['annotations'].get(
                        'cloudlab.io/observability-handoff-target-cluster-uid') == observed_uid)
                    and (action != 'hold' or row['intent']['afterSpecSHA256'] == handoff.digest(handoff.canonical(held))),
                    'Full entrypoint Application hold or source acknowledgement is absent')
        previous = {'record': record, 'intent': intent}
    authorization = journal['authorization']
    run_scope = qualification_scope(previous['intent']['qualifications']['references']['handoff'])
    if run_scope['kind'] == 'mechanism-rehearsal':
        handoff.require(run_scope['targetClusterUIDSHA256'] == handoff.digest(observed_uid.encode('ascii')),
            'Full entrypoint ran outside its authorized rehearsal cluster')
    handoff.require(authorization['version'] == VERSION and authorization['operationId'] == operation
        and authorization['bundleSHA256'] == bundle_sha256 and authorization['targetClusterUID'] == observed_uid
        and authorization['qualificationScope'] == run_scope
        and authorization['qualificationsSHA256'] == handoff.digest(handoff.canonical(previous['intent']['qualifications']))
        and authorization['sourceSHA256'] == handoff.digest(witnesses['source'][0])
        and authorization['baselineSHA256'] == handoff.digest(witnesses['baseline'][0])
        and entry['phaseHead'] == {'phase': 'native-paused', 'sha256': handoff.digest(handoff.canonical(previous['record']))},
        'Full entrypoint final authority or phase head differs')
    handoff.require({key.removeprefix('tracking:') for key in journal['steps'] if key.startswith('tracking:')}
        == set(previous['record']['transferIntents']), 'Full entrypoint tracking acknowledgement closure differs')
    for encoded, transfer in previous['record']['transferIntents'].items():
        row = journal['steps'].get('tracking:' + encoded, {})
        handoff.require(row.get('acknowledged') is True and row['intent']['uid'] == transfer['uid']
            and row['intent']['to'] == transfer['toTracking'], 'Full entrypoint tracking transfer is incomplete')
    full_backend_evidence(entry['backend'], operation, bundle_sha256, handoff.digest(handoff.canonical(previous['intent']['baseline'])))


def handoff_evidence(references, raw, modules, prepared):
    reference = references['handoff']
    scope = qualification_scope(reference)
    handoff.require('handoff-evidence.json' in raw, 'Reserved handoff evidence artifact is absent')
    evidence = handoff.strict_json(raw['handoff-evidence.json'])
    components = {name: handoff.digest(handoff.canonical(value)) for name, value in references.items() if name != 'handoff'}
    handoff.require(isinstance(evidence, dict) and set(evidence) == {'version', 'scope', 'observedClusterUID',
        'componentReferencesSHA256', 'coverage'} and evidence['version'] == 'cloudlab-observability-handoff-evidence/v1'
        and evidence['scope'] == scope and evidence['componentReferencesSHA256'] == components
        and isinstance(evidence['coverage'], dict) and evidence['coverage'].get('codeRevision') == reference['codeRevision'],
        'Handoff evidence scope, revision or component references differ')
    observed = cluster_uid(evidence['observedClusterUID'])
    if scope['kind'] == 'mechanism-rehearsal':
        handoff.require(handoff.digest(observed.encode('ascii')) == scope['targetClusterUIDSHA256'],
            'Mechanism evidence does not match its target commitment')
        mechanism_reports(evidence['coverage'], raw, references)
    else:
        full_entrypoint_evidence(evidence['coverage'], raw, references, modules, observed, prepared)


def qualification_inputs(prepared, files, artifacts, root, image_lock, contract_raw):
    from playbooks.observability.files import native_transport
    references = prepared['profiles']['acceptedArtifacts']
    handoff.require(set(references) == set(PROFILES) and isinstance(artifacts, dict) and set(artifacts) == set(PROFILES),
        'Every reviewed qualification and exact artifact set is required')
    modules = {name: repository_bytes(Path(root) / 'ansible', name) for name in handoff.HOST_FILES}
    modules = {'ansible/' + name: raw for name, raw in modules.items()}
    modules['ansible/playbooks/observability/files/handoff_source.py'] = repository_bytes(
        Path(root) / 'ansible', 'playbooks/observability/files/handoff_source.py')
    modules.update({'platform/observability/gitops/' + name: raw for name, raw in files.items()})
    modules.update({'platform/observability/contract.json': contract_raw, 'platform/observability/images.lock.json': image_lock})
    for name in ('alertmanager_checkpoint_proof.py', 'native_proof.py', 'storage_fixture.py', 'storage_lifecycle_proof.py',
                 'lifecycle_controller_proof.py', 'lifecycle_stack_proof.py', 'lifecycle_stack_preflight.py'):
        path = 'ansible/playbooks/observability/tests/' + name
        if (Path(root) / path).is_file(): modules[path] = repository_bytes(root, path)
    for name in ('handoff_execute.py', 'handoff_backend.py'):
        path = 'ansible/playbooks/observability/files/' + name
        if (Path(root) / path).is_file(): modules[path] = repository_bytes(root, path)
    path = 'ansible/playbooks/observability/handoff.yml'
    if (Path(root) / path).is_file(): modules[path] = repository_bytes(root, path)
    lock = handoff.strict_json(image_lock)
    verified, total, handoff_raw = {}, 0, {}
    for profile in PROFILES:
        reference = references[profile]
        validate_fragment(files, reference, '#/$defs/handoffQualification')
        handoff.require(reference['profile'] == profile and reference['version'] == prepared['profiles']['requiredProfiles'][profile],
            'Reviewed qualification profile identity differs')
        required = {'checkpoint': {'ansible/playbooks/observability/files/checkpoint.py'},
            'lifecycle': {'ansible/playbooks/observability/tests/lifecycle_controller_proof.py',
                'ansible/playbooks/observability/tests/lifecycle_stack_proof.py'},
            'storage': {'ansible/playbooks/observability/tests/storage_lifecycle_proof.py',
                'ansible/playbooks/observability/tests/storage_fixture.py'},
            'transport': {'ansible/playbooks/observability/files/native_transport.py'},
            'source': {'ansible/playbooks/observability/files/handoff_source.py', 'platform/observability/gitops/templates/_handoff.tpl'},
            'handoff': {'ansible/' + name for name in (*handoff.HOST_FILES, *RUNNER_FILES)}
                | {'platform/observability/contract.json'}}.get(profile, set())
        handoff.require(required <= set(reference['moduleDigests']), 'Qualification omits current source boundary code')
        for name in required:
            handoff.require(name in modules, 'Required qualification owner source is unavailable: ' + name)
        handoff.require(all(name in modules and handoff.digest(modules[name]) == expected
            for name, expected in reference['moduleDigests'].items()), 'Qualification module is unsupported or changed')
        applied = ({native_transport.ARGO_IMAGE, native_transport.PYTHON_IMAGE, native_transport.REDIS_IMAGE}
            if profile == 'transport' else {lock['operator'], lock['alertmanager']} if profile == 'checkpoint'
            else {lock[name] for name in ('operator', 'reloader', 'prometheus', 'alertmanager', 'grafana',
                'ksm', 'node', 'loki', 'tempo', 'alloy', 'kiali')} if profile == 'lifecycle'
            else {lock[name] for name in ('loki', 'tempo', 'grafana')} if profile == 'storage' else set())
        handoff.require(applied <= set(reference['imagePins'].values()), 'Qualification omits current runtime owner image pins')
        handoff.require(isinstance(artifacts[profile], dict) and set(artifacts[profile]) == set(reference['artifactDigests']),
            'Qualification artifact set differs')
        verified[profile] = {}
        for name, expected in reference['artifactDigests'].items():
            handoff.artifact_key(name)
            encoded = artifacts[profile][name]
            handoff.require(isinstance(encoded, str) and len(encoded) <= handoff.LIMIT * 2, 'Qualification artifact exceeds bound')
            raw = base64.b64decode(encoded, validate=True)
            total += len(raw)
            handoff.require(raw and len(raw) <= handoff.LIMIT and total <= 8 * handoff.LIMIT
                and handoff.digest(raw) == expected, 'Qualification artifact bytes differ')
            verified[profile][name] = expected
            if profile == 'handoff': handoff_raw[name] = raw
    handoff_evidence(references, handoff_raw, modules, prepared)
    return {'references': references, 'artifactDigests': verified,
        'qualificationsSHA256': handoff.digest(handoff.canonical(references))}


def prepare_phase(operation, binding_path, packet, phase, *, root=ROOT, deadline=None):
    from playbooks.argocd.files import source_snapshot
    handoff.require(phase in handoff.PHASES and isinstance(packet, dict)
        and set(packet) == {'observation', 'baseline', 'previous', 'artifacts', 'native'}, 'Invalid phase source observation')
    handoff.require(isinstance(packet['native'], dict)
        and set(packet['native']) == {'set', 'parent', 'pods', 'applications', 'api'}
        and set(packet['native']['applications']) == set(packet['baseline']), 'Incomplete native phase observation')
    handoff.phase_order(phase, packet['previous'], operation)
    deadline = time.monotonic() + 120 if deadline is None else deadline
    prepared = prepare(operation, binding_path, packet['observation'], root=root, deadline=deadline)
    pin = prepared['expectedSet']['spec']['template']['spec']['sources'][0]['targetRevision']
    files = source_snapshot.chart_files({'repository': prepared['publicSource']['repository'], 'revision': pin,
        'path': 'platform/observability/gitops'}, deadline=deadline)
    handoff.require({name: handoff.digest(raw) for name, raw in sorted(files.items())} == prepared['nativeFilesSHA256'],
        'Native phase chart changed during preparation')
    digest = baseline_digest(files, packet['baseline'])
    image_lock = public_file(prepared['publicSource']['repository'], pin, 'platform/observability/images.lock.json', deadline)
    contract_raw = public_file(prepared['publicSource']['repository'], pin, 'platform/observability/contract.json', deadline)
    qualifications = qualification_inputs(prepared, files, packet['artifacts'], root, image_lock, contract_raw)
    policy = handoff.strict_json(contract_raw)['ownership_handoff']
    handoff.require(policy['version'] == 'cloudlab-observability-handoff/v1' and phase in policy['phases'], 'Unsupported phase contract')
    parent = packet['native']['parent']
    private_pin = parent.get('spec', {}).get('sources', [{}, {}])[1].get('targetRevision')
    handoff.require(isinstance(private_pin, str) and re.fullmatch('[a-f0-9]{40}', private_pin), 'Candidate consumer pin is not immutable')
    revision = {obj['spec']['source']['targetRevision'] for obj in packet['baseline'].values()}
    handoff.require(len(revision) == 1, 'Baseline Applications require one immutable public revision')
    context = {'version': 'cloudlab-observability-handoff/v1', 'operationId': operation, 'phase': phase,
        'baselineDigest': digest, 'baselineRevision': revision.pop(), 'privateRevision': private_pin,
        'qualificationsSHA256': qualifications['qualificationsSHA256'], 'approvedStorageTarget': 'alertmanager-retained-1gi-v1'}
    source = {'expectedSet': prepared['expectedSet'], **{name: packet['native'][name] for name in ('set', 'parent', 'pods')},
        'phaseContext': context}
    intent = {'version': handoff.PHASE_VERSION, 'operationId': operation, 'phase': phase,
        'previousPhaseSHA256': None if packet['previous'] is None else handoff.digest(handoff.canonical(packet['previous']['record'])),
        'prepared': prepared, 'phaseContext': context, 'qualifications': qualifications,
        'resourcePolicy': policy['phases'][phase], 'resourcePolicySHA256': handoff.digest(contract_raw),
        'baseline': packet['baseline'], 'applicationBindings': packet['native']['applications']}
    if packet['previous'] is not None:
        intent['targetClusterUID'] = cluster_uid(packet['previous']['record']['targetClusterUID'])
        handoff.frozen_phase(intent, packet['previous']['intent'])
    value = {'version': 1, 'operation': operation, 'codeSHA256':
        handoff.digest(repository_bytes(Path(root) / 'ansible', 'playbooks/observability/files/native_transport.py')),
        'profile': 'phase-parent', 'source': source, 'api': packet['native']['api']}
    if phase == 'baseline':
        value['source']['originalBaselineApps'] = {name: {'accepted': packet['baseline'][name],
            'observed': packet['native']['applications'][name]} for name in handoff.inventory_apps()}
    from playbooks.observability.files import native_transport
    native_transport.validate_input(value)
    handoff.require(time.monotonic() < deadline, 'Phase preparation deadline expired')
    return {'intent': intent, 'transportInput': value}


def resource_index(inventory):
    from playbooks.observability.files import native_transport
    handoff.require(isinstance(inventory, dict) and set(inventory) == set(handoff.inventory_apps()),
        'Native resource inventory closure differs')
    result = {}
    for objects in inventory.values():
        native_transport.resource_manifests(handoff.canonical({'manifests': [handoff.canonical(obj).decode() for obj in objects]}))
        for obj in objects:
            key = (obj['apiVersion'], obj['kind'], obj['metadata'].get('namespace', ''), obj['metadata']['name'])
            handoff.require(key not in result, 'Native resources have multiple owners')
            result[key] = obj
    return result


def changed_fields(before, after, path=''):
    if type(before) is not type(after): return {path}
    if isinstance(before, dict) and isinstance(after, dict):
        result = set()
        for key in before.keys() | after.keys():
            child = path + '/' + key.replace('~', '~0').replace('/', '~1')
            result |= changed_fields(before[key], after[key], child) if key in before and key in after else {child}
        return result
    if isinstance(before, list):
        if len(before) != len(after): return {path}
        return set().union(*(changed_fields(left, right, path + '/' + str(index))
            for index, (left, right) in enumerate(zip(before, after))))
    return set() if before == after else {path}


def verify_resource_deltas(intent, baseline, current, applications):
    """Read-only comparison; neither this result nor a phase record permits Sync."""
    before, after = resource_index(baseline), resource_index(current)
    policy, phase = intent['resourcePolicy'], intent['phase']
    if policy['applicationMode'] == 'canonical-native':
        handoff.require(phase == 'native-paused', 'C2 cannot validate native activation')
        return
    handoff.require(policy['applicationMode'] == 'approved-baseline', 'Unknown resource delta policy')
    control = applications['cloudlab-observability']['spec']['source']['helm']['valuesObject']['ownershipHandoffInternal']
    quota = control.get('quotaIncrease')
    permitted = {}
    for row in policy['baselineResourceDeltas']:
        handoff.require(set(row) <= {'apiVersion', 'kind', 'namespace', 'name', 'action', 'fields', 'condition'}
            and row['action'] in ('change', 'present') and isinstance(row['fields'], list), 'Unsupported resource delta contract')
        if row.get('condition') == 'quotaIncrease' and not quota: continue
        handoff.require(row.get('condition') in (None, 'quotaIncrease'), 'Unsupported resource delta condition')
        key = (row['apiVersion'], row['kind'], row['namespace'], row['name'])
        handoff.require(key not in permitted, 'Duplicate resource delta contract')
        permitted[key] = row
    for key in before.keys() | after.keys():
        row = permitted.get(key)
        if key not in before:
            handoff.require(row is not None and row['action'] == 'present', 'Unapproved resource creation')
        elif key not in after:
            raise RuntimeError('Unapproved resource removal')
        else:
            changes = changed_fields(before[key], after[key])
            handoff.require(not changes or (row is not None and row['action'] == 'change'
                and all(any(path == allowed or path.startswith(allowed + '/') for allowed in row['fields'])
                    for path in changes)), 'Native resource changed outside the exact approved delta')
    for key, row in permitted.items():
        handoff.require(key in after, 'Approved phase resource is absent')
        obj = after[key]
        if key[1] == 'ResourceQuota':
            handoff.require(quota and obj['spec']['hard']['requests.storage'] == str(quota['requestsStorageGiB']) + 'Gi'
                and str(obj['spec']['hard']['persistentvolumeclaims']) == str(quota['persistentVolumeClaims']),
                'Quota differs from exact approved increase')
        elif key[1] == 'AuthorizationPolicy':
            handoff.require(key == ('security.istio.io/v1', 'AuthorizationPolicy', 'cloudlab-observability',
                'cloudlab-observability-handoff-write-deny') and key not in before
                and obj['spec'] == {'action': 'DENY', 'rules': [{'to': [{'operation': {'ports': ['9093']}}]}]},
                'Source write isolation policy escaped its fixed scope')
        elif key[1] == 'Alertmanager':
            from playbooks.observability.files import checkpoint
            handoff.require(obj['spec']['storage'] == {'volumeClaimTemplate': {
                'metadata': {'annotations': checkpoint.CLAIM_ANNOTATIONS}, 'spec': checkpoint.CLAIM_SPEC}}
                and obj['spec']['persistentVolumeClaimRetentionPolicy'] == checkpoint.RETENTION,
                'Alertmanager storage differs from retained Filesystem profile')
        elif key[1] == 'Secret':
            from playbooks.data.files.native import PrivateLoader
            original = yaml.load(base64.b64decode(before[key]['data']['alertmanager.yaml'], validate=True), Loader=PrivateLoader)
            actual = yaml.load(base64.b64decode(obj['data']['alertmanager.yaml'], validate=True), Loader=PrivateLoader)
            expected = copy.deepcopy(original)
            expected['receivers'] = [{'name': receiver['name']} for receiver in original['receivers']]
            handoff.require(not changed_fields(expected, actual), 'Maintenance changed routes, receiver identities or unrelated configuration')
        else:
            raise RuntimeError('Unsupported approved resource delta')


def finalize_phase(packet):
    """Packet comes only from protected host collection export over Ansible custody."""
    handoff.require(isinstance(packet, dict) and set(packet) == {'intent', 'draft', 'draftPayload', 'resources', 'baseline', 'baselineApplications', 'transferBindings'},
        'Raw caller receipts cannot finalize a phase')
    intent, draft, payload, resources = (packet[name] for name in ('intent', 'draft', 'draftPayload', 'resources'))
    handoff.require(draft['version'] == handoff.PHASE_VERSION and draft['stage'] == 'phase-draft'
        and draft['intentSHA256'] == handoff.digest(handoff.canonical(intent))
        and draft['payloadSHA256'] == handoff.digest(handoff.canonical(payload))
        and {obj['metadata']['name']: obj for obj in resources['objects']['parent']} == payload['phaseApplications'],
        'Phase draft or downstream whole-Application closure changed')
    current = {name: resources['objects'][name] for name in handoff.inventory_apps()}
    target = phase_target(payload['phaseApplications'])
    handoff.require(intent.get('targetClusterUID', target) == target, 'Frozen private target cluster changed')
    if intent['phase'] != 'native-paused':
        def quota(apps):
            return apps['cloudlab-observability']['spec']['source']['helm']['valuesObject']['ownershipHandoffInternal'].get('quotaIncrease')
        handoff.require(quota(payload['phaseApplications']) == quota(packet['baselineApplications']), 'Frozen quota increase changed')
    verify_resource_deltas(intent, packet['baseline'], current, payload['phaseApplications'])
    transfers = verify_transfers(intent, packet['baseline'], current, packet['transferBindings']) if intent['phase'] == 'native-paused' else {}
    return {'version': handoff.PHASE_VERSION, 'stage': 'phase-recorded', 'operationId': intent['operationId'],
        'targetClusterUID': target,
        'phase': intent['phase'], 'previousPhaseSHA256': intent['previousPhaseSHA256'],
        'intentSHA256': handoff.digest(handoff.canonical(intent)),
        'draftSHA256': handoff.digest(handoff.canonical(draft)),
        'payloadSHA256': handoff.digest(handoff.canonical(resources)),
        'baselineSHA256': handoff.digest(handoff.canonical(packet['baseline'])),
        'transferBindingsSHA256': handoff.digest(handoff.canonical(packet['transferBindings'])),
        'transferIntents': transfers,
        'inventory': [{'apiVersion': key[0], 'kind': key[1], 'namespace': key[2], 'name': key[3],
            'sha256': handoff.digest(handoff.canonical(obj))} for key, obj in sorted(resource_index(current).items())],
        'execution': 'not-authorized', 'ready': False}


def verify_transfers(intent, baseline, current, bindings):
    before, after = resource_index(baseline), resource_index(current)
    candidates = handoff.transfer_candidates(baseline)
    handoff.require(isinstance(bindings, dict) and set(bindings) == {'baseline', 'current'}
        and set(bindings['baseline']) == set(candidates) == set(bindings['current']), 'Transfer identity witnesses are incomplete')
    values = intent['baseline']['cloudlab-observability']['spec']['source']['helm'].get('valuesObject', {})
    required = set()
    if values.get('monitoringEnabled', True):
        required |= {('monitoring.coreos.com/v1', 'PodMonitor', 'cloudlab-observability', name)
            for name in ('notes', 'mesh-control', 'mesh-ambient', 'mesh-gateways')}
        required |= {('monitoring.coreos.com/v1', 'ServiceMonitor', 'cloudlab-observability', name) for name in ('alloy', 'native-dns')}
    if values.get('enabled', True):
        required |= {('gateway.networking.k8s.io/v1', 'HTTPRoute', 'cloudlab-observability', name)
            for name in values.get('routeNames', ['grafana', 'kiali'])}
    handoff.require(required <= {tuple(key.split('|')) for key in candidates}, 'Enabled baseline monitor or route is absent')
    result = {}
    for encoded, original in candidates.items():
        key = tuple(encoded.split('|'))
        handoff.require(key in before and key in after, 'Transferred resource is missing from native inventories')
        owners = [name for name, objects in current.items() if any(
            (obj['apiVersion'], obj['kind'], obj['metadata'].get('namespace', ''), obj['metadata']['name']) == key for obj in objects)]
        owner = 'cloudlab-kiali' if key[1] == 'HTTPRoute' and key[3] == 'kiali' else 'cloudlab-prometheus'
        handoff.require(owners == [owner], 'Transferred resource has a missing or unexpected destination owner')
        expected = copy.deepcopy(original)
        annotations = expected.setdefault('metadata', {}).setdefault('annotations', {})
        old_tracking = 'cloudlab-observability:' + key[0].split('/')[0] + '/' + key[1] + ':' + key[2] + '/' + key[3]
        new_tracking = owner + ':' + key[0].split('/')[0] + '/' + key[1] + ':' + key[2] + '/' + key[3]
        handoff.require(annotations.get('argocd.argoproj.io/tracking-id') == old_tracking, 'Original transfer owner is not native-proven')
        annotations['argocd.argoproj.io/tracking-id'] = new_tracking
        handoff.require(after[key] == expected, 'Transfer changed fields outside exact tracking ownership')
        old, now = bindings['baseline'][encoded], bindings['current'][encoded]
        handoff.require(old.get('apiVersion') == now.get('apiVersion') == key[0] and old.get('kind') == now.get('kind') == key[1]
            and old['metadata'].get('namespace') == now['metadata'].get('namespace') == key[2]
            and old['metadata'].get('name') == now['metadata'].get('name') == key[3]
            and old['metadata'].get('uid') == now['metadata'].get('uid') and now['metadata'].get('uid')
            and not now['metadata'].get('deletionTimestamp') and now.get('spec') == old.get('spec'),
            'Transfer backing UID or live specification changed')
        handoff.require(old['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') == old_tracking
            and now['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') in (old_tracking, new_tracking)
            and not now['metadata'].get('annotations', {}).get('argocd.argoproj.io/installation-id'),
            'Transfer live tracking authority changed')
        result[encoded] = {'uid': now['metadata']['uid'], 'resourceVersion': now['metadata']['resourceVersion'],
            'fromTracking': now['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id'),
            'toTracking': new_tracking, 'desiredSHA256': handoff.digest(handoff.canonical(after[key]))}
    return result


def original_config_inventory(source):
    """Accept only the original collector export over the protected Ansible channel."""
    from playbooks.observability.files import native_transport
    handoff.require(isinstance(source, dict) and set(source) == {
        'intent', 'draft', 'draftPayload', 'collector', 'transportInput', 'bundle', 'previous'},
        'Original native configuration requires protected collector ancestry')
    intent, draft, payload, collector, value, bundle = (source[name] for name in (
        'intent', 'draft', 'draftPayload', 'collector', 'transportInput', 'bundle'))
    handoff.require(source['previous'] is None and intent['phase'] == 'baseline'
        and intent['previousPhaseSHA256'] is None and intent['version'] == handoff.PHASE_VERSION
        and intent['prepared']['bundleSHA256'] == handoff.digest(handoff.canonical(bundle))
        and bundle['version'] == handoff.BUNDLE_VERSION and bundle['operationId'] == intent['operationId']
        and value['operation'] == intent['operationId'] and value['profile'] == 'phase-parent'
        and value['codeSHA256'] == bundle['moduleDigests']['playbooks/observability/files/native_transport.py']
        and value['source']['phaseContext'] == intent['phaseContext']
        and value['source']['expectedSet'] == intent['prepared']['expectedSet'],
        'Original native configuration source binding changed')
    native_transport.validate_input(value)
    handoff.require(collector.get('namespaceAbsent') is True
        and collector['context'] == {'operation': intent['operationId'], 'codeSHA256': value['codeSHA256'],
        'inputSHA256': handoff.digest(handoff.canonical(value))}
        and draft['version'] == handoff.PHASE_VERSION and draft['stage'] == 'phase-draft'
        and draft['operationId'] == intent['operationId'] and draft['phase'] == 'baseline'
        and draft['intentSHA256'] == handoff.digest(handoff.canonical(intent))
        and draft['payloadSHA256'] == handoff.digest(handoff.canonical(payload))
        and draft['custody'] == handoff.collection_binding(collector),
        'Original native configuration collector binding changed')
    handoff.require(set(payload['baseline']) == set(handoff.inventory_apps())
        and len(payload['applicationOrder']) == 6 and set(payload['applicationOrder']) == set(native_transport.CHILDREN)
        and set(payload['phaseApplications']) == set(native_transport.CHILDREN), 'Original native configuration closure differs')
    objects = {'parent': [payload['phaseApplications'][name] for name in payload['applicationOrder']],
        'baseline': payload['baseline']}
    handoff.require(handoff.digest(handoff.canonical(objects)) == collector['sourcePayloadSHA256'],
        'Original native configuration objects changed after collection')
    for name, entry in value['source']['originalBaselineApps'].items():
        handoff.require(entry['accepted'] == intent['baseline'][name], 'Original native Application source differs')
    native_transport.phase_applications(value['source'], objects['parent'])
    resource_index(payload['baseline'])
    return intent, payload['baseline']


def native_config_document(inventory):
    from playbooks.data.files.native import PrivateLoader
    key = ('v1', 'Secret', 'cloudlab-observability', 'alertmanager-cloudlab')
    indexed = resource_index(inventory)
    handoff.require(key in indexed, 'Accepted native Alertmanager configuration is unavailable')
    secret = indexed[key]
    encoded = secret.get('data', {}).get('alertmanager.yaml')
    handoff.require(isinstance(encoded, str) and len(encoded) <= 2 * handoff.LIMIT,
        'Accepted native Alertmanager configuration exceeds bound')
    raw = base64.b64decode(encoded, validate=True)
    handoff.require(raw and len(raw) <= handoff.LIMIT, 'Accepted native Alertmanager configuration exceeds bound')
    value = yaml.load(raw, Loader=PrivateLoader)
    handoff.require(isinstance(value, dict), 'Accepted native Alertmanager configuration is invalid')
    handoff.canonical(value)
    return value


def loaded_native_config(encoded):
    from playbooks.data.files.native import PrivateLoader
    handoff.require(isinstance(encoded, str) and len(encoded) <= 2 * handoff.LIMIT, 'Native status exceeds bound')
    raw = base64.b64decode(encoded, validate=True)
    status = handoff.strict_json(raw)
    handoff.require(isinstance(status, dict) and isinstance(status.get('config'), dict)
        and set(status['config']) == {'original'} and isinstance(status['config']['original'], str),
        'Native status configuration framing differs')
    text = status['config']['original'].encode()
    handoff.require(text and len(text) <= handoff.LIMIT, 'Loaded native configuration exceeds bound')
    value = yaml.load(text, Loader=PrivateLoader)
    handoff.require(isinstance(value, dict) and isinstance(value.get('receivers'), list)
        and value['receivers'] and all(isinstance(row, dict) and isinstance(row.get('name'), str)
            and row['name'] for row in value['receivers'])
        and len({row['name'] for row in value['receivers']}) == len(value['receivers']),
        'Loaded native receiver identities differ')
    handoff.canonical(value)
    return value, handoff.digest(text)


def native_config_profile(value, intent):
    """One native-observed public configuration; other inputs need qualification."""
    references = intent.get('qualifications', {}).get('references', {})
    handoff.require(set(references) == set(PROFILES)
        and references == intent.get('prepared', {}).get('profiles', {}).get('acceptedArtifacts')
        and NATIVE_CONFIG_PROFILE['image'] in references['checkpoint']['imagePins'].values(),
        'Native configuration profile image or qualification changed')
    handoff.require(handoff.digest(handoff.canonical(value)) == NATIVE_CONFIG_PROFILE['inputSHA256'],
        'Native configuration capability gap: input profile or integrations require qualification')
    return NATIVE_CONFIG_PROFILE['nativeSHA256']


def classification_config_inventory(source):
    handoff.require(isinstance(source, dict) and set(source) == {'phase', 'record', 'previous', 'bundle'},
        'Native configuration requires protected phase ancestry')
    packet, record, previous, bundle = (source[name] for name in ('phase', 'record', 'previous', 'bundle'))
    intent = packet['intent']
    handoff.require(intent['prepared']['bundleSHA256'] == handoff.digest(handoff.canonical(bundle))
        and bundle['version'] == handoff.BUNDLE_VERSION and bundle['operationId'] == intent['operationId']
        and finalize_phase(packet) == record, 'Native configuration phase record changed')
    handoff.phase_order(intent['phase'], previous, intent['operationId'])
    handoff.require(record['previousPhaseSHA256'] == intent['previousPhaseSHA256'] ==
        (None if previous is None else handoff.digest(handoff.canonical(previous['record']))),
        'Native configuration predecessor changed')
    if previous is not None:
        handoff.frozen_phase(intent, previous['intent'])
    payload, draft, resources = (packet[name] for name in ('draftPayload', 'draft', 'resources'))
    objects = [payload['phaseApplications'][name] for name in payload['applicationOrder']]
    original = {'parent': objects, 'baseline': payload['baseline']} if intent['phase'] == 'baseline' else objects
    handoff.require(handoff.digest(handoff.canonical(original)) == draft['custody']['objectsSHA256']
        and handoff.digest(handoff.canonical(resources['objects'])) == resources['custody']['objectsSHA256'],
        'Native configuration collected objects changed')
    current = {name: resources['objects'][name] for name in handoff.inventory_apps()}
    return intent, packet['baseline'], current


def validate_native_config(packet):
    """Classify protected native bytes; the host owns freshness, replay and write gates."""
    handoff.require(isinstance(packet, dict) and set(packet) == {
        'version', 'challenge', 'rawStatus', 'originalStatus', 'sourcePhase'}
        and packet['version'] == 'cloudlab-native-config-challenge/v1', 'Invalid native configuration challenge packet')
    challenge = packet['challenge']
    handoff.require(isinstance(challenge, dict) and set(challenge) == {'operationId', 'phase', 'purpose',
        'bundleSHA256', 'intentSHA256', 'previousPhaseSHA256', 'source', 'configSHA256', 'reloadTimestamp',
        'nonce', 'bootID', 'deadlineMonotonic'}, 'Native configuration challenge framing differs')
    purposes = {'original': ('baseline',), 'muted': ('maintenance', 'persistent-maintenance'),
        'restored': ('persistent-normal', 'native-paused')}
    purpose, phase = challenge['purpose'], challenge['phase']
    handoff.require(purpose in purposes and phase in purposes[purpose]
        and isinstance(challenge['operationId'], str) and re.fullmatch('[a-f0-9]{16}', challenge['operationId'])
        and all(isinstance(challenge[key], str) and re.fullmatch('[a-f0-9]{64}', challenge[key])
            for key in ('bundleSHA256', 'intentSHA256', 'configSHA256'))
        and (challenge['previousPhaseSHA256'] is None or isinstance(challenge['previousPhaseSHA256'], str)
            and re.fullmatch('[a-f0-9]{64}', challenge['previousPhaseSHA256']))
        and isinstance(challenge['nonce'], str) and re.fullmatch('[a-f0-9]{32}', challenge['nonce'])
        and isinstance(challenge['bootID'], str) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', challenge['bootID'])
        and all(type(challenge[key]) in (int, float) and math.isfinite(challenge[key]) and challenge[key] > 0
            for key in ('reloadTimestamp', 'deadlineMonotonic')), 'Native configuration challenge binding is invalid')
    source = challenge['source']
    handoff.require(isinstance(source, dict) and set(source) == {'name', 'namespace', 'uid', 'containerID', 'startedAt'}
        and source['namespace'] == 'cloudlab-observability' and isinstance(source['name'], str)
        and re.fullmatch('[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?', source['name'])
        and isinstance(source['uid'], str) and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', source['uid'])
        and isinstance(source['containerID'], str) and re.fullmatch('containerd://[a-f0-9]{64}', source['containerID'])
        and isinstance(source['startedAt'], str)
        and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.]\d+)?(?:Z|[+-]\d{2}:\d{2})', source['startedAt']),
        'Native source process binding is invalid')
    if purpose == 'original':
        handoff.require(packet['originalStatus'] is None, 'Original native classification cannot replace earlier source bytes')
        intent, baseline = original_config_inventory(packet['sourcePhase'])
        current = baseline
    else:
        intent, baseline, current = classification_config_inventory(packet['sourcePhase'])
    handoff.require(intent['operationId'] == challenge['operationId'] and intent['phase'] == phase
        and intent['prepared']['bundleSHA256'] == challenge['bundleSHA256']
        and handoff.digest(handoff.canonical(intent)) == challenge['intentSHA256']
        and intent['previousPhaseSHA256'] == challenge['previousPhaseSHA256'],
        'Native configuration challenge belongs to another protected source phase')
    actual, actual_digest = loaded_native_config(packet['rawStatus'])
    handoff.require(actual_digest == challenge['configSHA256'], 'Native configuration raw digest differs')
    original, original_digest = (actual, actual_digest) if purpose == 'original' else loaded_native_config(packet['originalStatus'])
    handoff.require(handoff.digest(handoff.canonical(original)) == native_config_profile(native_config_document(baseline), intent),
        'Original loaded native configuration differs from the qualified native profile')
    expected = copy.deepcopy(original)
    if purpose == 'muted':
        expected['receivers'] = [{key: value for key, value in row.items() if not key.endswith('_configs')}
            for row in original['receivers']]
    handoff.require(handoff.digest(handoff.canonical(actual)) == native_config_profile(native_config_document(current), intent)
        and not changed_fields(expected, actual), 'Loaded native configuration differs from exact accepted purpose')
    if purpose == 'restored':
        handoff.require(actual_digest == original_digest, 'Restored native configuration differs from exact original bytes')
    return {'version': 'cloudlab-native-config-classification/v1',
        'challengeSHA256': handoff.digest(handoff.canonical(challenge)), 'challenge': challenge,
        'classification': purpose, 'originalConfigSHA256': original_digest, 'configSHA256': actual_digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('bundle', 'prepare', 'prepare-phase', 'finalize-phase', 'qualification-bundle', 'validate-native-config'))
    parser.add_argument('--operation', required=True)
    parser.add_argument('--source-binding')
    parser.add_argument('--phase', choices=handoff.PHASES)
    parser.add_argument('--qualification-root')
    arguments = parser.parse_args()
    if arguments.action == 'bundle':
        result = bundle(arguments.operation)
    elif arguments.action == 'prepare':
        handoff.require(arguments.source_binding is not None, 'Protected private source binding is required')
        observed = handoff.strict_json(sys.stdin.buffer.read(handoff.LIMIT + 1))
        source = prepare(arguments.operation, arguments.source_binding, observed)
        result = {'source': source, 'sourceSHA256': handoff.digest(handoff.canonical(source))}
    elif arguments.action == 'qualification-bundle':
        prepared = handoff.strict_json(sys.stdin.buffer.read(handoff.LIMIT + 1))
        references = prepared['profiles']['acceptedArtifacts']
        handoff.require(arguments.qualification_root is not None and set(references) == set(PROFILES),
            'Registered qualification artifacts are required')
        files = {}
        for profile, reference in references.items():
            for name, expected in reference['artifactDigests'].items():
                key = profile + '/' + handoff.artifact_key(name)
                raw = handoff.read_private(Path(arguments.qualification_root) / key)
                handoff.require(raw and handoff.digest(raw) == expected, 'Reviewed qualification artifact differs')
                files[key] = base64.b64encode(raw).decode()
        handoff.require(len(handoff.canonical(files)) <= 12 * handoff.LIMIT, 'Qualification bundle exceeds total bound')
        result = {'files': files, 'directories': sorted({str(parent) for key in files for parent in Path(key).parents if str(parent) != '.'})}
    elif arguments.action == 'validate-native-config':
        result = validate_native_config(handoff.strict_json(sys.stdin.buffer.read(CLASSIFICATION_LIMIT + 1), CLASSIFICATION_LIMIT))
        handoff.require(result['challenge']['operationId'] == arguments.operation, 'Native configuration operation differs')
    else:
        packet = handoff.strict_json(sys.stdin.buffer.read(handoff.PRIVATE_LIMIT + 1), handoff.PRIVATE_LIMIT)
        if arguments.action == 'prepare-phase':
            handoff.require(arguments.source_binding is not None and arguments.phase is not None, 'Phase source inputs are required')
            proposal = prepare_phase(arguments.operation, arguments.source_binding, packet, arguments.phase)
        else:
            proposal = finalize_phase(packet)
            handoff.require(proposal['operationId'] == arguments.operation, 'Final phase operation differs')
        result = {'proposal': proposal, 'sha256': handoff.digest(handoff.canonical(proposal))}
    print(handoff.canonical(result).decode() if arguments.action == 'validate-native-config' else json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Handoff runner preparation failed; source or owner authority is unavailable') from None
