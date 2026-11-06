"""Bounded synthetic Argo/Longhorn lifecycle proof; never a lab installer."""
import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import time
import traceback
from types import SimpleNamespace
from urllib.parse import urlencode

PROFILE = 'observability-storage-lifecycle-v1'
OWNER = 'observability-lifecycle-proof'
LABEL = 'cloudlab.io/storage-proof'
REPOSITORY = 'https://github.com/UncleThreeHomeLab/yasai-cloudlab.git'
REVISION = 'e216fefeb8bd395990ea571c016c01ab909af7b1'
SOURCE_PATH = 'ansible/playbooks/observability/tests/fixtures/storage-lifecycle'
PUBLISHED_LOCK = '981e4699c145cf6084e3e70e3a2693029592d169986c19d4e50c195f9f1aa886'
PROM_ARCHIVES = ('88c3dd293db9689c25f7da4459a0c2f3c654a90630328a233babd898c51e9656',
                 'f38a02d00b2a3d1a7f657a43c0ed591b6bdb456f65e89abfa34b132376a50a78')
PYTHON_IMAGE = 'python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed'
PHASES = ('running', 'scaled-down', 'removed')
KINDS = {'ConfigMap', 'Secret', 'ServiceAccount', 'Service', 'PersistentVolumeClaim', 'StatefulSet', 'Deployment'}
PHASE_HASHES = {
    'running': '0a8fe3ba4b4ed11715e185927558bb9ee68b0dbd90c00cdc4f05ffe593471c6b',
    'scaled-down': 'ecf78530c08753c279ba516e15a1060540afc67dd6ab1f76c6b49f938f956e62',
    'removed': '0a7202bab8877ad2fec30f231e0c862049025a904233ffb2a04e14226f35cf6a',
}
UID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
OP = re.compile(r'[a-f0-9]{16}')
LIMIT = 4 * 1024 * 1024
ROOT = Path('/var/lib/cloudlab/proofs')
RECOVERY_PROFILE = 'observability-storage-empty-recovery-v1'
STORAGE_RECOVERY_PROFILE = 'observability-storage-cleanup-recovery-v1'
MARKER_RECOVERY_CASE = 'verified-marker-first-claim-released-v1'
MARKER_PREDECESSOR_DRIVER = '2d4b0c37a274d0de4498ee743f31067b0f94223ce4374def8a7b88686d6b2930'
STORAGE_PREDECESSOR_OPERATION = 'ceca2d4d362732f5'
STORAGE_PREDECESSOR_DRIVER = '8e95a60df775c6a9e66bc06c809114ede7bc6c4b45f8f58f005ce95296845204'
STORAGE_PREDECESSOR_INPUT = 'a68e858bbcd16783f94c5d871a89378db493453243f147d465f0b9ce25741cd5'
PREDECESSOR_DRIVER = '238e7bffe09658382b12e7d463a22c9aa81bed1b72c4c51ef3bce218a70d1b47'
PLURALS = {'Namespace': ('v1', 'namespaces'), 'AppProject': ('argoproj.io/v1alpha1', 'appprojects'),
           'Application': ('argoproj.io/v1alpha1', 'applications'), 'Pod': ('v1', 'pods'),
           'PersistentVolumeClaim': ('v1', 'persistentvolumeclaims'), 'PersistentVolume': ('v1', 'persistentvolumes'),
           'Volume': ('longhorn.io/v1beta2', 'volumes'), 'ServiceAccount': ('v1', 'serviceaccounts')}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parsed(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, 'Duplicate JSON key')
            value[key] = item
        return value
    require(len(raw) <= LIMIT, 'JSON exceeds bound')
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('Nonfinite JSON')))


def namespace(operation):
    require(type(operation) is str and OP.fullmatch(operation), 'Invalid operation')
    return 'obs-storage-' + operation


def helm_json(value):
    raw = canonical(value).decode()
    for character, replacement in [('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'),
                                    ('\u2028', '\\u2028'), ('\u2029', '\\u2029')]:
        raw = raw.replace(character, replacement)
    return raw.encode()


def normalized_objects(objects, operation, phase):
    """Bind every object byte except the one approved operation-name substitution."""
    ns = namespace(operation)
    require(phase in PHASES and type(objects) is list and 0 < len(objects) <= 24, 'Invalid phase objects')
    identities = [(o.get('kind'), o.get('metadata', {}).get('name')) for o in objects]
    require(len(set(identities)) == len(objects), 'Duplicate fixture identity')
    require(all(o['kind'] in KINDS and o['metadata'].get('namespace') == ns for o in objects), 'Fixture namespace or kind escape')
    indexed = {(o['kind'], o['metadata']['name']): o for o in objects}
    if phase != 'removed':
        for component in ('loki', 'tempo', 'grafana'):
            kind = 'Deployment' if component == 'grafana' else 'StatefulSet'
            obj = indexed[kind, ns + '-' + component]
            data = indexed['ConfigMap', ns + '-' + component + '-config']['data']
            require(obj['spec']['template']['metadata']['annotations']['checksum/config'] == digest(helm_json(data)),
                    'Fixture rollout checksum differs')
    def replace(value):
        if isinstance(value, str):
            require(all(match.group(0) == ns for match in re.finditer(r'obs-storage-[a-f0-9]{16}', value)),
                    'Foreign operation reference')
            return value.replace(ns, 'obs-storage-0000000000000000')
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == LABEL:
                    require(item == operation, 'Foreign operation ownership label')
                    result[key] = '0000000000000000'
                else:
                    result[key] = replace(item)
            return result
        return value
    result = replace(copy.deepcopy(objects))
    indexed = {(o['kind'], o['metadata']['name']): o for o in result}
    if phase != 'removed':
        for component in ('loki', 'tempo', 'grafana'):
            kind = 'Deployment' if component == 'grafana' else 'StatefulSet'
            prefix = 'obs-storage-0000000000000000-' + component
            data = indexed['ConfigMap', prefix + '-config']['data']
            indexed[kind, prefix]['spec']['template']['metadata']['annotations']['checksum/config'] = digest(helm_json(data))
    return sorted(result, key=lambda o: (o['kind'], o['metadata']['name']))


def validate_input(value, operation):
    require(type(value) is dict and set(value) == {'version', 'profile', 'operation', 'source', 'phases', 'pythonImage'},
            'Invalid preparation fields')
    require(type(value['version']) is int and value['version'] == 1 and value['profile'] == PROFILE and value['operation'] == operation,
            'Preparation context mismatch')
    require(value['source'] == {'repository': REPOSITORY, 'revision': REVISION, 'path': SOURCE_PATH,
                                'publishedLockSHA256': PUBLISHED_LOCK}, 'Unapproved fixture source')
    require(value['pythonImage'] == PYTHON_IMAGE and set(value['phases']) == set(PHASES), 'Unapproved image or phases')
    require(set(PHASE_HASHES) == set(PHASES), 'Published profile hashes unavailable')
    for phase in PHASES:
        require(digest(canonical(normalized_objects(value['phases'][phase], operation, phase))) == PHASE_HASHES[phase],
                'Published fixture profile differs')
    return value


def prepare(operation):
    # Runner only: the copied host driver has no YAML/Helm/Git-package dependency.
    from playbooks.observability.tests import storage_fixture as fixture
    ns = namespace(operation)
    committed = parsed((fixture.FIXTURE / 'derivation.lock.json').read_bytes())
    published = copy.deepcopy(committed)
    require(published['sources']['prometheus']['sha256'] in PROM_ARCHIVES, 'Unapproved Prometheus provenance')
    published['sources']['prometheus']['sha256'] = PROM_ARCHIVES[0]
    require(digest(json.dumps(published, sort_keys=True, indent=2).encode() + b'\n') == PUBLISHED_LOCK,
            'Published derivation provenance differs')
    built = fixture.build()
    generated = parsed(built['derivation.lock.json'])
    require(generated['sources']['prometheus']['sha256'] == committed['sources']['prometheus']['sha256'],
            'Current Prometheus archive differs from its accepted lock')
    expected = copy.deepcopy(published)
    expected['sources']['prometheus']['sha256'] = generated['sources']['prometheus']['sha256']
    require(generated == expected, 'Selected native source or transformation changed')
    for name, sha in published['artifacts'].items():
        require(digest((fixture.FIXTURE / name).read_bytes()) == sha and digest(built[name]) == sha,
                'Published fixture artifact changed')
    phases = {phase: fixture.render_fixture(fixture.FIXTURE, operation, phase) for phase in PHASES}
    for phase, objects in phases.items():
        fixture.validate_rendered(objects, operation, phase)
    value = {'version': 1, 'profile': PROFILE, 'operation': operation,
             'source': {'repository': REPOSITORY, 'revision': REVISION, 'path': SOURCE_PATH,
                        'publishedLockSHA256': PUBLISHED_LOCK}, 'phases': phases, 'pythonImage': PYTHON_IMAGE}
    return validate_input(value, operation)


def command(arguments, body=None, *, deadline=None):
    require(type(arguments) is list and all(type(a) is str for a in arguments), 'Invalid command argv')
    timeout = 60
    if deadline is not None:
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Operation deadline expired before native command')
        timeout = min(timeout, remaining)
    result = subprocess.run(arguments, input=body, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    require(len(result.stdout) <= LIMIT and len(result.stderr) <= LIMIT, 'Command output exceeds bound')
    if result.returncode != 0:
        error = RuntimeError('Native command failed; protected operation retained')
        error.native_failure = {'exitCode': result.returncode,
            'stderr': result.stderr[:65536].decode('utf-8', errors='replace'),
            'stderrTruncated': len(result.stderr) > 65536}
        raise error
    return result.stdout


def kubectl(*arguments, body=None, deadline=None):
    return command(['kubectl', '--request-timeout=30s', *arguments], body, deadline=deadline)


def get(kind, name=None, ns=None, *, managed_fields=False):
    args = ['get', kind]
    if name:
        args += [name, '--ignore-not-found']
    if ns:
        args += ['-n', ns]
    if managed_fields:
        args += ['--show-managed-fields']
    raw = kubectl(*args, '-o', 'json')
    return parsed(raw) if raw.strip() else None


def listed(kind, ns=None):
    value = get(kind, ns=ns)
    require(type(value) is dict and type(value.get('items')) is list
            and not value.get('metadata', {}).get('continue') and len(value['items']) <= 4096, 'Incomplete inventory')
    return value['items']


def object_id(obj):
    m = obj['metadata']
    require(UID.fullmatch(m['uid']) and isinstance(m['resourceVersion'], str) and m['resourceVersion'], 'Invalid native identity')
    return {'apiVersion': obj['apiVersion'], 'kind': obj['kind'], 'name': m['name'],
            'namespace': m.get('namespace'), 'uid': m['uid']}


def api_path(identity):
    api = identity['apiVersion']
    require(api == 'v1' or re.fullmatch(r'[a-z0-9.-]+/v[0-9]+(?:(?:alpha|beta)[0-9]+)?', api), 'Invalid API version')
    plurals = {'Namespace': 'namespaces', 'AppProject': 'appprojects', 'Application': 'applications',
               'Pod': 'pods', 'PersistentVolumeClaim': 'persistentvolumeclaims', 'PersistentVolume': 'persistentvolumes',
               'Volume': 'volumes', 'ServiceAccount': 'serviceaccounts'}
    require(identity['kind'] in plurals, 'Unsupported deletion kind')
    root = '/api/v1' if api == 'v1' else '/apis/' + api
    if identity['namespace']:
        root += '/namespaces/' + identity['namespace']
    return root + '/' + plurals[identity['kind']] + '/' + identity['name']


def current(identity):
    api, plural = identity['apiVersion'], api_path(identity).rsplit('/', 2)[1]
    kind = plural if api == 'v1' else plural + '.' + '.'.join(reversed(api.split('/')))
    value = get(kind, identity['name'], identity['namespace'])
    if value:
        require(object_id(value) == identity, 'Recorded resource replaced')
    return value


def wait(label, predicate, deadline, seconds=300):
    end = min(deadline, time.monotonic() + seconds)
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(2)
    raise RuntimeError('Timed out: ' + label)


def protected_directory(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Unsafe protected path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'Unprotected directory')
        return path
    finally:
        os.close(fd)


def ensure_protected_directory(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Unsafe protected creation path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=fd)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe protected directory owner')
    finally:
        os.close(fd)


def protected_bytes(path):
    path = Path(path)
    protected_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o077 and before.st_size <= LIMIT, 'Unsafe protected file')
        raw = stream.read(LIMIT + 1)
        require(len(raw) == before.st_size and os.fstat(stream.fileno()) == before, 'Protected file changed while reading')
    return raw


def atomic_json(path, value, *, exclusive=False):
    raw = canonical(value)
    require(len(raw) <= LIMIT, 'Receipt exceeds bound')
    parent = protected_directory(path.parent)
    temporary = parent / ('.pending-' + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        else:
            if path.exists():
                protected_bytes(path)
            os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


class Receipt:
    def __init__(self, directory, operation, payload, *, resume=False):
        self.directory = Path(directory)
        self.path = self.directory / 'receipt.json'
        self.operation = operation
        self.namespace = namespace(operation)
        context = {'version': 1, 'profile': PROFILE, 'operation': operation,
                   'driver': digest(Path(__file__).read_bytes()), 'input': digest(canonical(payload))}
        if resume:
            self.value = parsed(protected_bytes(self.path))
            require(self.value.get('context') == context, 'Receipt context changed')
        else:
            require(not self.directory.exists(), 'Existing receipt cannot be adopted')
            protected_directory(self.directory.parent)
            self.directory.mkdir(mode=0o700)
            self.value = {'context': context, 'phase': 'prepared', 'roots': {}, 'objects': {},
                          'intents': {}, 'storage': {}, 'markers': {}, 'evidence': {}}
            self.save()

    def save(self):
        atomic_json(self.path, self.value)

    def phase(self, phase):
        self.value['phase'] = phase
        self.save()

    def record(self, name, obj):
        identity = object_id(obj)
        previous = self.value['objects'].get(name)
        require(previous is None or previous == identity, 'Recorded object changed')
        self.value['objects'][name] = identity
        self.save()
        return identity

    def intention(self, name, identity, scope):
        prior = self.value['intents'].get(name)
        require(prior is None or prior['identity'] == identity and prior['scope'] == digest(canonical(scope)),
                'Mutation scope changed')
        if prior is None:
            self.value['intents'][name] = {'identity': identity, 'scope': digest(canonical(scope)),
                                         'accepted': False, 'complete': False}
            self.save()
        return self.value['intents'][name]


def record_failure(receipt, error):
    try:
        path = receipt.directory / 'failure.json'
        try:
            info = path.lstat()
        except FileNotFoundError:
            pass
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o077, 'Unsafe existing failure artifact')
            protected_bytes(path)
            return False
        value = {'version': 1, 'context': receipt.value['context'], 'phase': receipt.value.get('phase'),
            'pendingStep': receipt.value.get('pendingStep'), 'errorType': type(error).__name__[:128],
            'traceback': ''.join(traceback.format_exception(type(error), error, error.__traceback__, limit=32))[:65536]}
        native = getattr(error, 'native_failure', None)
        if native is not None:
            value['nativeCommand'] = native
        atomic_json(path, value, exclusive=True)
        return True
    except Exception:
        # A diagnostic write must never replace the operation's original failure.
        return False


def request_delete(receipt, key, obj, scope):
    identity = object_id(obj)
    deletion_scope(receipt, identity)
    previous = receipt.value['intents'].get(key)
    if previous:
        require(previous['identity'] == identity and previous['scope'] == digest(canonical(scope)), 'Mutation scope changed')
        require(not previous['complete'], 'Completed deletion target reappeared')
        if previous['accepted']:
            return
    fresh = current(identity)
    require(fresh is not None, 'Deletion target absent without acknowledged deletion')
    def profile(value):
        result = copy.deepcopy(value)
        result['metadata'].pop('resourceVersion', None)
        if identity['kind'] in ('Namespace', 'AppProject', 'Application', 'Pod'):
            result.pop('status', None)
        return result
    require(canonical(profile(fresh)) == canonical(profile(obj)), 'Deletion target authority changed')
    if identity['kind'] == 'Application':
        require(fresh.get('operation') is None and fresh.get('status', {}).get('operationState', {}).get('phase')
                in (None, 'Succeeded', 'Failed', 'Error'), 'Application is not idle before deletion')
    version = fresh['metadata'].get('resourceVersion')
    require(type(version) is str and version, 'Deletion target resourceVersion unavailable')
    intent = receipt.intention(key, identity, scope)
    require(not intent['complete'], 'Completed deletion target reappeared')
    intent['resourceVersion'] = version
    receipt.save()
    options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Foreground',
               'preconditions': {'uid': identity['uid'], 'resourceVersion': version}}
    kubectl('delete', '--raw', api_path(identity), '-f', '-', body=canonical(options))
    intent['accepted'] = True
    receipt.save()


def finish_delete(receipt, key, deadline):
    intent = receipt.value['intents'][key]
    require(intent['accepted'], 'Unaccepted deletion cannot be completed')
    wait('exact deletion', lambda: current(intent['identity']) is None, deadline)
    intent['complete'] = True
    receipt.save()


def root_documents(operation):
    ns = namespace(operation)
    labels = {'cloudlab.io/owner': OWNER, LABEL: operation}
    project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
        'metadata': {'name': ns, 'namespace': 'argocd', 'labels': labels},
        'spec': {'sourceRepos': [REPOSITORY], 'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': ns}],
                 'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [
                     {'group': 'apps' if kind in ('StatefulSet', 'Deployment') else '', 'kind': kind} for kind in sorted(KINDS)]}}
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': ns, 'namespace': 'argocd', 'labels': labels,
                     'finalizers': ['resources-finalizer.argocd.argoproj.io']},
        'spec': {'project': ns, 'source': {'repoURL': REPOSITORY, 'targetRevision': REVISION, 'path': SOURCE_PATH,
                  'helm': {'releaseName': 'fixture', 'valuesObject': {'operationId': operation, 'phase': 'running'}}},
                 'destination': {'server': 'https://kubernetes.default.svc', 'namespace': ns},
                 'syncPolicy': {'automated': {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': False},
                    'syncOptions': ['FailOnSharedResource=true', 'ServerSideApply=true', 'DisableClientSideApplyMigration=true', 'PruneLast=true'],
                    'retry': {'limit': 2, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '10s'}}}}}
    return ({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns, 'labels': labels | {
        'pod-security.kubernetes.io/enforce': 'baseline', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
        'istio-injection': 'disabled'}}}, project, app)


def root_current(receipt, key):
    identity = receipt.value['objects'][key]
    value = current(identity)
    require(value and value['metadata'].get('labels', {}).get('cloudlab.io/owner') == OWNER
            and value['metadata']['labels'].get(LABEL) == receipt.operation, 'Root ownership changed')
    if key == 'namespace':
        require(value['metadata']['labels'].get('pod-security.kubernetes.io/enforce') == 'baseline'
                and value['metadata']['labels'].get('pod-security.kubernetes.io/enforce-version') == 'v1.36'
                and value['metadata']['labels'].get('istio-injection') == 'disabled', 'Namespace security policy changed')
    if key == 'project':
        require(value['spec'] == root_documents(receipt.operation)[1]['spec'], 'Project authority changed')
    return value


def create_root(receipt, key, document):
    if key in receipt.value['roots']:
        require(key in receipt.value['objects'], 'Unacknowledged root creation requires separate recovery')
        obj = root_current(receipt, key)
        require(receipt.value['roots'][key]['documentHash'] == digest(canonical(document)), 'Root declaration changed')
        receipt.value['roots'][key]['accepted'] = True
        receipt.save()
        return obj
    require(get(document['kind'], document['metadata']['name'], document['metadata'].get('namespace')) is None,
            'Existing root cannot be adopted')
    receipt.value['roots'][key] = {'documentHash': digest(canonical(document)), 'accepted': False}
    receipt.save()
    obj = parsed(kubectl('create', '-f', '-', '-o', 'json', body=canonical(document)))
    require(obj['kind'] == document['kind'] and obj['apiVersion'] == document['apiVersion']
            and obj['metadata']['name'] == document['metadata']['name']
            and obj['metadata'].get('namespace') == document['metadata'].get('namespace')
            and not obj['metadata'].get('ownerReferences')
            and (obj['metadata'].get('finalizers') or []) == (document['metadata'].get('finalizers') or [])
            and all(obj['metadata'].get('labels', {}).get(k) == v for k, v in document['metadata']['labels'].items()),
            'Root admission changed ownership')
    if document['kind'] != 'Namespace':
        require(obj.get('spec') == document.get('spec'), 'Root admission changed specification')
    else:
        require(obj['metadata']['labels'].get('pod-security.kubernetes.io/enforce') == 'baseline', 'Namespace admission changed PSS')
    receipt.record(key, obj)
    receipt.value['roots'][key]['accepted'] = True
    receipt.save()
    return obj


def deletion_scope(receipt, identity):
    require(set(identity) == {'apiVersion', 'kind', 'name', 'namespace', 'uid'}
            and identity['kind'] in PLURALS and identity['apiVersion'] == PLURALS[identity['kind']][0]
            and UID.fullmatch(identity['uid']), 'Invalid deletion identity')
    ns, kind, name = receipt.namespace, identity['kind'], identity['name']
    if kind in ('Namespace', 'AppProject', 'Application'):
        key = {'Namespace': 'namespace', 'AppProject': 'project', 'Application': 'app'}[kind]
        require(identity == receipt.value['objects'].get(key), 'Unrecorded root deletion')
        require(name == ns and identity['namespace'] == (None if kind == 'Namespace' else 'argocd'), 'Root deletion escaped scope')
    elif kind == 'Pod':
        require(name == ns + '-marker' and identity['namespace'] == ns
                and identity in receipt.value['objects'].values(), 'Unrecorded marker deletion')
    elif kind == 'PersistentVolumeClaim':
        require(name in claim_names(receipt.operation).values() and identity['namespace'] == ns
                and any(identity == row['identity']['claim'] for row in receipt.value['storage'].values()), 'Unrecorded claim deletion')
    elif kind in ('PersistentVolume', 'Volume'):
        require(any(identity == row['identity']['pv' if kind == 'PersistentVolume' else 'volume']
                    for row in receipt.value['storage'].values()), 'Unrecorded backing deletion')
        require(identity['namespace'] == (None if kind == 'PersistentVolume' else 'longhorn-system')
                and re.fullmatch(r'pvc-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', name), 'Backing deletion escaped scope')
    else:
        raise RuntimeError('Unsupported deletion authority')


def storage_class():
    value = get('storageclass', 'cloudlab-telemetry')
    require(value and value.get('provisioner') == 'driver.longhorn.io' and value.get('reclaimPolicy') == 'Retain'
            and value.get('volumeBindingMode') == 'Immediate' and value.get('allowVolumeExpansion') is True
            and value.get('parameters') == {'numberOfReplicas': '2', 'staleReplicaTimeout': '30', 'dataLocality': 'disabled',
                'fsType': 'ext4', 'recurringJobSelector': '[{"name":"telemetry-disposable","isGroup":true}]'},
            'Unsupported telemetry StorageClass')
    return {'uid': value['metadata']['uid'], 'spec': digest(canonical({k: v for k, v in value.items()
            if k not in ('metadata', 'kind', 'apiVersion')}))}


def storage_baseline():
    available = set()
    for node in listed('nodes.longhorn.io', 'longhorn-system'):
        if node.get('spec', {}).get('allowScheduling') is not True:
            continue
        if not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in node.get('status', {}).get('conditions', [])):
            continue
        for name, disk in node['spec'].get('disks', {}).items():
            info = node.get('status', {}).get('diskStatus', {}).get(name, {})
            if (disk.get('path') == '/var/lib/longhorn' and disk.get('allowScheduling') is True
                    and info.get('storageAvailable', 0) >= 4 * 1024 ** 3
                    and any(c.get('type') == 'Schedulable' and c.get('status') == 'True' for c in info.get('conditions', []))):
                available.add(node['metadata']['name'])
    require(len(available) >= 2, 'Two schedulable Longhorn nodes with bounded capacity are required')
    result = {'boundary': datetime.now(timezone.utc).replace(microsecond=0).isoformat(), 'class': storage_class(),
              'nodes': sorted(available)}
    for key, kind, ns in [('pvs', 'pv', None), ('volumes', 'volumes.longhorn.io', 'longhorn-system')]:
        objects = listed(kind, ns)
        result[key] = {field: sorted(digest(o['metadata'][field].encode()) for o in objects) for field in ('uid', 'name')}
    return result


def no_restore(volume):
    spec, status_value = volume.get('spec', {}), volume.get('status', {})
    require(not any(spec.get(k) for k in ('fromBackup', 'dataSource', 'cloneMode', 'backingImage', 'Standby', 'standby'))
            and not any(status_value.get(k) for k in ('restoreRequired', 'restoreInitiated', 'lastBackup', 'lastRestoredBackup'))
            and not any(status_value.get('cloneStatus', {}).get(k) for k in ('sourceVolume', 'snapshot', 'state')),
            'Restore, clone or backing-image data is outside synthetic scope')
    require(spec.get('size') == '1073741824' and spec.get('dataEngine', 'v1') == 'v1'
            and spec.get('accessMode', 'rwo') == 'rwo' and not spec.get('migratable') and not spec.get('encrypted'),
            'Unapproved Longhorn data profile')


def claim_names(operation):
    ns = namespace(operation)
    return {'grafana': ns + '-grafana', 'loki': 'storage-' + ns + '-loki-0', 'tempo': 'storage-' + ns + '-tempo-0'}


def fresh_identity(receipt, claim, healthy=True):
    baseline, ns = receipt.value['baseline'], receipt.namespace
    require(claim['metadata']['namespace'] == ns and claim['metadata']['name'] in claim_names(receipt.operation).values()
            and claim['metadata'].get('labels', {}).get('cloudlab.io/owner') == OWNER
            and claim['metadata']['labels'].get(LABEL) == receipt.operation
            and not claim['metadata'].get('ownerReferences')
            and set(claim['metadata'].get('finalizers', [])) <= {'kubernetes.io/pvc-protection'}, 'Unowned or additional claim')
    require(not claim['metadata'].get('deletionTimestamp') or any(
        intent['accepted'] and intent['identity'] == object_id(claim) for intent in receipt.value['intents'].values()),
        'Claim already deleting without accepted proof intent')
    spec, metadata = claim['spec'], claim['metadata']
    require(spec.get('storageClassName') == 'cloudlab-telemetry' and spec.get('accessModes') == ['ReadWriteOnce']
            and spec.get('resources', {}).get('requests') == {'storage': '1Gi'}
            and spec.get('volumeMode', 'Filesystem') == 'Filesystem'
            and not any(spec.get(k) for k in ('dataSource', 'dataSourceRef', 'selector', 'volumeAttributesClassName')),
            'Unapproved claim profile')
    if claim.get('status', {}).get('phase') != 'Bound':
        return None
    require(storage_class() == baseline['class'], 'StorageClass changed')
    require(metadata.get('annotations', {}).get('volume.kubernetes.io/storage-provisioner') == 'driver.longhorn.io',
            'Claim was not dynamically provisioned')
    expected = 'pvc-' + metadata['uid']
    require(spec.get('volumeName') == expected, 'PV name is not bound to the exact claim UID')
    pv = get('pv', expected)
    require(pv and pv['metadata'].get('annotations', {}).get('pv.kubernetes.io/provisioned-by') == 'driver.longhorn.io'
            and pv['spec'].get('claimRef', {}).get('uid') == metadata['uid']
            and pv['spec']['claimRef'].get('name') == metadata['name'] and pv['spec']['claimRef'].get('namespace') == ns
            and pv['spec'].get('storageClassName') == 'cloudlab-telemetry'
            and pv['spec'].get('capacity', {}).get('storage') == '1Gi'
            and pv['spec'].get('persistentVolumeReclaimPolicy') == 'Retain'
            and pv['spec'].get('csi', {}).get('driver') == 'driver.longhorn.io'
            and pv['spec']['csi'].get('volumeHandle') == expected, 'PV ownership or retention differs')
    volume = get('volumes.longhorn.io', expected, 'longhorn-system')
    require(volume and volume['spec'].get('numberOfReplicas') == 2, 'Unapproved Longhorn volume')
    no_restore(volume)
    created = datetime.fromisoformat(metadata['creationTimestamp'].replace('Z', '+00:00'))
    require(created >= datetime.fromisoformat(baseline['boundary']), 'Claim predates baseline')
    for kind, obj in [('pvs', pv), ('volumes', volume)]:
        m = obj['metadata']
        require(digest(m['uid'].encode()) not in baseline[kind]['uid']
                and digest(m['name'].encode()) not in baseline[kind]['name']
                and datetime.fromisoformat(m['creationTimestamp'].replace('Z', '+00:00')) >= created,
                'Preexisting backing cannot become deletion scope')
    link = volume.get('status', {}).get('kubernetesStatus', {})
    if not link.get('pvName') or not link.get('pvcName'):
        return None
    require(link.get('pvName') == expected and link.get('pvcName') == metadata['name'] and link.get('namespace') == ns,
            'Longhorn claim linkage differs')
    if healthy and volume.get('status', {}).get('robustness') != 'healthy':
        return None
    return {'claim': object_id(claim), 'pv': object_id(pv), 'volume': object_id(volume), 'handle': expected}


def bind_storage(receipt, *, fresh=False, healthy=True):
    claims = listed('pvc', receipt.namespace)
    expected = claim_names(receipt.operation)
    require({c['metadata']['name'] for c in claims} <= set(expected.values()), 'Additional claim blocks storage authority')
    if len(claims) != 3:
        return False
    for component, name in expected.items():
        claim = next(c for c in claims if c['metadata']['name'] == name)
        identity = fresh_identity(receipt, claim, healthy=healthy)
        if identity is None:
            return False
        receipt.record('claim-' + component, claim)
        if fresh:
            previous = receipt.value['storage'].get(component)
            require(previous is None or previous['identity'] == identity, 'Provisioned storage changed')
            receipt.value['storage'].setdefault(component, {'identity': identity})
        else:
            require(receipt.value['storage'][component]['identity'] == identity, 'Retained storage identity changed')
    require(len({s['identity']['handle'] for s in receipt.value['storage'].values()}) == 3, 'Claims alias one backing volume')
    record_attachments(receipt, healthy=healthy)
    receipt.save()
    return True


def record_attachments(receipt, *, healthy):
    csi = listed('volumeattachments.storage.k8s.io')
    native = listed('volumeattachments.longhorn.io', 'longhorn-system')
    for component, row in receipt.value['storage'].items():
        identity = row['identity']
        matches = [obj for obj in csi if obj.get('spec', {}).get('source', {}).get('persistentVolumeName') == identity['pv']['name']]
        if healthy and receipt.value.get('appPhase', 'running') == 'running':
            require(len(matches) == 1 and matches[0].get('status', {}).get('attached') is True,
                    'Running claim lacks one genuine CSI attachment')
        for attachment in matches:
            require(attachment['apiVersion'] == 'storage.k8s.io/v1' and attachment['kind'] == 'VolumeAttachment'
                    and attachment['spec'].get('attacher') == 'driver.longhorn.io'
                    and attachment['spec'].get('nodeName') in receipt.value['baseline']['nodes'], 'CSI attachment profile changed')
            receipt.record('csi-attachment-' + attachment['metadata']['uid'], attachment)
        native_matches = [obj for obj in native if obj.get('spec', {}).get('volume') == identity['handle']]
        require(len(native_matches) == 1 and native_matches[0]['apiVersion'] == 'longhorn.io/v1beta2'
                and native_matches[0]['metadata'].get('namespace') == 'longhorn-system', 'Native attachment linkage is incomplete')
        matches += native_matches
        evidence = []
        for attachment in matches:
            require(attachment['kind'] == 'VolumeAttachment', 'Unexpected native attachment kind')
            record = receipt.record('attachment-' + attachment['metadata']['uid'], attachment)
            evidence.append({'identity': record, 'spec': digest(canonical(attachment['spec']))})
        row.setdefault('attachments', []).append({'phase': receipt.value.get('appPhase', 'running'), 'objects': evidence})


def detached(receipt, component):
    identity = receipt.value['storage'][component]['identity']
    pv, volume = current(identity['pv']), current(identity['volume'])
    require(pv and volume, 'Retained storage disappeared')
    no_restore(volume)
    for attachment in listed('volumeattachments.storage.k8s.io'):
        if attachment.get('spec', {}).get('source', {}).get('persistentVolumeName') == identity['pv']['name']:
            require(attachment['spec'].get('attacher') == 'driver.longhorn.io', 'Foreign volume attachment')
            if attachment.get('status', {}).get('attached'):
                return False
    return (volume.get('status', {}).get('state') == 'detached' and not volume['spec'].get('nodeID')
            and not volume.get('status', {}).get('currentNodeID'))


def app_current(receipt, phase):
    app = root_current(receipt, 'app')
    expected = root_documents(receipt.operation)[2]['spec']
    expected['source']['helm']['valuesObject']['phase'] = phase
    require(app['spec'] == expected and app['metadata'].get('finalizers') == ['resources-finalizer.argocd.argoproj.io'],
            'Application authority or finalizer changed')
    return app


def converged(receipt, phase):
    app = app_current(receipt, phase)
    status_value = app.get('status', {})
    require(not any(c.get('type') in ('ComparisonError', 'InvalidSpecError', 'SyncError') for c in status_value.get('conditions', [])),
            'Application reports an error')
    if app.get('operation') or status_value.get('operationState', {}).get('phase') in ('Running', 'Terminating'):
        return False
    if (status_value.get('sync', {}).get('revision') != REVISION
            or status_value['sync'].get('comparedTo', {}).get('source') != app['spec']['source']
            or status_value['sync'].get('comparedTo', {}).get('destination') != app['spec']['destination']):
        return False
    if phase == 'removed':
        operation = status_value.get('operationState', {})
        skipped = [r for r in operation.get('syncResult', {}).get('resources', []) if r.get('status') == 'PruneSkipped']
        return (status_value['sync'].get('status') == 'OutOfSync' and operation.get('phase') == 'Succeeded'
                and operation.get('finishedAt') and operation.get('syncResult', {}).get('source') == app['spec']['source']
                and operation.get('syncResult', {}).get('revision') == REVISION
                and {(r.get('kind'), r.get('name')) for r in skipped} == {('PersistentVolumeClaim', receipt.namespace + '-grafana')})
    return status_value['sync'].get('status') == 'Synced' and status_value.get('health', {}).get('status') == 'Healthy'


def advance(receipt, phase):
    require(phase in PHASES, 'Unknown phase transition')
    current_phase = receipt.value.get('appPhase', 'running')
    if phase == current_phase:
        app_current(receipt, phase)
        return
    app = root_current(receipt, 'app')
    previous = root_documents(receipt.operation)[2]['spec']
    previous['source']['helm']['valuesObject']['phase'] = current_phase
    desired = copy.deepcopy(previous)
    desired['source']['helm']['valuesObject']['phase'] = phase
    key = 'phase-' + str(len(receipt.value.get('advances', [])))
    receipt.intention(key, object_id(app), {'from': current_phase, 'to': phase, 'spec': desired})
    pending = {'key': key, 'identity': object_id(app), 'from': current_phase, 'to': phase,
               'previous': previous, 'desired': desired}
    old = receipt.value.get('pendingAdvance')
    require(old is None or old == pending, 'Interrupted phase source differs')
    require(app['metadata'].get('finalizers') == ['resources-finalizer.argocd.argoproj.io']
            and not app['metadata'].get('deletionTimestamp')
            and (app['spec'] == previous or old == pending and app['spec'] == desired), 'Phase authority changed')
    receipt.value['pendingAdvance'] = pending
    receipt.save()
    patches = [{'op': 'test', 'path': '/metadata/uid', 'value': app['metadata']['uid']},
               {'op': 'test', 'path': '/metadata/resourceVersion', 'value': app['metadata']['resourceVersion']},
               {'op': 'test', 'path': '/spec', 'value': app['spec']}, {'op': 'replace', 'path': '/spec', 'value': desired}]
    returned = app if app['spec'] == desired else parsed(kubectl('patch', 'applications.argoproj.io', receipt.namespace, '-n', 'argocd',
                             '--type=json', '-p', json.dumps(patches), '-o', 'json'))
    require(object_id(returned) == object_id(app) and returned['spec'] == desired, 'Phase update changed authority')
    receipt.value['intents'][key]['accepted'] = True
    receipt.value['intents'][key]['complete'] = True
    receipt.value.setdefault('advances', []).append(phase)
    receipt.value['appPhase'] = phase
    receipt.value.pop('pendingAdvance')
    receipt.save()


def workload(receipt, component, replicas):
    kind = 'Deployment' if component == 'grafana' else 'StatefulSet'
    value = get(kind, receipt.namespace + '-' + component, receipt.namespace)
    require(value is not None and value['metadata'].get('labels', {}).get('cloudlab.io/owner') == OWNER
            and value['metadata']['labels'].get(LABEL) == receipt.operation, 'Native workload ownership differs')
    key = 'workload-' + component
    if key in receipt.value['objects']:
        require(object_id(value) == receipt.value['objects'][key], 'Native workload replaced unexpectedly')
    else:
        receipt.record(key, value)
    if value['spec'].get('replicas') != replicas:
        return None
    if value.get('status', {}).get('observedGeneration') != value['metadata']['generation']:
        return None
    if replicas == 1 and not (value['status'].get('readyReplicas') == 1 and value['status'].get('updatedReplicas') == 1):
        return None
    return value


def source_spec(actual, expected):
    """Use Kubernetes defaulted declared fields; reject extra executable sources."""
    a, b = copy.deepcopy(actual), copy.deepcopy(expected)
    a.pop('nodeName', None)
    for value in (a, b):
        volumes = value.get('volumes', [])
        if len({v.get('name') for v in volumes}) != len(volumes):
            return False
        if 'volumes' in value:
            value['volumes'] = sorted(volumes, key=lambda v: v['name'])
    return a.get('automountServiceAccountToken') is False and admission_source(a, b)


def admission_source(actual, expected):
    """Allow enumerated built-in defaults, never admission-added authority or code."""
    a, b = copy.deepcopy(actual), copy.deepcopy(expected)
    if 'priority' not in b and type(a.get('priority')) is int and a['priority'] == 0:
        a.pop('priority')
    tolerations = [{'key': 'node.kubernetes.io/' + key, 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300}
                   for key in ('not-ready', 'unreachable')]
    if not b.get('tolerations') and a.get('tolerations') in (tolerations, list(reversed(tolerations))):
        a.pop('tolerations')
        b.pop('tolerations', None)
    for key, default in {'dnsPolicy': 'ClusterFirst', 'restartPolicy': 'Always', 'schedulerName': 'default-scheduler',
                         'terminationGracePeriodSeconds': 30, 'enableServiceLinks': True,
                         'preemptionPolicy': 'PreemptLowerPriority'}.items():
        if key not in b and key in a:
            if a[key] != default:
                return False
            a.pop(key)
    if 'serviceAccount' in a and 'serviceAccount' not in b:
        if a['serviceAccount'] != b.get('serviceAccountName'):
            return False
        a.pop('serviceAccount')
    if len(a.get('containers', [])) != len(b.get('containers', [])):
        return False
    for left, right in zip(a.get('containers', []), b.get('containers', [])):
        for key, default in {'terminationMessagePath': '/dev/termination-log', 'terminationMessagePolicy': 'File',
                             'imagePullPolicy': 'IfNotPresent'}.items():
            if key not in right and key in left:
                if left[key] != default:
                    return False
                left.pop(key)
        for left_port, right_port in zip(left.get('ports', []), right.get('ports', [])):
            if 'protocol' not in right_port and left_port.get('protocol') == 'TCP':
                left_port.pop('protocol')
        for key in ('livenessProbe', 'readinessProbe', 'startupProbe'):
            if key in left and key in right:
                for field, default in {'timeoutSeconds': 1, 'periodSeconds': 10, 'successThreshold': 1, 'failureThreshold': 3}.items():
                    if field not in right[key] and field in left[key]:
                        if left[key][field] != default:
                            return False
                        left[key].pop(field)
                if 'httpGet' in left[key] and 'httpGet' in right[key]:
                    for field, default in {'scheme': 'HTTP', 'path': '/'}.items():
                        if field not in right[key]['httpGet'] and field in left[key]['httpGet']:
                            if left[key]['httpGet'][field] != default:
                                return False
                            left[key]['httpGet'].pop(field)
        for left_env, right_env in zip(left.get('env', []), right.get('env', [])):
            left_ref = left_env.get('valueFrom', {}).get('fieldRef', {})
            right_ref = right_env.get('valueFrom', {}).get('fieldRef', {})
            if 'apiVersion' not in right_ref and left_ref.get('apiVersion') == 'v1':
                left_ref.pop('apiVersion')
        for mount in left.get('volumeMounts', []) + right.get('volumeMounts', []):
            if mount.get('subPath', False) is None:
                mount.pop('subPath')
            if mount.get('readOnly', None) is False:
                mount.pop('readOnly')
    for spec in (a, b):
        for volume in spec.get('volumes', []):
            for source in ('configMap', 'secret'):
                if source in volume and volume[source].get('defaultMode') is None:
                    volume[source]['defaultMode'] = 420
    return a == b


def validate_workloads(receipt, payload, replicas):
    desired = {o['metadata']['name']: o for o in payload['phases']['running'] if o['kind'] in ('Deployment', 'StatefulSet')}
    for component in ('loki', 'tempo', 'grafana'):
        obj = workload(receipt, component, replicas)
        if obj is None:
            return False
        expected = desired[obj['metadata']['name']]
        # The defaulted profile is captured by server admission before Argo creates resources.
        admitted = receipt.value['admission']['running'][obj['kind'] + '/' + obj['metadata']['name']]
        require(obj['spec']['template']['spec'] == admitted['spec']['template']['spec'], 'Native workload execution profile drifted')
        if obj['kind'] == 'StatefulSet':
            require(obj['spec'].get('persistentVolumeClaimRetentionPolicy', {'whenDeleted': 'Retain', 'whenScaled': 'Retain'})
                    == expected['spec'].get('persistentVolumeClaimRetentionPolicy', {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}),
                    'Native StatefulSet retention changed')
    return True


def workload_pods(receipt):
    return [p for p in listed('pods', receipt.namespace) if p['metadata']['name'] != receipt.namespace + '-marker']


def record_native_children(receipt, *, require_ready=True, known_only=False):
    require(not known_only or not require_ready, 'Strict pruning checks do not assess readiness')
    roots = {row['uid']: key.removeprefix('workload-') for key, row in receipt.value['objects'].items() if key.startswith('workload-')}
    replicas = listed('replicasets.apps', receipt.namespace)
    known = list(receipt.value['objects'].values())
    parents = dict(roots)
    if known_only:
        recorded = recorded_grafana_replicasets(receipt)
        parents.update({obj['uid']: 'grafana' for obj in known if (obj['kind'], obj['name']) in recorded})
    for item in replicas:
        owners = item['metadata'].get('ownerReferences', [])
        require(len(owners) == 1 and owners[0].get('uid') in roots and owners[0].get('kind') == 'Deployment'
                and owners[0].get('controller') is True, 'Foreign ReplicaSet')
        if known_only:
            require(object_id(item) in known, 'Unrecorded ReplicaSet during pruning')
            deployment = receipt.value['objects']['workload-grafana']
            require(owners[0].get('uid') == deployment['uid'] and owners[0].get('name') == deployment['name'],
                    'ReplicaSet parent changed during pruning')
            source = receipt.value['admission']['running']['Deployment/' + receipt.namespace + '-grafana']['spec']['template']
            require(source_spec(item['spec']['template']['spec'], source['spec'])
                    and all(item['metadata'].get('labels', {}).get(k) == v for k, v in source['metadata'].get('labels', {}).items()),
                    'ReplicaSet source changed during pruning')
        else:
            receipt.record('rs-' + item['metadata']['name'], item)
        parents[item['metadata']['uid']] = roots[owners[0]['uid']]
    pods = listed('pods', receipt.namespace) if known_only else workload_pods(receipt)
    for item in pods:
        if known_only:
            require(object_id(item) in known and item['metadata']['name'] != receipt.namespace + '-marker',
                    'Unrecorded or reappeared marker Pod during pruning')
        owners = item['metadata'].get('ownerReferences', [])
        require(len(owners) == 1 and owners[0].get('uid') in parents and owners[0].get('controller') is True,
                'Foreign workload Pod')
        component = parents[owners[0]['uid']]
        if known_only:
            parent = next(obj for obj in known if obj['uid'] == owners[0]['uid'])
            require(owners[0].get('kind') == ('ReplicaSet' if component == 'grafana' else 'StatefulSet')
                    and owners[0].get('name') == parent['name'] and owners[0].get('apiVersion') == parent['apiVersion'],
                    'Native Pod parent changed during pruning')
        kind = 'Deployment' if component == 'grafana' else 'StatefulSet'
        workload_doc = receipt.value['admission']['running'][kind + '/' + receipt.namespace + '-' + component]
        expected = copy.deepcopy(workload_doc['spec']['template']['spec'])
        if kind == 'StatefulSet':
            require(item['metadata']['name'] == receipt.namespace + '-' + component + '-0', 'Unexpected native ordinal')
            expected.setdefault('volumes', []).append({'name': 'storage', 'persistentVolumeClaim': {
                'claimName': claim_names(receipt.operation)[component]}})
            expected['hostname'] = item['metadata']['name']
            expected['subdomain'] = workload_doc['spec']['serviceName']
        require(item['spec'].get('nodeName') in receipt.value['baseline']['nodes'], 'Backend placed outside recorded native nodes')
        require(source_spec(item['spec'], expected), 'Native backend Pod source changed')
        if known_only:
            require(all(item['metadata'].get('labels', {}).get(k) == v
                        for k, v in workload_doc['spec']['template']['metadata'].get('labels', {}).items()),
                    'Native Pod ownership changed during pruning')
        else:
            receipt.record('pod-' + item['metadata']['uid'], item)
        statuses = item.get('status', {}).get('containerStatuses', [])
        if not require_ready:
            continue
        require(len(statuses) == 1 and type(statuses[0].get('restartCount')) is int and statuses[0]['restartCount'] == 0
                and statuses[0].get('name') == expected['containers'][0]['name'], 'Native backend restarted or is ambiguous')
        if not statuses[0].get('state', {}).get('running'):
            return False
        if not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in item.get('status', {}).get('conditions', [])):
            return False
    if known_only:
        return not replicas and not pods
    return not require_ready or len(workload_pods(receipt)) == 3


MARKER_PROGRAM = '''import hashlib,json,os,stat,sys
mode,leaf,content=sys.argv[1:]
assert mode in ('write','read') and len(content)==64 and all(c in '0123456789abcdef' for c in content)
prefix='.cloudlab-storage-'
assert leaf.startswith(prefix) and len(leaf)==len(prefix)+16 and all(c in '0123456789abcdef' for c in leaf[len(prefix):])
directory=os.open('/state',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL if mode=='write' else os.O_RDONLY
 fd=os.open(leaf,flags|os.O_NOFOLLOW,0o600,dir_fd=directory)
 with os.fdopen(fd,'wb' if mode=='write' else 'rb') as stream:
  info=os.fstat(stream.fileno()); assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
  if mode=='write': stream.write(content.encode()); stream.flush(); os.fsync(stream.fileno()); os.fsync(directory)
  else: assert info.st_size==64 and stream.read(65)==content.encode()
 print(json.dumps({'markerVerified':True,'sha256':hashlib.sha256(content.encode()).hexdigest()},sort_keys=True))
finally: os.close(directory)
'''


def marker_document(receipt, payload, component, mode):
    require(component in ('loki', 'tempo', 'grafana') and mode in ('write', 'read'), 'Invalid marker request')
    ns, identity = receipt.namespace, receipt.value['storage'][component]['identity']
    expected_name = claim_names(receipt.operation)[component]
    require(identity['claim']['name'] == expected_name and identity['claim']['namespace'] == ns, 'Marker claim scope differs')
    kind = 'Deployment' if component == 'grafana' else 'StatefulSet'
    workload_doc = next(o for o in payload['phases']['running'] if o['kind'] == kind and o['metadata']['name'] == ns + '-' + component)
    pod = workload_doc['spec']['template']['spec']
    security = pod['securityContext']
    require(security.get('runAsNonRoot') is True and security.get('runAsUser') in (472, 10001)
            and security.get('runAsGroup') == security['runAsUser'] and security.get('fsGroup') == security['runAsUser'],
            'Unexpected native marker identity')
    mounts = [m for m in pod['containers'][0]['volumeMounts'] if m['name'] == 'storage']
    require(len(mounts) == 1 and not mounts[0].get('readOnly') and not mounts[0].get('subPathExpr')
            and mounts[0].get('subPath') in (None, ''), 'Unsupported native marker subpath')
    marker = receipt.value['markers'][component]
    require(marker['content'] == marker_content(receipt, component) and marker['claimUID'] == identity['claim']['uid']
            and marker['sha256'] == digest(marker['content'].encode()), 'Marker evidence changed')
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': ns + '-marker', 'namespace': ns,
        'labels': {'cloudlab.io/owner': OWNER, LABEL: receipt.operation, 'cloudlab.io/storage-marker': 'true'}},
        'spec': {'restartPolicy': 'Never', 'activeDeadlineSeconds': 180, 'automountServiceAccountToken': False,
            'serviceAccountName': 'default', 'enableServiceLinks': False,
            'securityContext': {'runAsNonRoot': True, 'runAsUser': security['runAsUser'], 'runAsGroup': security['runAsGroup'],
                                'fsGroup': security['fsGroup'], 'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': 'marker', 'image': PYTHON_IMAGE,
                'command': ['python', '-c', MARKER_PROGRAM, mode, '.cloudlab-storage-' + receipt.operation, marker['content']],
                'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}},
                'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                                    'capabilities': {'drop': ['ALL']}},
                'volumeMounts': [{'name': 'state', 'mountPath': '/state'} | ({'readOnly': True} if mode == 'read' else {})]}],
            'volumes': [{'name': 'state', 'persistentVolumeClaim': {'claimName': expected_name} |
                         ({'readOnly': True} if mode == 'read' else {})}]}}


def marker_content(receipt, component):
    require(component in ('loki', 'tempo', 'grafana'), 'Invalid marker slot')
    return digest(canonical({'profile': PROFILE, 'operation': receipt.operation, 'component': component,
                             'claimUID': receipt.value['storage'][component]['identity']['claim']['uid']}))


def marker_claim(receipt, component):
    identity = receipt.value['storage'][component]['identity']
    claim = current(identity['claim'])
    require(claim is not None and fresh_identity(receipt, claim, healthy=False) == identity,
            'Recorded marker claim or backing identity changed')


def require_marker_verification(receipt, record, identity):
    component = record['component']
    evidence = record.get('verifiedIO')
    expected = {'identity': identity, 'document': record['document'], 'mode': record['mode'],
                'claimUID': receipt.value['storage'][component]['identity']['claim']['uid'],
                'sha256': receipt.value['markers'][component]['sha256']}
    require(type(evidence) is dict and type(evidence.get('finishedAt')) is str and evidence['finishedAt']
            and evidence == expected | {'finishedAt': evidence['finishedAt']}, 'Marker lacks verified I/O evidence')


def marker_io(receipt, payload, component, mode, deadline):
    ns = receipt.namespace
    require(receipt.value.get('appPhase') in ('scaled-down', 'removed'), 'Marker I/O requires an accepted stopped phase')
    marker_claim(receipt, component)
    app_current(receipt, receipt.value['appPhase'])
    project_guard(receipt, deadline=deadline)
    require(not workload_pods(receipt), 'Workloads must be absent before marker I/O')
    if component not in receipt.value['markers']:
        require(mode == 'write', 'Missing marker write evidence')
        content = marker_content(receipt, component)
        receipt.value['markers'][component] = {'content': content, 'sha256': digest(content.encode()),
            'claimUID': receipt.value['storage'][component]['identity']['claim']['uid']}
        receipt.save()
    document = marker_document(receipt, payload, component, mode)
    runs = receipt.value.setdefault('markerRuns', [])
    matches = [(index, run) for index, run in enumerate(runs) if run['component'] == component and run['mode'] == mode]
    require(len(matches) <= 1, 'Duplicate marker intent')
    if matches:
        index, record = matches[0]
        require(record['document'] == digest(canonical(document)), 'Marker intent source changed')
        expected = record['admittedSpec']
    else:
        require(get('pod', ns + '-marker', ns) is None, 'Existing marker Pod cannot be adopted')
        wait('exclusive detached marker claim', lambda: detached(receipt, component), deadline)
        admitted = parsed(kubectl('create', '--dry-run=server', '-f', '-', '-o', 'json', body=canonical(document)))
        expected = admitted['spec']
        require(admission_source(expected, document['spec'])
                and admitted['metadata'].get('labels') == document['metadata']['labels']
                and not admitted['metadata'].get('ownerReferences') and not admitted['metadata'].get('finalizers'),
                'Marker admission changed execution source')
        index = len(runs)
        record = {'component': component, 'mode': mode, 'document': digest(canonical(document)),
                  'admittedSpec': expected, 'accepted': False, 'complete': False}
        runs.append(record)
        receipt.save()
    require(admission_source(expected, document['spec']), 'Recorded marker admission differs')
    # Default SA must already be real, credential-free and not used by any other proof Pod.
    account = get('serviceaccount', 'default', ns)
    require(account and not account.get('secrets') and not account.get('imagePullSecrets'), 'Marker service account unavailable')
    def marker_profile(value):
        spec = copy.deepcopy(value['spec'])
        node = spec.pop('nodeName', '')
        require(not node or node in receipt.value['baseline']['nodes'], 'Marker placed outside recorded native nodes')
        require(spec == expected and not value['metadata'].get('ownerReferences')
                and not value['metadata'].get('finalizers') and value['metadata'].get('labels') == document['metadata']['labels'],
                'Marker source or ownership changed')
    key = 'marker-' + str(index)
    if record['accepted']:
        identity = receipt.value['objects'][key]
        deletion = receipt.value['intents'].get('delete-' + key)
        if deletion:
            require_marker_verification(receipt, record, identity)
            require(deletion['accepted'], 'Ambiguous marker deletion acknowledgment')
            finish_delete(receipt, 'delete-' + key, deadline)
            wait('marker volume detach', lambda: detached(receipt, component), deadline)
            record['complete'] = True
            receipt.save()
            return
        require(not record['complete'], 'Completed marker reappeared')
        obj = current(identity)
        require(obj is not None, 'Accepted marker disappeared without deletion intent')
        marker_profile(obj)
    else:
        require(get('pod', ns + '-marker', ns) is None, 'Ambiguous marker creation; retain unknown identity')
        obj = parsed(kubectl('create', '-f', '-', '-o', 'json', body=canonical(document)))
        require(obj['metadata'].get('namespace') == ns and obj['metadata'].get('name') == ns + '-marker', 'Marker creation changed identity')
        marker_profile(obj)
        identity = receipt.record(key, obj)
        record['accepted'] = True
        receipt.save()
    def complete():
        value = current(identity)
        require(value is not None, 'Marker disappeared')
        marker_profile(value)
        state = value.get('status', {})
        require(state.get('phase') not in ('Failed', 'Unknown'), 'Marker Pod failed')
        rows = state.get('containerStatuses', [])
        if not rows:
            return False
        require(len(rows) == 1 and rows[0].get('name') == 'marker' and type(rows[0].get('restartCount')) is int
                and rows[0]['restartCount'] == 0, 'Marker process restarted or changed')
        terminal = rows[0].get('state', {}).get('terminated')
        if not terminal:
            return False
        require(type(terminal.get('exitCode')) is int and terminal['exitCode'] == 0, 'Marker process failed')
        return value if state.get('phase') == 'Succeeded' and terminal.get('finishedAt') else False
    done = wait('fixed marker completion', complete, deadline, 240)
    raw = kubectl('logs', identity['name'], '-n', ns, '--limit-bytes=1024')
    result = parsed(raw)
    require(result == {'markerVerified': True, 'sha256': receipt.value['markers'][component]['sha256']}, 'Marker result differs')
    delete_obj = current(identity)
    marker_profile(delete_obj)
    record['verifiedIO'] = {'identity': identity, 'document': record['document'], 'mode': mode,
        'claimUID': receipt.value['storage'][component]['identity']['claim']['uid'], 'sha256': result['sha256'],
        'finishedAt': done['status']['containerStatuses'][0]['state']['terminated']['finishedAt']}
    require_marker_verification(receipt, record, identity)
    receipt.save()
    request_delete(receipt, 'delete-' + key, delete_obj, {'profile': PROFILE, 'marker': identity, 'document': digest(canonical(document))})
    finish_delete(receipt, 'delete-' + key, deadline)
    wait('marker volume detach', lambda: detached(receipt, component), deadline)
    receipt.value['markerRuns'][index]['complete'] = True
    receipt.save()


DIRECTORY_SCRIPT = ('set -eu; for directory in "$1" "$2"; do test -d "$directory"; test ! -L "$directory"; '
    'test -r "$directory"; test -x "$directory"; stat -c %d:%i "$directory"; done; '
    'if test -e "$3" || test -L "$3"; then test -d "$3"; test ! -L "$3"; stat -c %d:%i "$3"; '
    'printf "present\\n"; else printf "%s\\n%s\\n" - absent; fi')


def inspector_identity(pod):
    require(pod is not None and pod.get('metadata', {}).get('labels', {}).get('app') == 'longhorn-manager', 'Missing native inspector')
    rows = [r for r in pod.get('status', {}).get('containerStatuses', []) if r.get('name') == 'longhorn-manager']
    require(len(rows) == 1 and rows[0].get('state', {}).get('running') and type(rows[0].get('restartCount')) is int
            and re.fullmatch(r'containerd://[a-f0-9]{64}', rows[0].get('containerID', '')), 'Unstable native inspector')
    return {'uid': pod['metadata']['uid'], 'node': pod['spec']['nodeName'], 'containerID': rows[0]['containerID'],
            'startedAt': rows[0]['state']['running']['startedAt'], 'restarts': rows[0]['restartCount']}


def validate_replica_rows(rows):
    require(type(rows) is list and len(rows) == 2 and len({r['node'] for r in rows}) == 2
            and len({r['replicaUID'] for r in rows}) == 2, 'Two independent replicas are required')
    for row in rows:
        require(row['disk'] == '/var/lib/longhorn' and row['parent'] == '/var/lib/longhorn/replicas'
                and re.fullmatch(r'/var/lib/longhorn/replicas/[A-Za-z0-9_-]+', row['path'])
                and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', row['manager'])
                and UID.fullmatch(row['replicaUID']) and UID.fullmatch(row['inspector']['uid'])
                and row['node'] == row['inspector']['node'] and row['context']['present'] is True
                and all(re.fullmatch(r'[0-9]+:[0-9]+', row['context'][k]) for k in ('disk', 'parent'))
                and re.fullmatch(r'[0-9]+:[0-9]+', row['context']['replica'])
                and row['context']['disk'].split(':')[0] == row['context']['parent'].split(':')[0]
                == row['context']['replica'].split(':')[0], 'Unsafe replica context')


def directory_state(row):
    require(row['disk'] == '/var/lib/longhorn' and row['parent'] == row['disk'] + '/replicas'
            and re.fullmatch(re.escape(row['parent']) + r'/[A-Za-z0-9_-]+', row['path']), 'Unsafe replica path')
    before = get('pod', row['manager'], 'longhorn-system')
    require(inspector_identity(before) == row['inspector'], 'Replica inspector changed')
    raw = kubectl('exec', '-n', 'longhorn-system', row['manager'], '-c', 'longhorn-manager', '--', 'sh', '-ec',
                  DIRECTORY_SCRIPT, '_', row['disk'], row['parent'], row['path'])
    require(inspector_identity(get('pod', row['manager'], 'longhorn-system')) == row['inspector'], 'Replica inspector changed during read')
    lines = raw.decode('ascii').splitlines()
    require(len(lines) == 4 and all(re.fullmatch(r'[0-9]+:[0-9]+', v) for v in lines[:2])
            and lines[3] in ('present', 'absent'), 'Invalid backing evidence')
    if lines[3] == 'present':
        require(re.fullmatch(r'[0-9]+:[0-9]+', lines[2])
                and lines[0].split(':')[0] == lines[1].split(':')[0] == lines[2].split(':')[0], 'Backing crossed devices')
    else:
        require(lines[2] == '-', 'Invalid absence evidence')
    return {'disk': lines[0], 'parent': lines[1], 'replica': lines[2] if lines[3] == 'present' else None,
            'present': lines[3] == 'present'}


def capture_replicas(identity):
    rows = []
    managers = listed('pods', 'longhorn-system')
    for replica in listed('replicas.longhorn.io', 'longhorn-system'):
        spec = replica.get('spec', {})
        if spec.get('volumeName') != identity['handle']:
            continue
        matches = [p for p in managers if p.get('metadata', {}).get('labels', {}).get('app') == 'longhorn-manager'
                   and p.get('spec', {}).get('nodeName') == spec.get('nodeID')]
        require(len(matches) == 1 and spec.get('diskPath') == '/var/lib/longhorn'
                and re.fullmatch(re.escape(identity['handle']) + r'-[a-f0-9]{8}', spec.get('dataDirectoryName', '')),
                'Unqualified replica inspector')
        row = {'node': spec['nodeID'], 'replicaUID': replica['metadata']['uid'], 'manager': matches[0]['metadata']['name'],
               'inspector': inspector_identity(matches[0]), 'disk': '/var/lib/longhorn', 'parent': '/var/lib/longhorn/replicas',
               'path': '/var/lib/longhorn/replicas/' + spec['dataDirectoryName']}
        row['context'] = directory_state(row)
        rows.append(row)
    validate_replica_rows(rows)
    return rows


def backing_absent(rows):
    validate_replica_rows(rows)
    for row in rows:
        now = directory_state(row)
        require(now['disk'] == row['context']['disk'] and now['parent'] == row['context']['parent'], 'Backing parent changed')
        if now['present']:
            return False
    return True


def body_profile(obj):
    result = {k: copy.deepcopy(v) for k, v in obj.items() if k not in ('metadata', 'status')}
    if obj['kind'] == 'Service':
        for key in ('clusterIP', 'clusterIPs'):
            if result['spec'].get(key) not in ('None', ['None']):
                result['spec'].pop(key, None)
    if obj['kind'] == 'PersistentVolumeClaim':
        result['spec'].pop('volumeName', None)
    return result


def observe_declared(receipt, payload, *, partial=False):
    for desired in payload['phases']['running']:
        key = desired['kind'] + '/' + desired['metadata']['name']
        actual = get(desired['kind'], desired['metadata']['name'], receipt.namespace)
        if actual is None and partial:
            continue
        require(actual is not None, 'Declared resource absent before retention transition')
        admitted = [receipt.value['admission'][phase][key] for phase in ('running', 'scaled-down')]
        require(any(body_profile(actual) == body_profile(profile) for profile in admitted), 'Declared resource body changed')
        labels = actual['metadata'].get('labels', {})
        require(labels.get('cloudlab.io/owner') == OWNER and labels.get(LABEL) == receipt.operation,
                'Declared resource ownership changed')
        group = actual['apiVersion'].split('/')[0] if '/' in actual['apiVersion'] else ''
        tracking = receipt.namespace + ':' + group + '/' + actual['kind'] + ':' + receipt.namespace + '/' + actual['metadata']['name']
        require(actual['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') == tracking,
                'Declared resource lacks exact Argo tracking')
        receipt.record('declared-' + key, actual)
        if actual['kind'] in ('StatefulSet', 'Deployment'):
            component = actual['metadata']['name'].removeprefix(receipt.namespace + '-')
            receipt.record('workload-' + component, actual)


def namespace_inventory(ns):
    groups = parsed(kubectl('get', '--raw', '/apis')).get('groups')
    require(type(groups) is list and len(groups) <= 256, 'API discovery exceeds bound')
    versions = ['v1']
    group_names = set()
    for group in groups:
        require(type(group.get('name')) is str and re.fullmatch(r'[a-z0-9.-]+', group['name'])
                and group['name'] not in group_names and type(group.get('versions')) is list
                and 0 < len(group['versions']) <= 32, 'Malformed API group discovery')
        group_names.add(group['name'])
        require(all(type(row.get('groupVersion')) is str and row['groupVersion'].startswith(group['name'] + '/')
                    and row.get('version', row['groupVersion'].split('/')[-1]) == row['groupVersion'].split('/')[-1]
                    for row in group['versions']), 'Contradictory API group version')
        preferred = group['preferredVersion']['groupVersion']
        require(preferred in [v['groupVersion'] for v in group['versions']], 'Incomplete preferred API discovery')
        versions.extend([preferred] + [v['groupVersion'] for v in group['versions'] if v['groupVersion'] != preferred])
    collections = {}
    for version in dict.fromkeys(versions):
        require(version == 'v1' or re.fullmatch(r'[a-z0-9.-]+/v[0-9]+(?:(?:alpha|beta)[0-9]+)?', version), 'Invalid API discovery version')
        root = '/api/v1' if version == 'v1' else '/apis/' + version
        discovery = parsed(kubectl('get', '--raw', root))
        require(discovery.get('groupVersion') == version and type(discovery.get('resources')) is list
                and len(discovery['resources']) <= 1024, 'Incomplete API discovery')
        group = version.split('/')[0] if '/' in version else ''
        for row in discovery['resources']:
            name = row.get('name', '')
            require(type(row.get('namespaced')) is bool and type(row.get('verbs')) is list
                    and all(type(verb) is str for verb in row['verbs'])
                    and type(row.get('kind')) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9]+', row['kind']), 'Malformed resource discovery')
            # Projected metrics/review APIs do not store namespace-owned objects.
            if row['namespaced'] and {'list', 'delete'} <= set(row['verbs']) and '/' not in name:
                require(re.fullmatch(r'[a-z0-9.-]+', name), 'Invalid discovered resource path')
                key = (group, name)
                require(key not in collections or collections[key]['kind'] == row['kind'], 'Contradictory API resource discovery')
                collections.setdefault(key, {'path': root + '/namespaces/' + ns + '/' + name,
                                              'kind': row['kind'], 'version': version})
    require(len(collections) <= 1024, 'Namespace discovery exceeds bound')
    result = {}
    origins = {}
    for collection in collections.values():
        path, kind, version = (collection[key] for key in ('path', 'kind', 'version'))
        token, seen, resource_version, collection_uids = '', set(), None, set()
        for _ in range(32):
            query = {'limit': '100'} | ({'continue': token} if token else {})
            page = parsed(kubectl('get', '--raw', path + '?' + urlencode(query)))
            require(page.get('apiVersion') == version and page.get('kind') == kind + 'List'
                    and type(page.get('items')) is list and type(page.get('metadata')) is dict
                    and type(page['metadata'].get('resourceVersion')) is str and page['metadata']['resourceVersion'],
                    'Incomplete namespace inventory')
            require(resource_version is None or resource_version == page['metadata']['resourceVersion'], 'Inventory snapshot changed during pagination')
            resource_version = page['metadata']['resourceVersion']
            for obj in page['items']:
                require(type(obj) is dict and obj.get('kind', kind) == kind and obj.get('apiVersion', version) == version,
                        'Discovered resource TypeMeta contradicts its collection')
                obj = copy.deepcopy(obj)
                obj.setdefault('kind', kind)
                obj.setdefault('apiVersion', version)
                require(obj.get('metadata', {}).get('namespace') == ns and UID.fullmatch(obj['metadata'].get('uid', '')),
                        'Namespace inventory identity mismatch')
                uid = obj['metadata']['uid']
                require(uid not in collection_uids and type(obj['metadata'].get('name')) is str
                        and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', obj['metadata']['name']), 'Repeated or malformed namespace identity')
                object_id(obj)
                collection_uids.add(uid)
                if uid in result:
                    prior = result[uid]
                    require(origins[uid] != path and prior['kind'] == obj['kind'] == 'Event'
                            and {origins[uid].split('/namespaces/')[0], path.split('/namespaces/')[0]}
                            == {'/api/v1', '/apis/events.k8s.io/v1'}
                            and prior['metadata']['name'] == obj['metadata']['name']
                            and event_reference(prior) == event_reference(obj), 'Aliased inventory identity differs')
                    if version == 'v1':
                        result[uid] = obj
                else:
                    result[uid] = obj
                    origins[uid] = path
                require(len(result) <= 1024, 'Namespace inventory exceeds bound')
            token = page.get('metadata', {}).get('continue', '')
            require(type(token) is str, 'Invalid namespace inventory pagination')
            remaining = page['metadata'].get('remainingItemCount')
            require(remaining is None or type(remaining) is int and remaining >= 0 and (token or remaining == 0),
                    'Incomplete namespace inventory pagination')
            if not token:
                break
            require(token not in seen, 'Namespace inventory pagination repeats')
            seen.add(token)
        else:
            raise RuntimeError('Namespace inventory incomplete')
    for obj in result.values():
        if obj['kind'] == 'Event' and obj['apiVersion'] == 'events.k8s.io/v1':
            obj['apiVersion'] = 'v1'
            obj['involvedObject'] = obj.pop('regarding')
            if 'reportingController' in obj:
                obj['reportingComponent'] = obj.pop('reportingController')
    return sorted(result.values(), key=lambda obj: (obj['kind'], obj['metadata']['name'], obj['metadata']['uid']))


def event_reference(obj):
    reference = obj.get('involvedObject') if obj['apiVersion'] == 'v1' else obj.get('regarding')
    require(type(reference) is dict and UID.fullmatch(reference.get('uid', ''))
            and reference.get('apiVersion') and reference.get('kind') and reference.get('name')
            and set(reference) <= {'apiVersion', 'kind', 'name', 'namespace', 'uid', 'fieldPath', 'resourceVersion'}
            and all(type(reference.get(key, '')) is str for key in ('apiVersion', 'kind', 'name', 'namespace', 'fieldPath', 'resourceVersion')),
            'Malformed native Event reference')
    result = {key: reference.get(key, '') for key in ('apiVersion', 'kind', 'name', 'namespace', 'uid', 'fieldPath', 'resourceVersion')}
    alternate = obj.get('regarding' if obj['apiVersion'] == 'v1' else 'involvedObject')
    require(alternate is None or type(alternate) is dict and result == {key: alternate.get(key, '') for key in result},
            'Contradictory Event references')
    return result


def inventory_gate(receipt):
    root_current(receipt, 'namespace')
    records = list(receipt.value['objects'].values())
    records += [identity for storage in receipt.value['storage'].values() for identity in storage['identity'].values() if type(identity) is dict]
    known = {r['uid']: r for r in records}
    services = {r['name'] for r in records if r['kind'] == 'Service'}
    all_known = set(known)
    housekeeping_rows = {row['identity']['uid']: row for row in receipt.value.get('housekeeping', {}).values()}
    inventory = namespace_inventory(receipt.namespace)
    for obj in sorted(inventory, key=lambda o: {'ControllerRevision': 0, 'ReplicaSet': 0, 'EndpointSlice': 0,
                                               'Endpoints': 1, 'Event': 2}.get(o['kind'], 0)):
        metadata, kind = obj['metadata'], obj['kind']
        uid = metadata['uid']
        if uid in housekeeping_rows:
            require(housekeeping_identity(obj, receipt.namespace, receipt.value['evidence']['namespaceCreatedAt'],
                                          receipt.value['evidence']['housekeepingRoots']) == housekeeping_rows[uid],
                    'Housekeeping provenance or data changed')
            continue
        if uid in known:
            expected = known[uid]
            require(kind == expected['kind'] and metadata['name'] == expected['name']
                    and metadata['namespace'] == expected['namespace'], 'Known namespace identity changed')
            continue
        if kind == 'Event':
            involved = obj.get('involvedObject', obj.get('regarding', {}))
            require(obj['apiVersion'] == 'v1' and involved.get('uid') in known and involved.get('namespace') == receipt.namespace,
                    'Foreign namespace Event')
            continue
        owners = metadata.get('ownerReferences') or []
        if kind in ('ControllerRevision', 'ReplicaSet', 'EndpointSlice'):
            expected_owner = {'ControllerRevision': 'StatefulSet', 'ReplicaSet': 'Deployment', 'EndpointSlice': 'Service'}[kind]
            require(len(owners) == 1 and owners[0].get('controller') is True and owners[0].get('kind') == expected_owner
                    and owners[0].get('uid') in known and metadata['name'].startswith(owners[0]['name'] + '-'),
                    'Unknown native child')
            receipt.record('observed-' + uid, obj)
            known[uid] = object_id(obj)
            all_known.add(uid)
            continue
        if kind == 'Endpoints':
            require(metadata['name'] in services and not owners and all(
                address.get('targetRef', {}).get('uid') in all_known for subset in obj.get('subsets', [])
                for address in subset.get('addresses', []) + subset.get('notReadyAddresses', [])), 'Unknown native Endpoints')
            receipt.record('observed-' + uid, obj)
            known[uid] = object_id(obj)
            all_known.add(uid)
            continue
        raise RuntimeError('Unknown namespace resource blocks mutation')


def certificate_hash(value):
    require(type(value) is str and 0 < len(value) <= 65536, 'Invalid public root certificate bundle')
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----', value)
    require(blocks and not re.sub(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----', '', value).strip(),
            'Unexpected public root certificate content')
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=value)
    return digest(canonical(sorted(ssl.PEM_cert_to_DER_cert(block).hex() for block in blocks)))


def revocation_hash(value):
    # Recognize the native public copy; this is not cryptographic CRL validation.
    require(type(value) is str and len(value) <= 65536, 'Invalid public revocation list')
    return digest(value.encode())


def housekeeping_roots():
    encoded = kubectl('config', 'view', '--raw', '--minify', '-o',
                      'jsonpath={.clusters[0].cluster.certificate-authority-data}').strip()
    require(0 < len(encoded) <= 131072, 'Selected public cluster CA unavailable')
    kubernetes = certificate_hash(base64.b64decode(encoded, validate=True).decode('ascii'))
    roots = {'kube-root-ca.crt': kubernetes}
    for name, key in (('istio-ca-root-cert', 'root-cert.pem'), ('istio-ca-crl', 'ca-crl.pem')):
        obj = get('ConfigMap', name, 'istio-system')
        require(obj and set(obj.get('data', {})) == {key} and not obj.get('binaryData'), 'Trusted Istio public data unavailable')
        roots[name] = revocation_hash(obj['data'][key]) if name == 'istio-ca-crl' else certificate_hash(obj['data'][key])
    return roots


def housekeeping_identity(obj, ns, created_at, roots):
    metadata, kind = obj['metadata'], obj['kind']
    name = metadata['name']
    require(obj['apiVersion'] == 'v1' and metadata.get('namespace') == ns
            and type(metadata.get('creationTimestamp')) is str
            and datetime.fromisoformat(metadata['creationTimestamp'].replace('Z', '+00:00')) >=
                datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            and set(metadata) <= {'name', 'namespace', 'uid', 'resourceVersion', 'creationTimestamp', 'managedFields', 'labels', 'annotations'}
            and ('managedFields' not in metadata or type(metadata['managedFields']) is list), 'Foreign housekeeping metadata')
    identity = object_id(obj)
    writers = {row['manager'] for row in metadata.get('managedFields', [])}
    if kind == 'ServiceAccount' and name == 'default':
        require(set(obj) <= {'apiVersion', 'kind', 'metadata'} and not metadata.get('labels')
                and not metadata.get('annotations') and writers <= {'kube-controller-manager', 'k3s'},
                'Foreign default ServiceAccount shape or writer')
        content = digest(canonical({'kind': kind, 'name': name}))
    else:
        require(kind == 'ConfigMap' and name in roots and set(obj) <= {'apiVersion', 'kind', 'metadata', 'data'},
                'Foreign root ConfigMap shape')
        if name == 'kube-root-ca.crt':
            managers, key = {'kube-controller-manager', 'k3s'}, 'ca.crt'
            require(not metadata.get('labels') and set(metadata.get('annotations', {})) <= {'kubernetes.io/description'},
                    'Foreign Kubernetes root metadata')
        else:
            managers = {'pilot-discovery', 'istiod'}
            key = 'ca-crl.pem' if name == 'istio-ca-crl' else 'root-cert.pem'
            require(metadata.get('labels') == {'istio.io/config': 'true'} and not metadata.get('annotations'), 'Foreign Istio root metadata')
        require(writers and writers <= managers and set(obj.get('data', {})) == {key}, 'Foreign root ConfigMap provenance or schema')
        content = revocation_hash(obj['data'][key]) if name == 'istio-ca-crl' else certificate_hash(obj['data'][key])
        require(content == roots[name], 'Housekeeping data differs from trusted public reference')
    return {'identity': identity, 'writers': sorted(writers), 'createdAt': metadata['creationTimestamp'], 'contentHash': content,
            'bodyHash': digest(canonical({key: value for key, value in obj.items() if key != 'metadata'})),
            'metadataHash': digest(canonical({key: metadata.get(key) for key in ('labels', 'annotations')}))}


def housekeeping(receipt, deadline):
    ns = root_current(receipt, 'namespace')
    created_at = ns['metadata']['creationTimestamp']
    evidence = receipt.value['evidence']
    require(evidence.get('namespaceCreatedAt', created_at) == created_at, 'Namespace creation boundary changed')
    roots = housekeeping_roots()
    require(evidence.get('housekeepingRoots', roots) == roots, 'Trusted housekeeping references changed')
    evidence.update(namespaceCreatedAt=created_at, housekeepingRoots=roots)
    rows = receipt.value.setdefault('housekeeping', {})
    for kind, name, key in [('ServiceAccount', 'default', 'default-account'), ('ConfigMap', 'kube-root-ca.crt', 'namespace-ca'),
                            ('ConfigMap', 'istio-ca-root-cert', 'istio-ca-root-cert'), ('ConfigMap', 'istio-ca-crl', 'istio-ca-crl')]:
        obj = wait('native housekeeping ' + name, lambda: get(kind, name, receipt.namespace, managed_fields=True), deadline)
        row = housekeeping_identity(obj, receipt.namespace, created_at, roots)
        require(name not in rows or rows[name] == row, 'Housekeeping identity, content or metadata changed')
        rows[name] = row
        receipt.record(key, obj)
    receipt.save()


def dry_run_phases(receipt, payload):
    receipt.value['admission'] = {}
    for phase, documents in payload['phases'].items():
        admitted = {}
        for document in documents:
            result = parsed(kubectl('create', '--dry-run=server', '-f', '-', '-o', 'json', body=canonical(document)))
            require(result['kind'] == document['kind'] and result['metadata']['name'] == document['metadata']['name']
                    and result['metadata'].get('namespace') == receipt.namespace, 'Phase admission changed identity')
            require(admitted_document(result, document), 'Phase admission changed published authority')
            admitted[result['kind'] + '/' + result['metadata']['name']] = result
        receipt.value['admission'][phase] = admitted
    receipt.save()


def admitted_document(result, document):
    kind = document['kind']
    if document['kind'] == 'PersistentVolumeClaim' and result.get('spec', {}).get('volumeName'):
        return False
    if kind == 'Secret':
        if 'stringData' in result:
            return False
        for obj, fields in ((document, ('data', 'stringData')), (result, ('data',))):
            if any(field in obj and (type(obj[field]) is not dict or any(
                    type(key) is not str or type(value) is not str for key, value in obj[field].items())) for field in fields):
                return False
            if 'type' in obj and type(obj['type']) is not str:
                return False
    def nonnull(value):
        if type(value) is dict:
            return {k: nonnull(v) for k, v in value.items() if v is not None}
        if type(value) is list:
            return [nonnull(v) for v in value]
        return value
    def defaults(actual, expected, values):
        for key, value in values.items():
            if key not in expected and actual.get(key) == value:
                actual.pop(key)
    metadata = result['metadata']
    if (metadata.get('labels', {}) != document['metadata'].get('labels', {})
            or (metadata.get('annotations') or {}) != (document['metadata'].get('annotations') or {})
            or metadata.get('ownerReferences')
            or (metadata.get('finalizers') or []) != (document['metadata'].get('finalizers') or [])
            or metadata.get('generateName')):
        return False
    a, b = nonnull(body_profile(result)), nonnull(body_profile(document))
    if kind == 'Secret':
        try:
            data = {key: base64.b64encode(base64.b64decode(value, validate=True)).decode('ascii')
                    for key, value in document.get('data', {}).items()}
            data.update({key: base64.b64encode(value.encode('utf-8')).decode('ascii')
                         for key, value in document.get('stringData', {}).items()})
        except (ValueError, UnicodeError):
            return False
        b.pop('stringData', None)
        b.pop('data', None)
        if data:
            b['data'] = data
        elif a.get('data') == {}:
            a.pop('data')
        defaults(a, b, {'type': 'Opaque'})
    if kind in ('Deployment', 'StatefulSet'):
        actual, wanted = a['spec'], b['spec']
        if not admission_source(actual['template']['spec'], wanted['template']['spec']):
            return False
        actual['template']['spec'] = copy.deepcopy(wanted['template']['spec'])
        actual['template']['metadata'].pop('creationTimestamp', None)
        defaults(actual, wanted, {'replicas': 1, 'revisionHistoryLimit': 10})
        if kind == 'Deployment':
            defaults(actual, wanted, {'progressDeadlineSeconds': 600})
        else:
            defaults(actual, wanted, {'podManagementPolicy': 'OrderedReady',
                'persistentVolumeClaimRetentionPolicy': {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}})
            defaults(actual['updateStrategy'], wanted['updateStrategy'], {'rollingUpdate': {'partition': 0}})
            defaults(actual['updateStrategy'], wanted['updateStrategy'], {'type': 'RollingUpdate'})
            for claim, source in zip(actual.get('volumeClaimTemplates', []), wanted.get('volumeClaimTemplates', [])):
                defaults(claim['spec'], source['spec'], {'volumeMode': 'Filesystem'})
                defaults(claim, source, {'status': {'phase': 'Pending'}})
    if kind == 'PersistentVolumeClaim':
        defaults(a['spec'], b['spec'], {'volumeMode': 'Filesystem'})
    if kind == 'Service':
        defaults(a['spec'], b['spec'], {'type': 'ClusterIP', 'sessionAffinity': 'None', 'internalTrafficPolicy': 'Cluster',
            'ipFamilyPolicy': 'SingleStack', 'ipFamilies': ['IPv4']})
        if b['spec'].get('clusterIP') == 'None':
            defaults(a['spec'], b['spec'], {'clusterIPs': ['None']})
        for port, source in zip(a['spec'].get('ports', []), b['spec'].get('ports', [])):
            defaults(port, source, {'protocol': 'TCP', 'targetPort': source['port']})
    return a == b


def drift_and_repair(receipt, deadline):
    before = workload(receipt, 'loki', 1)
    require(before is not None, 'Cannot drift an unready workload')
    identity = object_id(before)
    receipt.intention('replica-drift', identity, {'replicas': 0, 'restore': 1})
    patches = [{'op': 'test', 'path': '/metadata/uid', 'value': identity['uid']},
               {'op': 'test', 'path': '/metadata/resourceVersion', 'value': before['metadata']['resourceVersion']},
               {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
    result = parsed(kubectl('patch', 'statefulset', identity['name'], '-n', receipt.namespace,
                           '--type=json', '-p', json.dumps(patches), '-o', 'json'))
    require(object_id(result) == identity and result['spec']['replicas'] == 0, 'Drift mutation changed authority')
    receipt.value['intents']['replica-drift']['accepted'] = True
    receipt.save()
    wait('native Argo replica repair', lambda: workload(receipt, 'loki', 1), deadline)
    wait('native backend readiness after replica repair', lambda: record_native_children(receipt), deadline)
    receipt.value['intents']['replica-drift']['complete'] = True
    receipt.save()


def project_guard(receipt, *, deadline, app_absent=False):
    root_current(receipt, 'project')
    count, identity = 0, None
    for app in paginated_namespaced('applications.argoproj.io', 'argocd', deadline=deadline):
        if app.get('spec', {}).get('project') == receipt.namespace:
            count += 1
            identity = object_id(app)
    if app_absent:
        require(count == 0, 'Project still has a consumer')
    else:
        require(count == 1 and identity == receipt.value['objects']['app'], 'Unexpected project consumer')


def released_pv(receipt, identity, pv):
    require(pv and object_id(pv) == identity['pv'], 'Released PV identity changed')
    require(pv.get('status', {}).get('phase') == 'Released' and pv['spec'].get('persistentVolumeReclaimPolicy') == 'Retain'
            and pv['spec'].get('claimRef', {}).get('uid') == identity['claim']['uid']
            and pv['spec']['claimRef'].get('name') == identity['claim']['name']
            and pv['spec']['claimRef'].get('namespace') == receipt.namespace
            and pv['spec'].get('storageClassName') == 'cloudlab-telemetry'
            and pv['spec'].get('csi', {}).get('driver') == 'driver.longhorn.io'
            and pv['spec']['csi'].get('volumeHandle') == identity['handle'], 'Released PV linkage differs')


def backing_deletion_gate(identity, volume):
    require(volume.get('status', {}).get('state') == 'detached' and not volume['spec'].get('nodeID')
            and not volume.get('status', {}).get('currentNodeID'), 'Backing volume is not detached')
    for pv in listed('pv'):
        csi = pv.get('spec', {}).get('csi', {})
        if csi.get('driver') == 'driver.longhorn.io' and csi.get('volumeHandle') == identity['handle']:
            require(object_id(pv) == identity['pv'], 'Another PV references the backing handle')
    for attachment in listed('volumeattachments.storage.k8s.io'):
        require(attachment.get('spec', {}).get('source', {}).get('persistentVolumeName') != identity['pv']['name'],
                'CSI attachment blocks backing deletion')
    for attachment in listed('volumeattachments.longhorn.io', 'longhorn-system'):
        if attachment.get('spec', {}).get('volume') == identity['handle']:
            require(not attachment['spec'].get('attachmentTickets'), 'Native attachment tickets block backing deletion')
    discovery = parsed(kubectl('get', '--raw', '/apis'))
    require(type(discovery.get('groups')) is list, 'Incomplete API discovery')
    if any(group.get('name') == 'snapshot.storage.k8s.io' for group in discovery['groups']):
        for snapshot in listed('volumesnapshotcontents.snapshot.storage.k8s.io'):
            require(snapshot.get('spec', {}).get('source', {}).get('volumeHandle') != identity['handle'],
                    'External snapshot references backing data')


def recorded_grafana_replicasets(receipt):
    # rs-* is recorded only after record_native_children validates its Deployment controller UID.
    deployment = receipt.value['objects'].get('workload-grafana')
    result = set()
    for key, identity in receipt.value['objects'].items():
        if not key.startswith('rs-'):
            continue
        require(deployment and deployment['apiVersion'] == 'apps/v1' and deployment['kind'] == 'Deployment'
                and deployment['name'] == receipt.namespace + '-grafana' and deployment['namespace'] == receipt.namespace
                and UID.fullmatch(deployment['uid']) and identity['apiVersion'] == 'apps/v1'
                and identity['kind'] == 'ReplicaSet' and identity['namespace'] == receipt.namespace
                and key == 'rs-' + identity['name'] and UID.fullmatch(identity['uid'])
                and identity['name'].startswith(deployment['name'] + '-'), 'Unqualified recorded ReplicaSet')
        result.add(('ReplicaSet', identity['name']))
    return result


def validate_standalone_marker_history(receipt, payload, component, entry):
    require(type(entry) is dict and set(entry) == {'podName', 'podStatus', 'workloadName', 'workloadType'}
            and entry['podName'] == receipt.namespace + '-marker' and entry['podStatus'] == 'Succeeded'
            and entry['workloadName'] == '' and entry['workloadType'] == '', 'Unsupported standalone marker history')
    require(payload is not None, 'Authenticated fixture input required for marker history')
    validate_input(payload, receipt.operation)
    runs = receipt.value.get('markerRuns')
    require(type(runs) is list and 1 <= len(runs) <= 6, 'Marker history is incomplete')
    identities, components = set(), set()
    for index, record in enumerate(runs):
        require(type(record) is dict and record.get('component') in ('loki', 'tempo', 'grafana')
                and record['component'] in receipt.value['markers'] and record.get('mode') in ('write', 'read')
                and record.get('accepted') is True and record.get('complete') is True, 'Unverified marker history')
        identity = receipt.value['objects'].get('marker-' + str(index))
        require(type(identity) is dict and set(identity) == {'apiVersion', 'kind', 'name', 'namespace', 'uid'}
                and identity['apiVersion'] == 'v1' and identity['kind'] == 'Pod'
                and identity['name'] == entry['podName'] and identity['namespace'] == receipt.namespace
                and type(identity['uid']) is str and UID.fullmatch(identity['uid'])
                and identity['uid'] not in identities, 'Marker creator identity differs')
        document = marker_document(receipt, payload, record['component'], record['mode'])
        require(type(record.get('admittedSpec')) is dict and record.get('document') == digest(canonical(document))
                and admission_source(record.get('admittedSpec'), document['spec']), 'Marker execution source differs')
        require_marker_verification(receipt, record, identity)
        scope = {'profile': PROFILE, 'marker': identity, 'document': record['document']}
        deletion = receipt.value['intents'].get('delete-marker-' + str(index), {})
        require(deletion.get('identity') == identity and deletion.get('scope') == digest(canonical(scope))
                and deletion.get('accepted') is True and deletion.get('complete') is True, 'Marker deletion history differs')
        identities.add(identity['uid'])
        components.add(record['component'])
    known = {obj['uid'] for obj in receipt.value['objects'].values()
             if obj.get('kind') == 'Pod' and obj.get('name') == entry['podName'] and obj.get('namespace') == receipt.namespace}
    require(identities == known and component in components, 'Marker history does not bind this component')


def paired_intents(receipt, component, pv, volume, *, payload=None):
    row = receipt.value['storage'][component]
    identity = row['identity']
    validate_replica_rows(row['replicas'])
    require(all(re.fullmatch('/var/lib/longhorn/replicas/' + re.escape(identity['handle']) + r'-[a-f0-9]{8}', r['path'])
                for r in row['replicas']), 'Replica path is not bound to the exact volume handle')
    require(current(identity['claim']) is None, 'Live claim blocks backing deletion')
    released_pv(receipt, identity, pv)
    require(volume and object_id(volume) == identity['volume'], 'Backing identity changed')
    backing_deletion_gate(identity, volume)
    fresh_replicas = capture_replicas(identity)
    require(sorted(fresh_replicas, key=lambda r: r['replicaUID']) == sorted(row['replicas'], key=lambda r: r['replicaUID']),
            'Native replicas changed before backing deletion')
    no_restore(volume)
    link = volume.get('status', {}).get('kubernetesStatus', {})
    require(volume['spec'].get('numberOfReplicas') == 2 and link.get('pvName') == identity['pv']['name']
            and link.get('pvStatus') == 'Released' and link.get('pvcName') == identity['claim']['name']
            and link.get('namespace') == receipt.namespace and link.get('lastPVCRefAt')
            and (not link.get('workloadsStatus') or link.get('lastPodRefAt')), 'Released Longhorn linkage differs')
    known_workloads = {(o['kind'], o['name']) for o in receipt.value['objects'].values()
                       if o['namespace'] == receipt.namespace and o['kind'] in ('Pod', 'StatefulSet', 'Deployment')
                       and not (o['kind'] == 'Pod' and o['name'] == receipt.namespace + '-marker')}
    known_workloads |= recorded_grafana_replicasets(receipt)
    standalone = False
    for workload_status in link.get('workloadsStatus', []):
        require(type(workload_status) is dict, 'Released volume has an unknown workload')
        pair = (workload_status.get('workloadType'), workload_status.get('workloadName'))
        if workload_status.get('podName') == receipt.namespace + '-marker' or pair in (
                ('Pod', receipt.namespace + '-marker'), ('', '')):
            validate_standalone_marker_history(receipt, payload, component, workload_status)
            standalone = True
        else:
            require(pair in known_workloads, 'Released volume has an unknown workload')
    if standalone:
        root_current(receipt, 'namespace')
        require(not listed('pods', receipt.namespace), 'Current namespace consumers block marker history')
    keys = ('delete-pv-' + component, 'delete-volume-' + component)
    previous = [receipt.value['intents'].get(k) for k in keys]
    require(bool(previous[0]) == bool(previous[1]), 'Unpaired backing intent cannot be repaired retrospectively')
    scope = {'profile': PROFILE, 'operation': receipt.operation, 'component': component,
             'identity': identity, 'replicas': row['replicas']}
    staged = copy.deepcopy(receipt.value)
    for key, obj in zip(keys, (pv, volume)):
        old = staged['intents'].get(key)
        require(old is None or old['identity'] == object_id(obj) and old['scope'] == digest(canonical(scope))
                and not old['complete'], 'Backing intent changed or completed resource reappeared')
        require(old is not None or not obj['metadata'].get('deletionTimestamp'), 'Backing already deleting without intent')
        staged['intents'][key] = (old or {'identity': object_id(obj), 'scope': digest(canonical(scope)),
                                       'accepted': False, 'complete': False}) | {'resourceVersion': obj['metadata']['resourceVersion']}
    # One atomic durable write protects both sides of Longhorn's native PV cascade.
    original = receipt.value
    receipt.value = staged
    try:
        receipt.save()
    except BaseException:
        receipt.value = original
        raise
    return scope


def verify_no_storage_dependents(identity):
    handle = identity['handle']
    for kind in ('engines.longhorn.io', 'replicas.longhorn.io', 'volumeattachments.longhorn.io', 'snapshots.longhorn.io'):
        for obj in listed(kind, 'longhorn-system'):
            field = 'volume' if kind in ('volumeattachments.longhorn.io', 'snapshots.longhorn.io') else 'volumeName'
            require(obj.get('spec', {}).get(field) != handle, 'Longhorn dependent still exists')
    for obj in listed('volumeattachments.storage.k8s.io'):
        require(obj.get('spec', {}).get('source', {}).get('persistentVolumeName') != identity['pv']['name'],
                'CSI attachment still exists')


def cleanup_storage(receipt, component, deadline, *, payload=None):
    row = receipt.value['storage'][component]
    identity, replicas = row['identity'], row['replicas']
    validate_replica_rows(replicas)
    require(all(re.fullmatch('/var/lib/longhorn/replicas/' + re.escape(identity['handle']) + r'-[a-f0-9]{8}', r['path'])
                for r in replicas), 'Cleanup replica path escaped recorded volume')
    claim = current(identity['claim'])
    key = 'delete-claim-' + component
    if claim is not None:
        require(not workload_pods(receipt) and get('pod', receipt.namespace + '-marker', receipt.namespace) is None,
                'Consumers block claim cleanup')
        wait('claim detached for cleanup', lambda: detached(receipt, component), deadline)
        require(fresh_identity(receipt, claim, healthy=False) == identity, 'Claim changed before cleanup')
        request_delete(receipt, key, claim, identity)
        finish_delete(receipt, key, deadline)
    else:
        intent = receipt.value['intents'].get(key)
        require(intent and intent['identity'] == identity['claim'] and intent['accepted'], 'Claim absent without accepted intent')
        if not intent['complete']:
            finish_delete(receipt, key, deadline)
    pv, volume = current(identity['pv']), current(identity['volume'])
    pv_key, volume_key = 'delete-pv-' + component, 'delete-volume-' + component
    if pv is not None and volume is not None:
        wait('released native PV', lambda: current(identity['pv']).get('status', {}).get('phase') == 'Released', deadline)
        pv, volume = current(identity['pv']), current(identity['volume'])
        scope = paired_intents(receipt, component, pv, volume, payload=payload)
        # Validate original inspector/filesystem identity before granting a native backing deletion.
        for replica in replicas:
            now = directory_state(replica)
            require(now == replica['context'], 'Backing changed before native deletion')
        request_delete(receipt, volume_key, volume, scope)
        finish_delete(receipt, volume_key, deadline)
    else:
        pair = [receipt.value['intents'].get(k) for k in (pv_key, volume_key)]
        require(all(pair) and pair[1]['accepted'], 'Backing missing without paired accepted deletion')
        require(pair[0]['identity'] == identity['pv'] and pair[1]['identity'] == identity['volume'], 'Backing scope changed')
        if volume is not None:
            require(not pair[1]['complete'], 'Completed volume reappeared')
            finish_delete(receipt, volume_key, deadline)
        elif not pair[1]['complete']:
            finish_delete(receipt, volume_key, deadline)
    pv = current(identity['pv'])
    if pv is not None:
        require(not receipt.value['intents'][pv_key]['complete'], 'Completed PV reappeared')
        require(current(identity['claim']) is None, 'Claim reappeared before PV deletion')
        released_pv(receipt, identity, pv)
        scope = {'profile': PROFILE, 'operation': receipt.operation, 'component': component,
                 'identity': identity, 'replicas': replicas}
        request_delete(receipt, pv_key, pv, scope)
        finish_delete(receipt, pv_key, deadline)
    else:
        require(receipt.value['intents'][volume_key]['accepted'], 'PV disappeared before accepted backing deletion')
        receipt.value['intents'][pv_key]['complete'] = True
        receipt.value['intents'][pv_key]['cascade'] = True
        receipt.save()
    wait('physical replica removal', lambda: backing_absent(replicas), deadline)
    verify_no_storage_dependents(identity)
    require(current(identity['pv']) is None and current(identity['volume']) is None, 'Backing reappeared')
    receipt.value['storage'][component]['cleaned'] = True
    receipt.save()


def require_removed(receipt):
    ns = receipt.namespace
    retained = set(claim_names(receipt.operation).values())
    pending = False
    def declared(obj):
        metadata, kind = obj['metadata'], obj['kind']
        key = kind + '/' + metadata['name']
        require(object_id(obj) == receipt.value['objects'].get('declared-' + key), 'Unrecorded resource during pruning')
        profiles = [receipt.value['admission'][phase][key] for phase in ('running', 'scaled-down')]
        require(any(body_profile(obj) == body_profile(profile) for profile in profiles), 'Declared resource body changed during pruning')
        require(metadata.get('labels', {}).get('cloudlab.io/owner') == OWNER
                and metadata['labels'].get(LABEL) == receipt.operation, 'Declared ownership changed during pruning')
        group = obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
        tracking = ns + ':' + group + '/' + kind + ':' + ns + '/' + metadata['name']
        annotations = metadata.get('annotations') or {}
        require(annotations.get('argocd.argoproj.io/tracking-id') == tracking, 'Declared tracking changed during pruning')
        expected = profiles[0]['metadata']
        require((metadata.get('ownerReferences') or []) == (expected.get('ownerReferences') or [])
                and all(annotations.get(key) == (expected.get('annotations') or {}).get(key) for key in
                        ('argocd.argoproj.io/sync-options', 'helm.sh/resource-policy', 'argocd.argoproj.io/hook')),
                'Declared retention or ownership changed during pruning')
        allowed = set(expected.get('finalizers') or []) | ({'foregroundDeletion'} if metadata.get('deletionTimestamp') else set())
        require(set(metadata.get('finalizers') or []) <= allowed, 'Unknown finalizer during pruning')
    for kind in sorted(KINDS):
        objects = listed(kind, ns)
        if kind == 'PersistentVolumeClaim':
            require({o['metadata']['name'] for o in objects} == retained, 'Retained claim inventory changed')
            for obj in objects:
                identity = next(row['identity'] for row in receipt.value['storage'].values()
                                if row['identity']['claim']['name'] == obj['metadata']['name'])
                require(object_id(obj) == identity['claim'] and fresh_identity(receipt, obj, healthy=False) == identity,
                        'Retained storage changed during pruning')
        elif kind == 'ConfigMap':
            expected = {ns + '-sentinel', 'kube-root-ca.crt', 'istio-ca-root-cert', 'istio-ca-crl'}
            require(expected <= {o['metadata']['name'] for o in objects}, 'Retained ConfigMaps disappeared')
        elif kind == 'ServiceAccount':
            require('default' in {o['metadata']['name'] for o in objects}, 'Default service account disappeared')
        if kind != 'PersistentVolumeClaim':
            for obj in objects:
                name = obj['metadata']['name']
                housekeeping_row = receipt.value.get('housekeeping', {}).get(name)
                if housekeeping_row is not None:
                    actual = get(kind, name, ns, managed_fields=True)
                    require(actual is not None and object_id(actual) == object_id(obj)
                            and housekeeping_identity(actual, ns, receipt.value['evidence']['namespaceCreatedAt'],
                                receipt.value['evidence']['housekeepingRoots']) == housekeeping_row,
                            'Retained housekeeping changed during pruning')
                else:
                    declared(obj)
                    if not (kind == 'ConfigMap' and name == ns + '-sentinel'):
                        pending = True
    children_gone = record_native_children(receipt, require_ready=False, known_only=True)
    return not pending and children_gone


def cleanup_markers(receipt, payload, deadline):
    existing = get('pod', receipt.namespace + '-marker', receipt.namespace)
    for index, record in enumerate(receipt.value.get('markerRuns', [])):
        key = 'marker-' + str(index)
        if not record['accepted']:
            continue
        identity = receipt.value['objects'][key]
        if record['complete']:
            intent = receipt.value['intents'].get('delete-' + key)
            require(intent and intent['accepted'] and intent['complete'] and intent['identity'] == identity
                    and (existing is None or object_id(existing) != identity), 'Completed marker reappeared')
            continue
        document = marker_document(receipt, payload, record['component'], record['mode'])
        require(record['document'] == digest(canonical(document))
                and admission_source(record['admittedSpec'], document['spec']), 'Marker cleanup source changed')
        obj = current(identity)
        if obj is not None:
            require(existing is not None and object_id(existing) == identity and not record['complete'], 'Marker cleanup identity changed')
            actual = copy.deepcopy(obj['spec'])
            node = actual.pop('nodeName', '')
            require((not node or node in receipt.value['baseline']['nodes']) and actual == record['admittedSpec']
                    and obj['metadata'].get('labels') == document['metadata']['labels']
                    and not obj['metadata'].get('ownerReferences') and not obj['metadata'].get('finalizers'),
                    'Marker cleanup authority changed')
            request_delete(receipt, 'delete-' + key, obj, {'profile': PROFILE, 'marker': identity,
                           'document': digest(canonical(document))})
            finish_delete(receipt, 'delete-' + key, deadline)
            existing = None
        else:
            intent = receipt.value['intents'].get('delete-' + key)
            require(intent and intent['accepted'] and intent['identity'] == identity, 'Marker absent without accepted deletion')
            finish_delete(receipt, 'delete-' + key, deadline)
        wait('cleanup marker detach', lambda: detached(receipt, record['component']), deadline)
        record['complete'] = True
        receipt.save()
    require(existing is None, 'Unknown marker Pod blocks cleanup')


def cleanup(receipt, payload, deadline):
    require('namespace' in receipt.value['objects'], 'Unrecorded root creation requires separate guarded recovery')
    if not receipt.value.get('cleanupStarted'):
        receipt.value['cleanupStarted'] = True
        receipt.save()
    if 'app' not in receipt.value['objects']:
        require(not receipt.value['storage'] and get('Application', receipt.namespace, 'argocd') is None,
                'Unknown application or storage blocks root-only cleanup')
        if 'project' not in receipt.value['objects']:
            require(get('AppProject', receipt.namespace, 'argocd') is None, 'Unknown project retained')
        elif current(receipt.value['objects']['project']) is not None:
            project_guard(receipt, deadline=deadline, app_absent=True)
        ns = current(receipt.value['objects']['namespace'])
        if ns is not None:
            root_current(receipt, 'namespace')
            require(not listed('pvc', receipt.namespace), 'Unrecorded claims block root-only cleanup')
            housekeeping(receipt, deadline)
            inventory_gate(receipt)
            request_delete(receipt, 'delete-namespace', ns, {'namespace': object_id(ns), 'noApplicationOrStorage': True})
            finish_delete(receipt, 'delete-namespace', deadline)
        else:
            require(receipt.value['intents'].get('delete-namespace', {}).get('accepted'), 'Namespace absent without cleanup intent')
            finish_delete(receipt, 'delete-namespace', deadline)
        if 'project' in receipt.value['objects']:
            project = current(receipt.value['objects']['project'])
            if project is not None:
                project_guard(receipt, deadline=deadline, app_absent=True)
                request_delete(receipt, 'delete-project', project, {'project': object_id(project), 'noConsumers': True})
            else:
                require(receipt.value['intents'].get('delete-project', {}).get('accepted'), 'Project absent without cleanup intent')
            finish_delete(receipt, 'delete-project', deadline)
        else:
            require(get('AppProject', receipt.namespace, 'argocd') is None, 'Unknown project retained')
        receipt.value['cleanupComplete'] = True
        receipt.phase('cleaned')
        return
    require('baseline' in receipt.value, 'Storage baseline unavailable for cleanup')
    if receipt.value.get('cleanupComplete'):
        require(all(current(o) is None for k, o in receipt.value['objects'].items() if k in ('namespace', 'app', 'project')),
                'Completed cleanup root reappeared')
        for row in receipt.value['storage'].values():
            require(current(row['identity']['claim']) is None and current(row['identity']['pv']) is None
                    and current(row['identity']['volume']) is None and backing_absent(row['replicas']), 'Completed storage reappeared')
        return
    ns_current = current(receipt.value['objects']['namespace'])
    if ns_current:
        root_current(receipt, 'namespace')
        housekeeping(receipt, deadline)
        cleanup_markers(receipt, payload, deadline)
        app = current(receipt.value['objects']['app'])
        if app is not None:
            project_guard(receipt, deadline=deadline)
            if receipt.value.get('pendingAdvance'):
                advance(receipt, receipt.value['pendingAdvance']['to'])
            app_current(receipt, receipt.value.get('appPhase', 'running'))
            observe_declared(receipt, payload, partial=True)
            record_native_children(receipt, require_ready=False)
            inventory_gate(receipt)
            # Fresh ownership, rather than qualification success, authorizes failed-run cleanup.
            wait('all fresh cleanup claims qualified', lambda: bind_storage(receipt, fresh=True, healthy=False), deadline)
            for component in ('loki', 'tempo', 'grafana'):
                row = receipt.value['storage'][component]
                if 'replicas' not in row:
                    row['replicas'] = capture_replicas(row['identity'])
                    receipt.save()
            request_delete(receipt, 'delete-app', app, {'source': payload['source'], 'app': object_id(app)})
            finish_delete(receipt, 'delete-app', deadline)
        else:
            require(receipt.value['intents'].get('delete-app', {}).get('accepted'), 'Application absent without accepted cleanup')
            if not receipt.value['intents']['delete-app']['complete']:
                finish_delete(receipt, 'delete-app', deadline)
        wait('foreground workload cleanup', lambda: not workload_pods(receipt), deadline)
        remaining = listed('pvc', receipt.namespace)
        if not receipt.value['evidence'].get('cascadeRetainedClaims'):
            require({p['metadata']['name'] for p in remaining} == set(claim_names(receipt.operation).values()),
                    'Application cascade did not retain exactly three claims')
            receipt.value['evidence']['cascadeRetainedClaims'] = True
            receipt.save()
        else:
            require(all(object_id(p) in [r['identity']['claim'] for r in receipt.value['storage'].values()] for p in remaining),
                    'Foreign claim appeared during resumed cleanup')
        inventory_gate(receipt)
        for component in ('loki', 'tempo', 'grafana'):
            cleanup_storage(receipt, component, deadline, payload=payload)
        require(not listed('pvc', receipt.namespace), 'Claims remain after exact cleanup')
        inventory_gate(receipt)
        ns_obj = root_current(receipt, 'namespace')
        request_delete(receipt, 'delete-namespace', ns_obj, {'namespace': object_id(ns_obj), 'storageCleaned': True})
        finish_delete(receipt, 'delete-namespace', deadline)
    else:
        require(receipt.value['intents'].get('delete-namespace', {}).get('accepted'), 'Namespace absent without accepted cleanup')
        if not receipt.value['intents']['delete-namespace']['complete']:
            finish_delete(receipt, 'delete-namespace', deadline)
    project = current(receipt.value['objects']['project'])
    if project is not None:
        project_guard(receipt, deadline=deadline, app_absent=True)
        project = root_current(receipt, 'project')
        request_delete(receipt, 'delete-project', project, {'project': object_id(project), 'noConsumers': True})
    else:
        require(receipt.value['intents'].get('delete-project', {}).get('accepted'), 'Project absent without accepted cleanup')
    finish_delete(receipt, 'delete-project', deadline)
    receipt.value['cleanupComplete'] = True
    receipt.phase('cleaned')


def step(receipt, name, action):
    steps = receipt.value.setdefault('steps', [])
    if name in steps:
        return
    receipt.value['pendingStep'] = name
    receipt.save()
    action()
    steps.append(name)
    receipt.value.pop('pendingStep', None)
    receipt.phase(name)


def run(receipt, payload, deadline):
    require(not receipt.value.get('cleanupStarted') and not receipt.value.get('cleanupComplete'),
            'Cleanup is terminal for qualification; retain the cleanup result')
    namespace_doc, project_doc, app_doc = root_documents(receipt.operation)
    step(receipt, 'namespace-created', lambda: create_root(receipt, 'namespace', namespace_doc))
    def baseline():
        require(not listed('pvc', receipt.namespace) and get('Application', receipt.namespace, 'argocd') is None,
                'Storage baseline must precede application creation')
        receipt.value['baseline'] = storage_baseline()
        receipt.save()
        housekeeping(receipt, deadline)
        cm = get('configmap', 'argocd-cm', 'argocd')
        require(cm and cm.get('data', {}).get('application.resourceTrackingMethod') == 'annotation', 'Unsupported Argo resource tracking')
        dry_run_phases(receipt, payload)
    step(receipt, 'baseline-qualified', baseline)
    step(receipt, 'project-created', lambda: create_root(receipt, 'project', project_doc))
    step(receipt, 'application-created', lambda: create_root(receipt, 'app', app_doc))
    def running():
        project_guard(receipt, deadline=deadline)
        wait('running native application', lambda: converged(receipt, 'running'), deadline, 600)
        wait('native backend readiness', lambda: validate_workloads(receipt, payload, 1), deadline)
        wait('native backend processes', lambda: record_native_children(receipt), deadline)
        wait('fresh CSI claims', lambda: bind_storage(receipt, fresh=True), deadline)
        observe_declared(receipt, payload)
        inventory_gate(receipt)
        for component, row in receipt.value['storage'].items():
            row['replicas'] = capture_replicas(row['identity'])
        receipt.save()
    step(receipt, 'running-qualified', running)
    step(receipt, 'drift-repaired', lambda: drift_and_repair(receipt, deadline))
    def down():
        inventory_gate(receipt)
        advance(receipt, 'scaled-down')
        wait('scaled-down native application', lambda: converged(receipt, 'scaled-down'), deadline)
        wait('scaled-down workloads', lambda: validate_workloads(receipt, payload, 0), deadline)
        wait('no workload Pods', lambda: not workload_pods(receipt), deadline)
        for component in ('loki', 'tempo', 'grafana'):
            wait('detached retained claim', lambda component=component: detached(receipt, component), deadline)
    step(receipt, 'scaled-down-qualified', down)
    for component in ('loki', 'tempo', 'grafana'):
        step(receipt, 'marker-written-' + component, lambda component=component: marker_io(receipt, payload, component, 'write', deadline))
    def restarted():
        inventory_gate(receipt)
        advance(receipt, 'running')
        wait('native reattachment application', lambda: converged(receipt, 'running'), deadline)
        wait('reattached backend readiness', lambda: validate_workloads(receipt, payload, 1), deadline)
        wait('reattached backend processes', lambda: record_native_children(receipt), deadline)
        require(bind_storage(receipt), 'Storage identity changed after native reattachment')
        observe_declared(receipt, payload)
    step(receipt, 'reattachment-qualified', restarted)
    def removed():
        inventory_gate(receipt)
        advance(receipt, 'removed')
        wait('explicit retained Argo prune blocker', lambda: converged(receipt, 'removed'), deadline, 600)
        wait('ordinary resource pruning', lambda: require_removed(receipt), deadline)
        for component in ('loki', 'tempo', 'grafana'):
            wait('detached retained claim after removal', lambda component=component: detached(receipt, component), deadline)
        require(bind_storage(receipt, healthy=False), 'Storage changed after native workload removal')
    step(receipt, 'removal-qualified', removed)
    for component in ('loki', 'tempo', 'grafana'):
        step(receipt, 'marker-read-' + component, lambda component=component: marker_io(receipt, payload, component, 'read', deadline))
    receipt.value['evidence']['qualified'] = True
    receipt.save()
    cleanup(receipt, payload, deadline)
    return {'qualified': True, 'retention': True, 'sameCSIIdentity': True, 'markerBytesVerified': True,
            'claims': 3, 'sizeGiB': 3, 'backingCleanup': True, 'gitPropagation': 'not claimed'}


def recovery_input(value, operation):
    require(type(value) is dict and set(value) == {'version', 'profile', 'operation', 'predecessor'}
            and type(value['version']) is int and value['version'] == 1 and value['profile'] == RECOVERY_PROFILE
            and value['operation'] == operation, 'Invalid empty recovery envelope')
    namespace(operation)
    previous = value['predecessor']
    require(type(previous) is dict and set(previous) == {'operation', 'driverSHA256', 'inputSHA256', 'receiptSHA256', 'namespaceUID'},
            'Invalid predecessor envelope')
    namespace(previous['operation'])
    require(previous['operation'] != operation and previous['driverSHA256'] == PREDECESSOR_DRIVER
            and all(type(previous[key]) is str and re.fullmatch(r'[a-f0-9]{64}', previous[key])
                    for key in ('driverSHA256', 'inputSHA256', 'receiptSHA256'))
            and type(previous['namespaceUID']) is str and UID.fullmatch(previous['namespaceUID']), 'Unapproved predecessor scope')
    return value


def original_tree(directory):
    protected_directory(directory)
    rows, buffers = {}, {}
    def metadata(info):
        return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
                info.st_size, info.st_atime_ns, info.st_mtime_ns, info.st_ctime_ns]
    def visit(fd, relative):
        before = os.fstat(fd)
        require(before.st_uid == 0 and not before.st_mode & 0o077, 'Unsafe original directory')
        rows[relative] = {'metadata': metadata(before)}
        with os.scandir(fd) as entries:
            names = sorted(entry.name for entry in entries)
        require(len(names) <= 16, 'Original artifact tree exceeds scope')
        for name in names:
            path = (relative + '/' if relative else '') + name
            require(path in ('proof.py', 'input.json', 'operation.lock', 'state', 'state/receipt.json', 'state/failure.json'),
                    'Unexpected original artifact')
            if path == 'state':
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=fd)
                try:
                    visit(child, path)
                finally:
                    os.close(child)
                continue
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=fd)
            try:
                info = os.fstat(child)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077
                        and info.st_nlink == 1 and info.st_size <= LIMIT, 'Unsafe original artifact')
                raw = b''
                while len(raw) <= LIMIT:
                    part = os.read(child, min(65536, LIMIT + 1 - len(raw)))
                    if not part:
                        break
                    raw += part
                require(len(raw) == info.st_size and os.fstat(child) == info, 'Original artifact changed while reading')
                buffers[path] = raw
                rows[path] = {'metadata': metadata(info), 'sha256': digest(raw)}
            finally:
                os.close(child)
        require(os.fstat(fd) == before, 'Original directory changed while reading')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME)
    try:
        visit(fd, '')
    finally:
        os.close(fd)
    required = {'', 'proof.py', 'input.json', 'operation.lock', 'state', 'state/receipt.json'}
    require(required <= set(rows) <= required | {'state/failure.json'}, 'Incomplete original artifact tree')
    return rows, buffers


def predecessor_identity(envelope, buffers):
    previous = envelope['predecessor']
    for key, path in (('driverSHA256', 'proof.py'), ('inputSHA256', 'input.json'), ('receiptSHA256', 'state/receipt.json')):
        require(digest(buffers[path]) == previous[key], 'Original artifact hash differs from approved envelope')
    payload = validate_input(parsed(buffers['input.json']), previous['operation'])
    receipt = parsed(buffers['state/receipt.json'])
    require(type(receipt) is dict and set(receipt) <= {'context', 'phase', 'roots', 'objects', 'intents', 'storage', 'markers',
            'evidence', 'steps', 'pendingStep', 'baseline', 'cleanupStarted', 'cleanupComplete', 'admission'}
            and receipt.get('context') == {'version': 1, 'profile': PROFILE, 'operation': previous['operation'],
                'driver': PREDECESSOR_DRIVER, 'input': digest(canonical(payload))}
            and receipt.get('phase') == 'namespace-created' and receipt.get('steps') == ['namespace-created']
            and receipt.get('pendingStep') in (None, 'baseline-qualified') and not receipt.get('cleanupComplete')
            and not receipt.get('admission') and receipt.get('intents') == {} and receipt.get('storage') == {}
            and receipt.get('markers') == {} and receipt.get('evidence') == {}, 'Unsupported predecessor receipt state')
    require(all(key not in receipt or type(receipt[key]) is bool for key in ('cleanupStarted', 'cleanupComplete'))
            and ('admission' not in receipt or type(receipt['admission']) is dict and not receipt['admission'])
            and ('baseline' not in receipt or type(receipt['baseline']) is dict
                 and set(receipt['baseline']) == {'boundary', 'class', 'nodes', 'pvs', 'volumes'}), 'Malformed predecessor phase state')
    document = root_documents(previous['operation'])[0]
    require(receipt.get('roots') == {'namespace': {'documentHash': digest(canonical(document)), 'accepted': True}}
            and receipt['roots']['namespace']['accepted'] is True
            and type(receipt.get('objects')) is dict and 'namespace' in receipt['objects']
            and set(receipt['objects']) <= {'namespace', 'default-account', 'namespace-ca'}, 'Predecessor has another root or resource')
    expected = {'namespace': ('Namespace', document['metadata']['name'], None),
                'default-account': ('ServiceAccount', 'default', document['metadata']['name']),
                'namespace-ca': ('ConfigMap', 'kube-root-ca.crt', document['metadata']['name'])}
    for key, identity in receipt['objects'].items():
        kind, name, ns = expected[key]
        require(set(identity) == {'apiVersion', 'kind', 'name', 'namespace', 'uid'} and identity['apiVersion'] == 'v1'
                and (identity['kind'], identity['name'], identity['namespace']) == (kind, name, ns)
                and UID.fullmatch(identity['uid']), 'Unsupported predecessor resource identity')
    identity = receipt['objects']['namespace']
    require(identity['uid'] == previous['namespaceUID'], 'Predecessor Namespace UID differs')
    return identity


class EmptyRecoveryJournal:
    def __init__(self, directory, envelope, raw, tree, identity):
        self.directory = Path(directory)
        self.path = self.directory / 'recovery.json'
        self.operation = envelope['predecessor']['operation']
        self.namespace = namespace(self.operation)
        context = {'version': 1, 'profile': RECOVERY_PROFILE, 'operation': envelope['operation'],
                   'driver': digest(Path(__file__).read_bytes()), 'input': digest(raw), 'predecessor': envelope['predecessor']}
        if self.directory.exists():
            self.value = parsed(protected_bytes(self.path))
            require(self.value.get('context') == context and self.value.get('originalTree') == tree
                    and self.value.get('qualified') is False and self.value.get('phase') in ('prepared', 'intent', 'accepted', 'completed')
                    and self.value.get('objects', {}).get('namespace') == identity, 'Recovery journal context changed')
        else:
            protected_directory(self.directory.parent)
            self.directory.mkdir(mode=0o700)
            self.value = {'context': context, 'originalTree': tree, 'qualified': False, 'phase': 'prepared',
                          'objects': {'namespace': identity}, 'evidence': {}, 'housekeeping': {}, 'events': {}, 'namespaceDelete': None}
            self.save()

    def save(self):
        require(self.value['qualified'] is False, 'Recovery cannot qualify the original proof')
        atomic_json(self.path, self.value)

    def record(self, key, obj):
        identity = object_id(obj)
        require(key not in self.value['objects'] or self.value['objects'][key] == identity, 'Recovery resource replaced')
        self.value['objects'][key] = identity
        self.save()
        return identity


def paginated_namespaced(kind, ns=None, *, deadline):
    profiles = {'applications.argoproj.io': ('argoproj.io/v1alpha1', 'Application', 'applications'),
                'appprojects.argoproj.io': ('argoproj.io/v1alpha1', 'AppProject', 'appprojects'),
                'pvc': ('v1', 'PersistentVolumeClaim', 'persistentvolumeclaims')}
    require(kind in profiles and (ns is None or type(ns) is str and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', ns)),
            'Unsupported paginated inventory scope')
    version, object_kind, plural = profiles[kind]
    root = '/api/v1' if version == 'v1' else '/apis/' + version
    path = root + ('/namespaces/' + ns if ns is not None else '') + '/' + plural
    token, resource_version = '', None
    uids, token_hashes = set(), set()
    for unused in range(4096):
        require(deadline > time.monotonic(), 'Inventory operation deadline expired')
        query = {'limit': '1'} | ({'continue': token} if token else {})
        page = parsed(kubectl('get', '--raw', path + '?' + urlencode(query), deadline=deadline))
        require(deadline > time.monotonic(), 'Inventory operation deadline expired')
        require(type(page) is dict and page.get('apiVersion') == version and page.get('kind') == object_kind + 'List'
                and type(page.get('metadata')) is dict and type(page.get('items')) is list and len(page['items']) <= 1,
                'Malformed paginated inventory page')
        metadata = page['metadata']
        rv = metadata.get('resourceVersion')
        require(type(rv) is str and rv and (resource_version is None or resource_version == rv), 'Inventory resourceVersion changed')
        resource_version = rv
        next_token = metadata.get('continue', '')
        remaining = metadata.get('remainingItemCount')
        require(type(next_token) is str and (remaining is None or type(remaining) is int and remaining >= 0
                and (next_token or remaining == 0)), 'Incomplete paginated inventory metadata')
        if next_token:
            hashed = digest(next_token.encode())
            require(hashed not in token_hashes, 'Inventory continuation token repeated')
            token_hashes.add(hashed)
        for row in page['items']:
            require(type(row) is dict and row.get('apiVersion', version) == version
                    and row.get('kind', object_kind) == object_kind and type(row.get('metadata')) is dict,
                    'Inventory row TypeMeta contradicts its collection')
            row.setdefault('apiVersion', version)
            row.setdefault('kind', object_kind)
            identity = row['metadata']
            require(type(identity.get('namespace')) is str
                    and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', identity['namespace'])
                    and (ns is None or identity['namespace'] == ns) and type(identity.get('name')) is str
                    and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', identity['name']), 'Invalid namespaced inventory identity')
            require(type(identity.get('uid')) is str and UID.fullmatch(identity['uid'])
                    and type(identity.get('resourceVersion')) is str and identity['resourceVersion'], 'Invalid inventory UID or resourceVersion')
            identifier = object_id(row)
            require(identifier['uid'] not in uids and len(uids) < 4096, 'Repeated or excessive inventory UID')
            uids.add(identifier['uid'])
            yield row
        require(deadline > time.monotonic(), 'Inventory operation deadline expired')
        if not next_token:
            return
        token = next_token
    raise RuntimeError('Paginated inventory exceeds page bound')


def all_namespaced(kind, *, deadline):
    return paginated_namespaced(kind, deadline=deadline)


def recovery_alias_gate(journal, *, deadline):
    ns, operation = journal.namespace, journal.operation
    def owned(obj):
        metadata = obj.get('metadata', {})
        return metadata.get('labels', {}).get(LABEL) == operation or ns in metadata.get('name', '')
    for app in all_namespaced('applications.argoproj.io', deadline=deadline):
        spec = app.get('spec', {})
        sources = ([spec['source']] if 'source' in spec else []) + spec.get('sources', [])
        require(not owned(app) and spec.get('project') != ns and spec.get('destination', {}).get('namespace') != ns
                and all(source.get('helm', {}).get('valuesObject', {}).get('operationId') != operation
                        and all(parameter.get('name') != 'operationId' or parameter.get('value') != operation
                                for parameter in source.get('helm', {}).get('parameters', [])) for source in sources),
                'Application aliases the predecessor namespace or operation')
    for project in all_namespaced('appprojects.argoproj.io', deadline=deadline):
        require(not owned(project) and all(destination.get('namespace') != ns for destination in project.get('spec', {}).get('destinations', [])),
                'Project aliases the predecessor namespace or operation')
    for claim in all_namespaced('pvc', deadline=deadline):
        require(not owned(claim) and claim['metadata'].get('namespace') != ns, 'Claim aliases the predecessor namespace or operation')
    for pv in listed('pv'):
        reference = pv.get('spec', {}).get('claimRef', {})
        require(not owned(pv) and reference.get('namespace') != ns and ns not in reference.get('name', ''),
                'PV aliases the predecessor namespace or operation')
    for volume in listed('volumes.longhorn.io', 'longhorn-system'):
        reference = volume.get('status', {}).get('kubernetesStatus', {})
        require(not owned(volume) and reference.get('namespace') != ns and ns not in reference.get('pvcName', ''),
                'Longhorn volume aliases the predecessor namespace or operation')


def recovery_namespace(journal):
    identity = journal.value['objects']['namespace']
    obj = current(identity)
    if obj is None:
        return None
    document = root_documents(journal.operation)[0]
    metadata = obj['metadata']
    require(metadata.get('labels') == document['metadata']['labels'] | {'kubernetes.io/metadata.name': journal.namespace}
            and not metadata.get('ownerReferences') and not metadata.get('finalizers')
            and obj.get('spec', {}).get('finalizers', []) in ([], ['kubernetes'])
            and type(metadata.get('creationTimestamp')) is str, 'Recovery Namespace authority changed')
    previous = journal.value['evidence'].get('namespaceCreatedAt')
    require(previous is None or previous == metadata['creationTimestamp'], 'Recovery Namespace creation boundary changed')
    if metadata.get('deletionTimestamp'):
        require(journal.value.get('namespaceDelete') is not None, 'Unknown Namespace termination')
    else:
        require(obj.get('status', {}).get('phase') == 'Active' and obj['spec'].get('finalizers') == ['kubernetes'],
                'Active recovery Namespace lost native cascade protection')
    return obj


def recovery_inventory(journal, *, freeze=False):
    roots = housekeeping_roots()
    require(roots == journal.value['evidence'].get('housekeepingRoots'), 'Recovery public references changed')
    known = {row['identity']['uid']: row for row in journal.value['housekeeping'].values()}
    identities = {row['identity']['uid']: row['identity'] for row in journal.value['housekeeping'].values()}
    ns_identity = journal.value['objects']['namespace']
    identities[ns_identity['uid']] = ns_identity
    for obj in namespace_inventory(journal.namespace):
        metadata = obj['metadata']
        uid = metadata['uid']
        if uid in known:
            require(housekeeping_identity(obj, journal.namespace, journal.value['evidence']['namespaceCreatedAt'], roots) == known[uid],
                    'Recovery housekeeping changed')
            continue
        require(obj['kind'] == 'Event' and obj['apiVersion'] == 'v1' and not metadata.get('ownerReferences')
                and not metadata.get('finalizers'), 'Unknown object blocks empty namespace recovery')
        reference = event_reference(obj)
        require(reference['uid'] in identities, 'Foreign Event reference blocks recovery')
        expected = identities[reference['uid']]
        require((reference['apiVersion'], reference['kind'], reference['name'], reference['namespace'])
                == (expected['apiVersion'], expected['kind'], expected['name'], expected['namespace'] or ''), 'Event reference identity differs')
        reporter = obj.get('reportingComponent') or obj.get('source', {}).get('component', '')
        require(reporter in {'namespace-controller', 'root-ca-cert-publisher', 'serviceaccount-controller',
                             'kube-controller-manager', 'k3s', 'pilot-discovery', 'istiod'}, 'Unknown recovery Event writer')
        row = {'identity': object_id(obj), 'reference': reference, 'reporter': reporter}
        prior = journal.value['events'].get(uid)
        require(prior == row or freeze and prior is None, 'Unknown or changed recovery Event')
        if prior is None:
            journal.value['events'][uid] = row
    if freeze:
        journal.save()


def recovery_scope(journal):
    return digest(canonical({'context': journal.value['context'], 'namespace': journal.value['objects']['namespace'],
        'housekeeping': journal.value['housekeeping'], 'evidence': journal.value['evidence'], 'events': journal.value['events']}))


def empty_recovery(envelope, directory, raw, deadline):
    import fcntl
    recovery_input(envelope, envelope['operation'])
    require(parsed(raw) == envelope, 'Recovery input buffer differs from envelope')
    old = ROOT / ('observability-storage-' + envelope['predecessor']['operation'])
    expected = ROOT / ('observability-storage-recovery-' + envelope['operation']) / 'state'
    require(Path(directory) == expected and old != expected.parent and old.parent == expected.parent.parent,
            'Recovery sibling scope differs')
    protected_directory(expected.parent)
    protected_directory(old)
    new_lock = os.open(expected.parent / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    old_lock = None
    try:
        info = os.fstat(new_lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077,
                'Unsafe recovery lock')
        fcntl.flock(new_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old_lock = os.open(old / 'operation.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
        info = os.fstat(old_lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077,
                'Unsafe original operation lock')
        fcntl.flock(old_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        tree, buffers = original_tree(old)
        def unchanged():
            require(original_tree(old)[0] == tree, 'Original artifacts changed; recovery retained')
        try:
            identity = predecessor_identity(envelope, buffers)
            journal = EmptyRecoveryJournal(expected, envelope, raw, tree, identity)
            unchanged()
            intent = journal.value['namespaceDelete']
            if intent is not None:
                require(set(intent) == {'identity', 'resourceVersion', 'scope', 'accepted', 'complete'}
                        and intent['identity'] == identity and type(intent['resourceVersion']) is str and intent['resourceVersion']
                        and type(intent['accepted']) is bool and type(intent['complete']) is bool
                        and intent['scope'] == recovery_scope(journal)
                        and set(journal.value['housekeeping']) == {'default', 'kube-root-ca.crt', 'istio-ca-root-cert', 'istio-ca-crl'}
                        and journal.value['phase'] in ('intent', 'accepted', 'completed'), 'Recovery intent is incomplete or changed')
                require(housekeeping_roots() == journal.value['evidence'].get('housekeepingRoots'), 'Recovery public references changed')
            recovery_alias_gate(journal, deadline=deadline)
            obj = recovery_namespace(journal)
            if obj is None:
                require(intent and intent['identity'] == identity, 'Namespace absent without matching durable recovery intent')
            else:
                require(journal.value['phase'] != 'completed', 'Completed recovery Namespace reappeared')
                if intent is None:
                    housekeeping(journal, deadline)
                    recovery_inventory(journal, freeze=True)
                else:
                    recovery_inventory(journal)
                recovery_alias_gate(journal, deadline=deadline)
                obj = recovery_namespace(journal)
                require(obj is not None, 'Namespace disappeared before durable intent')
                scope = recovery_scope(journal)
                if intent is None:
                    intent = {'identity': identity, 'resourceVersion': obj['metadata']['resourceVersion'],
                              'scope': scope, 'accepted': False, 'complete': False}
                    journal.value['namespaceDelete'] = intent
                    journal.value['phase'] = 'intent'
                    journal.save()
                require(intent['identity'] == identity and intent['scope'] == scope and not intent['complete'], 'Recovery intent scope changed')
                unchanged()
                recovery_alias_gate(journal, deadline=deadline)
                recovery_inventory(journal)
                obj = recovery_namespace(journal)
                if obj is not None and not obj['metadata'].get('deletionTimestamp'):
                    require(obj['metadata']['resourceVersion'] == intent['resourceVersion'], 'Namespace changed after recovery intent')
                    options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Foreground',
                        'preconditions': {'uid': identity['uid'], 'resourceVersion': intent['resourceVersion']}}
                    unchanged()
                    kubectl('delete', '--raw', api_path(identity), '-f', '-', body=canonical(options))
                    intent['accepted'] = True
                    journal.value['phase'] = 'accepted'
                    journal.save()
                def gone():
                    unchanged()
                    recovery_alias_gate(journal, deadline=deadline)
                    value = recovery_namespace(journal)
                    if value is None:
                        return True
                    recovery_inventory(journal)
                    return False
                wait('exact empty Namespace native cascade', gone, deadline)
            unchanged()
            recovery_alias_gate(journal, deadline=deadline)
            require(housekeeping_roots() == journal.value['evidence'].get('housekeepingRoots'), 'Recovery public references changed')
            require(recovery_namespace(journal) is None, 'Recovery Namespace still exists')
            intent['complete'] = True
            journal.value['phase'] = 'completed'
            journal.save()
            return {'cleanup': True, 'recoveryOnly': True, 'qualified': False, 'originalQualified': False}
        finally:
            unchanged()
    finally:
        if old_lock is not None:
            os.close(old_lock)
        os.close(new_lock)


def storage_recovery_input(value, operation):
    marker = type(value) is dict and value.get('case') == MARKER_RECOVERY_CASE
    fields = {'version', 'profile', 'operation', 'predecessor', 'dataScope'}
    require(type(value) is dict and set(value) == fields | ({'case', 'scopeWitnessSHA256'} if marker else set())
            and type(value['version']) is int and value['version'] == 1
            and value['profile'] == STORAGE_RECOVERY_PROFILE and value['operation'] == operation,
            'Invalid storage cleanup recovery envelope')
    namespace(operation)
    previous = value['predecessor']
    if marker:
        require(type(previous) is dict and set(previous) == {'operation', 'driverSHA256', 'inputSHA256', 'receiptSHA256',
                'namespaceUID', 'treeSHA256'} and previous['driverSHA256'] == MARKER_PREDECESSOR_DRIVER
                and all(type(item) is str and re.fullmatch(r'[a-f0-9]{64}', item) for item in
                        (previous['inputSHA256'], previous['receiptSHA256'], previous['treeSHA256'], value['scopeWitnessSHA256']))
                and type(previous['namespaceUID']) is str and UID.fullmatch(previous['namespaceUID'])
                and previous['operation'] != operation, 'Unapproved marker cleanup predecessor')
        namespace(previous['operation'])
    else:
        require(type(previous) is dict and set(previous) == {'operation', 'driverSHA256', 'inputSHA256', 'receiptSHA256', 'namespaceUID'}
                and previous['operation'] == STORAGE_PREDECESSOR_OPERATION and previous['operation'] != operation
                and previous['driverSHA256'] == STORAGE_PREDECESSOR_DRIVER and previous['inputSHA256'] == STORAGE_PREDECESSOR_INPUT
            and type(previous['receiptSHA256']) is str and re.fullmatch(r'[a-f0-9]{64}', previous['receiptSHA256'])
            and type(previous['namespaceUID']) is str and UID.fullmatch(previous['namespaceUID']), 'Unapproved storage predecessor')
    scope = value['dataScope']
    require(type(scope) is dict and set(scope) == {'loki', 'tempo', 'grafana'}, 'Recovery requires exactly three claim scopes')
    ns = namespace(previous['operation'])
    for component, row in scope.items():
        require(type(row) is dict and set(row) == {'identity', 'replicasSHA256'} and type(row['replicasSHA256']) is str
                and re.fullmatch(r'[a-f0-9]{64}', row['replicasSHA256']), 'Invalid recorded replica scope')
        identity = row['identity']
        require(type(identity) is dict and set(identity) == {'claim', 'pv', 'volume', 'handle'}, 'Invalid storage identity')
        claim = identity['claim']
        for key, kind, version, target_ns in [('claim', 'PersistentVolumeClaim', 'v1', ns),
                ('pv', 'PersistentVolume', 'v1', None), ('volume', 'Volume', 'longhorn.io/v1beta2', 'longhorn-system')]:
            obj = identity[key]
            require(type(obj) is dict and set(obj) == {'apiVersion', 'kind', 'name', 'namespace', 'uid'}
                    and obj['apiVersion'] == version and obj['kind'] == kind and obj['namespace'] == target_ns
                    and type(obj['uid']) is str and UID.fullmatch(obj['uid']), 'Invalid recovery object scope')
        require(claim['name'] == claim_names(previous['operation'])[component]
                and identity['handle'] == 'pvc-' + claim['uid']
                and identity['pv']['name'] == identity['volume']['name'] == identity['handle'], 'Recovery backing alias')
    require(all(len({row['identity'][key]['uid'] for row in scope.values()}) == 3 for key in ('claim', 'pv', 'volume')),
            'Recovery claims must have independent storage')
    return value


def storage_predecessor(envelope, buffers):
    previous = envelope['predecessor']
    for key, path in (('driverSHA256', 'proof.py'), ('inputSHA256', 'input.json'), ('receiptSHA256', 'state/receipt.json')):
        require(digest(buffers[path]) == previous[key], 'Original storage artifact differs from envelope')
    payload = validate_input(parsed(buffers['input.json']), previous['operation'])
    value = parsed(buffers['state/receipt.json'])
    if envelope.get('case') == MARKER_RECOVERY_CASE:
        return marker_storage_predecessor(envelope, payload, value)
    require(value.get('context') == {'version': 1, 'profile': PROFILE, 'operation': previous['operation'],
                'driver': STORAGE_PREDECESSOR_DRIVER, 'input': STORAGE_PREDECESSOR_INPUT}
            and value.get('phase') == 'drift-repaired' and value.get('pendingStep') == 'scaled-down-qualified'
            and value.get('appPhase', 'running') == 'running' and not value.get('pendingAdvance')
            and value.get('cleanupStarted') is True and value.get('cleanupComplete', False) is False
            and value.get('markers') == {} and value.get('evidence', {}).get('qualified', False) is False
            and value.get('evidence', {}).get('cascadeRetainedClaims') is True
            and type(value.get('baseline')) is dict and type(value.get('admission')) is dict and value['admission'],
            'Unsupported failed storage predecessor state')
    objects, roots, intents = value.get('objects', {}), value.get('roots', {}), value.get('intents', {})
    require(type(objects) is dict and type(roots) is dict and type(intents) is dict
            and len(objects) <= 128 and len(intents) <= 256 and set(roots) == {'namespace', 'app', 'project'},
            'Invalid predecessor ownership records')
    for key, document in zip(('namespace', 'project', 'app'), root_documents(previous['operation'])):
        require(roots[key] == {'accepted': True, 'documentHash': digest(canonical(document))}, 'Predecessor root declaration changed')
        identity = objects[key]
        require(identity['kind'] == document['kind'] and identity['apiVersion'] == document['apiVersion']
                and identity['name'] == document['metadata']['name'] and identity['namespace'] == document['metadata'].get('namespace')
                and UID.fullmatch(identity['uid']), 'Predecessor root identity changed')
    require(objects['namespace']['uid'] == previous['namespaceUID'], 'Predecessor Namespace differs')
    def intent_matches(key, identity, scope, *, accepted, complete, cascade=False):
        item = intents.get(key, {})
        require(item.get('identity') == identity and item.get('scope') == digest(canonical(scope))
                and item.get('accepted') is accepted and item.get('complete') is complete
                and (not cascade or item.get('cascade') is True), 'Predecessor deletion provenance differs')
    intent_matches('delete-app', objects['app'], {'source': payload['source'], 'app': objects['app']}, accepted=True, complete=True)
    require(set(value.get('storage', {})) == {'loki', 'tempo', 'grafana'}, 'Incomplete predecessor data scope')
    for component, scope in envelope['dataScope'].items():
        row = value['storage'][component]
        identity = row['identity']
        require(identity == scope['identity'] and digest(canonical(row['replicas'])) == scope['replicasSHA256']
                and objects.get('claim-' + component) == identity['claim'] and row.get('cleaned', False) is False,
                'Predecessor storage scope changed')
        validate_replica_rows(row['replicas'])
        require(all(re.fullmatch('/var/lib/longhorn/replicas/' + re.escape(identity['handle']) + r'-[a-f0-9]{8}', r['path'])
                    for r in row['replicas']), 'Predecessor replica path escaped claim')
        intent_matches('delete-claim-' + component, identity['claim'], identity, accepted=True, complete=True)
        backing = {'profile': PROFILE, 'operation': previous['operation'], 'component': component,
                   'identity': identity, 'replicas': row['replicas']}
        if component == 'grafana':
            require('delete-pv-grafana' not in intents and 'delete-volume-grafana' not in intents, 'Unexpected Grafana backing intent')
        else:
            intent_matches('delete-volume-' + component, identity['volume'], backing, accepted=True, complete=True)
            intent_matches('delete-pv-' + component, identity['pv'], backing, accepted=False, complete=True, cascade=True)
    require(set(intents) == {'delete-app', 'replica-drift'} | {'delete-claim-' + c for c in envelope['dataScope']}
            | {'delete-' + k + '-' + c for k in ('pv', 'volume') for c in ('loki', 'tempo')}, 'Unexpected predecessor mutation')
    return payload, value


def marker_storage_predecessor(envelope, payload, value):
    previous = envelope['predecessor']
    require(value.get('context') == {'version': 1, 'profile': PROFILE, 'operation': previous['operation'],
                'driver': MARKER_PREDECESSOR_DRIVER, 'input': digest(canonical(payload))}
            and value.get('cleanupStarted') is True and value.get('cleanupComplete', False) is False
            and value.get('evidence', {}).get('qualified', False) is False and value.get('appPhase') == 'scaled-down'
            and not value.get('pendingAdvance') and value.get('phase') == 'marker-written-tempo'
            and value.get('pendingStep') == 'marker-written-grafana', 'Unsupported marker cleanup predecessor state')
    objects, roots, intents = value.get('objects', {}), value.get('roots', {}), value.get('intents', {})
    require(type(objects) is dict and len(objects) <= 128 and type(intents) is dict and len(intents) <= 256
            and type(roots) is dict and set(roots) == {'namespace', 'project', 'app'}
            and type(value.get('baseline')) is dict and type(value.get('admission')) is dict and value['admission']
            and set(value.get('storage', {})) == {'loki', 'tempo', 'grafana'},
            'Incomplete marker predecessor ownership')
    for key, document in zip(('namespace', 'project', 'app'), root_documents(previous['operation'])):
        identity = objects[key]
        require(roots[key] == {'accepted': True, 'documentHash': digest(canonical(document))}
                and identity['apiVersion'] == document['apiVersion'] and identity['kind'] == document['kind']
                and identity['name'] == document['metadata']['name'] and identity['namespace'] == document['metadata'].get('namespace')
                and UID.fullmatch(identity['uid']), 'Marker predecessor root differs')
    require(objects['namespace']['uid'] == previous['namespaceUID'], 'Marker predecessor namespace differs')
    def completed(key, identity, scope):
        item = intents.get(key, {})
        require(item.get('identity') == identity and item.get('scope') == digest(canonical(scope))
                and item.get('accepted') is True and item.get('complete') is True, 'Marker predecessor deletion differs')
    completed('delete-app', objects['app'], {'source': payload['source'], 'app': objects['app']})
    require(len(value.get('markerRuns', [])) == 3 and [r.get('component') for r in value['markerRuns']] == ['loki', 'tempo', 'grafana']
            and all(r.get('mode') == 'write' for r in value['markerRuns']), 'Marker predecessor histories differ')
    view = SimpleNamespace(value=value, operation=previous['operation'], namespace=namespace(previous['operation']))
    for component, scope in envelope['dataScope'].items():
        row = value['storage'][component]
        identity = row['identity']
        require(identity == scope['identity'] and objects.get('claim-' + component) == identity['claim']
                and digest(canonical(row['replicas'])) == scope['replicasSHA256'] and not row.get('cleaned'),
                'Marker predecessor data scope differs')
        validate_replica_rows(row['replicas'])
        require(all(re.fullmatch('/var/lib/longhorn/replicas/' + re.escape(identity['handle']) + r'-[a-f0-9]{8}', r['path'])
                    for r in row['replicas']), 'Marker predecessor path escaped backing')
        require(not any('delete-' + kind + '-' + component in intents for kind in ('pv', 'volume')),
                'Marker predecessor already granted backing deletion')
        if component == 'loki':
            completed('delete-claim-loki', identity['claim'], identity)
        else:
            require('delete-claim-' + component not in intents, 'Unexpected remaining-claim deletion intent')
        validate_standalone_marker_history(view, payload, component,
            {'podName': view.namespace + '-marker', 'podStatus': 'Succeeded', 'workloadName': '', 'workloadType': ''})
    require(set(intents) == {'replica-drift', 'phase-0', 'delete-app', 'delete-claim-loki',
            'delete-marker-0', 'delete-marker-1', 'delete-marker-2'}, 'Unexpected marker predecessor mutation')
    return payload, value


class StorageRecoveryReceipt(Receipt):
    def __init__(self, directory, envelope, raw, tree, original, unchanged):
        self.directory, self.path = Path(directory), Path(directory) / 'recovery.json'
        self.operation = envelope['predecessor']['operation']
        self.namespace = namespace(self.operation)
        self.envelope, self.tree, self.unchanged = envelope, tree, unchanged
        self.original_markers = {key: copy.deepcopy(original.get(key)) for key in ('markers', 'markerRuns')}
        self.original_identities = {key: copy.deepcopy(value) for key, value in original['objects'].items()
                                    if key in ('namespace', 'project', 'app') or key.startswith(('marker-', 'claim-'))}
        self.context = {'version': 1, 'profile': STORAGE_RECOVERY_PROFILE, 'operation': envelope['operation'],
                        'driver': digest(Path(__file__).read_bytes()), 'input': digest(raw), 'predecessor': envelope['predecessor']}
        if self.directory.exists():
            self.value = parsed(protected_bytes(self.path))
        else:
            protected_directory(self.directory.parent)
            self.directory.mkdir(mode=0o700)
            self.value = copy.deepcopy(original)
            self.value.update(context=self.context, originalTree=tree, dataScope=envelope['dataScope'])
            self.value['evidence']['qualified'] = False
            self.save()
        self.validate()

    def validate(self):
        require(self.value.get('context') == self.context and self.value.get('originalTree') == self.tree
                and self.value.get('dataScope') == self.envelope['dataScope']
                and self.value.get('evidence', {}).get('qualified') is False, 'Recovery journal identity or qualification changed')
        for component, scope in self.envelope['dataScope'].items():
            row = self.value['storage'][component]
            require(row['identity'] == scope['identity'] and digest(canonical(row['replicas'])) == scope['replicasSHA256'],
                    'Recovery data scope changed')
        if self.envelope.get('case') == MARKER_RECOVERY_CASE:
            require(all(self.value.get(key) == value for key, value in self.original_markers.items()),
                    'Original marker provenance changed in recovery')
            require(all(self.value['objects'].get(key) == identity for key, identity in self.original_identities.items()),
                    'Original recovery ownership identities changed')

    def save(self):
        self.validate()
        self.unchanged()
        atomic_json(self.path, self.value)


def storage_recovery_alias_gate(receipt, *, deadline):
    ns, operation = receipt.namespace, receipt.operation
    for app in all_namespaced('applications.argoproj.io', deadline=deadline):
        spec = app.get('spec', {})
        sources = ([spec['source']] if 'source' in spec else []) + spec.get('sources', [])
        require(app['metadata'].get('labels', {}).get(LABEL) != operation and ns not in app['metadata']['name']
                and spec.get('project') != ns and spec.get('destination', {}).get('namespace') != ns
                and all(source.get('helm', {}).get('valuesObject', {}).get('operationId') != operation
                    and all(p.get('name') != 'operationId' or p.get('value') != operation
                            for p in source.get('helm', {}).get('parameters', [])) for source in sources), 'Application aliases recovery data')
    for project in all_namespaced('appprojects.argoproj.io', deadline=deadline):
        if object_id(project) == receipt.value['objects']['project']:
            root_current(receipt, 'project')
            continue
        require(project['metadata'].get('labels', {}).get(LABEL) != operation and ns not in project['metadata']['name']
                and all(d.get('namespace') != ns for d in project.get('spec', {}).get('destinations', [])), 'Foreign project aliases recovery data')
    for claim in all_namespaced('pvc', deadline=deadline):
        if getattr(receipt, 'envelope', {}).get('case') == MARKER_RECOVERY_CASE:
            own = next((row['identity']['claim'] for row in receipt.value['storage'].values()
                        if object_id(claim) == row['identity']['claim']), None)
            if own:
                component = next(c for c, row in receipt.value['storage'].items() if row['identity']['claim'] == own)
                require(not receipt.value['intents'].get('delete-claim-' + component, {}).get('complete'),
                        'Completed claim reappeared')
                continue
        require(claim['metadata'].get('namespace') != ns and claim['metadata'].get('labels', {}).get(LABEL) != operation,
                'Claim appeared after completed original claim deletions')
    for kind, key in [('pv', 'pv'), ('volumes.longhorn.io', 'volume')]:
        for obj in listed(kind, 'longhorn-system' if key == 'volume' else None):
            own = next((r['identity'][key] for r in receipt.value['storage'].values()
                        if r['identity'][key]['name'] == obj['metadata']['name']), None)
            if own:
                require(object_id(obj) == own, 'Recovery backing identity changed')
                continue
            link = obj.get('spec', {}).get('claimRef', {}) if key == 'pv' else obj.get('status', {}).get('kubernetesStatus', {})
            handle = obj.get('spec', {}).get('csi', {}).get('volumeHandle') if key == 'pv' else obj['metadata']['name']
            require(obj['metadata'].get('labels', {}).get(LABEL) != operation and link.get('namespace') != ns
                    and handle not in {r['identity']['handle'] for r in receipt.value['storage'].values()}, 'Foreign backing aliases recovery data')


def storage_recovery_preflight(receipt, *, deadline, payload=None):
    if getattr(receipt, 'envelope', {}).get('case') == MARKER_RECOVERY_CASE:
        return marker_storage_recovery_preflight(receipt, payload, deadline)
    storage_recovery_alias_gate(receipt, deadline=deadline)
    require(current(receipt.value['objects']['app']) is None, 'Original Application reappeared')
    require(storage_class() == receipt.value['baseline']['class'], 'Original StorageClass changed')
    for component, row in receipt.value['storage'].items():
        identity = row['identity']
        require(current(identity['claim']) is None, 'Deleted original claim reappeared')
        pv, volume = current(identity['pv']), current(identity['volume'])
        if component in ('loki', 'tempo'):
            require(pv is None and volume is None, 'Completed original backing reappeared')
            continue
        pair = [receipt.value['intents'].get('delete-' + k + '-grafana') for k in ('pv', 'volume')]
        if pv is None or volume is None:
            require(all(pair) and pair[1]['accepted'], 'Grafana backing absent without durable recovery intent')
        if pv is not None:
            released_pv(receipt, identity, pv)
            require(pv['spec'].get('capacity', {}).get('storage') == '1Gi'
                    and pv['metadata'].get('annotations', {}).get('pv.kubernetes.io/provisioned-by') == 'driver.longhorn.io',
                    'Grafana original PV profile changed')
        if volume is not None:
            require(object_id(volume) == identity['volume'], 'Grafana volume identity changed')
            no_restore(volume)
            backing_deletion_gate(identity, volume)
        if not any(pair):
            require(pv is not None and volume is not None, 'Initial Grafana backing missing')
            for key, obj in [('pvs', pv), ('volumes', volume)]:
                meta = obj['metadata']
                require(digest(meta['uid'].encode()) not in receipt.value['baseline'][key]['uid']
                        and digest(meta['name'].encode()) not in receipt.value['baseline'][key]['name']
                        and datetime.fromisoformat(meta['creationTimestamp'].replace('Z', '+00:00'))
                            >= datetime.fromisoformat(receipt.value['baseline']['boundary']), 'Grafana backing predates original fresh baseline')
            require(sorted(capture_replicas(identity), key=lambda r: r['replicaUID'])
                    == sorted(row['replicas'], key=lambda r: r['replicaUID']), 'Original Grafana replicas changed')
            # Validate all normal guards without publishing an intent in this preflight.
            require(recorded_grafana_replicasets(receipt), 'Original Grafana ReplicaSet provenance missing')


def marker_storage_recovery_preflight(receipt, payload, deadline):
    storage_recovery_alias_gate(receipt, deadline=deadline)
    require(current(receipt.value['objects']['app']) is None, 'Original Application reappeared')
    require(storage_class() == receipt.value['baseline']['class'], 'Original StorageClass changed')
    ns = current(receipt.value['objects']['namespace'])
    if ns is None:
        require(receipt.value['intents'].get('delete-namespace', {}).get('accepted') is True,
                'Namespace absent without acknowledged recovery deletion')
    else:
        root_current(receipt, 'namespace')
        require(not receipt.value['intents'].get('delete-namespace', {}).get('complete')
                and not listed('pods', receipt.namespace), 'Recovery namespace has current consumers or reappeared')
    replicas = listed('replicas.longhorn.io', 'longhorn-system')
    identities = [row['identity'] for row in receipt.value['storage'].values()]
    for attachment in listed('volumeattachments.storage.k8s.io'):
        require(attachment.get('spec', {}).get('source', {}).get('persistentVolumeName')
                not in {identity['pv']['name'] for identity in identities}, 'Recovery CSI attachment remains')
    for attachment in listed('volumeattachments.longhorn.io', 'longhorn-system'):
        if attachment.get('spec', {}).get('volume') in {identity['handle'] for identity in identities}:
            require(not attachment['spec'].get('attachmentTickets'), 'Recovery native attachment remains')
    def intent(key, identity, scope):
        item = receipt.value['intents'].get(key)
        if item is not None:
            require(item.get('identity') == identity and item.get('scope') == digest(canonical(scope))
                    and type(item.get('accepted')) is bool and type(item.get('complete')) is bool,
                    'Recovery progress intent changed')
        return item or {}
    for component, row in receipt.value['storage'].items():
        identity = row['identity']
        claim = current(identity['claim'])
        deletion = intent('delete-claim-' + component, identity['claim'], identity)
        if claim is None:
            require(deletion.get('accepted') is True, 'Claim absent without acknowledged recovery deletion')
        else:
            require(not deletion.get('complete') and fresh_identity(receipt, claim, healthy=False) == identity,
                    'Original remaining claim changed or reappeared')
        scope = {'profile': PROFILE, 'operation': receipt.operation, 'component': component,
                 'identity': identity, 'replicas': row['replicas']}
        pv_intent = intent('delete-pv-' + component, identity['pv'], scope)
        volume_intent = intent('delete-volume-' + component, identity['volume'], scope)
        require(bool(pv_intent) == bool(volume_intent), 'Unpaired recovery backing intent')
        pv, volume = current(identity['pv']), current(identity['volume'])
        if claim is not None:
            require(pv is not None and volume is not None and pv.get('status', {}).get('phase') == 'Bound',
                    'Remaining claim backing is not bound')
        if pv is None or volume is None:
            require(volume_intent.get('accepted') is True, 'Backing absent without acknowledged paired deletion')
        if pv_intent.get('complete'):
            require(pv is None and (pv_intent.get('accepted') is True
                    or pv_intent.get('cascade') is True and volume_intent.get('accepted') is True), 'Completed PV reappeared')
        if volume_intent.get('complete'):
            require(volume is None and volume_intent.get('accepted') is True, 'Completed volume reappeared')
        if pv is not None and claim is None:
            released_pv(receipt, identity, pv)
        if volume is not None:
            no_restore(volume)
            require(volume['spec'].get('numberOfReplicas') == 2, 'Recovery replica policy changed')
            link = volume.get('status', {}).get('kubernetesStatus', {})
            if not volume_intent.get('accepted'):
                require(link.get('pvName') == identity['pv']['name'] and link.get('pvcName') == identity['claim']['name']
                        and link.get('namespace') == receipt.namespace
                        and link.get('pvStatus') == ('Bound' if claim is not None else 'Released'),
                        'Recovery native claim linkage changed')
                backing_deletion_gate(identity, volume)
                require(not volume['metadata'].get('deletionTimestamp') and not pv['metadata'].get('deletionTimestamp'),
                        'Backing deletion began without acknowledgement')
                for entry in link.get('workloadsStatus', []):
                    if entry.get('podName') == receipt.namespace + '-marker' or not entry.get('workloadType'):
                        validate_standalone_marker_history(receipt, payload, component, entry)
        actual = [obj for obj in replicas if obj.get('spec', {}).get('volumeName') == identity['handle']]
        current_uids, recorded_uids = {obj['metadata']['uid'] for obj in actual}, {r['replicaUID'] for r in row['replicas']}
        require(current_uids <= recorded_uids and (volume_intent.get('accepted') or current_uids == recorded_uids),
                'Recovery native replica identities changed')
        for obj in actual:
            replica = next(r for r in row['replicas'] if r['replicaUID'] == obj['metadata']['uid'])
            require(obj['spec'].get('nodeID') == replica['node'] and obj['spec'].get('diskPath') == replica['disk']
                    and obj['spec'].get('dataDirectoryName') == Path(replica['path']).name,
                    'Recovery native replica backing changed')
        for replica in row['replicas']:
            now = directory_state(replica)
            require(now['disk'] == replica['context']['disk'] and now['parent'] == replica['context']['parent'],
                    'Recovery backing parent changed')
            require(now == replica['context'] if now['present'] else volume_intent.get('accepted') is True,
                    'Backing changed or disappeared without acknowledged deletion')
            require(not row.get('cleaned') or not now['present'], 'Cleaned backing reappeared')
        if row.get('cleaned'):
            require(claim is None and pv is None and volume is None, 'Cleaned storage reappeared')


def storage_cleanup_recovery(envelope, directory, raw, deadline):
    import fcntl
    storage_recovery_input(envelope, envelope['operation'])
    require(parsed(raw) == envelope, 'Recovery envelope buffer changed')
    old = ROOT / ('observability-storage-' + envelope['predecessor']['operation'])
    expected = ROOT / ('observability-storage-recovery-' + envelope['operation']) / 'state'
    require(Path(directory) == expected and old != expected.parent, 'Storage recovery sibling scope differs')
    protected_directory(expected.parent)
    protected_directory(old)
    new_lock = os.open(expected.parent / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    old_lock = None
    try:
        for fd in (new_lock,):
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077,
                    'Unsafe storage recovery lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old_lock = os.open(old / 'operation.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
        info = os.fstat(old_lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077, 'Unsafe predecessor lock')
        fcntl.flock(old_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        tree, buffers = original_tree(old)
        if envelope.get('case') == MARKER_RECOVERY_CASE:
            require(digest(canonical(tree)) == envelope['predecessor']['treeSHA256'], 'Approved predecessor tree changed')
        def unchanged():
            require(original_tree(old)[0] == tree, 'Original storage artifacts changed; recovery retained')
        try:
            payload, original = storage_predecessor(envelope, buffers)
            receipt = StorageRecoveryReceipt(expected, envelope, raw, tree, original, unchanged)
            storage_recovery_preflight(receipt, deadline=deadline, payload=payload)
            unchanged()
            cleanup(receipt, payload, deadline)
            storage_recovery_alias_gate(receipt, deadline=deadline)
            require(all(backing_absent(row['replicas']) and row.get('cleaned') is True
                        for row in receipt.value['storage'].values()), 'Not all original backing paths are absent')
            return {'cleanup': True, 'recoveryOnly': True, 'qualified': False, 'originalQualified': False}
        finally:
            unchanged()
    finally:
        if old_lock is not None:
            os.close(old_lock)
        os.close(new_lock)


def host_preflight(directory, operation, driver_hash, mode, envelope=None):
    require(os.geteuid() == 0 and re.fullmatch(r'[a-f0-9]{64}', driver_hash), 'Host root authority required')
    if __file__ != '<stdin>':
        require(digest(Path(__file__).read_bytes()) == driver_hash, 'Host driver hash differs')
    else:
        require(mode in ('fresh', 'recovery-fresh'), 'Cleanup preflight requires the installed driver')
    recovery = mode.startswith('recovery-')
    if recovery:
        require(envelope is not None, 'Recovery envelope required before staging')
        supplied = parsed(envelope)
        (storage_recovery_input if supplied.get('profile') == STORAGE_RECOVERY_PROFILE else recovery_input)(supplied, operation)
        if supplied.get('case') == MARKER_RECOVERY_CASE:
            tree, buffers = original_tree(ROOT / ('observability-storage-' + supplied['predecessor']['operation']))
            require(digest(canonical(tree)) == supplied['predecessor']['treeSHA256'], 'Approved predecessor tree changed')
            storage_predecessor(supplied, buffers)
    expected = ROOT / (('observability-storage-recovery-' if recovery else 'observability-storage-') + operation)
    require(Path(directory) == expected, 'Host operation path differs')
    if mode in ('fresh', 'recovery-fresh'):
        require(not expected.exists(), 'Existing operation cannot be adopted')
        ensure_protected_directory(ROOT)
        expected.mkdir(mode=0o700)
    else:
        protected_directory(expected)
        require(digest(protected_bytes(expected / 'proof.py')) == driver_hash, 'Installed driver differs')
        if recovery and (expected / 'input.json').exists():
            require(parsed(protected_bytes(expected / 'input.json')) == parsed(envelope), 'Installed recovery envelope differs')
    return {'hostPreflight': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--prepare', action='store_true')
    modes.add_argument('--host-preflight', action='store_true')
    modes.add_argument('--run', action='store_true')
    modes.add_argument('--cleanup', action='store_true')
    modes.add_argument('--recover-empty-namespace', action='store_true')
    modes.add_argument('--recover-storage-cleanup', action='store_true')
    parser.add_argument('--operation', required=True)
    parser.add_argument('--directory')
    parser.add_argument('--input')
    parser.add_argument('--driver-hash')
    parser.add_argument('--host-mode', choices=('fresh', 'cleanup', 'recovery-fresh', 'recovery-installed'), default='fresh')
    parser.add_argument('--recovery-envelope')
    args = parser.parse_args()
    namespace(args.operation)
    if args.prepare:
        print(canonical(prepare(args.operation)).decode())
        return
    if args.host_preflight:
        print(json.dumps(host_preflight(args.directory, args.operation, args.driver_hash, args.host_mode, args.recovery_envelope)))
        return
    if args.recover_empty_namespace or args.recover_storage_cleanup:
        expected = ROOT / ('observability-storage-recovery-' + args.operation)
        require(os.geteuid() == 0 and args.driver_hash and digest(Path(__file__).read_bytes()) == args.driver_hash
                and Path(__file__) == expected / 'proof.py' and Path(args.directory) == expected / 'state'
                and Path(args.input) == expected / 'input.json', 'Recovery staging or code identity differs')
        raw = protected_bytes(Path(args.input))
        validator = storage_recovery_input if args.recover_storage_cleanup else recovery_input
        action = storage_cleanup_recovery if args.recover_storage_cleanup else empty_recovery
        envelope = validator(parsed(raw), args.operation)
        print(json.dumps(action(envelope, args.directory, raw, time.monotonic() + 1800)))
        return
    require(os.geteuid() == 0 and args.driver_hash and digest(Path(__file__).read_bytes()) == args.driver_hash
            and Path(args.directory) == ROOT / ('observability-storage-' + args.operation) / 'state'
            and Path(args.input) == Path(args.directory).parent / 'input.json', 'Host operation scope differs')
    payload = validate_input(parsed(protected_bytes(Path(args.input))), args.operation)
    import fcntl
    lock_path = Path(args.directory).parent / 'operation.lock'
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077 and info.st_nlink == 1,
                'Unsafe operation lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = Receipt(Path(args.directory), args.operation, payload, resume=Path(args.directory).exists())
        deadline = time.monotonic() + (3600 if args.run else 1800)
        try:
            if args.cleanup:
                cleanup(receipt, payload, deadline)
                print(json.dumps({'cleanup': True, 'qualified': bool(receipt.value['evidence'].get('qualified'))}))
            else:
                print(json.dumps(run(receipt, payload, deadline)))
        except Exception as error:
            record_failure(receipt, error)
            raise
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Storage lifecycle proof incomplete; protected operation retained') from None
