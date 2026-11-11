"""Check fresh vault authentication and disposable ESO reconciliation without logging secrets."""

import base64
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

NAMESPACE = 'external-secrets'
API = 'external-secrets.io/v1'


class KubernetesError(RuntimeError):
    def __init__(self, collision=False):
        super().__init__('Kubernetes operation failed (details withheld)')
        self.collision = collision


def kubectl(*args, body=None, namespace=NAMESPACE):
    scope = ['-n', namespace] if namespace else []
    result = subprocess.run(
        ['/usr/local/bin/k3s', 'kubectl', '--request-timeout=30s', *scope, *args],
        input=json.dumps(body) if body is not None else None, text=True,
        capture_output=True, timeout=180)
    if result.returncode:
        raise KubernetesError('(AlreadyExists)' in (result.stderr or ''))
    if len(result.stdout) > 2097152:
        raise RuntimeError('Kubernetes proof response exceeded its bound')
    return json.loads(result.stdout) if result.stdout.strip().startswith('{') else None


def resource(kind, name, spec):
    return dict(apiVersion=API, kind=kind,
                metadata=dict(name=name, namespace=NAMESPACE), spec=spec)


def wait(predicate):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(3)
    raise RuntimeError('External Secrets verification timed out')


def ready(kind, name):
    value = kubectl('get', kind, name, '-o', 'json')
    return any(c['type'] == 'Ready' and c['status'] == 'True'
               for c in value.get('status', {}).get('conditions', []))


def operator_drift():
    """Exercise Argo repair of a declared label without rolling controller pods."""
    original = kubectl('get', 'deployment', 'external-secrets', '-o', 'json')
    label = 'app.kubernetes.io/version'
    value = original['metadata']['labels'][label]
    if not original['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(
            'cloudlab-external-secrets:'):
        raise RuntimeError('ESO operator drift proof requires Argo ownership')
    try:
        kubectl('patch', 'deployment', 'external-secrets', '--type=merge',
                '-p', json.dumps({'metadata': {'labels': {label: 'drift-fixture'}}}))
        def repaired():
            current = kubectl('get', 'deployment', 'external-secrets', '-o', 'json')
            if current['metadata']['uid'] != original['metadata']['uid'] or current['spec'] != original['spec']:
                raise RuntimeError('ESO metadata fixture changed operator identity or spec')
            return current['metadata']['labels'].get(label) == value
        wait(repaired)
    finally:
        current = kubectl('get', 'deployment', 'external-secrets', '-o', 'json')
        if current['metadata']['labels'].get(label) == 'drift-fixture':
            kubectl('patch', 'deployment', 'external-secrets', '--type=merge',
                    '-p', json.dumps({'metadata': {'labels': {label: value}}}))
    print('Argo repaired ESO operator metadata drift without replacing or changing its workload.')


PROOF_LABEL = 'cloudlab.io/consumer-proof'
PROOF_API = {
    'Secret': ('v1', 'secrets', '/api/v1'),
    'ExternalSecret': (API, 'externalsecrets', '/apis/' + API),
    'ClusterSecretStore': (API, 'clustersecretstores', '/apis/' + API),
}


def _name(value):
    return isinstance(value, str) and len(value) <= 63 and re.fullmatch(
        r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?', value)


def _complete(value, limit=512):
    if not isinstance(value, dict) or not isinstance(value.get('metadata', {}), dict):
        raise RuntimeError('Consumer proof discovery is incomplete')
    metadata = value.get('metadata', {})
    remaining = metadata.get('remainingItemCount')
    if (not isinstance(value.get('items'), list) or len(value['items']) > limit or
            metadata.get('continue') not in (None, '') or
            (remaining is not None and (type(remaining) is not int or remaining != 0))):
        raise RuntimeError('Consumer proof discovery is incomplete')
    return value['items']


def _ready(value, status='True', reason=None):
    return any(row.get('type') == 'Ready' and row.get('status') == status and
               (reason is None or row.get('reason') == reason)
               for row in value.get('status', {}).get('conditions', []))


class ConsumerScopeProof:
    """A caller-qualified, fake-only fixture; its journal is the cleanup authority."""
    def __init__(self, scope, journal):
        self.scope = copy.deepcopy(scope)
        self.path = Path(journal)
        self.state = None
        self.uncertain = False
        self.denial_event_uid = None

    def save(self, initial=False):
        folder = self.path.parent
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        for parent in (folder, *folder.parents):
            if parent.is_symlink():
                raise RuntimeError('Consumer proof journal path contains a symlink')
        info = folder.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError('Consumer proof journal directory is not private')
        raw = json.dumps(self.state, sort_keys=True).encode()
        if initial:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        else:
            descriptor, temporary = tempfile.mkstemp(prefix=self.path.name + '.', dir=folder)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        descriptor = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def namespace(self, role):
        reference = self.scope['namespaces'][role]
        value = kubectl('get', 'namespace', reference['name'], '-o', 'json', namespace=None)
        metadata = value.get('metadata', {})
        labels = metadata.get('labels', {})
        if (metadata.get('uid') != reference['uid'] or metadata.get('deletionTimestamp') or
                labels.get('kubernetes.io/metadata.name') != reference['name'] or
                (role == 'operator' and labels.get('cloudlab.io/service-secrets') == 'approved') or
                (role == 'application' and labels.get('cloudlab.io/service-secrets') != 'approved')):
            raise RuntimeError('Consumer proof namespace qualification changed')
        return reference['name']

    def preflight(self):
        scope = self.scope
        if set(scope) != {'clusterUID', 'source', 'namespaces', 'beforeConditions', 'afterConditions'}:
            raise RuntimeError('Consumer proof requires its exact qualified scope')
        if not isinstance(scope['clusterUID'], str) or not scope['clusterUID']:
            raise RuntimeError('Consumer proof requires its qualified cluster identity')
        if set(scope['namespaces']) != {'operator', 'core', 'application'}:
            raise RuntimeError('Consumer proof requires three qualified namespaces')
        for role, reference in scope['namespaces'].items():
            if (set(reference) != {'name', 'uid'} or not _name(reference['name']) or
                    not isinstance(reference['uid'], str) or not reference['uid']):
                raise RuntimeError('Consumer proof namespace reference is malformed')
        names = {role: reference['name'] for role, reference in scope['namespaces'].items()}
        if (len(set(names.values())) != 3 or names['operator'] != NAMESPACE or
                not names['application'].startswith('cloudlab-app-')):
            raise RuntimeError('Consumer proof namespace scope is not approved')
        source = scope['source']
        if (set(source) != {'rootUID', 'publicRevision', 'privateRevision', 'storeName', 'storeUID',
                           'runtimeNamespacesChecked', 'declarationsChecked'} or
                source['runtimeNamespacesChecked'] is not True or
                not (source['declarationsChecked'] is None or type(source['declarationsChecked']) is bool) or
                not _name(source['storeName']) or
                any(not isinstance(source[key], str) or not source[key] for key in ('rootUID', 'storeUID')) or
                not re.fullmatch('[a-f0-9]{40}', source['publicRevision'] or '') or
                (source['privateRevision'] is not None and
                 not re.fullmatch('[a-f0-9]{40}', source['privateRevision'] or ''))):
            raise RuntimeError('Consumer proof lacks current runtime qualification')
        before, after = scope['beforeConditions'], scope['afterConditions']
        if (not isinstance(before, list) or len(before) != 2 or
                set(before[0]) != {'namespaces'} or not isinstance(before[0]['namespaces'], list) or
                not all(_name(name) for name in before[0]['namespaces']) or
                len(set(before[0]['namespaces'])) != len(before[0]['namespaces']) or
                before[1] != {'namespaceSelector': {'matchLabels': {'cloudlab.io/service-secrets': 'approved'}}}):
            raise RuntimeError('Consumer proof conditions are not the reviewed effective contract')
        expected = copy.deepcopy(before)
        if (NAMESPACE not in expected[0]['namespaces'] or names['core'] not in expected[0]['namespaces'] or
                names['application'] in expected[0]['namespaces']):
            raise RuntimeError('Consumer proof does not exercise both permitted condition branches')
        expected[0]['namespaces'].remove(NAMESPACE)
        if after != expected:
            raise RuntimeError('Consumer proof may withdraw only its operator namespace')
        cluster = kubectl('get', 'namespace', 'kube-system', '-o', 'json', namespace=None)
        if cluster.get('metadata', {}).get('uid') != scope['clusterUID']:
            raise RuntimeError('Consumer proof cluster identity changed')
        root = kubectl('get', 'application.argoproj.io', 'cloudlab-public-root', '-o', 'json', namespace='argocd')
        private = root.get('spec', {}).get('source', {}).get('helm', {}).get(
            'valuesObject', {}).get('identity', {}).get('argo', {}).get('valuesRevision')
        if (root.get('metadata', {}).get('uid') != source['rootUID'] or
                root.get('metadata', {}).get('deletionTimestamp') or
                root.get('status', {}).get('sync', {}).get('revision') != source['publicRevision'] or
                root.get('status', {}).get('sync', {}).get('status') != 'Synced' or
                root.get('status', {}).get('health', {}).get('status') != 'Healthy' or
                root.get('status', {}).get('sync', {}).get('comparedTo', {}).get('source') !=
                    root.get('spec', {}).get('source') or root.get('operation') or
                root.get('status', {}).get('operationState', {}).get('phase') in ('Running', 'Terminating') or
                any(str(row.get('type', '')).endswith('Error') for row in root.get('status', {}).get('conditions', [])) or
                private != source['privateRevision']):
            raise RuntimeError('Consumer proof source qualification changed')
        store = kubectl('get', 'clustersecretstore', source['storeName'], '-o', 'json', namespace=None)
        if (store.get('metadata', {}).get('uid') != source['storeUID'] or
                store.get('metadata', {}).get('deletionTimestamp') or
                store.get('spec', {}).get('conditions') != before or not _ready(store)):
            raise RuntimeError('Consumer proof production store qualification changed')
        consumers = _complete(kubectl('get', 'externalsecrets', '-o', 'json'))
        if any(not isinstance(row, dict) or row.get('kind') != 'ExternalSecret' or
               row.get('metadata', {}).get('namespace') != NAMESPACE or
               not isinstance(row.get('spec', {}).get('secretStoreRef'), dict) or
               not isinstance(row['spec']['secretStoreRef'].get('name'), str) or
               not row['spec']['secretStoreRef']['name'] for row in consumers):
            raise RuntimeError('Consumer proof discovery is incomplete')
        if any(row.get('spec', {}).get('secretStoreRef', {}).get('name') == source['storeName'] and
               row.get('spec', {}).get('secretStoreRef', {}).get('kind') == 'ClusterSecretStore'
               for row in consumers):
            raise RuntimeError('Consumer proof operator namespace has a shared-store consumer')
        for role in names:
            self.namespace(role)

    def prepare(self):
        self.preflight()
        nonce = uuid.uuid4().hex[:16]
        name = 'cloudlab-consumer-proof-' + nonce
        objects = []
        for kind in ('Secret', 'ClusterSecretStore', 'ExternalSecret'):
            for role in (('store',) if kind == 'ClusterSecretStore' else ('operator', 'core', 'application')):
                namespace = '' if role == 'store' else self.scope['namespaces'][role]['name']
                objects.append(dict(key=role + '-' + kind, kind=kind, name=name, namespace=namespace,
                                    uid=None, state='planned'))
        self.state = dict(phase='intent', nonce=nonce, scope=self.scope, resources=objects,
                          productionPolicyReady=False,
                          dummyValues=['phase1', 'phase2'],
                          cleanupOrder=['ExternalSecret', 'Secret', 'ClusterSecretStore'])
        self.save(initial=True)

    def request(self, entry, *args, body=None):
        return kubectl(*args, body=body, namespace=entry['namespace'] or None)

    def create(self, entry, spec=None):
        metadata = dict(name=entry['name'], labels={PROOF_LABEL: self.state['nonce']})
        if entry['namespace']:
            metadata['namespace'] = entry['namespace']
            role = next(role for role, ref in self.scope['namespaces'].items()
                        if ref['name'] == entry['namespace'])
            self.namespace(role)
        document = dict(apiVersion=PROOF_API[entry['kind']][0], kind=entry['kind'], metadata=metadata)
        if entry['kind'] == 'Secret':
            document.update(type='Opaque', data={})
        else:
            document['spec'] = spec
        entry['state'] = 'creating'
        try:
            self.save()
        except Exception:
            self.uncertain = True
            raise RuntimeError('Consumer proof intent journal failed; retain its records and stop') from None
        try:
            result = self.request(entry, 'create', '-f', '-', '-o', 'json', body=document)
            meta = result.get('metadata', {}) if isinstance(result, dict) else {}
            if (result.get('kind') != entry['kind'] or meta.get('name') != entry['name'] or
                    meta.get('namespace', '') != entry['namespace'] or
                    not isinstance(meta.get('uid'), str) or not meta['uid']):
                raise RuntimeError('Consumer proof CREATE response has no exact identity')
            entry.update(uid=meta['uid'], state='known')
            self.save()
        except Exception as error:
            self.uncertain = True
            entry['state'] = 'collision' if isinstance(error, KubernetesError) and error.collision else 'uncertain'
            try:
                self.save()
            except Exception:
                pass
            raise RuntimeError('Consumer proof CREATE ownership unresolved; retain its journal and stop') from None

    def get(self, entry, absent=False, retiring=False):
        if not entry.get('uid') or entry['state'] != 'known':
            raise RuntimeError('Consumer proof cannot inspect unjournaled ownership')
        value = self.request(entry, 'get', PROOF_API[entry['kind']][1], entry['name'],
                             '--ignore-not-found', '-o', 'json')
        if value is None and absent:
            return None
        meta = value.get('metadata', {}) if isinstance(value, dict) else {}
        if (meta.get('uid') != entry['uid'] or meta.get('labels', {}).get(PROOF_LABEL) != self.state['nonce'] or
                meta.get('ownerReferences') or meta.get('finalizers') or
                (meta.get('deletionTimestamp') and not retiring)):
            raise RuntimeError('Consumer proof object identity or lifecycle changed')
        return value

    def events(self, entry):
        return _complete(self.request(entry, 'get', 'events',
            '--field-selector', 'involvedObject.uid=' + entry['uid'], '-o', 'json'), limit=128)

    def delivered(self, phase, previous_events=()):
        entries = {entry['key']: entry for entry in self.state['resources']}
        for role in ('operator', 'core', 'application'):
            secret = self.get(entries[role + '-Secret'])
            expected = 'phase1' if role == 'operator' else phase
            if secret.get('data', {}).get('probe') != base64.b64encode(expected.encode()).decode():
                return False
            external = self.get(entries[role + '-ExternalSecret'])
            if phase == 'phase1' or role != 'operator':
                if not _ready(external):
                    return False
            else:
                if not _ready(external, 'False', 'SecretSyncedError'):
                    return False
                denial = ('using cluster store "' + entries['store-ClusterSecretStore']['name'] +
                          '" is not allowed from namespace "' + NAMESPACE + '": denied by spec.condition')
                matches = [event for event in self.events(entries[role + '-ExternalSecret'])
                           if event.get('metadata', {}).get('uid') not in previous_events and
                           event.get('metadata', {}).get('uid') and
                           event.get('involvedObject', {}).get('uid') == external['metadata']['uid'] and
                           event.get('reason') == 'UpdateFailed' and denial in event.get('message', '')]
                if not matches:
                    return False
                self.denial_event_uid = matches[0]['metadata']['uid']
        return True

    def cleanup(self):
        if self.uncertain:
            raise RuntimeError('Consumer proof has unresolved CREATE ownership; automatic cleanup forbidden')
        self.state['phase'] = 'cleaning'
        self.save()
        for kind in self.state['cleanupOrder']:
            for entry in self.state['resources']:
                if entry['kind'] != kind or entry['state'] != 'known':
                    continue
                if entry['namespace']:
                    role = next(role for role, ref in self.scope['namespaces'].items()
                                if ref['name'] == entry['namespace'])
                    self.namespace(role)
                if self.get(entry, absent=True, retiring=True) is not None:
                    _, plural, prefix = PROOF_API[kind]
                    route = prefix + ('/namespaces/' + entry['namespace'] if entry['namespace'] else '') + '/' + plural + '/' + entry['name']
                    self.request(entry, 'delete', '--raw', route, '-f', '-', body={
                        'apiVersion': 'v1', 'kind': 'DeleteOptions',
                        'preconditions': {'uid': entry['uid']}})
                    wait(lambda: self.get(entry, absent=True, retiring=True) is None)
                entry['state'] = 'removed'
                self.save()
        self.state['phase'] = 'cleaned'
        self.save()

    def run(self):
        self.prepare()
        entries = {entry['key']: entry for entry in self.state['resources']}
        completed = False
        try:
            for role in ('operator', 'core', 'application'):
                self.create(entries[role + '-Secret'])
            self.create(entries['store-ClusterSecretStore'], dict(
                conditions=self.scope['beforeConditions'], provider=dict(fake=dict(
                    data=[dict(key='probe', value='phase1')]))))
            for role in ('operator', 'core', 'application'):
                self.get(entries[role + '-Secret'])
                self.create(entries[role + '-ExternalSecret'], dict(
                    refreshInterval='1s',
                    secretStoreRef=dict(name=entries['store-ClusterSecretStore']['name'], kind='ClusterSecretStore'),
                    target=dict(name=entries[role + '-Secret']['name'], creationPolicy='Merge', deletionPolicy='Retain'),
                    data=[dict(secretKey='probe', remoteRef=dict(key='probe'))]))
            wait(lambda: self.delivered('phase1'))
            self.state['phase1Delivered'] = True
            self.save()
            previous = {event['metadata']['uid'] for event in self.events(entries['operator-ExternalSecret'])}
            store = self.get(entries['store-ClusterSecretStore'])
            self.request(entries['store-ClusterSecretStore'], 'patch', 'clustersecretstore',
                store['metadata']['name'], '--type=json', '-p', json.dumps([
                    dict(op='test', path='/metadata/uid', value=store['metadata']['uid']),
                    dict(op='test', path='/metadata/resourceVersion', value=store['metadata']['resourceVersion']),
                    dict(op='replace', path='/spec/conditions', value=self.scope['afterConditions']),
                    dict(op='replace', path='/spec/provider/fake/data/0/value', value='phase2')]))
            wait(lambda: self.delivered('phase2', previous))
            self.state['phase'] = 'qualified'
            self.state['qualified'] = True
            self.state['denialEventUID'] = self.denial_event_uid
            self.state['phase2Delivered'] = ['core', 'application']
            self.state['operatorRetainedPhase1'] = True
            self.save()
            completed = True
        finally:
            if not self.uncertain:
                self.cleanup()
        if not completed:
            raise RuntimeError('Consumer proof did not complete')
        return dict(consumer_scope_qualified=True, fixture_cleaned=True,
                    provider_authentication=False, production_policy_ready=False,
                    declarations_checked=self.scope['source']['declarationsChecked'], journal=str(self.path))


def main(store_name):
    name = 'cloudlab-verify-' + uuid.uuid4().hex[:12]
    vault_name = name + '-vault'
    try:
        store = kubectl('get', 'clustersecretstore', store_name, '-o', 'json')
        wait(lambda: ready('clustersecretstore', store_name))
        # A new store forces a new SDK client and real vault lookup, bypassing cached readiness.
        provider = store['spec']['provider']
        provider['onepasswordSDK']['auth']['serviceAccountSecretRef'].pop('namespace', None)
        kubectl('create', '-f', '-', body=resource('SecretStore', vault_name, dict(provider=provider)))
        wait(lambda: ready('secretstore', vault_name))

        # No write permission or manually created 1Password test item is required.
        fake = resource('SecretStore', name, dict(provider=dict(fake=dict(data=[
            dict(key='probe', value='first')]))))
        kubectl('create', '-f', '-', body=fake)
        secret = resource('ExternalSecret', name, dict(
            refreshInterval='5s', secretStoreRef=dict(name=name, kind='SecretStore'),
            target=dict(name=name, creationPolicy='Owner'),
            data=[dict(secretKey='probe', remoteRef=dict(key='probe'))]))
        kubectl('create', '-f', '-', body=secret)

        # Workload-shaped fake consumer proof: same disposable fake store, catalog
        # shape (24h/Owner/Retain, target == name). Never touches the production
        # ClusterSecretStore, pins, catalog, grants, or private declarations.
        workload = resource('ExternalSecret', name + '-workload', dict(
            refreshInterval='24h', secretStoreRef=dict(name=name, kind='SecretStore'),
            target=dict(name=name + '-workload', creationPolicy='Owner', deletionPolicy='Retain'),
            data=[dict(secretKey='probe', remoteRef=dict(key='probe'))]))
        kubectl('create', '-f', '-', body=workload)

        def has_named_value(target, expected):
            value = kubectl('get', 'secret', target, '--ignore-not-found', '-o', 'json')
            return value is not None and value.get('data', {}).get('probe') == base64.b64encode(expected.encode()).decode()

        def has_value(expected):
            return has_named_value(name, expected)

        wait(lambda: has_value('first'))
        wait(lambda: has_named_value(name + '-workload', 'first'))
        kubectl('patch', 'secretstore', name, '--type=merge', '-p', json.dumps(dict(
            spec=dict(provider=dict(fake=dict(data=[dict(key='probe', value='second')]))))))
        wait(lambda: has_value('second'))
        kubectl('patch', 'secret', name, '--type=merge', '-p', json.dumps(dict(
            data=dict(probe=base64.b64encode(b'drift').decode()))))
        wait(lambda: has_value('second'))
        print('Fresh CloudLab authentication, Secret creation, refresh, and drift repair passed.')
    finally:
        # Explicitly remove both owned and source resources even after partial failure.
        for kind, target in [('externalsecret', name), ('externalsecret', name + '-workload'),
                             ('secret', name), ('secret', name + '-workload'),
                             ('secretstore', name), ('secretstore', vault_name)]:
            kubectl('delete', kind, target, '--ignore-not-found', '--wait=true', '--timeout=60s')


def run_cli(arguments):
    if arguments[:1] == ['--consumer-scope']:
        if len(arguments) != 2:
            raise RuntimeError('Consumer proof requires its explicit journal path')
        raw = sys.stdin.read(65537)
        if len(raw) > 65536:
            raise RuntimeError('Consumer proof scope exceeded its bound')
        return ConsumerScopeProof(json.loads(raw), arguments[1]).run()
    if (len(arguments) not in (1, 2) or arguments[0].startswith('-') or
            (len(arguments) == 2 and arguments[1] != 'argo')):
        raise RuntimeError('Unknown External Secrets verification mode')
    main(arguments[0])
    if arguments[1:] == ['argo']:
        operator_drift()


if __name__ == '__main__':
    try:
        result = run_cli(sys.argv[1:])
        if result is not None:
            print(json.dumps(result))
    except Exception:
        print('External Secrets proof failed; details withheld to protect credentials.', file=sys.stderr)
        sys.exit(1)
