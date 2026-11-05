"""Qualify native Argo RBAC convergence in a disposable local Kubernetes cluster.

The standalone Compose file mounts explicit candidate chart/guard bytes,
this driver and verified Argo inputs. Remove its exact
unique Compose project and volumes after inspecting the receipt; interrupted or
failed runs retain their receipt and never resume granting automatically.
"""
import base64
import copy
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml
from playbooks.admission.files import verify as admission_verify
from playbooks.argocd.tests.fixtures import (require, git_backend, GitServer, ReadOnlyGit, command, GitSource, NativeAPI, install_argocd)

SOURCE = 'http://10.245.233.3:8000/'
NAMESPACE = 'permissions-fixture'
APPLICATION = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/cloudlab-permissions'
RBAC = '/apis/rbac.authorization.k8s.io/v1'
BINDING = RBAC + '/namespaces/' + NAMESPACE + '/rolebindings/cloudlab-permissions-fixture-reader'
ROLE = RBAC + '/clusterroles/cloudlab-permissions-viewer-namespace'
TRACKING = 'cloudlab-permissions:rbac.authorization.k8s.io/RoleBinding:' + NAMESPACE + '/cloudlab-permissions-fixture-reader'
CONTROLLER = admission_verify.PERMISSIONS_CONTROLLER
GUARD_API = '/apis/admissionregistration.k8s.io/v1'
GUARD_NAME = admission_verify.PERMISSIONS_GUARD_NAME
GUARD_APPLICATION = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/cloudlab-workload-policy'
PARENT = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applicationsets/cloudlab-permissions'
PROFILES = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/cloudlab-permissions-profiles'
PARAMETER = '/api/v1/namespaces/argocd/configmaps/cloudlab-permissions-profiles'
INPUT_GUARD = 'cloudlab-permissions-input'
APPSET_CONTROLLER = 'system:serviceaccount:argocd:argocd-applicationset-controller'
SERVER = 'system:serviceaccount:argocd:argocd-server'
PUBLIC_COORDINATE = 'https://github.com/example/platform.git'
PRIVATE_COORDINATE = 'https://github.com/example/private.git'
CATALOG_FILES = ('Chart.yaml', 'values.yaml', 'values.schema.json', 'profiles.yaml', 'templates/rbac.yaml')


def catalog_files():
    root = Path('/inputs/catalog')
    if not root.exists(): root = Path(__file__).resolve().parents[4] / 'platform/connectivity/permissions'
    return {name: (root / name).read_bytes().decode('utf-8') for name in CATALOG_FILES}


def guard_path():
    path = Path('/inputs/guard.yaml')
    return path if path.exists() else Path(__file__).resolve().parents[4] / 'platform/delivery/admission/policies/templates/permissions.yaml'


def input_guard_path():
    path = Path('/inputs/input-guard.yaml')
    return path if path.exists() else Path(__file__).resolve().parents[4] / 'platform/delivery/admission/policies/templates/permission-input.yaml'


def root_path():
    path = Path('/inputs/root')
    return path if path.exists() else Path(__file__).resolve().parents[4] / 'gitops/roots/public'


def consumer_receipt(revision, nonce):
    require(re.fullmatch('[a-f0-9]{40}', revision) and re.fullmatch('[a-f0-9]{64}', nonce), 'Invalid fixture approval coordinates')
    receipt = {'version': 'cloudlab-consumer-source-acceptance/v1', 'consumer': 'permissions',
        'paths': ['platform/permissions.yaml'], 'revision': revision, 'nonce': nonce}
    preimage = '\n'.join([receipt['version'], receipt['consumer'], PRIVATE_COORDINATE, '1', *receipt['paths'], revision, nonce, ''])
    return receipt, hashlib.sha256(preimage.encode()).hexdigest()


def rendered_owner(directory, revision, commitment):
    """Render the real Root, recording only finite local transport/timing changes."""
    settings = {'repository': PUBLIC_COORDINATE, 'permissions': {'enabled': True, 'revision': revision,
        'acceptanceCommitment': commitment}, 'identity': {'enabled': True, 'argo': {
            'valuesRepository': PRIVATE_COORDINATE, 'valuesRevision': 'b' * 40}}}
    path = directory / 'root-input.yaml'
    path.write_text(yaml.safe_dump(settings))
    raw = command(['helm', 'template', 'cloudlab-public-root', str(root_path()), '--namespace', 'argocd', '-f', str(path)])
    rows = [row for row in yaml.safe_load_all(raw) if row and (
        row['kind'] == 'AppProject' and row['metadata']['name'] in ('cloudlab-permissions', 'cloudlab-permissions-profiles') or
        row['kind'] == 'ApplicationSet' and row['metadata']['name'] == 'cloudlab-permissions' or
        row['kind'] == 'Application' and row['metadata']['name'] == 'cloudlab-permissions-profiles')]
    require(len(rows) == 4, 'Real Root lacks the complete permission owner')
    selected = copy.deepcopy(rows)
    public, private = SOURCE + 'public.git', SOURCE + 'private.git'
    changes = []
    for obj in selected:
        spec = obj['spec']
        if obj['kind'] == 'AppProject':
            require(set(spec['sourceRepos']) <= {PUBLIC_COORDINATE, PRIVATE_COORDINATE}, 'Unexpected fixture project source')
            spec['sourceRepos'] = [public if value == PUBLIC_COORDINATE else private for value in spec['sourceRepos']]
            changes.append(obj['metadata']['name'] + '.sourceRepos')
        elif obj['kind'] == 'Application':
            require(spec['source']['repoURL'] == PUBLIC_COORDINATE, 'Unexpected public profile source')
            spec['source']['repoURL'] = public
            spec['source']['helm']['valuesObject']['context']['repository'] = public
            changes.extend(['profiles.source.repoURL', 'profiles.context.repository'])
        else:
            require(spec['template']['spec']['source']['repoURL'] == PUBLIC_COORDINATE, 'Unexpected permission chart source')
            spec['template']['spec']['source']['repoURL'] = public
            generators = spec['generators'][0]['matrix']['generators']
            require(len(generators) == 2 and all(item['git']['repoURL'] == PRIVATE_COORDINATE for item in generators), 'Unexpected native input generators')
            gate = generators[1]['git']['revision']
            for item in generators:
                item['git']['repoURL'] = private
                item['git']['requeueAfterSeconds'] = 2
            require(generators[1]['git']['revision'] == gate, 'Fixture transport changed the native approval gate')
            changes.extend(['parent.template.source.repoURL', 'parent.git[0:2].repoURL', 'parent.git[0:2].requeueAfterSeconds=2'])
        if obj['kind'] in ('Application', 'ApplicationSet'):
            obj['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = (
                'cloudlab-public-root:argoproj.io/' + obj['kind'] + ':argocd/' + obj['metadata']['name'])
    return selected, {'rawSelectedSHA256': hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest(),
        'fixtureSelectedSHA256': hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest(),
        'transportAndTimingChanges': changes}


def source_converged(app, source):
    status = app.get('status', {})
    sync = status.get('sync', {})
    return (app.get('spec', {}).get('source') == source and sync.get('revision') == source.get('targetRevision')
        and sync.get('comparedTo', {}).get('source') == source
        and sync.get('comparedTo', {}).get('destination') == app.get('spec', {}).get('destination')
        and sync.get('status') == 'Synced' and status.get('health', {}).get('status') == 'Healthy'
        and not app.get('operation') and (status.get('operationState') or {}).get('phase') in (None, 'Succeeded')
        and not any(str(row.get('type', '')).endswith('Error') for row in status.get('conditions') or []))


class ActorAPI(NativeAPI):
    """One fixed synthetic admission actor per client; never broaden the shared API."""
    def __init__(self, directory, document, actor):
        directory.mkdir()
        super().__init__(directory, document, allowed_impersonation=actor)
        self.actor = actor

    def application(self, obj, *, dry_run=True):
        require(obj['metadata']['name'] == 'cloudlab-permissions' and obj['metadata']['namespace'] == 'argocd',
                'Actor probe escaped its exact Application')
        return self._result(APPLICATION, obj, dry_run)

    def projection(self, obj):
        require(obj['metadata']['name'] == 'cloudlab-permissions-profiles' and obj['metadata']['namespace'] == 'argocd',
                'Actor probe escaped its exact ConfigMap')
        return self._result(PARAMETER, obj, True)

    def profile_operation(self, obj):
        require(self.actor == SERVER and obj['metadata']['name'] == 'cloudlab-permissions-profiles'
            and obj['metadata']['namespace'] == 'argocd', 'Manual fixture sync escaped the public profile owner')
        return self._result(PROFILES, obj, False)

    def _result(self, path, obj, dry_run):
        request = urllib.request.Request('https://cluster:6443' + path + ('?dryRun=All' if dry_run else ''),
            method='PUT', data=json.dumps(obj).encode(), headers={'Content-Type': 'application/json', 'Impersonate-User': self.actor})
        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read(65537)
                require(len(raw) <= 65536, 'Admission probe response exceeded bound')
                return response.status, json.loads(raw)
        except urllib.error.HTTPError as error:
            raw = error.read(65537)
            require(len(raw) <= 65536, 'Admission denial exceeded bound')
            return error.code, json.loads(raw)


def probe_active_operation(fetch, submit, transform, identity, conflict, deadline, *, clock=time.monotonic, pause=time.sleep):
    """Rebuild only these active-operation dry-runs after a resourceVersion conflict."""
    started = clock()
    stop = min(deadline, started + 30)
    for attempt in range(1, 6):
        require(clock() < stop, 'Active operation probe exceeded its bounded deadline')
        current = fetch()
        operation_state = (current.get('status') or {}).get('operationState') or {}
        require(current['metadata']['uid'] == identity['uid'] and current['spec'] == identity['spec']
            and current.get('operation') == identity['operation'] and bool(current.get('operation'))
            and operation_state.get('phase') == 'Running' and operation_state.get('retryCount', 0) >= 1,
            'Active operation identity, admitted specification or pending command changed')
        require(clock() < stop, 'Active operation probe exceeded its bounded deadline')
        candidate = copy.deepcopy(current)
        transform(candidate)
        code, body = submit(candidate)
        if code == 409:
            conflict({'attempt': attempt, 'code': 409, 'elapsedSeconds': round(clock() - started, 3)})
        require(clock() < stop, 'Active operation probe exceeded its bounded deadline')
        if code != 409:
            require(code in (200, 422), 'Unexpected active operation probe response')
            return code, body
        if attempt < 5:
            pause(min(0.2, max(0, stop - clock())))
    raise RuntimeError('Active operation probe exhausted its conflict attempts')


def render_projection(directory, chart, inputs):
    path = directory / 'projection-input.yaml'
    path.write_text(yaml.safe_dump(inputs))
    path.chmod(0o600)
    rows = [row for row in yaml.safe_load_all(command(['helm', 'template', 'cloudlab-permissions-profiles', str(chart),
        '--namespace', 'argocd', '-f', str(path)])) if row]
    require(len(rows) == 1 and rows[0]['kind'] == 'ConfigMap', 'Public projection chart must render exactly one ConfigMap')
    return rows[0]


def publish_profile_approval(prepared, commit, apply_profile, record):
    prepared['proposalRevision'] = commit({'platform/acceptance/permissions.yaml': yaml.safe_dump(prepared['receipt'])})
    require(prepared['proposalRevision'] != prepared['revision'], 'Receipt proposal must be distinct from accepted input')
    record('receipt-published')
    apply_profile()
    record('profile-prepared')
    return prepared


def require_current_proposal(prepared, current):
    require(current == prepared['proposalRevision'], 'Prepared receipt proposal was superseded before parent advancement')


def failure_journal(api, expected):
    """Five fixed GETs, bounded safe fields, no bodies or arbitrary diagnostics."""
    result = {}
    def token(value, allowed):
        return value if value in allowed else 'other'
    def duration(value):
        return value if isinstance(value, str) and re.fullmatch(r'[0-9.]+(?:ms|s|m|h)', value) and len(value) <= 32 else 'other'
    def identity(obj):
        meta = obj.get('metadata') or {}
        return {key: meta.get(key) for key in ('uid', 'generation', 'resourceVersion')}
    for label, path in (('parent', PARENT), ('roles', APPLICATION), ('profiles', PROFILES),
            ('repository', '/apis/apps/v1/namespaces/argocd/deployments/argocd-repo-server'),
            ('reconciliation', '/api/v1/namespaces/argocd/configmaps/argocd-cm')):
        try:
            obj = api.request(path)
            row = identity(obj)
            if label == 'parent':
                generators = obj['spec']['generators'][0]['matrix']['generators']
                gate = generators[1]['git']['revision']
                row.update(receiptRevisionIsMain=generators[0]['git']['revision'] == 'main',
                    gateSHA256=hashlib.sha256(gate.encode()).hexdigest(), gateMatchesPrepared=gate == expected.get('gate'),
                    gateContainsPreparedCommitment=bool(expected.get('commitment')) and json.dumps(expected['commitment']) in gate)
                row['conditions'] = []
                for condition in ((obj.get('status') or {}).get('conditions') or [])[:4]:
                    message = condition.get('message', '')
                    classification = next((tag for text, tag in (
                        ('Consumer source acceptance refused', 'receipt-gate'), ('New or reused assignment IDs', 'convergence-fence'),
                        ('Permission input violates', 'private-input'), ('no params found', 'missing-parameter')) if text in message), 'other')
                    row['conditions'].append({'type': token(condition.get('type'), ('ErrorOccurred', 'ParametersGenerated', 'ResourcesUpToDate')),
                        'status': token(condition.get('status'), ('True', 'False', 'Unknown')),
                        'reason': token(condition.get('reason'), ('ApplicationGenerationFromParamsError', 'AppGenerationFromParamsError',
                            'ApplicationParamsGenerationError', 'ApplicationValidationError', 'ParametersGenerated', 'ApplicationSetUpToDate')),
                        'classification': classification})
            elif label in ('roles', 'profiles'):
                spec, status = obj.get('spec') or {}, obj.get('status') or {}
                source, sync = spec.get('source') or {}, status.get('sync') or {}
                pin = source.get('targetRevision')
                row.update(publicPin=pin if isinstance(pin, str) and re.fullmatch('[a-f0-9]{40}', pin) else 'other',
                    comparedSourceMatches=(sync.get('comparedTo') or {}).get('source') == source,
                    comparedDestinationMatches=(sync.get('comparedTo') or {}).get('destination') == spec.get('destination'),
                    sync=token(sync.get('status'), ('Synced', 'OutOfSync', 'Unknown')),
                    health=token((status.get('health') or {}).get('status'), ('Healthy', 'Progressing', 'Degraded', 'Suspended', 'Missing', 'Unknown')),
                    operation=bool(obj.get('operation')),
                    phase=token((status.get('operationState') or {}).get('phase'), ('Running', 'Terminating', 'Succeeded', 'Failed', 'Error')))
            elif label == 'repository':
                containers = obj['spec']['template']['spec']['containers']
                require(len(containers) == 1, 'Unexpected repository diagnostic container count')
                container = containers[0]
                row['timingArgs'] = []
                args = container.get('args') or []
                for index, argument in enumerate(args):
                    for flag in ('--revision-cache-expiration', '--revision-cache-lock-timeout', '--repo-cache-expiration'):
                        if argument == flag and index + 1 < len(args):
                            row['timingArgs'].append(flag + '=' + duration(args[index + 1]))
                        elif argument.startswith(flag + '='):
                            row['timingArgs'].append(flag + '=' + duration(argument[len(flag) + 1:]))
                row['timingArgs'] = row['timingArgs'][:3]
                row['reconciliationEnvReferences'] = []
                for env in container.get('env') or []:
                    if env.get('name') == 'ARGOCD_RECONCILIATION_TIMEOUT':
                        reference = (env.get('valueFrom') or {}).get('configMapKeyRef') or {}
                        row['reconciliationEnvReferences'].append({'name': 'ARGOCD_RECONCILIATION_TIMEOUT',
                            'configMapIsArgo': reference.get('name') == 'argocd-cm',
                            'keyIsReconciliation': reference.get('key') == 'timeout.reconciliation',
                            'optional': reference.get('optional') is True})
                row['reconciliationEnvReferences'] = row['reconciliationEnvReferences'][:2]
            else:
                row['settings'] = {key: duration((obj.get('data') or {}).get(key))
                    for key in ('timeout.reconciliation', 'timeout.reconciliation.jitter')}
            result[label] = row
        except Exception as error:
            result[label] = {'errorType': type(error).__name__}
    return result


def record_failure_journal(api, state, expected, save):
    try:
        state['failureJournal'] = failure_journal(api, expected)
        save(state['phase'])
    except Exception as error:
        state['failureJournalError'] = type(error).__name__


def qualify_initial_projection(probe, unchanged, record, deadline, *, clock=time.monotonic, pause=time.sleep):
    """Bound first-install dispatch qualification; never retry an unrelated failure."""
    started = clock()
    stop = min(deadline, started + 30)
    prefix = "ValidatingAdmissionPolicy 'cloudlab-permissions-profiles' with binding 'cloudlab-permissions-profiles' denied request:"
    for _ in range(16):
        if clock() >= stop:
            break
        unchanged()
        code, body = probe()
        result = {'label': 'foreign-profile-adoption-dispatch', 'code': code, 'reason': body.get('reason'),
            'elapsedSeconds': round(clock() - started, 3), 'policyAndBinding': prefix in body.get('message', ''),
            'expectedMessage': 'implicit adoption' in body.get('message', '')}
        record(result)
        unchanged()
        require(clock() < stop, 'Initial projection dispatch exceeded its bounded deadline')
        if code == 422 and result['reason'] == 'Invalid' and result['policyAndBinding'] and result['expectedMessage']:
            return
        require(code == 200, 'Unexpected response during initial projection dispatch qualification')
        remaining = stop - clock()
        if remaining > 0:
            pause(min(2, remaining))
    raise RuntimeError('Initial projection dispatch remained allowed until its bounded deadline')


class Processors:
    """Journal and fence fixture-only processor changes on the existing controller."""
    path = '/apis/apps/v1/namespaces/argocd/statefulsets/argocd-application-controller'

    def __init__(self, api, state, save, wait):
        self.api, self.state, self.save, self.wait = api, state, save, wait
        obj = api.request(self.path)
        self.uid, self.original = obj['metadata']['uid'], copy.deepcopy(obj['spec'])
        require(len(self.original['template']['spec']['containers']) == 1, 'Unexpected controller sidecar')
        self.expected = copy.deepcopy(self.original)
        self.state['processorJournal'] = {'uid': self.uid, 'originalArgs': self.original['template']['spec']['containers'][0].get('args'), 'restored': True}

    def set(self, *, operation=None, status=None, jitter=None):
        require(jitter is None or (type(jitter) is int and jitter >= 0), 'Fixture resync jitter requires nonnegative integer seconds')
        desired = copy.deepcopy(self.original)
        container = desired['template']['spec']['containers'][0]
        arguments = list(container.get('args', []))
        for name, value in (('operation-processors', operation), ('status-processors', status), ('app-resync-jitter', jitter)):
            if value is None: continue
            retained, index = [], 0
            while index < len(arguments):
                argument = arguments[index]
                if argument == '--' + name:
                    index += 2
                    continue
                if not argument.startswith('--' + name + '='): retained.append(argument)
                index += 1
            arguments = retained + ['--' + name + '=' + str(value)]
        if operation is not None or status is not None or jitter is not None: container['args'] = arguments
        current = self.api.request(self.path)
        require(current['metadata']['uid'] == self.uid and current['spec'] == self.expected, 'Processor owner or specification changed')
        self.api.request(self.path, 'PATCH', [
            {'op': 'test', 'path': '/metadata/uid', 'value': self.uid},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
            {'op': 'test', 'path': '/spec', 'value': self.expected}, {'op': 'replace', 'path': '/spec', 'value': desired}],
            content_type='application/json-patch+json')
        self.expected = desired
        self.state['processorJournal'].update(currentArgs=container.get('args'), restored=desired == self.original)
        self.save('processor-change')
        def ready():
            obj = self.api.request(self.path)
            return (obj['metadata']['uid'] == self.uid and obj['spec'] == desired and
                obj.get('status', {}).get('observedGeneration') == obj['metadata']['generation'] and
                obj['status'].get('readyReplicas') == 1 and obj['status'].get('currentRevision') == obj['status'].get('updateRevision'))
        self.wait(ready, 'fixture processor rollout', 180)


class API(NativeAPI):
    def __init__(self, directory, document):
        super().__init__(directory, document, field_manager='permissions-fixture', allowed_impersonation=CONTROLLER)

    def dry_run(self, document, caller, *, update=False):
        kind = document['kind']
        names = {'ClusterRole': 'clusterroles', 'ClusterRoleBinding': 'clusterrolebindings', 'RoleBinding': 'rolebindings'}
        require(kind in names and caller in (None, CONTROLLER), 'Unsupported fixture admission probe')
        namespace = document['metadata'].get('namespace', NAMESPACE)
        require(namespace in (NAMESPACE, 'argocd'), 'Admission probe namespace escaped fixture')
        path = RBAC + ('/namespaces/' + namespace if kind == 'RoleBinding' else '') + '/' + names[kind]
        if update: path += '/' + document['metadata']['name']
        headers = {'Content-Type': 'application/json'}
        if caller: headers['Impersonate-User'] = caller
        request = urllib.request.Request('https://cluster:6443' + path + '?dryRun=All',
            method='PUT' if update else 'POST', data=json.dumps(document).encode(), headers=headers)
        try:
            with self.opener.open(request, timeout=15) as response:
                require(response.status in (200, 201), 'Unexpected admission probe status')
                return 0, ''
        except urllib.error.HTTPError as error:
            diagnostic = error.read(8193)
            require(len(diagnostic) <= 8192, 'Admission probe response exceeds bound')
            return error.code, diagnostic.decode('utf-8')


def values(assignments=True, state='active', cluster=False):
    subject = {'kind': 'ServiceAccount', 'name': 'reader', 'namespace': NAMESPACE}
    rows = [{'id': 'fixture-reader', 'profile': 'viewer', 'subject': subject,
             'scope': {'namespace': NAMESPACE}}] if assignments else []
    if cluster:
        rows.append({'id': 'node-reader', 'profile': 'platform-engineer', 'subject': subject, 'scope': {'cluster': True}})
    return yaml.safe_dump({'permissions': {'state': state, 'assignments': rows}})


def guarded_qualification(api, expected):
    admission_verify.permission_guard_validate([api.request(GUARD_API + '/' +
        ('validatingadmissionpolicies' if row['kind'] == 'ValidatingAdmissionPolicy' else 'validatingadmissionpolicybindings') +
        '/' + row['metadata']['name']) for row in expected], expected)
    admission_verify.permission_guard_probes(api.dry_run)
    return True


def guard_denied(api, document, caller, update=False):
    code, message = api.dry_run(document, caller, update=update)
    name = GUARD_NAME + ('-roles' if document['kind'] == 'ClusterRole' else '-bindings')
    require(code and name in message and admission_verify.PERMISSIONS_GUARD_MESSAGE in message,
            'Expected native permission-guard denial')


def install(api, directory):
    return install_argocd(api, directory, Path('/inputs/argo-cd-10.9.6.tgz'),
                         Path('/inputs/artifact.lock.json'), Path('/inputs/values.yaml'))


def run():
    os.umask(0o077)
    deadline = time.monotonic() + 3600
    project_name = os.environ.get('FIXTURE_PROJECT', '')
    require(re.fullmatch(r'permissions-proof-[a-z0-9][a-z0-9-]{0,43}', project_name), 'Use a unique permissions-proof-<run> Compose project')
    receipt = Path('/receipts/state.json')
    require(not receipt.exists(), 'Existing fixture receipt blocks grant resumption')
    state = {'version': 2, 'run': secrets.token_hex(16), 'project': project_name, 'phase': 'starting', 'checks': [],
        'inputs': {name: hashlib.sha256(Path('/inputs', name).read_bytes()).hexdigest() for name in
            ('permissions_proof.py', 'argo-cd-10.9.6.tgz', 'artifact.lock.json', 'values.yaml')}, 'observations': [],
        'limits': ['local synthetic Git transport', 'no ESO, real credential or production Root-handoff qualification',
            'server actor probes are admission-level; server replicas remain zero', 'no production timing bound',
            'first named projection denial establishes dispatch only, not current evaluator body',
            'complete causal sequence qualifies only this fresh cluster and single candidate'],
        'timing': {'existingArgoReconciliation': '5s', 'fixtureGitRequeueAfterSeconds': 2,
            'proposalTransitionWaitSeconds': 240, 'proofDeadlineSeconds': 3600,
            'failureJournalMaxRequests': 5, 'failureJournalRequestTimeoutSeconds': 15}, 'approvals': []}
    state['catalog_inputs'] = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in catalog_files().items()}
    state['root_inputs'] = {file.relative_to(root_path()).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest()
        for file in root_path().rglob('*') if file.is_file()}
    state['guard_inputs'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (guard_path(), input_guard_path())}

    def save(phase):
        state['phase'] = phase
        pending = receipt.with_suffix('.pending')
        with pending.open('w') as stream:
            os.chmod(pending, 0o600)
            json.dump(state, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, receipt)
        descriptor = os.open(receipt.parent, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def wait(predicate, label, seconds=150):
        stop = min(deadline, time.monotonic() + seconds)
        while time.monotonic() < stop:
            try:
                value = predicate()
                if value: return value
            except (OSError, ValueError, urllib.error.URLError, RuntimeError):
                pass
            time.sleep(2)
        raise RuntimeError('Fixture timed out: ' + label)

    save('cluster-startup')
    try:
        document = wait(lambda: yaml.safe_load(Path('/fixture/kubeconfig').read_text()), 'cluster credentials')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            api = API(directory, document)
            wait(lambda: api.request('/api/v1/nodes')['items'], 'cluster API')
            state['cluster_uid'] = api.request('/api/v1/namespaces/kube-system')['metadata']['uid']
            state['images'] = sorted(install(api, directory))
            deployment_path = '/apis/apps/v1/namespaces/argocd/deployments/argocd-applicationset-controller'
            deployment = api.request(deployment_path)
            original_deployment = copy.deepcopy(deployment['spec'])
            require(original_deployment.get('replicas') == 0, 'Unexpected active ApplicationSet install')
            require(all(container['image'] in state['images'] for container in original_deployment['template']['spec']['containers']), 'Unpinned ApplicationSet image')
            active_deployment = copy.deepcopy(original_deployment)
            active_deployment['replicas'] = 1
            api.request(deployment_path, 'PATCH', [
                {'op': 'test', 'path': '/metadata/uid', 'value': deployment['metadata']['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': deployment['metadata']['resourceVersion']},
                {'op': 'test', 'path': '/spec', 'value': original_deployment},
                {'op': 'replace', 'path': '/spec', 'value': active_deployment}], content_type='application/json-patch+json')
            state['appSetActivation'] = {'uid': deployment['metadata']['uid'], 'oldReplicas': 0, 'newReplicas': 1}
            wait(lambda: all(api.request('/apis/apps/v1/namespaces/argocd/' + kind + '/' + name).get('status', {}).get('readyReplicas') == 1
                for kind, name in [('deployments', 'argocd-repo-server'), ('deployments', 'argocd-redis'),
                    ('deployments', 'argocd-applicationset-controller'), ('statefulsets', 'argocd-application-controller')]), 'native controller readiness', 420)
            processors = Processors(api, state, save, wait)
            for namespace in (NAMESPACE, 'cloudlab-policy'):
                api.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace}})
            for name in ('reader', 'reader-second'):
                api.apply({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': name, 'namespace': NAMESPACE}, 'automountServiceAccountToken': False})
            recovery = api.apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding',
                'metadata': {'name': 'fixture-recovery'}, 'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'cluster-admin'},
                'subjects': [{'kind': 'User', 'name': 'fixture-recovery'}]})
            state['recovery_uid'] = recovery['metadata']['uid']
            recovery_spec = {key: recovery[key] for key in ('roleRef', 'subjects')}
            api.apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'name': 'fixture-application-writer', 'namespace': 'argocd'},
                'rules': [{'apiGroups': ['argoproj.io'], 'resources': ['applications'], 'resourceNames': ['cloudlab-permissions'], 'verbs': ['get', 'update']}]})
            api.apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'name': 'fixture-application-writer', 'namespace': 'argocd'},
                'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'fixture-application-writer'},
                'subjects': [{'kind': 'User', 'name': 'fixture-metadata'}]})
            actors = {label: ActorAPI(directory / label, document, actor) for label, actor in
                (('controller', CONTROLLER), ('appset', APPSET_CONTROLLER), ('server', SERVER), ('metadata', 'fixture-metadata'))}
            collision = api.apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole',
                'metadata': {'name': 'cloudlab-permissions-collision-namespace'}, 'rules': []})
            foreign = api.apply({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'cloudlab-permissions-profiles', 'namespace': 'argocd',
                'labels': {'cloudlab.io/owner': 'foreign'}}, 'data': {'fixture': 'foreign'}})
            state['foreignParameterUID'] = foreign['metadata']['uid']
            candidate_chart = catalog_files()
            guards = admission_verify.permission_guard_desired(guard_path())
            input_guards = admission_verify.permission_input_desired(input_guard_path())
            public_files = {'platform/connectivity/permissions/' + name: value for name, value in candidate_chart.items()}
            public_files.update({'gitops/roots/public/' + path.relative_to(root_path()).as_posix(): path.read_bytes()
                for path in root_path().rglob('*') if path.is_file()})
            public_files.update({'guard/Chart.yaml': 'apiVersion: v2\nname: permission-guard-proof\nversion: 0.1.0\n',
                'guard/templates/permissions.yaml': guard_path().read_text(), 'guard/templates/permission-input.yaml': input_guard_path().read_text(),
                'noop/Chart.yaml': 'apiVersion: v2\nname: permission-noop-proof\nversion: 0.1.0\n'})
            sources = directory / 'sources'
            sources.mkdir()
            public = GitSource(sources, 'public', public_files)
            private = GitSource(sources, 'private', {'platform/permissions.yaml': values(assignments=False)})
            server = GitServer(('0.0.0.0', 8000), functools.partial(ReadOnlyGit, directory=str(sources)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            owners, project_record = {}, None
            current_approval = None
            diagnostic_expected = {}
            public_pin = public.revision
            state['public_revision'] = public_pin
            try:
                def freeze_sources():
                    for name, source in (('public', public), ('private', private)):
                        pending = receipt.parent / (name + '.bundle.pending')
                        command(['git', '--git-dir', str(source.bare), 'bundle', 'create', str(pending), '--all'])
                        state.setdefault('gitBundles', {})[name] = hashlib.sha256(pending.read_bytes()).hexdigest()
                        os.replace(pending, receipt.parent / (name + '.bundle'))

                def private_commit(files):
                    revision = private.commit(files)
                    freeze_sources()
                    return revision

                def public_commit(files):
                    revision = public.commit(files)
                    freeze_sources()
                    return revision

                def checkpoint(label):
                    current = api.request(RBAC + '/clusterrolebindings/fixture-recovery')
                    require(current['metadata']['uid'] == state['recovery_uid'] and all(current[key] == value for key, value in recovery_spec.items()), 'Independent recovery binding changed')
                    state['checks'].append(label)
                    save(label)

                def owned_spec(path, spec):
                    current = api.request(path)
                    require(path in owners and current['metadata']['uid'] == owners[path]['uid'] and current['spec'] == owners[path]['spec'], 'Fixture owner or specification changed')
                    result = api.request(path, 'PATCH', [
                        {'op': 'test', 'path': '/metadata/uid', 'value': current['metadata']['uid']},
                        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                        {'op': 'test', 'path': '/spec', 'value': current['spec']}, {'op': 'replace', 'path': '/spec', 'value': spec}],
                        content_type='application/json-patch+json')
                    owners[path]['spec'] = copy.deepcopy(result['spec'])
                    state.setdefault('ownerIdentities', {})[path] = {'uid': owners[path]['uid'],
                        'specSHA256': hashlib.sha256(json.dumps(result['spec'], sort_keys=True).encode()).hexdigest()}
                    return result

                def guard_ready():
                    guard_app = api.request(GUARD_APPLICATION)
                    result = (guard_app.get('status', {}).get('operationState') or {}).get('syncResult') or {}
                    expected_guards = {(row['kind'], row['metadata']['name']) for row in guards + input_guards}
                    state['guardDiagnostics'] = [{'kind': row.get('kind'), 'name': row.get('name'),
                        'status': row.get('status'), 'message': str(row.get('message', ''))[:2048]}
                        for row in (result.get('resources') or [])
                        if row.get('group') == 'admissionregistration.k8s.io' and
                        (row.get('kind'), row.get('name')) in expected_guards][:8]
                    save('guard-installation-and-qualification')
                    guarded_qualification(api, guards)
                    for expected in input_guards:
                        plural = 'validatingadmissionpolicies' if expected['kind'] == 'ValidatingAdmissionPolicy' else 'validatingadmissionpolicybindings'
                        actual = api.request(GUARD_API + '/' + plural + '/' + expected['metadata']['name'])
                        metadata, status = actual['metadata'], actual.get('status', {})
                        state.setdefault('inputGuardStatus', {})[expected['kind'] + '/' + metadata['name']] = {
                            'uid': metadata['uid'], 'generation': metadata.get('generation'), 'status': status}
                        require(actual['spec'] == expected['spec'] and metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id') ==
                            'cloudlab-workload-policy:admissionregistration.k8s.io/' + expected['kind'] + ':cloudlab-policy/' + metadata['name'], 'Native input owner differs')
                        if expected['kind'] == 'ValidatingAdmissionPolicy':
                            require(status.get('observedGeneration') == metadata['generation'] and isinstance(status.get('typeChecking'), dict)
                                and not status['typeChecking'].get('expressionWarnings')
                                and not any(row.get('status') == 'False' for row in status.get('conditions') or []), 'Native input type checking is incomplete')
                    return True

                def observe(code, body, policy, message, label):
                    prefix = "ValidatingAdmissionPolicy '" + policy + "' with binding '" + policy + "' denied request:"
                    item = {'label': label, 'code': code, 'reason': body.get('reason'), 'policyAndBinding': prefix in body.get('message', ''),
                        'expectedMessage': message in body.get('message', '')}
                    state['observations'].append(item)
                    save(label)
                    return code == 422 and item['reason'] == 'Invalid' and item['policyAndBinding'] and item['expectedMessage']

                def deny(actor, obj, message, label):
                    code, body = actors[actor].application(obj)
                    require(observe(code, body, INPUT_GUARD, message, label), 'Expected specific native input denial: ' + label)

                def allow(actor, obj, label):
                    code, _ = actors[actor].application(obj)
                    require(code == 200, 'Expected admitted native actor: ' + label)
                    state['observations'].append({'label': label, 'code': code})
                    save(label)

                def binding_rows():
                    rows = api.request(RBAC + '/rolebindings')['items'] + api.request(RBAC + '/clusterrolebindings')['items']
                    return [row for row in rows if row.get('roleRef', {}).get('name', '').startswith('cloudlab-permissions-') or
                        row['metadata']['name'].startswith('cloudlab-permissions-') or row['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'permissions-platform']

                def profile_ready():
                    return source_converged(api.request(PROFILES), owners[PROFILES]['spec']['source'])

                def child_source(approval):
                    current = api.request(APPLICATION)
                    return ((not state.get('child_uid') or current['metadata']['uid'] == state['child_uid']) and
                        current['metadata'].get('ownerReferences') == [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
                            'name': 'cloudlab-permissions', 'uid': owners[PARENT]['uid'], 'controller': True, 'blockOwnerDeletion': True}] and
                        current['metadata'].get('annotations', {}).get('cloudlab.io/permission-revision') == approval['revision'] and
                        current['metadata']['annotations'].get('cloudlab.io/permission-commitment') == approval['commitment'] and
                        source_converged(current, current['spec']['source']))

                def prepare_owner(revision, label, *, profile_sync=False):
                    nonlocal project_record
                    accepted, commitment = consumer_receipt(revision, secrets.token_hex(32))
                    declarations, rendering = rendered_owner(directory, public_pin, commitment)
                    projects = [row for row in declarations if row['kind'] == 'AppProject']
                    for obj in projects:
                        path = '/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/' + obj['metadata']['name']
                        if path not in owners:
                            actual = api.apply(obj)
                            owners[path] = {'uid': actual['metadata']['uid'], 'spec': copy.deepcopy(actual['spec'])}
                            state.setdefault('ownerIdentities', {})[path] = {'uid': actual['metadata']['uid']}
                            if obj['metadata']['name'] == 'cloudlab-permissions': project_record = path
                        else: require(api.request(path)['spec'] == owners[path]['spec'], 'Fixture project changed outside journal')
                    profile = next(row for row in declarations if row['kind'] == 'Application')
                    parent = next(row for row in declarations if row['kind'] == 'ApplicationSet')
                    prepared = {'revision': revision, 'commitment': commitment, 'receipt': accepted, 'parent': parent, 'rendering': rendering}
                    diagnostic_expected.update(gate=parent['spec']['generators'][0]['matrix']['generators'][1]['git']['revision'], commitment=commitment)
                    def apply_profile():
                        if PROFILES not in owners:
                            actual = api.apply(profile)
                            owners[PROFILES] = {'uid': actual['metadata']['uid'], 'spec': copy.deepcopy(actual['spec'])}
                            state.setdefault('ownerIdentities', {})[PROFILES] = {'uid': actual['metadata']['uid']}
                        else: owned_spec(PROFILES, profile['spec'])
                        if profile_sync:
                            wait(lambda: not api.request(PROFILES).get('operation'), 'public profile operation available')
                            current = api.request(PROFILES)
                            require(current['metadata']['uid'] == owners[PROFILES]['uid'] and current['spec'] == owners[PROFILES]['spec'], 'Public profile owner changed before fixture sync')
                            source = copy.deepcopy(current['spec']['source'])
                            current['operation'] = {'sync': {'source': source, 'revision': public_pin, 'prune': True,
                                'syncOptions': copy.deepcopy(current['spec']['syncPolicy']['syncOptions'])},
                                'initiatedBy': {'username': 'fixture-public-profile-sync'}}
                            current.setdefault('status', {}).pop('operationState', None)
                            code, _ = actors['server'].profile_operation(current)
                            require(code == 200, 'Source-pinned public profile operation was not admitted')
                            state.setdefault('profileSyncOperations', []).append({'label': label, 'uid': owners[PROFILES]['uid'],
                                'sourceSHA256': hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()})
                            def completed():
                                profile = api.request(PROFILES)
                                operation = profile.get('status', {}).get('operationState') or {}
                                data = api.request(PARAMETER).get('data', {})
                                return (profile['metadata']['uid'] == owners[PROFILES]['uid'] and profile['spec'] == owners[PROFILES]['spec']
                                    and not profile.get('operation') and operation.get('phase') == 'Succeeded'
                                    and operation.get('operation', {}).get('sync', {}).get('source') == source
                                    and data.get('commitment') == commitment and data.get('revision') == public_pin
                                    and data.get('repository') == SOURCE + 'public.git' and data.get('inputVersion') == 'cloudlab-permissions-input/v2')
                            wait(completed, 'native public profile operation while status workers paused')
                        else:
                            wait(profile_ready, 'independent public profile owner')
                    def record(stage):
                        state['approvals'].append(dict(rendering, label=label, publicRevision=public_pin, acceptedRevision=revision,
                            proposalRevision=prepared['proposalRevision'], commitment=commitment, stage=stage))
                        save(label + '-' + stage)
                    return publish_profile_approval(prepared, private_commit, apply_profile, record)

                def advance_parent(prepared, label):
                    nonlocal current_approval
                    require_current_proposal(prepared, private.revision)
                    parent = prepared['parent']
                    if PARENT not in owners:
                        actual = api.apply(parent)
                        owners[PARENT] = {'uid': actual['metadata']['uid'], 'spec': copy.deepcopy(actual['spec'])}
                        state.setdefault('ownerIdentities', {})[PARENT] = {'uid': actual['metadata']['uid']}
                    else: owned_spec(PARENT, parent['spec'])
                    current_approval = {'revision': prepared['revision'], 'commitment': prepared['commitment']}
                    state['approvals'].append(dict(prepared['rendering'], label=label, publicRevision=public_pin, acceptedRevision=prepared['revision'],
                        proposalRevision=prepared['proposalRevision'], commitment=prepared['commitment'], stage='parent-advanced'))
                    save(label)
                    return copy.deepcopy(current_approval)

                def approval_at(revision, label, *, profile_sync=False):
                    return advance_parent(prepare_owner(revision, label, profile_sync=profile_sync), label)

                def approve(content, label, *, profile_sync=False):
                    return approval_at(private_commit({'platform/permissions.yaml': content}), label, profile_sync=profile_sync)

                def token(name='reader'):
                    return api.request('/api/v1/namespaces/' + NAMESPACE + '/serviceaccounts/' + name + '/token', 'POST',
                        {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest', 'spec': {'expirationSeconds': 600,
                            'audiences': ['https://kubernetes.default.svc.cluster.local']}}, expected=201)['status']['token']

                def access(resource, expected, reader='reader'):
                    return api.request('/api/v1/namespaces/' + NAMESPACE + '/' + resource, token=token(reader), expected=expected)

                def deny_condition():
                    conditions = api.request(PARENT).get('status', {}).get('conditions') or []
                    return any(row.get('type') == 'ErrorOccurred' and row.get('status') == 'True' and INPUT_GUARD in row.get('message', '') for row in conditions)

                freeze_sources()
                save('guard-installation-and-qualification')
                api.apply({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject', 'metadata': {'name': 'permission-guard-proof', 'namespace': 'argocd'},
                    'spec': {'sourceRepos': [SOURCE + 'public.git'], 'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-policy'}],
                        'clusterResourceWhitelist': [{'group': 'admissionregistration.k8s.io', 'kind': kind} for kind in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding')],
                        'namespaceResourceWhitelist': []}})
                api.apply({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {'name': 'cloudlab-workload-policy', 'namespace': 'argocd'},
                    'spec': {'project': 'permission-guard-proof', 'source': {'repoURL': SOURCE + 'public.git', 'targetRevision': public_pin, 'path': 'guard'},
                        'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-policy'}, 'syncPolicy': {'automated': {'prune': True, 'selfHeal': True}}}})
                wait(guard_ready, 'all exact native guards')
                candidate = copy.deepcopy(api.request(PARAMETER))
                candidate['metadata']['labels'] = {'cloudlab.io/owner': 'permissions-profile-platform'}
                candidate['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': 'cloudlab-permissions-profiles:/ConfigMap:argocd/cloudlab-permissions-profiles'}
                guard_identities = {}
                for reference in guards + input_guards:
                    plural = 'validatingadmissionpolicies' if reference['kind'] == 'ValidatingAdmissionPolicy' else 'validatingadmissionpolicybindings'
                    path = GUARD_API + '/' + plural + '/' + reference['metadata']['name']
                    actual = api.request(path)
                    require(actual['spec'] == reference['spec'] and actual['metadata'].get('uid'), 'Guard changed before dispatch qualification')
                    guard_identities[path] = {'uid': actual['metadata']['uid'], 'spec': copy.deepcopy(actual['spec'])}

                def guards_unchanged():
                    for path, identity in guard_identities.items():
                        actual = api.request(path)
                        require(actual['metadata']['uid'] == identity['uid'] and actual['spec'] == identity['spec'], 'Guard identity or specification changed during qualification')

                def foreign_unchanged():
                    guards_unchanged()
                    actual = api.request(PARAMETER)
                    require(actual['metadata']['uid'] == foreign['metadata']['uid'] and actual.get('data') == foreign.get('data')
                        and actual['metadata'].get('labels') == foreign['metadata'].get('labels')
                        and actual['metadata'].get('annotations') == foreign['metadata'].get('annotations'), 'Foreign projection changed during dispatch qualification')

                def record_dispatch(result):
                    state['observations'].append(result)
                    save('initial-projection-dispatch-qualification')

                qualify_initial_projection(lambda: actors['controller'].projection(candidate), foreign_unchanged, record_dispatch, deadline)
                unrelated_cm = api.apply({'apiVersion': 'v1', 'kind': 'ConfigMap',
                    'metadata': {'name': 'cloudlab-unrelated-projection-proof', 'namespace': 'argocd'}, 'data': {'fixture': 'create'}})
                unrelated_path = '/api/v1/namespaces/argocd/configmaps/cloudlab-unrelated-projection-proof'
                unrelated_cm['data']['fixture'] = 'update'
                updated_cm = api.request(unrelated_path, 'PUT', unrelated_cm)
                require(updated_cm['metadata']['uid'] == unrelated_cm['metadata']['uid'] and updated_cm['data'] == {'fixture': 'update'}, 'Unrelated projection update changed identity or data')
                api.request(unrelated_path, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': unrelated_cm['metadata']['uid']}})
                state['observations'].append({'label': 'unrelated-configmap-create-update-allowed', 'uid': unrelated_cm['metadata']['uid']})
                foreign_unchanged()
                api.request(PARAMETER, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': foreign['metadata']['uid']}})
                wait(lambda: api.absent(PARAMETER), 'foreign parameter removed')
                require(not binding_rows(), 'Reserved bindings exist before empty role activation')
                empty = approve(values(assignments=False), 'initial-empty-approval')
                wait(lambda: child_source(empty), 'actual native ApplicationSet empty child', 240)
                child = api.request(APPLICATION)
                owner = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': 'cloudlab-permissions', 'uid': owners[PARENT]['uid'], 'controller': True, 'blockOwnerDeletion': True}
                require(child['metadata'].get('ownerReferences') == [owner] and not binding_rows(), 'Native empty owner or zero-grant boundary failed')
                guards_unchanged()
                projection = api.request(PARAMETER)
                expected_projection = render_projection(directory, public.work / 'platform/connectivity/permissions',
                    owners[PROFILES]['spec']['source']['helm']['valuesObject'])
                require(projection['metadata']['uid'] != foreign['metadata']['uid'] and projection.get('data') == expected_projection.get('data')
                    and projection['metadata'].get('labels', {}).get('cloudlab.io/owner') == expected_projection['metadata']['labels']['cloudlab.io/owner']
                    and projection['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') ==
                        'cloudlab-permissions-profiles:/ConfigMap:argocd/cloudlab-permissions-profiles'
                    and not projection['metadata'].get('ownerReferences') and not projection['metadata'].get('deletionTimestamp'),
                    'Independent public projection identity or canonical data differs')
                state['projectionIdentity'] = {'uid': projection['metadata']['uid'],
                    'dataSHA256': hashlib.sha256(json.dumps(projection['data'], sort_keys=True).encode()).hexdigest()}
                state['child_uid'] = child['metadata']['uid']
                invalid = copy.deepcopy(child)
                invalid['spec']['source']['helm']['valuesObject']['permissions']['unexpected'] = True
                deny('appset', invalid, 'violates its bounded', 'canonical-private-rejection-before-first-grant')
                adopted = copy.deepcopy(collision)
                adopted['metadata']['labels'] = {'cloudlab.io/owner': 'permissions-platform',
                    'cloudlab.io/permission-profile': 'collision', 'cloudlab.io/permission-scope': 'namespace'}
                adopted['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
                    admission_verify.permission_tracking('ClusterRole', adopted['metadata']['name'])}
                guard_denied(api, adopted, CONTROLLER, update=True)
                checkpoint('real-native-empty-child-and-independent-projection')
                initial = approve(values(cluster=True), 'assignment-A')
                wait(lambda: child_source(initial), 'assignment A', 240)
                access('pods', 200)
                access('services', 200)
                access('secrets', 403)
                api.request('/api/v1/nodes', token=token(), expected=200)
                api.request('/api/v1/namespaces/default/pods', token=token(), expected=403)
                checkpoint('namespace-and-explicit-cluster-positive-authorization')
                current = api.request(APPLICATION)
                for actor in ('metadata', 'appset', 'server'):
                    forged = copy.deepcopy(current)
                    forged['status']['sync']['comparedTo']['source']['targetRevision'] = 'f' * 40
                    deny(actor, forged, 'convergence status', actor + '-status-forgery-denied')
                for name, operation in [('manifests', {'manifests': ['arbitrary']}), ('force', {'syncOptions': ['Force=true']})]:
                    candidate = copy.deepcopy(current)
                    candidate['operation'] = {'sync': operation}
                    deny('server', candidate, 'cannot override', 'unsafe-' + name)
                candidate = copy.deepcopy(current)
                candidate['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'] = 'false'
                deny('metadata', candidate, 'cannot be disabled', 'skip-reconcile-denied')
                candidate = copy.deepcopy(current)
                candidate['operation'] = {'sync': {'source': copy.deepcopy(current['spec']['source']), 'revision': public_pin,
                    'syncOptions': copy.deepcopy(current['spec']['syncPolicy']['syncOptions'])}, 'retry': copy.deepcopy(current['spec']['syncPolicy']['retry'])}
                candidate['status'].pop('operationState', None)
                allow('server', candidate, 'server-start-admission-only')
                # Public context B is ready before pausing all operation workers.
                # Parent and admitted child remain at A while B's receipt/public context is prepared.
                prepared_b = prepare_owner(private_commit({'platform/permissions.yaml': values()}), 'prestage-public-context-B')
                processors.set(operation=0)
                binding = api.request(BINDING)
                api.request(BINDING, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': binding['metadata']['uid']}})
                pending = wait(lambda: api.request(APPLICATION).get('operation'), 'real pending operation A')
                require(pending['sync']['source'] == current['spec']['source'], 'Pending native operation source differs from A')
                following = advance_parent(prepared_b, 'no-addition-spec-B')
                carried = wait(lambda: (lambda row: row if row['metadata'].get('annotations', {}).get('cloudlab.io/permission-revision') == following['revision'] else None)(api.request(APPLICATION)), 'valid no-addition specification B', 240)
                require(carried['spec']['source'] != current['spec']['source'] and carried.get('operation') == pending, 'Authorized A operation did not carry into B')
                project_spec = copy.deepcopy(owners[project_record]['spec'])
                blocked = copy.deepcopy(project_spec)
                blocked['namespaceResourceBlacklist'] = [{'group': 'rbac.authorization.k8s.io', 'kind': 'RoleBinding'}]
                owned_spec(project_record, blocked)
                state['projectRestore'] = {'path': project_record, 'uid': owners[project_record]['uid'], 'restored': False}
                save('retry-injection')
                processors.set()
                retry = wait(lambda: (lambda row: row if row.get('status', {}).get('operationState', {}).get('retryCount', 0) >= 1 and row.get('operation') else None)(api.request(APPLICATION)), 'real native retry')
                require(retry['operation'] == pending, 'Retry replaced the admitted carried command')
                active_identity = {'uid': state['child_uid'], 'spec': copy.deepcopy(carried['spec']), 'operation': copy.deepcopy(pending)}
                def active_probe(actor, transform, label, message=None):
                    def conflict(item):
                        state.setdefault('operationProbeConflicts', []).append(dict(item, label=label))
                        save(label + '-conflict')
                    code, body = probe_active_operation(lambda: api.request(APPLICATION), actors[actor].application,
                        transform, active_identity, conflict, deadline)
                    if message:
                        require(observe(code, body, INPUT_GUARD, message, label), 'Expected specific active operation denial: ' + label)
                    else:
                        require(code == 200, 'Expected admitted active operation actor: ' + label)
                        state['observations'].append({'label': label, 'code': code})
                        save(label)
                def terminating(row):
                    row['status']['operationState']['phase'] = 'Terminating'
                def forged_termination(row):
                    terminating(row)
                    row['status']['operationState']['retryCount'] = 99
                active_probe('server', terminating, 'server-termination-admission-only')
                active_probe('server', forged_termination, 'server-termination-status-forgery-denied', 'convergence status')
                active_probe('metadata', lambda row: row.pop('operation'), 'metadata-operation-clear-denied', 'can clear')
                owned_spec(project_record, project_spec)
                state['projectRestore']['restored'] = True
                wait(lambda: child_source(following), 'native retry completion and B convergence', 240)
                access('pods', 200)
                api.request('/api/v1/nodes', token=token(), expected=403)
                checkpoint('real-operation-carry-retry-controller-clear-and-project-restore')
                profiles = yaml.safe_load(candidate_chart['profiles.yaml'])
                profiles['profiles']['viewer']['namespaceRules'] = [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list']}]
                public_pin = public_commit({'platform/connectivity/permissions/profiles.yaml': yaml.safe_dump(profiles)})
                prepared_narrowing = prepare_owner(private_commit({'platform/permissions.yaml': values()}), 'prestage-public-profile-narrowing')
                catalog_probe = copy.deepcopy(api.request(APPLICATION))
                catalog_probe['spec']['source']['targetRevision'] = public_pin
                catalog_probe['metadata']['annotations'].update({
                    'cloudlab.io/permission-public-revision': public_pin,
                    'cloudlab.io/permission-revision': prepared_narrowing['revision'],
                    'cloudlab.io/permission-commitment': prepared_narrowing['commitment']})
                catalog_assignments = catalog_probe['spec']['source']['helm']['valuesObject']['permissions']['assignments']
                catalog_assignments.append(copy.deepcopy(catalog_assignments[0]) | {'id': 'catalog-probe'})
                deny('appset', catalog_probe, 'already converged catalog pin', 'new-id-with-unconverged-catalog-denied')
                narrowed = advance_parent(prepared_narrowing, 'public-profile-narrowing')
                wait(lambda: child_source(narrowed), 'same-pin public projection and narrowed role', 240)
                access('pods', 200)
                wait(lambda: access('services', 403), 'narrowed native authorization')
                checkpoint('public-profile-update-and-narrowing')
                last_valid = copy.deepcopy(api.request(APPLICATION))
                invalid = yaml.safe_load(values())
                invalid['permissions']['unexpected'] = True
                rejected = approve(yaml.safe_dump(invalid), 'approved-invalid-private-input')
                wait(deny_condition, 'specific canonical input rejection', 240)
                unchanged = api.request(APPLICATION)
                require(unchanged['metadata']['uid'] == state['child_uid'] and unchanged['spec'] == last_valid['spec'] and
                    unchanged['metadata']['annotations']['cloudlab.io/permission-revision'] != rejected['revision'], 'Invalid private input replaced the stored source')
                role = api.request(ROLE)
                role['rules'] = [{'apiGroups': [''], 'resources': ['pods', 'services'], 'verbs': ['get', 'list']}]
                api.request(ROLE, 'PUT', role, impersonate=CONTROLLER)
                wait(lambda: api.request(ROLE)['rules'] == [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list']}], 'last-valid role drift repair')
                wait(lambda: access('services', 403), 'last-valid authorization repaired')
                checkpoint('invalid-private-input-retains-spec-and-continues-repair')
                restored = approve(values(), 'valid-input-restoration')
                wait(lambda: child_source(restored), 'valid source restoration', 240)
                processors.set(operation=0)
                parameter = api.request(PARAMETER)
                api.request(PARAMETER, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': parameter['metadata']['uid']}})
                wait(lambda: api.absent(PARAMETER), 'parameter absent')
                missing_message = 'no params found for policy binding with `Deny` parameterNotFoundAction'
                wait(lambda: observe(*actors['controller'].application(api.request(APPLICATION)), INPUT_GUARD, missing_message, 'missing-parameter-protected-denied'), 'specific missing parameter denial')
                unrelated = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {'name': 'cloudlab-permission-unrelated-proof', 'namespace': 'argocd',
                    'annotations': {'fixture.example/update': 'created-without-parameters'}},
                    'spec': {'project': 'default', 'source': {'repoURL': SOURCE + 'public.git', 'targetRevision': public_pin, 'path': 'noop'},
                        'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}}}
                unrelated_path = APPLICATION.rsplit('/', 1)[0] + '/cloudlab-permission-unrelated-proof'
                save('unrelated-application-create')
                unrelated = api.apply(unrelated)
                save('unrelated-application-created')
                save('unrelated-application-annotation-update')
                updated = api.request(unrelated_path, 'PATCH', [
                    {'op': 'test', 'path': '/metadata/uid', 'value': unrelated['metadata']['uid']},
                    {'op': 'add', 'path': '/metadata/annotations/fixture.example~1update', 'value': 'allowed-without-parameters'}],
                    content_type='application/json-patch+json')
                require(updated['metadata']['uid'] == unrelated['metadata']['uid'] and
                    updated['metadata'].get('annotations', {}).get('fixture.example/update') == 'allowed-without-parameters',
                    'Unrelated Application annotation update changed identity or missed its owned field')
                save('unrelated-application-annotation-updated')
                save('unrelated-application-delete')
                api.request(unrelated_path, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': unrelated['metadata']['uid']}})
                save('unrelated-application-deleted')
                processors.set()
                wait(lambda: (lambda row: row['metadata']['uid'] != parameter['metadata']['uid'] and row.get('data', {}).get('commitment') == restored['commitment'])(api.request(PARAMETER)), 'independent profile owner self-heal')
                wait(profile_ready, 'restored profile convergence')
                wait(lambda: child_source(restored), 'permission updates resume after independent restoration')
                checkpoint('missing-param-protected-deny-unrelated-create-update-allow-and-independent-repair')
                # Operation workers remain available for source-pinned profile-only
                # syncs through native resync dispatch; no role command is created.
                before_hold = api.request(APPLICATION)
                require(processors.expected == processors.original and before_hold['metadata']['uid'] == state['child_uid']
                    and not before_hold['metadata'].get('deletionTimestamp')
                    and source_converged(before_hold, before_hold['spec']['source']), 'Reuse hold requires settled native B and original workers')
                processors.set(status=0, jitter=1)
                frozen = api.request(APPLICATION)
                require(frozen['metadata']['uid'] == state['child_uid'] and frozen['spec'] == before_hold['spec']
                    and not frozen['metadata'].get('deletionTimestamp')
                    and source_converged(frozen, before_hold['spec']['source']), 'Native B changed during reuse hold rollout')
                frozen_status = copy.deepcopy(frozen['status'])
                state['reuseHold'] = {'uid': frozen['metadata']['uid'], 'jitterSeconds': 1,
                    'specSHA256': hashlib.sha256(json.dumps(frozen['spec'], sort_keys=True).encode()).hexdigest(),
                    'statusSHA256': hashlib.sha256(json.dumps(frozen_status, sort_keys=True).encode()).hexdigest()}
                save('native-B-frozen-after-worker-rollout')
                def frozen_role(row):
                    require(row['metadata']['uid'] == frozen['metadata']['uid'] and row.get('status') == frozen_status
                        and not row.get('operation') and not row['metadata'].get('deletionTimestamp'),
                        'Role owner status or operation changed during the native reuse hold')
                removed = approve(values(assignments=False), 'removal-M', profile_sync=True)
                removal = wait(lambda: (lambda row: row if row['metadata'].get('annotations', {}).get('cloudlab.io/permission-revision') == removed['revision'] else None)(api.request(APPLICATION)), 'stored removal M with frozen old status', 240)
                frozen_role(removal)
                require(removal['status']['sync']['comparedTo']['source'] != removal['spec']['source'] and not removal.get('operation'), 'Reuse race lacks genuinely stale settled native evidence')
                replacement = yaml.safe_load(values())
                replacement['permissions']['assignments'][0]['subject']['name'] = 'reader-second'
                premature = approve(yaml.safe_dump(replacement), 'premature-reuse-C', profile_sync=True)
                wait(deny_condition, 'early reuse rejected', 240)
                held = api.request(APPLICATION)
                frozen_role(held)
                require(held['spec'] == removal['spec'], 'Premature reuse changed the removal source')
                conditions = api.request(PARENT).get('status', {}).get('conditions') or []
                require(any('New or reused assignment IDs' in row.get('message', '') for row in conditions), 'Premature reuse was not specifically rejected for convergence')
                restored_removal = approval_at(removed['revision'], 'restore-M-before-unfreeze', profile_sync=True)
                wait(lambda: api.request(APPLICATION)['metadata']['annotations']['cloudlab.io/permission-commitment'] == restored_removal['commitment'], 'parent restored to M', 240)
                require(api.request(PARAMETER)['data']['commitment'] == restored_removal['commitment'], 'Public profile context was not restored to M')
                frozen_role(api.request(APPLICATION))
                processors.set()
                wait(lambda: child_source(restored_removal), 'M native removal convergence', 240)
                wait(lambda: api.absent(BINDING), 'old binding absent')
                access('pods', 403)
                access('pods', 403, 'reader-second')
                checkpoint('early-reuse-rejected-and-native-revocation-observed')
                replacement_approval = approval_at(premature['revision'], 'qualified-reuse-C')
                wait(lambda: child_source(replacement_approval), 'qualified replacement', 240)
                require(api.request(BINDING)['subjects'][0]['name'] == 'reader-second', 'Replacement bound the old subject')
                access('pods', 403)
                access('pods', 200, 'reader-second')
                checkpoint('same-id-reuse-only-after-complete-convergence-and-fresh-denial')
                retired = approve(values(assignments=False, state='retired'), 'retired-empty-owner')
                wait(lambda: child_source(retired), 'retired owner convergence', 240)
                wait(lambda: not binding_rows(), 'all reserved bindings absent')
                access('pods', 403)
                access('pods', 403, 'reader-second')
                require(not api.absent(ROLE) and not api.absent(APPLICATION), 'Retirement removed retained roles or owner')
                require(processors.expected == processors.original and state['projectRestore']['restored'], 'Fixture restoration remains pending')
                require(api.request(RBAC + '/clusterroles/' + collision['metadata']['name'])['metadata']['uid'] == collision['metadata']['uid'], 'Foreign collision changed')
                api.request(RBAC + '/clusterroles/' + collision['metadata']['name'], 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': collision['metadata']['uid']}})
                checkpoint('retired-bindings-pruned-roles-and-native-owner-retained')
                save('complete')
                print(json.dumps({'status': 'passed', 'run': state['run'], 'checks': state['checks'], 'limits': state['limits'],
                    'cleanup': 'inspect and remove exact local Compose project; preserve receipts'}, sort_keys=True))
            except Exception:
                record_failure_journal(api, state, diagnostic_expected, save)
                raise
            finally:
                # Failure never automatically resumes a paused grant-producing controller.
                # Original/current args and project restoration remain journalled.
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
    except Exception as error:
        state['failure_type'] = type(error).__name__
        if isinstance(error, RuntimeError): state['failure'] = str(error)
        save('failed-' + state['phase'])
        raise


if __name__ == '__main__':
    try:
        run()
    except Exception as error:
        # HTTP bodies, credentials, subprocess output and kubeconfig never enter logs.
        print('Permission controller fixture failed; inspect receipt phase; details withheld', flush=True)
        raise SystemExit(1) from None
