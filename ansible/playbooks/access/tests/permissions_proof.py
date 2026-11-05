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
CATALOG_FILES = ('Chart.yaml', 'values.yaml', 'values.schema.json', 'profiles.yaml', 'templates/rbac.yaml')


def catalog_files():
    root = Path('/inputs/catalog')
    if not root.exists(): root = Path(__file__).resolve().parents[4] / 'platform/connectivity/permissions'
    return {name: (root / name).read_bytes().decode('utf-8') for name in CATALOG_FILES}


def guard_path():
    path = Path('/inputs/guard.yaml')
    return path if path.exists() else Path(__file__).resolve().parents[4] / 'platform/delivery/admission/policies/templates/permissions.yaml'


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


def current_sync(status, revisions):
    return (status.get('sync', {}).get('status') == 'Synced' and
            status['sync'].get('revisions') == revisions and
            status.get('operationState', {}).get('phase') == 'Succeeded' and
            not any(condition.get('type') in ('ComparisonError', 'InvalidSpecError')
                    for condition in status.get('conditions', [])))


def current_project_rejection(status, revisions):
    operation = status.get('operationState', {})
    if (operation.get('phase') in ('Failed', 'Error') and
        operation.get('syncResult', {}).get('revisions') == revisions):
        return 'sync-rejected'
    if status.get('sync', {}).get('revisions') == revisions and any(
            condition.get('type') in ('ComparisonError', 'InvalidSpecError') and
            'not permitted' in condition.get('message', '') and
            'RoleBinding' in condition.get('message', '') for condition in status.get('conditions', [])):
        return 'comparison-rejected'
    return False


def install(api, directory):
    return install_argocd(api, directory, Path('/inputs/argo-cd-10.9.6.tgz'),
                         Path('/inputs/artifact.lock.json'), Path('/inputs/values.yaml'))


def run():
    deadline = time.monotonic() + 1200
    project_name = os.environ.get('FIXTURE_PROJECT', '')
    require(re.fullmatch(r'permissions-proof-[a-z0-9][a-z0-9-]{0,43}', project_name),
            'Use a unique permissions-proof-<run> Compose project')
    receipt = Path('/receipts/state.json')
    require(not receipt.exists(), 'Existing fixture receipt: inspect and clean exact Compose project before a new run')
    state = {'version': 1, 'run': secrets.token_hex(16), 'project': project_name, 'phase': 'starting', 'checks': [],
             'inputs': {name: hashlib.sha256(Path('/inputs', name).read_bytes()).hexdigest() for name in
                        ('permissions_proof.py', 'argo-cd-10.9.6.tgz', 'artifact.lock.json', 'values.yaml')}}
    state['catalog_inputs'] = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in catalog_files().items()}
    state['guard_input'] = hashlib.sha256(guard_path().read_bytes()).hexdigest()

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
        try: os.fsync(descriptor)
        finally: os.close(descriptor)

    def wait(predicate, label, seconds=150):
        stop = min(deadline, time.monotonic() + seconds)
        while time.monotonic() < stop:
            try:
                result = predicate()
                if result: return result
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
            save('controller-install')
            state['images'] = sorted(install(api, directory))
            wait(lambda: all(api.request('/apis/apps/v1/namespaces/argocd/' + kind + '/' + name)
                 .get('status', {}).get('readyReplicas') == 1 for kind, name in
                 [('deployments', 'argocd-repo-server'), ('deployments', 'argocd-redis'),
                  ('statefulsets', 'argocd-application-controller')]), 'native controller readiness', 420)
            api.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NAMESPACE}})
            api.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'cloudlab-policy'}})
            api.apply({'apiVersion': 'v1', 'kind': 'ServiceAccount',
                       'metadata': {'name': 'reader', 'namespace': NAMESPACE}, 'automountServiceAccountToken': False})
            recovery = api.apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding',
               'metadata': {'name': 'fixture-recovery'}, 'roleRef': {'apiGroup': 'rbac.authorization.k8s.io',
               'kind': 'ClusterRole', 'name': 'cluster-admin'}, 'subjects': [{'kind': 'User', 'name': 'fixture-recovery'}]})
            recovery_spec = {key: recovery[key] for key in ('roleRef', 'subjects')}
            state['recovery_uid'] = recovery['metadata']['uid']
            sources = directory / 'sources'
            sources.mkdir()
            candidate_chart = catalog_files()
            candidate_guard = guard_path().read_bytes().decode('utf-8')
            guard_expected = admission_verify.permission_guard_desired(guard_path())
            public = GitSource(sources, 'public', {'chart/' + key: value for key, value in candidate_chart.items()} | {
                'guard/Chart.yaml': 'apiVersion: v2\nname: permission-guard-proof\nversion: 0.1.0\n',
                'guard/templates/permissions.yaml': candidate_guard})
            private = GitSource(sources, 'private', {'permissions.yaml': values(assignments=False)})
            state['public_revision'] = public.revision
            state['private_revision'] = private.revision
            handler = functools.partial(ReadOnlyGit, directory=str(sources))
            server = GitServer(('0.0.0.0', 8000), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                save('guard-before-activation')
                command(['git', 'ls-remote', SOURCE + 'public.git', 'refs/heads/main'])
                def checkpoint(label):
                    current = api.request(RBAC + '/clusterrolebindings/fixture-recovery')
                    require(current['metadata']['uid'] == state['recovery_uid'] and
                            all(current[key] == value for key, value in recovery_spec.items()),
                            'Independent recovery binding changed')
                    state['checks'].append(label)
                    save(label)

                def require_no_activation(expected):
                    try: guarded_qualification(api, expected)
                    except RuntimeError: pass
                    else: raise RuntimeError('Unqualified guard incorrectly allowed activation')
                    require(api.absent(APPLICATION), 'Permissions activated before guard qualification')

                require_no_activation(guard_expected)
                collision = api.apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole',
                    'metadata': {'name': 'cloudlab-permissions-collision-namespace'}, 'rules': []})
                state['collision_uid'] = collision['metadata']['uid']
                api.apply({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
                    'metadata': {'name': 'permission-guard-proof', 'namespace': 'argocd'}, 'spec': {
                    'sourceRepos': [SOURCE + 'public.git'],
                    'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-policy'}],
                    'clusterResourceWhitelist': [{'group': 'admissionregistration.k8s.io', 'kind': kind}
                        for kind in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding')],
                    'namespaceResourceWhitelist': []}})
                bad_guard = copy.deepcopy(guard_expected)
                bad_guard[0]['spec']['validations'][0]['expression'] += ' && object.nonExistentPermissionField == true'
                public.commit({'guard/templates/permissions.yaml': yaml.safe_dump_all(bad_guard)})
                api.apply({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
                    'metadata': {'name': 'cloudlab-workload-policy', 'namespace': 'argocd'}, 'spec': {
                    'project': 'permission-guard-proof', 'source': {'repoURL': SOURCE + 'public.git',
                    'targetRevision': public.revision, 'path': 'guard'},
                    'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-policy'},
                    'syncPolicy': {'automated': {'prune': True, 'selfHeal': True}}}})
                wait(lambda: api.request(GUARD_API + '/validatingadmissionpolicies/' + GUARD_NAME + '-roles')
                     .get('status', {}).get('typeChecking', {}).get('expressionWarnings'), 'native guard warning')
                require_no_activation(bad_guard)
                public.commit({'guard/templates/permissions.yaml': candidate_guard})
                api.request(GUARD_APPLICATION, 'PATCH', {'spec': {'source': {'targetRevision': public.revision}}},
                            content_type='application/merge-patch+json')
                wait(lambda: api.request(GUARD_APPLICATION).get('status', {}).get('sync', {}).get('revision') == public.revision,
                     'exact guard source')
                wait(lambda: guarded_qualification(api, guard_expected), 'current native guard qualification')
                state['guard_public_revision'] = public.revision
                checkpoint('guard-qualified-before-empty-owner')
                require(api.dry_run({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole',
                        'metadata': {'name': 'fixture-unrelated'}, 'rules': []}, None)[0] == 0,
                        'Unrelated RBAC was incorrectly guarded')
                adopted = copy.deepcopy(collision)
                adopted['metadata']['labels'] = {'cloudlab.io/owner': 'permissions-platform',
                    'cloudlab.io/permission-profile': 'collision', 'cloudlab.io/permission-scope': 'namespace'}
                adopted['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
                    admission_verify.permission_tracking('ClusterRole', adopted['metadata']['name'])}
                guard_denied(api, adopted, CONTROLLER, update=True)
                project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
                    'metadata': {'name': 'cloudlab-permissions', 'namespace': 'argocd'}, 'spec': {
                    'sourceRepos': [SOURCE + 'public.git', SOURCE + 'private.git'],
                    'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': '*'}],
                    'clusterResourceWhitelist': [{'group': 'rbac.authorization.k8s.io', 'kind': kind}
                        for kind in ('ClusterRole', 'ClusterRoleBinding')],
                    'namespaceResourceWhitelist': [{'group': 'rbac.authorization.k8s.io', 'kind': 'RoleBinding'}]}}
                project_record = api.apply(project)
                project_spec = copy.deepcopy(project_record['spec'])
                project_path = '/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/cloudlab-permissions'
                api.apply({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
                    'metadata': {'name': 'cloudlab-permissions', 'namespace': 'argocd'}, 'spec': {
                    'project': 'cloudlab-permissions', 'sources': [
                    {'repoURL': SOURCE + 'public.git', 'targetRevision': public.revision, 'path': 'chart',
                     'helm': {'valueFiles': ['$values/permissions.yaml']}},
                    {'repoURL': SOURCE + 'private.git', 'targetRevision': 'main', 'ref': 'values'}],
                    'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                    'syncPolicy': {'automated': {'prune': True, 'selfHeal': True, 'allowEmpty': False},
                                   'retry': {'limit': 1, 'backoff': {'duration': '1s', 'factor': 1, 'maxDuration': '2s'}},
                                   'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true',
                                                   'PrunePropagationPolicy=background']}}})
                def synced():
                    app = api.request(APPLICATION)
                    return current_sync(app.get('status', {}), [public.revision, private.revision])

                def advance(content):
                    state['private_revision'] = private.commit({'permissions.yaml': content})
                    save('reconciling')
                    refresh()

                def refresh():
                    api.request(APPLICATION, 'PATCH', {'metadata': {
                        'annotations': {'argocd.argoproj.io/refresh': 'hard'}}},
                        content_type='application/merge-patch+json')

                def token():
                    return api.request('/api/v1/namespaces/' + NAMESPACE + '/serviceaccounts/reader/token',
                        'POST', {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest',
                                 'spec': {'expirationSeconds': 600,
                                          'audiences': ['https://kubernetes.default.svc.cluster.local']}},
                        expected=201)['status']['token']

                def access(resource, expected):
                    return api.request('/api/v1/namespaces/' + NAMESPACE + '/' + resource,
                                       token=token(), expected=expected)

                wait(synced, 'initial native multi-source reconciliation')
                def tracked_bindings():
                    rows = api.request(RBAC + '/rolebindings')['items'] + api.request(RBAC + '/clusterrolebindings')['items']
                    return [row for row in rows if row['metadata'].get('annotations', {}).get(
                        'argocd.argoproj.io/tracking-id', '').startswith('cloudlab-permissions:') or
                        row['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'permissions-platform']
                require(not tracked_bindings(), 'Empty owner produced permission grants')
                checkpoint('empty-owner-before-first-assignment')
                advance(values())
                wait(synced, 'first exact private assignment')
                require(api.request(BINDING)['metadata']['annotations'].get('argocd.argoproj.io/tracking-id') == TRACKING,
                        'Native binding ownership mismatch')
                access('pods', 200)
                access('services', 200)
                access('secrets', 403)
                api.request('/api/v1/namespaces/default/pods', token=token(), expected=403)
                api.request('/api/v1/nodes', token=token(), expected=403)
                checkpoint('create-and-real-token-authentication')
                for mutation in ('strip', 'tracking', 'scope'):
                    changed = copy.deepcopy(api.request(ROLE))
                    if mutation == 'strip': changed['metadata']['labels'] = {}
                    if mutation == 'tracking': changed['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
                    if mutation == 'scope': changed['metadata']['labels']['cloudlab.io/permission-scope'] = 'cluster'
                    guard_denied(api, changed, CONTROLLER, update=True)
                    changed_binding = copy.deepcopy(api.request(BINDING))
                    if mutation == 'strip': changed_binding['metadata']['labels'] = {}
                    if mutation == 'tracking': changed_binding['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
                    if mutation == 'scope': changed_binding['metadata']['labels']['cloudlab.io/permission-scope'] = 'cluster'
                    guard_denied(api, changed_binding, CONTROLLER, update=True)
                guard_denied(api, api.request(BINDING), None, update=True)
                checkpoint('actual-guard-caller-tracking-adoption-and-stripping')
                advance(values(cluster=True))
                wait(synced, 'explicit cluster assignment')
                api.request('/api/v1/nodes', token=token(), expected=200)
                api.request('/api/v1/secrets', token=token(), expected=403)
                advance(values())
                wait(synced, 'cluster assignment removal')
                wait(lambda: api.request('/api/v1/nodes', token=token(), expected=403), 'cluster authorization removed')
                checkpoint('namespace-and-explicit-cluster-scopes')
                profiles = yaml.safe_load(candidate_chart['profiles.yaml'])
                profiles['profiles']['viewer']['namespaceRules'] = [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list']}]
                public.commit({'chart/profiles.yaml': yaml.safe_dump(profiles)})
                current_sources = api.request(APPLICATION)['spec']['sources']
                current_sources[0]['targetRevision'] = public.revision
                api.request(APPLICATION, 'PATCH', {'spec': {'sources': current_sources}}, content_type='application/merge-patch+json')
                wait(synced, 'native narrowing')
                access('pods', 200)
                wait(lambda: access('services', 403), 'narrowed authorization')
                checkpoint('narrowing')
                role = api.request(ROLE)
                require(not role['metadata'].get('ownerReferences') and not api.request(BINDING)['metadata'].get('ownerReferences'),
                        'Catalog RBAC unexpectedly owns child resources')
                role['rules'] = [{'apiGroups': [''], 'resources': ['pods', 'services'], 'verbs': ['get', 'list']}]
                api.request(ROLE, 'PUT', role, impersonate=CONTROLLER)
                wait(lambda: api.request(ROLE)['rules'][0]['resources'] == ['pods'], 'native drift repair')
                wait(lambda: access('services', 403), 'repaired authorization')
                checkpoint('drift-repair')
                for label, content in [('invalid-source', 'permissions: [invalid]\n'), ('missing-source', None), ('empty-source', '')]:
                    advance(content)
                    wait(lambda: any(c.get('type') == 'ComparisonError' for c in
                         api.request(APPLICATION).get('status', {}).get('conditions', [])), label)
                    require(not api.absent(BINDING), 'Invalid source removed prior binding')
                    access('pods', 200)
                    checkpoint(label + '-retains-grants')
                    # Clear the observed failure at an exact successful revision
                    # before inducing another failure; stale errors never count.
                    advance(values())
                    wait(synced, label + ' recovery')
                server.block_private = True
                refresh()
                wait(lambda: any(c.get('type') == 'ComparisonError' for c in
                     api.request(APPLICATION).get('status', {}).get('conditions', [])), 'unavailable-source')
                require(not api.absent(BINDING), 'Unavailable source removed prior binding')
                access('pods', 200)
                checkpoint('unavailable-source-retains-grants')
                server.block_private = False
                refresh()
                wait(synced, 'unavailable source recovery')
                # A failed replacement is attempted only after observed revocation.
                advance(values(assignments=False))
                wait(synced, 'old assignment removal')
                wait(lambda: api.absent(BINDING), 'old binding absent')
                wait(lambda: access('pods', 403), 'old authorization denied')
                checkpoint('remove-before-replacement')
                require(api.request(project_path)['metadata']['uid'] == project_record['metadata']['uid'],
                        'Fixture project ownership changed')
                blocked = copy.deepcopy(project)
                blocked['spec'] = copy.deepcopy(project_spec)
                blocked['spec']['namespaceResourceBlacklist'] = [
                    {'group': 'rbac.authorization.k8s.io', 'kind': 'RoleBinding'}]
                api.apply(blocked)
                require(api.request(project_path)['spec'] == blocked['spec'], 'Fixture project failure injection mismatch')
                advance(values())
                rejection = wait(lambda: current_project_rejection(api.request(APPLICATION).get('status', {}),
                                 [public.revision, private.revision]), 'controlled replacement rejection')
                state['replacement_failure'] = rejection
                require(api.absent(BINDING), 'Failed replacement restored old binding')
                access('pods', 403)
                checkpoint('failed-replacement-remains-revoked')
                restore = copy.deepcopy(project)
                restore['spec'] = project_spec
                api.apply(restore)
                restored = api.request(project_path)
                require(restored['metadata']['uid'] == project_record['metadata']['uid'] and restored['spec'] == project_spec,
                        'Fixture project restoration mismatch')
                advance(values())
                wait(synced, 'valid replacement')
                access('pods', 200)
                checkpoint('replacement')
                leftover = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding',
                    'metadata': {'name': 'cloudlab-permissions-leftover', 'labels': {
                        'cloudlab.io/owner': 'permissions-platform', 'cloudlab.io/permission-profile': 'platform-engineer',
                        'cloudlab.io/permission-scope': 'cluster'}, 'annotations': {'argocd.argoproj.io/tracking-id':
                        admission_verify.permission_tracking('ClusterRoleBinding', 'cloudlab-permissions-leftover')}},
                    'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole',
                        'name': 'cloudlab-permissions-platform-engineer-cluster'},
                    'subjects': [{'kind': 'User', 'apiGroup': 'rbac.authorization.k8s.io', 'name': 'fixture-unused'}]}
                api.request(RBAC + '/clusterrolebindings', 'POST', leftover, expected=201, impersonate=CONTROLLER)
                advance(values(assignments=False, state='retired'))
                wait(synced, 'retired owner reconciliation')
                wait(lambda: api.absent(BINDING), 'retired binding absent')
                access('pods', 403)
                wait(lambda: not tracked_bindings(), 'all tracked catalog bindings absent')
                require(not api.absent(ROLE) and not api.absent(APPLICATION), 'Retired owner was removed')
                require(api.request(RBAC + '/clusterroles/' + collision['metadata']['name'])['metadata']['uid'] == state['collision_uid'],
                        'Foreign collision identity changed')
                api.request(RBAC + '/clusterroles/' + collision['metadata']['name'], 'DELETE',
                            {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': state['collision_uid']}})
                checkpoint('retired-inert-owner')
                save('complete')
                print(json.dumps({'status': 'passed', 'run': state['run'], 'checks': state['checks'],
                                  'cleanup': 'remove exact Compose project and volumes'}, sort_keys=True))
            finally:
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
