"""Qualify native Argo RBAC convergence in a disposable local Kubernetes cluster.

This is a synthetic test chart, not a deployable permission catalog. The standalone
Compose file mounts only this driver and verified Argo inputs. Remove its exact
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

SOURCE = 'http://10.245.233.3:8000/'
NAMESPACE = 'permissions-fixture'
APPLICATION = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/permissions-proof'
RBAC = '/apis/rbac.authorization.k8s.io/v1'
BINDING = RBAC + '/namespaces/' + NAMESPACE + '/rolebindings/fixture-reader'
ROLE = RBAC + '/clusterroles/fixture-reader'
TRACKING = 'permissions-proof:rbac.authorization.k8s.io/RoleBinding:' + NAMESPACE + '/fixture-reader'
CHART = {
    'Chart.yaml': 'apiVersion: v2\nname: permissions-proof\nversion: 0.1.0\n',
    'values.yaml': '{}\n',
    'templates/rbac.yaml': '''{{- $p := required "permissions required" .Values.permissions -}}
{{- if not (hasKey $p "assignments") }}{{ fail "assignments required" }}{{ end -}}
{{- if not (has $p.state (list "active" "retired")) }}{{ fail "state required" }}{{ end -}}
{{- if and (eq $p.state "retired") $p.assignments }}{{ fail "retired must be empty" }}{{ end }}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fixture-reader
rules:
- apiGroups: [""]
  resources: {{ $p.resources | toJson }}
  verbs: [get, list]
{{ range $p.assignments }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: fixture-reader
  namespace: permissions-fixture
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ .role }}
subjects:
- kind: ServiceAccount
  name: reader
  namespace: permissions-fixture
{{ end }}
''',
}


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def git_backend(body, environment, timeout=15):
    """Bound native Git's input, output, lifetime and owned process group."""
    process = subprocess.Popen(['git', 'http-backend'], env=environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    output = bytearray()
    error_size = 0
    position = 0
    stop = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            if body:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while selector.get_map():
                remaining = stop - time.monotonic()
                require(remaining > 0, 'Fixture Git backend timed out')
                for key, _ in selector.select(min(remaining, 0.2)):
                    stream = key.fileobj
                    if stream is process.stdin:
                        position += os.write(stream.fileno(), body[position:position + 4096])
                        if position == len(body):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        chunk = os.read(stream.fileno(), 65536)
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                        elif stream is process.stdout:
                            output.extend(chunk)
                            require(len(output) <= 4 * 1024 * 1024, 'Fixture Git backend output exceeded bound')
                        else:
                            error_size += len(chunk)
                            require(error_size <= 65536, 'Fixture Git backend diagnostics exceeded bound')
            # Retain the leader's PID until group cleanup; reaping first permits
            # PID reuse before killpg and could target an unrelated process.
            while True:
                finished = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if finished is not None:
                    require(finished.si_code == os.CLD_EXITED and finished.si_status == 0, 'Fixture Git backend failed')
                    break
                require(time.monotonic() < stop, 'Fixture Git backend timed out')
                time.sleep(0.01)
        return bytes(output)
    finally:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed: stream.close()


class GitServer(http.server.ThreadingHTTPServer):
    """At most four fixture reads execute concurrently."""
    daemon_threads = False
    request_queue_size = 4

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(4)
        self.block_private = False
        super().__init__(address, handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


class ReadOnlyGit(http.server.BaseHTTPRequestHandler):
    """Expose only smart-HTTP upload-pack against two synthetic bare repositories."""
    def __init__(self, *args, directory, **kwargs):
        self.directory = Path(directory).resolve()
        super().__init__(*args, **kwargs)

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.read_git()

    def do_POST(self):
        self.read_git()

    def read_git(self):
        parsed = urllib.parse.urlsplit(self.path)
        paths = {'/' + name + '/' + suffix for name in ('public.git', 'private.git')
                 for suffix in ('info/refs', 'git-upload-pack')}
        path = self.directory / parsed.path.lstrip('/')
        if (parsed.path not in paths or parsed.fragment or parsed.scheme or parsed.netloc or
            not path.resolve().is_relative_to(self.directory) or
            any(parent.is_symlink() for parent in (path, *path.parents)) or
            self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding')):
            self.send_error(403)
            return
        if self.server.block_private and parsed.path.startswith('/private.git/'):
            self.send_error(503)
            return
        valid = ((self.command == 'GET' and parsed.path.endswith('/info/refs') and
                  parsed.query == 'service=git-upload-pack' and not self.headers.get('Content-Length')) or
                 (self.command == 'POST' and parsed.path.endswith('/git-upload-pack') and not parsed.query and
                  self.headers.get('Content-Type') == 'application/x-git-upload-pack-request'))
        length = self.headers.get('Content-Length', '0')
        if not valid or not length.isdecimal() or int(length) > 1024 * 1024 or (self.command == 'POST' and int(length) == 0):
            self.send_error(403)
            return
        try:
            body = self.rfile.read(int(length))
            require(len(body) == int(length), 'Incomplete fixture Git request')
            environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'GIT_PROJECT_ROOT': str(self.directory),
                'GIT_HTTP_EXPORT_ALL': '1', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                'REQUEST_METHOD': self.command, 'PATH_INFO': parsed.path, 'QUERY_STRING': parsed.query,
                'CONTENT_TYPE': self.headers.get('Content-Type', ''), 'CONTENT_LENGTH': str(len(body))}
            result = git_backend(body, environment)
            headers, separator, content = result.partition(b'\r\n\r\n')
            require(separator and len(headers) <= 4096, 'Malformed fixture Git response')
            response_headers = dict(line.decode('ascii').split(': ', 1) for line in headers.split(b'\r\n'))
            content_type = response_headers.get('Content-Type')
            require(content_type in ('application/x-git-upload-pack-advertisement', 'application/x-git-upload-pack-result')
                    and response_headers.get('Status', '200 OK') == '200 OK', 'Unexpected fixture Git response')
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_error(502)


def command(arguments, cwd=None):
    result = subprocess.run(arguments, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=90, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 8 * 1024 * 1024,
            'Fixture subprocess failed; output withheld')
    return result.stdout.decode()


class GitSource:
    def __init__(self, root, name, files):
        self.work = root / (name + '-work')
        self.bare = root / (name + '.git')
        self.work.mkdir()
        command(['git', 'init', '-b', 'main', str(self.work)])
        command(['git', 'config', 'user.email', 'fixture@example.invalid'], self.work)
        command(['git', 'config', 'user.name', 'Disposable permission fixture'], self.work)
        command(['git', 'init', '--bare', str(self.bare)])
        command(['git', 'remote', 'add', 'origin', str(self.bare)], self.work)
        self.commit(files)

    def commit(self, files):
        for name, value in files.items():
            path = self.work / name
            require(path.resolve().is_relative_to(self.work.resolve()), 'Unsafe fixture source path')
            if value is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
        command(['git', 'add', '--all'], self.work)
        command(['git', 'commit', '--allow-empty', '-m', 'Synthetic permission declaration'], self.work)
        command(['git', 'push', 'origin', 'HEAD:refs/heads/main'], self.work)
        command(['git', 'update-server-info'], self.bare)
        self.revision = command(['git', 'rev-parse', 'HEAD'], self.work).strip()
        return self.revision


class API:
    def __init__(self, directory, document):
        user = document['users'][0]['user']
        authority = document['clusters'][0]['cluster']
        for name, data in [('ca', authority['certificate-authority-data']),
                           ('cert', user['client-certificate-data']), ('key', user['client-key-data'])]:
            path = directory / name
            path.write_bytes(base64.b64decode(data, validate=True))
            path.chmod(0o600)
        self.context = ssl.create_default_context(cafile=str(directory / 'ca'))
        self.client = ssl.create_default_context(cafile=str(directory / 'ca'))
        self.context.load_cert_chain(str(directory / 'cert'), str(directory / 'key'))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPSHandler(context=self.context))
        self.client_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                        urllib.request.HTTPSHandler(context=self.client))

    def request(self, path, method='GET', value=None, token=None, expected=200, content_type=None):
        require(path.startswith('/') and not path.startswith('//'), 'Invalid fixture API path')
        headers = {'Content-Type': 'application/json'}
        if method == 'PATCH': headers['Content-Type'] = 'application/apply-patch+yaml'
        if content_type: headers['Content-Type'] = content_type
        if token is not None: headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request('https://cluster:6443' + path, method=method,
                    data=json.dumps(value).encode() if value is not None else None, headers=headers)
        opener = self.client_opener if token is not None else self.opener
        try:
            with opener.open(request, timeout=15) as response:
                require(response.status == expected, 'Unexpected fixture API success status')
                body = response.read(8 * 1024 * 1024 + 1)
                require(len(body) <= 8 * 1024 * 1024, 'Fixture API response exceeded bound')
                return json.loads(body)
        except urllib.error.HTTPError as error:
            if error.code == expected: return {'expectedStatus': expected}
            raise RuntimeError('Fixture API HTTP ' + str(error.code)) from None

    def apply(self, obj):
        version, kind = obj['apiVersion'], obj['kind']
        names = {'Namespace': 'namespaces', 'ConfigMap': 'configmaps', 'Secret': 'secrets',
                 'ServiceAccount': 'serviceaccounts', 'Service': 'services', 'Role': 'roles',
                 'RoleBinding': 'rolebindings', 'ClusterRole': 'clusterroles', 'ClusterRoleBinding': 'clusterrolebindings',
                 'Deployment': 'deployments', 'StatefulSet': 'statefulsets', 'Job': 'jobs',
                 'CustomResourceDefinition': 'customresourcedefinitions', 'Application': 'applications',
                 'AppProject': 'appprojects'}
        require(kind in names, 'Unexpected fixture installation kind')
        cluster = kind in {'Namespace', 'ClusterRole', 'ClusterRoleBinding', 'CustomResourceDefinition'}
        prefix = '/api/v1' if version == 'v1' else '/apis/' + version
        if not cluster:
            obj['metadata'].setdefault('namespace', 'argocd')
            prefix += '/namespaces/' + obj['metadata']['namespace']
        return self.request(prefix + '/' + names[kind] + '/' + obj['metadata']['name'] +
                            '?fieldManager=permissions-fixture&force=false', 'PATCH', obj,
                            expected=201 if self.absent(prefix + '/' + names[kind] + '/' + obj['metadata']['name']) else 200)

    def absent(self, path):
        try:
            self.request(path)
            return False
        except RuntimeError as error:
            if str(error) == 'Fixture API HTTP 404': return True
            raise


def values(resources=('pods', 'services'), assignments=True, state='active', role='fixture-reader'):
    return yaml.safe_dump({'permissions': {'state': state, 'resources': list(resources),
                           'assignments': [{'role': role}] if assignments else []}})


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
    lock = json.loads(Path('/inputs/artifact.lock.json').read_text())
    archive = Path('/inputs/argo-cd-10.9.6.tgz')
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == lock['chart']['sha256'], 'Argo chart checksum mismatch')
    config = yaml.safe_load(Path('/inputs/values.yaml').read_text())['argo-cd']
    config['server']['replicas'] = 0
    config['applicationSet']['replicas'] = 0
    config['redisSecretInit']['enabled'] = False
    config['configs']['cm']['timeout.reconciliation'] = '5s'
    config['configs']['cm']['timeout.reconciliation.jitter'] = '0s'
    config['controller']['resources'] = {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'memory': '1Gi'}}
    path = directory / 'argo-values.yaml'
    path.write_text(yaml.safe_dump(config))
    rendered = command(['helm', 'template', 'argocd', str(archive), '--namespace', 'argocd',
                        '--include-crds', '--values', str(path), '--kube-version', lock['kube_version']])
    documents = [obj for obj in yaml.safe_load_all(rendered) if obj]
    running = {obj['metadata']['name'] for obj in documents if obj['kind'] in ('Deployment', 'StatefulSet')
               and obj['spec'].get('replicas', 1) > 0}
    require(running == {'argocd-repo-server', 'argocd-redis', 'argocd-application-controller'},
            'Unexpected active fixture controller')
    images = {container['image'] for obj in documents for container in
              obj.get('spec', {}).get('template', {}).get('spec', {}).get('containers', []) +
              obj.get('spec', {}).get('template', {}).get('spec', {}).get('initContainers', [])}
    expected = {image + '@' + digest for image, digest in lock['images'].items()}
    require(images and images <= expected, 'Unpinned fixture controller image')
    api.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'argocd'}})
    api.apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'argocd-redis', 'namespace': 'argocd'},
               'stringData': {'auth': secrets.token_urlsafe(32)}})
    for obj in documents:
        if obj['kind'] == 'CustomResourceDefinition': api.apply(obj)
    for obj in documents:
        if obj['kind'] != 'CustomResourceDefinition': api.apply(obj)
    return images


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
            api.apply({'apiVersion': 'v1', 'kind': 'ServiceAccount',
                       'metadata': {'name': 'reader', 'namespace': NAMESPACE}, 'automountServiceAccountToken': False})
            recovery = api.apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding',
               'metadata': {'name': 'fixture-recovery'}, 'roleRef': {'apiGroup': 'rbac.authorization.k8s.io',
               'kind': 'ClusterRole', 'name': 'cluster-admin'}, 'subjects': [{'kind': 'User', 'name': 'fixture-recovery'}]})
            recovery_spec = {key: recovery[key] for key in ('roleRef', 'subjects')}
            state['recovery_uid'] = recovery['metadata']['uid']
            sources = directory / 'sources'
            sources.mkdir()
            public = GitSource(sources, 'public', {'chart/' + key: value for key, value in CHART.items()})
            private = GitSource(sources, 'private', {'permissions.yaml': values()})
            state['public_revision'] = public.revision
            state['private_revision'] = private.revision
            handler = functools.partial(ReadOnlyGit, directory=str(sources))
            server = GitServer(('0.0.0.0', 8000), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                save('initial-native-sync')
                command(['git', 'ls-remote', SOURCE + 'public.git', 'refs/heads/main'])
                project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
                    'metadata': {'name': 'permissions-proof', 'namespace': 'argocd'}, 'spec': {
                    'sourceRepos': [SOURCE + 'public.git', SOURCE + 'private.git'],
                    'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE}],
                    'clusterResourceWhitelist': [{'group': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole'}],
                    'namespaceResourceWhitelist': [{'group': 'rbac.authorization.k8s.io', 'kind': 'RoleBinding'}]}}
                project_record = api.apply(project)
                project_spec = copy.deepcopy(project_record['spec'])
                project_path = '/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/permissions-proof'
                api.apply({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
                    'metadata': {'name': 'permissions-proof', 'namespace': 'argocd'}, 'spec': {
                    'project': 'permissions-proof', 'sources': [
                    {'repoURL': SOURCE + 'public.git', 'targetRevision': public.revision, 'path': 'chart',
                     'helm': {'valueFiles': ['$values/permissions.yaml']}},
                    {'repoURL': SOURCE + 'private.git', 'targetRevision': 'main', 'ref': 'values'}],
                    'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
                    'syncPolicy': {'automated': {'prune': True, 'selfHeal': True, 'allowEmpty': True},
                                   'retry': {'limit': 1, 'backoff': {'duration': '1s', 'factor': 1, 'maxDuration': '2s'}},
                                   'syncOptions': ['FailOnSharedResource=true']}}})
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

                def checkpoint(label):
                    current = api.request(RBAC + '/clusterrolebindings/fixture-recovery')
                    require(current['metadata']['uid'] == state['recovery_uid'] and
                            all(current[key] == value for key, value in recovery_spec.items()),
                            'Independent recovery binding changed')
                    state['checks'].append(label)
                    save(label)

                wait(synced, 'initial native multi-source reconciliation')
                require(api.request(BINDING)['metadata']['annotations'].get('argocd.argoproj.io/tracking-id') == TRACKING,
                        'Native binding ownership mismatch')
                access('pods', 200)
                access('services', 200)
                access('secrets', 403)
                api.request('/api/v1/namespaces/default/pods', token=token(), expected=403)
                checkpoint('create-and-real-token-authentication')
                advance(values(resources=('pods',)))
                wait(synced, 'native narrowing')
                access('pods', 200)
                wait(lambda: access('services', 403), 'narrowed authorization')
                checkpoint('narrowing')
                role = api.request(ROLE)
                role['rules'] = [{'apiGroups': [''], 'resources': ['pods', 'services'], 'verbs': ['get', 'list']}]
                api.request(ROLE, 'PUT', role)
                wait(lambda: api.request(ROLE)['rules'][0]['resources'] == ['pods'], 'native drift repair')
                wait(lambda: access('services', 403), 'repaired authorization')
                checkpoint('drift-repair')
                for label, content in [('invalid-source', 'permissions: [invalid]\n'), ('missing-source', None)]:
                    advance(content)
                    wait(lambda: any(c.get('type') == 'ComparisonError' for c in
                         api.request(APPLICATION).get('status', {}).get('conditions', [])), label)
                    require(not api.absent(BINDING), 'Invalid source removed prior binding')
                    access('pods', 200)
                    checkpoint(label + '-retains-grants')
                    # Clear the observed failure at an exact successful revision
                    # before inducing another failure; stale errors never count.
                    advance(values(resources=('pods',)))
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
                advance(values(resources=('pods',), assignments=False))
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
                advance(values(resources=('pods',)))
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
                advance(values(resources=('pods',)))
                wait(synced, 'valid replacement')
                access('pods', 200)
                checkpoint('replacement')
                advance(values(resources=('pods',), assignments=False, state='retired'))
                wait(synced, 'retired owner reconciliation')
                wait(lambda: api.absent(BINDING), 'retired binding absent')
                access('pods', 403)
                bindings = api.request(RBAC + '/namespaces/' + NAMESPACE + '/rolebindings')['items']
                require(not bindings, 'Retired owner left binding grants')
                require(not api.absent(ROLE) and not api.absent(APPLICATION), 'Retired owner was removed')
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
