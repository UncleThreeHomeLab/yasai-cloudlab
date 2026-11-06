"""Synthetic activation inputs and bounded native Argo controller fixtures."""
import copy
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml


def first_binding_observation(*, patched=True, replicas=1):
    from playbooks.data.files import native
    from playbooks.argocd.files.private_activation import prepare
    public = {'repository': 'https://github.com/UncleThreeHomeLab/yasai-cloudlab.git',
        'identity': {'enabled': True}, 'data': {'configuration': {}}}
    target = {'valuesRepository': 'https://github.com/UncleThreeHomeLab/private.git', 'valuesRevision': 'a' * 40}
    original = {'repoURL': public['repository'], 'targetRevision': 'main', 'path': 'gitops/roots/public',
        'helm': {'releaseName': 'cloudlab-public-root', 'valuesObject': {'identity': {'enabled': True}}}}
    proposed = copy.deepcopy(original); proposed['helm']['valuesObject']['identity']['argo'] = target
    root = {'metadata': {'uid': 'root'}, 'spec': {'project': 'cloudlab-root', 'source': copy.deepcopy(proposed if patched else original),
        'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
        'ignoreDifferences': native.delegations(), 'syncPolicy': {'syncOptions': [
            'FailOnSharedResource=true', 'DisableClientSideApplyMigration=true', 'RespectIgnoreDifferences=true']}}}
    project = {'metadata': {'uid': 'project'}, 'spec': {'sourceRepos': [public['repository']],
        'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
        'clusterResourceWhitelist': [{'group': '', 'kind': 'Namespace'}],
        'namespaceResourceWhitelist': [{'group': 'argoproj.io', 'kind': kind} for kind in ('Application', 'AppProject', 'ApplicationSet')]
            + [{'group': 'external-secrets.io', 'kind': 'ExternalSecret'}]}}
    objects = {('application.argoproj.io', 'cloudlab-public-root'): root,
        ('appproject.argoproj.io', 'cloudlab-root'): project,
        ('statefulset', 'argocd-application-controller'): {'metadata': {'uid': 'controller'}, 'spec': {'replicas': replicas}}}
    binding = {'phase': 'resumed' if patched and replicas == 1 else 'paused', 'target': target, 'publicRevision': 'b' * 40,
        'root_uid': 'root', 'controller_uid': 'controller', 'project_uid': 'project',
        'originalSource': original, 'patchedSource': proposed,
        'privateActivation': prepare(public, target['valuesRepository'], target['valuesRevision'])}
    return public, objects, binding


def source_approval(public, repository, revision='d' * 40):
    receipt = {'version': 'cloudlab-private-source-acceptance/v1', 'consumer': 'private-sources',
        'revision': revision, 'nonce': '1' * 64}
    commitment = hashlib.sha256(('\n'.join([receipt['version'], receipt['consumer'], repository,
        'platform/sources.yaml', revision, receipt['nonce'], ''])).encode()).hexdigest()
    public['privateSources']['acceptanceCommitment'] = commitment
    return {'acceptanceCommitment': commitment, 'acceptedRevision': revision, 'acceptanceReceipt': receipt}


def private_policies(evidence):
    return {('validatingpolicy.policies.kyverno.io', name): {
        'metadata': {'uid': name + '-uid', 'generation': 2, 'annotations': {
            'argocd.argoproj.io/tracking-id': 'cloudlab-workload-policy:policies.kyverno.io/ValidatingPolicy:cloudlab-policy/' + name}},
        'spec': copy.deepcopy(spec), 'status': {'conditionStatus': {'ready': True, 'conditions': [
            {'type': 'WebhookConfigured', 'status': 'True'}, {'type': 'RBACPermissionsGranted', 'status': 'True'}]}}}
        for name, spec in evidence['policies'].items()}


def private_probe(evidence, document):
    rejected = (document['metadata']['labels']['cloudlab.io/owner'] == 'foreign' or
                (document['kind'] == 'Secret' and 'ownerReferences' not in document['metadata']))
    if not rejected: return 0, ''
    name = 'cloudlab-private-source-credentials' if document['kind'] == 'Secret' else 'cloudlab-private-source-ownership'
    message = evidence['policies'][name]['validations'][0]['message']
    return 1, 'admission webhook denied the request: ' + name + ': ' + message


def binding_fixture(required=True, *, repository='https://github.com/example/platform.git',
                    private_repository='https://github.com/example/private.git'):
    from service_activation import prepare
    from private_activation import prepare as prepare_private
    target = {'valuesRepository': private_repository, 'valuesRevision': 'b' * 40}
    public = {'repository': repository, 'services': {'enabled': required, 'revision': 'c' * 40}}
    evidence = prepare(public, target['valuesRepository'], target['valuesRevision'],
                       {'catalog': [], 'dataApprovals': {}} if required else None)
    objects = {
        ('application.argoproj.io', 'cloudlab-public-root'): {
            'metadata': {'uid': 'root', 'resourceVersion': '1'},
            'spec': {'project': 'cloudlab-root', 'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}, 'source': {'repoURL': repository,
                'targetRevision': 'main', 'path': 'gitops/roots/public',
                'helm': {'valuesObject': {'services': {'enabled': required}}}}}},
        ('statefulset', 'argocd-application-controller'): {'metadata': {'uid': 'controller'}, 'spec': {'replicas': 1}},
        ('appproject.argoproj.io', 'cloudlab-root'): {
            'metadata': {'uid': 'project', 'resourceVersion': '1'}, 'spec': {
                'sourceRepos': [repository],
                'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
                'clusterResourceWhitelist': [{'group': '', 'kind': 'Namespace'}],
                'namespaceResourceWhitelist': [{'group': 'argoproj.io', 'kind': kind}
                                               for kind in ('Application', 'AppProject', 'ApplicationSet')]}}}
    payload = {'repository': repository, 'branch': 'main', 'revision': 'a' * 40,
               'private_repository': target['valuesRepository'], 'argo': {'serviceActivation': evidence,
                   'accessActivation': access_evidence(repository, target),
                   'dataActivation': data_evidence(repository, target),
                   'privateActivation': prepare_private(public, target['valuesRepository'], target['valuesRevision'])}}
    original = copy.deepcopy(objects['application.argoproj.io', 'cloudlab-public-root']['spec']['source'])
    patched = copy.deepcopy(original)
    patched['helm']['valuesObject']['identity'] = {'enabled': True, 'argo': target}
    checkpoint = {'phase': 'source-updated', 'target': target, 'root_uid': 'root', 'controller_uid': 'controller',
                  'project_uid': 'project', 'originalSource': original, 'patchedSource': patched,
                  'serviceActivation': evidence, 'privateActivation': payload['argo']['privateActivation'],
                  'accessActivation': payload['argo']['accessActivation'],
                  'dataActivation': payload['argo']['dataActivation']}
    return objects, payload, target, checkpoint


def access_evidence(repository, target, administrator=None):
    import hashlib
    from access_activation import validate
    return validate({'required': False, 'enabled': True, 'repository': repository, 'revision': 'e' * 40,
        'private_repository': target['valuesRepository'], 'private_revision': target['valuesRevision'],
        'administratorHash': hashlib.sha256(administrator.encode()).hexdigest() if administrator is not None else None}, target)


def access_authority(repository):
    import hashlib
    import access_activation
    administrator = 'admin@example.invalid'
    receipt = {'phase': 'configured', 'application_uid': 'access-app',
               'administrator': hashlib.sha256(administrator.encode()).hexdigest()}
    objects = {('application.argoproj.io', access_activation.APP): {
        'metadata': {'uid': 'access-app', 'labels': {'cloudlab.io/owner': 'cloudlab-access-bootstrap'}},
        'spec': {'source': {'repoURL': repository, 'targetRevision': 'main', 'path': 'platform/connectivity/access'}}},
        ('clusterrolebinding.rbac.authorization.k8s.io', access_activation.BINDING): {
            'metadata': {'uid': 'access-binding', 'annotations': {'argocd.argoproj.io/tracking-id':
                access_activation.APP + ':rbac.authorization.k8s.io/ClusterRoleBinding:tailscale/' + access_activation.BINDING}},
            'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'cluster-admin'},
            'subjects': [{'kind': 'User', 'apiGroup': 'rbac.authorization.k8s.io', 'name': administrator}]}}
    return administrator, receipt, objects


def data_evidence(repository, target):
    from data_activation import validate
    return validate({'required': False, 'enabled': False, 'repository': repository,
        'revision': None, 'seaweedfsRevision': None, 'private_repository': target['valuesRepository'],
        'private_revision': target['valuesRevision'], 'settings': None,
        'absence': {'path': 'platform/data.yaml', 'revision': target['valuesRevision'], 'authenticated404': True}}, target)


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
    repositories = ('public.git', 'private.git')
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
        paths = {'/' + name + '/' + suffix for name in self.repositories
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
                path.write_bytes(value) if isinstance(value, bytes) else path.write_text(value)
        command(['git', 'add', '--all'], self.work)
        command(['git', 'commit', '--allow-empty', '-m', 'Synthetic permission declaration'], self.work)
        command(['git', 'push', 'origin', 'HEAD:refs/heads/main'], self.work)
        command(['git', 'update-server-info'], self.bare)
        self.revision = command(['git', 'rev-parse', 'HEAD'], self.work).strip()
        return self.revision


class NativeAPI:
    def __init__(self, directory, document, field_manager="native-argo-fixture", allowed_impersonation=None):
        self.field_manager = field_manager
        self.allowed_impersonation = allowed_impersonation
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


    def request(self, path, method='GET', value=None, token=None, expected=200, content_type=None, impersonate=None):
        require(path.startswith('/') and not path.startswith('//'), 'Invalid fixture API path')
        headers = {'Content-Type': 'application/json'}
        if method == 'PATCH': headers['Content-Type'] = 'application/apply-patch+yaml'
        if content_type: headers['Content-Type'] = content_type
        if token is not None: headers['Authorization'] = 'Bearer ' + token
        if impersonate is not None:
            require(self.allowed_impersonation is not None and impersonate == self.allowed_impersonation and token is None, 'Unsupported fixture impersonation')
            headers['Impersonate-User'] = impersonate
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
                 'AppProject': 'appprojects', 'ApplicationSet': 'applicationsets', 'ValidatingAdmissionPolicy': 'validatingadmissionpolicies',
                 'ValidatingAdmissionPolicyBinding': 'validatingadmissionpolicybindings'}
        require(kind in names, 'Unexpected fixture installation kind')
        cluster = kind in {'Namespace', 'ClusterRole', 'ClusterRoleBinding', 'CustomResourceDefinition',
                           'ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding'}
        prefix = '/api/v1' if version == 'v1' else '/apis/' + version
        if not cluster:
            obj['metadata'].setdefault('namespace', 'argocd')
            prefix += '/namespaces/' + obj['metadata']['namespace']
        return self.request(prefix + '/' + names[kind] + '/' + obj['metadata']['name'] +
                            '?fieldManager=' + self.field_manager + '&force=false', 'PATCH', obj,
                            expected=201 if self.absent(prefix + '/' + names[kind] + '/' + obj['metadata']['name']) else 200)


    def absent(self, path):
        try:
            self.request(path)
            return False
        except RuntimeError as error:
            if str(error) == 'Fixture API HTTP 404': return True
            raise


def install_argocd(api, directory, archive, lock_path, values_path, baseline_health=False):
    lock = json.loads(Path(lock_path).read_text())
    archive = Path(archive)
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == lock['chart']['sha256'], 'Argo chart checksum mismatch')
    config = yaml.safe_load(Path(values_path).read_text())['argo-cd']
    if baseline_health:
        config['configs']['cm'].pop('resource.customizations.health.argoproj.io_Application', None)
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
