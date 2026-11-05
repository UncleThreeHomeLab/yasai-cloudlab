"""Actual six-chart local qualification; static local volumes are explicitly NON-CSI."""
import base64
import copy
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile
import threading
import time

import yaml

from playbooks.argocd.tests.fixtures import (
    GitServer, GitSource, NativeAPI, ReadOnlyGit, command, install_argocd, require)
from playbooks.argocd.files.render import images
from playbooks.observability.tests.lifecycle_dns import (
    GRAFANA_HOST, ISSUER, KIALI_HOST, LOGIN_HOST, ZONE,
    diagnostic_code, diagnostic_config, digest as dns_digest, log_records, matrix_ready,
    pod_identity, read_logs, same_execution_source, update_gate)

ROOT = Path('/workspace')
PUBLIC = 'https://github.com/cloudlab-fixtures/observability-public.git'
PRIVATE = 'https://github.com/cloudlab-fixtures/observability-private.git'
INTERNAL = 'http://10.245.239.3:8000/'
OWNER = INTERNAL + 'owner.git'
APPS = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/'
NS = 'cloudlab-observability'
PARENT = 'cloudlab-observability-gitops'
CHILDREN = ('cloudlab-observability', 'cloudlab-prometheus', 'cloudlab-loki',
            'cloudlab-tempo', 'cloudlab-alloy', 'cloudlab-kiali')
ALLOWED_KINDS = set(('Namespace ConfigMap Secret ServiceAccount Service Role RoleBinding ClusterRole '
    'ClusterRoleBinding Deployment StatefulSet DaemonSet Job PodDisruptionBudget '
    'CustomResourceDefinition Application AppProject ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding '
    'ValidatingWebhookConfiguration MutatingWebhookConfiguration PeerAuthentication Gateway GatewayClass HTTPRoute '
    'ClusterSecretStore ExternalSecret NetworkPolicy PersistentVolume').split())


class StackAPI(NativeAPI):
    """Fixture-only discovery for native prerequisite kinds; never writes status."""
    def apply(self, obj, namespace='argocd'):
        require(obj['kind'] in ALLOWED_KINDS and 'status' not in obj, 'Unsupported fixture prerequisite')
        version = obj['apiVersion']
        prefix = '/api/v1' if version == 'v1' else '/apis/' + version
        resources = self.request(prefix)['resources']
        resource = next(r for r in resources if r['kind'] == obj['kind'] and '/' not in r['name'])
        if resource['namespaced']:
            obj['metadata'].setdefault('namespace', namespace)
            prefix += '/namespaces/' + obj['metadata']['namespace']
        path = prefix + '/' + resource['name'] + '/' + obj['metadata']['name']
        return self.request(path + '?fieldManager=observability-stack-fixture&force=false', 'PATCH', obj,
                            expected=201 if self.absent(path) else 200)


class ObservedGit(ReadOnlyGit):
    repositories = ('public.git', 'private.git', 'owner.git')

    def read_git(self):
        with self.server.observation_lock:
            require(len(self.server.observations) < 2000, 'Fixture Git observation bound exceeded')
            self.server.observations.append((self.command, self.path))
        super().read_git()


def helm(path, values, namespace='argocd', name='fixture'):
    arguments = ['helm', 'template', name, str(ROOT / path), '--namespace', namespace,
                 '--kube-version', '1.36.5', '--include-crds']
    if (ROOT / path / 'values.json').is_file():
        arguments += ['--values', str(ROOT / path / 'values.json')]
    result = subprocess.run(arguments + ['--values', '-'], input=yaml.safe_dump(values),
        capture_output=True, text=True, timeout=90)
    require(result.returncode == 0 and len(result.stdout) <= 8 * 1024 * 1024,
            'Native fixture chart render failed; output withheld')
    return [obj for obj in yaml.safe_load_all(result.stdout) if obj]


def git_files(ca):
    files = {p.relative_to(ROOT).as_posix(): p.read_bytes()
            for directory in ('platform/observability', 'gitops/roots/public')
            for p in (ROOT / directory).rglob('*') if p.is_file()}
    path = 'platform/observability/kiali/templates/fixture-issuer-ca.yaml'
    require(path not in files and isinstance(ca, str) and len(ca) < 16384
            and re.fullmatch(r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n', ca),
            'Fixture supplement requires only one public CA certificate')
    try:
        ssl.create_default_context(cadata=ca)
    except (ssl.SSLError, ValueError):
        raise RuntimeError('Fixture supplement contains an invalid public CA certificate') from None
    files[path] = yaml.safe_dump({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
        'name': 'cloudlab-kiali-cabundle', 'namespace': NS,
        'annotations': {'argocd.argoproj.io/sync-wave': '-1'}}, 'data': {'openid-server-ca.crt': ca}}).encode()
    return files


def pinned_images(objects, allowed):
    def identity(reference):
        require(re.fullmatch(r'[^@]+@sha256:[a-f0-9]{64}', reference) is not None,
                'Fixture workload image is not digest-pinned')
        location, digest = reference.rsplit('@', 1)
        prefix, slash, name = location.rpartition('/')
        return prefix + slash + name.split(':', 1)[0], digest
    expected = {identity(reference) for reference in allowed}
    require({identity(reference) for reference in images(objects)} <= expected,
            'Fixture workload image repository or digest differs from existing pins')


def source_guard(app, public_revision, private_revision):
    sources = app['spec'].get('sources', [app['spec'].get('source')])
    expected_urls = [PUBLIC, PRIVATE] if 'sources' in app['spec'] else [PUBLIC]
    require([s.get('repoURL') for s in sources if s] == expected_urls, 'Parent/child declared source roles changed')
    for source in sources:
        require(source and source['repoURL'] in (PUBLIC, PRIVATE), 'Declared source URL changed')
        expected = public_revision if source['repoURL'] == PUBLIC else private_revision
        require(re.fullmatch('[a-f0-9]{40}', source['targetRevision']) is not None
                and source['targetRevision'] == expected, 'Declared source is not the full fixture SHA')
    if app['metadata']['name'] in CHILDREN:
        name = app['metadata']['name']
        path = 'platform/observability' + ('' if name == 'cloudlab-observability' else '/' + name.removeprefix('cloudlab-'))
        require(sources[0]['path'] == path, 'Actual child chart path changed')


def parent_objects(public_revision, private_revision):
    values = {'repository': PUBLIC, 'identity': {'argo': {'valuesRepository': PRIVATE,
        'valuesRevision': private_revision}}, 'observability': {'configuration': {
            'enabled': True, 'paused': False, 'revision': public_revision}}}
    objects = helm('gitops/roots/public', values)
    parent = next(o for o in objects if o['kind'] == 'Application' and o['metadata']['name'] == PARENT)
    # Fixture adaptation only: public-root's private main binding is a separate C2 gate.
    parent['spec']['sources'][1]['targetRevision'] = private_revision
    source_guard(parent, public_revision, private_revision)
    require(parent['spec']['sources'][0]['path'] == 'platform/observability/gitops'
            and parent['spec']['sources'][0]['helm']['valueFiles'] == [
                '$values/services/catalog.json', '$values/platform/observability.yaml'], 'Actual parent chart path changed')
    projects = [o for o in objects if o['kind'] == 'AppProject' and o['metadata']['name'] in (PARENT, 'cloudlab-observability')]
    return parent, projects


def repo_values():
    values = yaml.safe_load((ROOT / 'platform/delivery/argocd/values.yaml').read_text())
    values['kialiBackendObserver'] = True
    repo = values['argo-cd']['repoServer']
    repo.setdefault('env', []).append({'name': 'GIT_CONFIG_GLOBAL', 'value': '/fixture/gitconfig'})
    repo['podLabels'] = {'cloudlab.io/restricted-git': 'true'}
    repo['volumes'] = [{'name': 'fixture-git', 'configMap': {'name': 'fixture-git'}}]
    repo['volumeMounts'] = [{'name': 'fixture-git', 'mountPath': '/fixture', 'readOnly': True}]
    require(not any(e['name'] == 'GIT_CONFIG_COUNT' for e in repo['env']), 'Unsupported Git environment transport')
    values['argo-cd']['controller'].setdefault('extraArgs', []).append('--persist-resource-health')
    return values


def kiali_observer():
    template = ROOT / 'platform/delivery/argocd/templates/kiali.yaml'
    require(hashlib.sha256(template.read_bytes()).hexdigest() ==
            '534d4230499094a98038d347e85c8ddb2dc2bcf2714a80baa24965eb994b46ba',
            'Canonical Argo backend observer changed')
    objects = [obj for obj in helm('platform/delivery/argocd', repo_values(), name='argocd')
               if obj['metadata']['name'] == 'kiali-backend-observer']
    expected = [([''], ['configmaps', 'pods', 'replicationcontrollers', 'services']),
                (['apps'], ['daemonsets', 'deployments', 'replicasets', 'statefulsets']),
                (['batch'], ['cronjobs', 'jobs']),
                (['networking.istio.io', 'security.istio.io', 'extensions.istio.io', 'telemetry.istio.io',
                  'inference.networking.k8s.io'], ['*']),
                (['gateway.networking.k8s.io'], ['gateways', 'grpcroutes', 'httproutes', 'referencegrants',
                                               'tcproutes', 'tlsroutes', 'udproutes'])]
    require(len(objects) == 2 and {o['kind'] for o in objects} == {'Role', 'RoleBinding'}
            and all(o['apiVersion'] == 'rbac.authorization.k8s.io/v1'
                    and o['metadata'] == {'name': 'kiali-backend-observer', 'namespace': 'argocd'} for o in objects),
            'Unexpected Argo backend observer objects')
    role = next(o for o in objects if o['kind'] == 'Role')
    binding = next(o for o in objects if o['kind'] == 'RoleBinding')
    require(set(role) == {'apiVersion', 'kind', 'metadata', 'rules'} and role['rules'] == [
        {'apiGroups': groups, 'resources': resources, 'verbs': ['get', 'list', 'watch']} for groups, resources in expected]
        and set(binding) == {'apiVersion', 'kind', 'metadata', 'roleRef', 'subjects'}
        and binding['roleRef'] == {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'kiali-backend-observer'}
        and binding['subjects'] == [{'kind': 'ServiceAccount', 'name': 'cloudlab-kiali', 'namespace': NS}],
        'Argo backend observer authority differs from canonical scope')
    return objects


def kiali_configuration(objects):
    configs = [o for o in objects
               if o['kind'] == 'ConfigMap' and o['metadata'].get('name') == 'cloudlab-kiali'
               and o['metadata'].get('namespace') == NS]
    routes = [o for o in objects if o['kind'] == 'HTTPRoute' and o['metadata'].get('name') == 'kiali'
              and o['metadata'].get('namespace') == NS]
    require(len(configs) == 1 and len(routes) == 1, 'Kiali fixture configuration is ambiguous')
    require(isinstance(configs[0].get('data'), dict) and isinstance(configs[0]['data'].get('config.yaml'), str),
            'Kiali fixture configuration payload is missing')
    config = yaml.safe_load(configs[0]['data']['config.yaml'])
    server, auth = config['server'], config['auth']['openid']
    # Absent fields retain the pinned Kiali application's OpenID defaults.
    require(server.get('web_root') == '/kiali' and server.get('web_fqdn') == KIALI_HOST
            and server.get('web_schema') == 'https' and str(server.get('web_port')) == '443'
            and auth.get('client_id') == 'kiali' and auth.get('issuer_uri') == ISSUER
            and auth.get('additional_request_params', {}) == {}
            and auth.get('scopes', ['openid', 'profile', 'email']) == ['openid', 'profile', 'email']
            and routes[0]['spec']['hostnames'] == [KIALI_HOST]
            and routes[0]['spec']['rules'][0]['matches'] == [{'path': {'type': 'PathPrefix', 'value': '/'}}],
            'Kiali fixture canonical root or OpenID configuration changed')


def python_image():
    image = next(line.split()[1] for line in (ROOT / 'ansible/runner/Dockerfile').read_text().splitlines()
                 if line.startswith('FROM python:'))
    require('@sha256:' in image, 'Fixture Python image must reuse the existing pinned runner base')
    return image


def fixture_mesh_values(component):
    canonical = json.loads((ROOT / 'platform/connectivity/istio' / component / 'values.json').read_text())
    values = copy.deepcopy(canonical)
    if component == 'cni':
        # Legacy descope runs after profiles; Docker K3s searches /bin.
        values['cni'].setdefault('cni', {})['cniBinDir'] = '/bin'
    return values


def owner_application():
    project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
        'metadata': {'name': 'fixture-observability-owner', 'namespace': 'argocd'}, 'spec': {
            'sourceRepos': [OWNER], 'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
            'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [{'group': 'argoproj.io', 'kind': 'Application'}]}}
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': 'fixture-observability-owner', 'namespace': 'argocd'}, 'spec': {
            'project': 'fixture-observability-owner', 'source': {'repoURL': OWNER, 'targetRevision': 'main', 'path': 'parent'},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True},
                           'retry': {'limit': 3, 'backoff': {'duration': '2s', 'factor': 2, 'maxDuration': '10s'}}}}}
    return project, app


def denied_github_job():
    code = ('import socket\n'
        'addresses=socket.getaddrinfo("github.com",443,family=socket.AF_INET,type=socket.SOCK_STREAM)\n'
        'assert addresses\n'
        'for address in sorted({entry[4][0] for entry in addresses})[:2]:\n'
        ' try: connection=socket.create_connection((address,443),timeout=4)\n'
        ' except OSError: continue\n'
        ' else: connection.close(); raise SystemExit(1)\n')
    compile(code, 'fixture-deny-github.py', 'exec')
    return {'apiVersion': 'batch/v1', 'kind': 'Job', 'metadata': {'name': 'fixture-deny-github', 'namespace': 'argocd'},
        'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': 150, 'template': {
            'metadata': {'labels': {'cloudlab.io/restricted-git': 'true'}}, 'spec': {
                'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'seccompProfile': {'type': 'RuntimeDefault'}},
                'containers': [{'name': 'deny', 'image': python_image(), 'command': ['python', '-c', code],
                    'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                                        'capabilities': {'drop': ['ALL']}},
                    'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '128Mi'}}}]}}}}


def issuer_probe_code():
    return 'issuer=' + repr(ISSUER) + '\n' + '''import json,socket,ssl,time,urllib.error,urllib.request
try:
 context=ssl.create_default_context(cafile="/fixture/ca.crt")
except Exception:
 print("issuer-probe stage=local-ca failure=local-ca",flush=True)
 raise SystemExit(1)
for attempt in range(45):
 stage="request"
 try:
  response=urllib.request.urlopen(issuer+"/.well-known/openid-configuration",context=context,timeout=3)
  stage="payload"
  assert json.load(response)["issuer"]==issuer
  break
 except Exception as error:
  if attempt==44:
   reason=error.reason if isinstance(error,urllib.error.URLError) else error
   if stage=="payload": category="payload"
   elif isinstance(error,urllib.error.HTTPError): category="http-status"
   elif isinstance(reason,socket.gaierror): category="dns"
   elif isinstance(reason,TimeoutError): category="timeout"
   elif isinstance(reason,ssl.SSLError): category="tls-verify-or-handshake"
   elif isinstance(reason,OSError): category="connect"
   else: category="unknown"
   print("issuer-probe stage="+stage+" failure="+category,flush=True)
   raise SystemExit(1)
  time.sleep(2)
'''


def kiali_probe_code():
    return ('issuer=' + repr(ISSUER) + '\nkiali_host=' + repr(KIALI_HOST) + '\n' + '''import http.cookies,re,ssl,urllib.error,urllib.parse,urllib.request
def validate_redirect(status,headers):
 assert status==302,"unexpected-status"
 fields=list(headers.items())
 assert len(fields)<=32 and sum(len(key)+len(value) for key,value in fields)<=16384,"header-bound"
 for value in headers.get_all("Set-Cookie",[]):
  assert len(value)<=4096 and "\\r" not in value and "\\n" not in value,"cookie-bound"
  cookie=http.cookies.SimpleCookie(); cookie.load(value)
  assert cookie and all(0<len(item.value)<=2048 for item in cookie.values()),"cookie-shape"
 locations=headers.get_all("Location",[])
 assert len(locations)==1,"location-cardinality"
 location=locations[0]
 assert 0<len(location)<=4096 and all(32<ord(c)<127 for c in location) and "#" not in location,"location-shape"
 target=urllib.parse.urlsplit(location)
 expected=urllib.parse.urlsplit(issuer+"/auth")
 assert (target.scheme,target.hostname,443 if target.port is None else target.port,target.path)==(expected.scheme,expected.hostname,443,expected.path),"location-target"
 assert target.username is None and target.password is None and not target.fragment,"location-authority"
 pairs=urllib.parse.parse_qsl(target.query,keep_blank_values=True,strict_parsing=True,max_num_fields=8)
 keys={"client_id","response_type","redirect_uri","scope","nonce","state","code_challenge","code_challenge_method"}
 assert len(pairs)==8 and {key for key,value in pairs}==keys,"query-keys"
 query=dict(pairs)
 assert query["client_id"]=="kiali" and query["response_type"]=="code","client-flow"
 assert query["redirect_uri"]=="https://"+kiali_host+"/kiali","callback"
 assert query["scope"]=="openid profile email","scopes"
 assert all(0<len(query[key])<=2048 and all(32<ord(c)<127 for c in query[key]) for key in ("nonce","state")),"opaque-state"
 assert query["code_challenge_method"]=="S256" and re.fullmatch(r"[A-Za-z0-9_-]{43}",query["code_challenge"]),"pkce"
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
try:
 context=ssl.create_default_context(cafile="/fixture/ca.crt")
 opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=context))
 try:
  response=opener.open("https://"+kiali_host+"/kiali/api/auth/openid_redirect",timeout=3)
 except urllib.error.HTTPError as response:
  validate_redirect(response.code,response.headers)
 else:
  validate_redirect(response.status,response.headers)
except Exception:
 print("kiali-openid-redirect failure=verification",flush=True)
 raise SystemExit(1)
print("kiali-openid-redirect result=passed",flush=True)
''')


class Qualification:
    def __init__(self):
        require(os.environ.get('FIXTURE_PROJECT', '').startswith('obs-lifecycle-stack-'), 'Use an isolated stack project')
        self.deadline = time.monotonic() + 3600
        self.api = None
        self.pvs = {}

    def wait(self, predicate, label, seconds=300, *, fatal=False):
        print('Waiting: ' + label, flush=True)
        stop = min(self.deadline, time.monotonic() + seconds)
        last_type = None
        while time.monotonic() < stop:
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, ValueError, RuntimeError, StopIteration) as error:
                if fatal: raise
                last_type = type(error).__name__
            time.sleep(2)
        raise RuntimeError('Fixture timed out: ' + label + (' (' + last_type + ')' if last_type else ''))

    def apply_all(self, objects, namespace):
        for obj in objects:
            if obj['kind'] == 'CustomResourceDefinition':
                self.api.apply(obj, namespace)
        names = [o['metadata']['name'] for o in objects if o['kind'] == 'CustomResourceDefinition']
        if names:
            self.wait(lambda: all(any(c['type'] == 'Established' and c['status'] == 'True' for c in
                self.api.request('/apis/apiextensions.k8s.io/v1/customresourcedefinitions/' + name)
                    .get('status', {}).get('conditions', [])) for name in names), 'prerequisite CRDs established')
        for obj in objects:
            if obj['kind'] != 'CustomResourceDefinition':
                self.api.apply(obj, namespace)

    def pinned_chart(self, path, namespace, wrapper=False):
        base = ROOT / path
        lock = json.loads((base / 'artifact.lock.json').read_text())
        archive = base / lock['archive']
        require(hashlib.sha256(archive.read_bytes()).hexdigest() == lock['sha256'], 'Prerequisite chart checksum changed')
        values = json.loads((base / 'values.json').read_text())
        if not wrapper:
            values = values[yaml.safe_load((base / 'Chart.yaml').read_text())['dependencies'][0]['name']]
        return archive, values

    def controller_ready(self):
        return all(self.api.request('/apis/apps/v1/namespaces/argocd/' + kind + '/' + name)
            .get('status', {}).get('readyReplicas') == 1 for kind, name in
            [('deployments', 'argocd-repo-server'), ('deployments', 'argocd-redis'),
             ('statefulsets', 'argocd-application-controller')])

    def transport(self, directory, public, private, server):
        api = self.api
        api.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'argocd'}})
        config = '\n'.join('[url "' + INTERNAL + name + '.git"]\n\tinsteadOf = ' + url
                           for name, url in [('public', PUBLIC), ('private', PRIVATE)]) + '\n'
        api.apply({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'fixture-git', 'namespace': 'argocd'},
                   'data': {'gitconfig': config}})
        api.apply({'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': {'name': 'fixture-repo-egress', 'namespace': 'argocd'}, 'spec': {
                'podSelector': {'matchLabels': {'cloudlab.io/restricted-git': 'true'}}, 'policyTypes': ['Egress'],
                'egress': [{'to': [{'ipBlock': {'cidr': '10.245.239.3/32'}}], 'ports': [{'protocol': 'TCP', 'port': 8000}]},
                    {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                             'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
                     'ports': [{'protocol': 'UDP', 'port': 53}, {'protocol': 'TCP', 'port': 53}]},
                    {'to': [{'podSelector': {'matchLabels': {'app.kubernetes.io/component': 'redis'}}}],
                     'ports': [{'protocol': 'TCP', 'port': 6379}]}]}})
        path = directory / 'argo-diagnostic-values.yaml'
        path.write_text(yaml.safe_dump(repo_values()))
        argo = ROOT / 'platform/delivery/argocd'
        install_argocd(api, directory, argo / 'charts/argo-cd-10.9.6.tgz', argo / 'artifact.lock.json', path)
        for obj in kiali_observer():
            api.apply(obj)
        self.wait(self.controller_ready, 'pinned Argo readiness', 600)
        parent, projects = parent_objects(public.revision, private.revision)
        for project in projects:
            api.apply(project)
        parent['spec']['syncPolicy']['automated']['enabled'] = False
        api.apply(parent)

        def compared():
            app = api.request(APPS + PARENT)
            source_guard(app, public.revision, private.revision)
            status = app.get('status', {})
            return (status.get('sync', {}).get('revisions') == [public.revision, private.revision]
                    and status.get('sync', {}).get('comparedTo', {}).get('sources') == app['spec']['sources']
                    and status.get('sync', {}).get('comparedTo', {}).get('destination') == app['spec']['destination']
                    and not status.get('conditions') and len(status.get('resources', [])) == 6 and app)

        self.wait(compared, 'actual parent public/private render through pinned repo-server', 300)
        with server.observation_lock:
            paths = [path for _, path in server.observations]
        require(all(any(path.startswith('/' + name + '.git/') for path in paths) for name in ('public', 'private')),
                'Internal public/private Git reads were not observed')
        require(api.absent('/api/v1/namespaces/' + NS), 'Transport qualification created the observability namespace')
        api.apply(denied_github_job())
        self.wait(lambda: api.request('/apis/batch/v1/namespaces/argocd/jobs/fixture-deny-github')
                  .get('status', {}).get('succeeded') == 1, 'external GitHub TCP denied with working DNS', 180)
        print(json.dumps({'transport': 'passed', 'declaredSources': 'two distinct HTTPS URLs, full SHAs',
            'rewrite': 'read-only repo-server-only GIT_CONFIG_GLOBAL', 'externalGitHub': 'denied',
            'rootSourceApproval': 'not qualified; pinned-private fixture adaptation only'}), flush=True)
        return parent

    def run(self):
        document = self.wait(lambda: yaml.safe_load(Path('/fixture/kubeconfig').read_text()), 'private local kubeconfig')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.api = StackAPI(directory, document)
            nodes = self.wait(lambda: self.api.request('/api/v1/nodes')['items'], 'cluster API')
            require(int(nodes[0]['status']['capacity']['cpu']) >= 4, 'Fixture requires at least four CPUs')
            require(int(nodes[0]['status']['capacity']['memory'].removesuffix('Ki')) >= 12 * 1024 * 1024,
                    'Fixture requires at least 12GiB node memory')
            self.generate_pki(directory)
            files = git_files(self.ca)
            require(sum(len(value) for value in files.values()) < 4 * 1024 * 1024, 'Fixture source exceeds bounded Git transport')
            sources = directory / 'sources'
            sources.mkdir()
            public = GitSource(sources, 'public', files)
            private = GitSource(sources, 'private', {'services/catalog.json': json.dumps({'catalog': []}),
                'platform/observability.yaml': yaml.safe_dump({'observabilityInputs': {
                    'loginHost': LOGIN_HOST, 'grafanaHost': GRAFANA_HOST,
                    'kialiHost': KIALI_HOST, 'apiPeers': ['10.245.239.2/32', '10.43.0.1/32'],
                    'monitoringEnabled': True}})})
            # Reject fixture input mistakes before testing native repo-server transport.
            values = yaml.safe_load((private.work / 'platform/observability.yaml').read_text())
            values.update(catalog=[], nativeSource={'repository': PUBLIC, 'revision': public.revision, 'valuesRepository': PRIVATE})
            rendered = helm('platform/observability/gitops', values)
            require({o['metadata']['name'] for o in rendered} == set(CHILDREN), 'Native fixture input preflight changed child graph')
            server = GitServer(('0.0.0.0', 8000), functools.partial(ObservedGit, directory=str(sources)))
            server.observation_lock = threading.Lock()
            server.observations = []
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                parent = self.transport(directory, public, private, server)
                self.native_stack(directory, public, private, parent, files)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def native_stack(self, directory, public, private, parent, files):
        api = self.api
        values = yaml.safe_load((private.work / 'platform/observability.yaml').read_text())
        values.update(catalog=[], nativeSource={'repository': PUBLIC, 'revision': public.revision, 'valuesRepository': PRIVATE})
        children = helm('platform/observability/gitops', values)
        rendered = [obj for child in children for obj in helm(child['spec']['source']['path'],
            child['spec']['source']['helm']['valuesObject'], NS, child['metadata']['name'])]
        allowed = set(json.loads((ROOT / 'platform/observability/images.lock.json').read_text()).values())
        pinned_images(rendered, allowed)
        kiali_configuration(rendered)
        services = {obj['metadata']['name'] for obj in rendered if obj['kind'] == 'Service'}
        for obj in rendered:
            if obj['kind'] == 'StatefulSet':
                require(obj['spec']['serviceName'] in services,
                    'Native governing Service is missing: ' + obj['metadata']['name'] + '/' + obj['spec']['serviceName'])
        require(api.absent('/api/v1/namespaces/' + NS), 'Cold-start namespace already exists')
        require(api.absent('/apis/apiextensions.k8s.io/v1/customresourcedefinitions/prometheuses.monitoring.coreos.com'),
                'Cold-start monitoring CRDs already exist')
        self.prerequisites(directory)
        # The actual parent and all actual chart bytes stay in the synthetic public Git.
        require(all((public.work / path).read_bytes() == value for path, value in files.items()), 'Actual chart bytes changed')
        require(api.absent('/api/v1/namespaces/' + NS), 'Platform prerequisites created observability namespace or secrets')
        parent['spec']['syncPolicy']['automated']['enabled'] = True
        self.owner = GitSource(public.work.parent, 'owner', {'parent/application.yaml': yaml.safe_dump(parent)})
        project, owner = owner_application()
        api.apply(project)
        api.apply(owner)

        def ready():
            if not api.absent('/api/v1/namespaces/' + NS):
                self.bind_static_volumes()
            return self.app_ready(PARENT, public.revision, private.revision) and all(
                self.app_ready(name, public.revision, private.revision) for name in CHILDREN)

        self.wait(ready, 'actual six-chart cold start, current-source Synced and Healthy', 1800)
        require(len(self.pvs) == 5, 'Expected exactly five static local backing volumes')
        claims = api.request('/api/v1/namespaces/' + NS + '/persistentvolumeclaims')['items']
        require(len(claims) == 5 and sum(int(p['spec']['resources']['requests']['storage'].removesuffix('Gi'))
                    for p in claims) == 71, 'Actual 71Gi claim inventory changed')
        for route in ('grafana', 'kiali'):
            self.wait(lambda route=route: self.route_ready(NS, route), 'genuine ' + route + ' Gateway route')
        retained = self.external_secret_records()
        self.issuer_probe(NS, 'fixture-observability-issuer')
        self.issuer_probe(NS, 'fixture-kiali-openid', kiali=True)
        print(json.dumps({'coldStart': 'passed', 'children': list(CHILDREN),
            'readiness': 'all current-source Synced+Healthy', 'routes': 'Accepted+ResolvedRefs, current generation',
            'storage': 'five static local 71Gi PVs; NON-CSI', 'externalSecrets': 'four real ESO-owned Secrets'}), flush=True)
        self.retention(public, private, parent, retained, files)

    def app_ready(self, name, public_revision, private_revision):
        app = self.api.request(APPS + name)
        source_guard(app, public_revision, private_revision)
        status = app.get('status', {})
        sync, operation = status.get('sync', {}), status.get('operationState', {})
        if name == PARENT:
            current = (sync.get('revisions') == [public_revision, private_revision]
                and sync.get('comparedTo', {}).get('sources') == app['spec']['sources'])
            digest_current = True
        else:
            current = (sync.get('revision') == public_revision and sync.get('comparedTo', {}).get('source') == app['spec']['source'])
            annotations = app['metadata'].get('annotations', {})
            marker = annotations.get('cloudlab.io/observability-input-digest')
            digest_current = (isinstance(marker, str) and re.fullmatch('[a-f0-9]{64}', marker) is not None
                and annotations.get('cloudlab.io/observability-health') == 'required'
                and app['spec']['source'].get('helm', {}).get('valuesObject', {}).get('nativeInputDigest') == marker)
        errors = {'ComparisonError', 'InvalidSpecError', 'SyncError', 'UnknownError', 'DeletionError'}
        return (current and digest_current and app.get('operation') is None
                and sync.get('comparedTo', {}).get('destination') == app['spec']['destination']
                and operation.get('phase') not in ('Running', 'Terminating')
                and not any(c.get('type') in errors for c in status.get('conditions', []))
                and app['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') != 'true'
                and app['spec'].get('syncPolicy', {}).get('automated', {}).get('enabled') is True
                and sync.get('status') == 'Synced' and status.get('health', {}).get('status') == 'Healthy')

    def bind_static_volumes(self):
        claims = self.api.request('/api/v1/namespaces/' + NS + '/persistentvolumeclaims')['items']
        require(len(claims) <= 5, 'Unexpected native persistent claims')
        for claim in claims:
            name = claim['metadata']['name']
            if name in self.pvs:
                continue
            require(claim['spec']['storageClassName'] == 'cloudlab-telemetry', 'Unexpected claim storage class')
            slot = len(self.pvs)
            volume = {'apiVersion': 'v1', 'kind': 'PersistentVolume',
                'metadata': {'name': 'fixture-static-' + str(slot), 'labels': {'cloudlab.io/purpose': 'observability-native-stack-proof'}},
                'spec': {'capacity': copy.deepcopy(claim['spec']['resources']['requests']),
                    'accessModes': ['ReadWriteOnce'], 'persistentVolumeReclaimPolicy': 'Retain',
                    'storageClassName': 'cloudlab-telemetry', 'volumeMode': 'Filesystem',
                    'local': {'path': '/var/lib/lifecycle-storage/' + str(slot)},
                    'claimRef': {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'namespace': NS,
                                 'name': name, 'uid': claim['metadata']['uid']},
                    'nodeAffinity': {'required': {'nodeSelectorTerms': [{'matchExpressions': [{
                        'key': 'kubernetes.io/hostname', 'operator': 'In', 'values': ['obs-lifecycle-stack']}]}]}}}}
            self.pvs[name] = self.api.apply(volume)['metadata']['uid']

    def prerequisites(self, directory):
        api = self.api
        for namespace in ('external-secrets', 'istio-system', 'cloudlab-app-notes', 'cloudlab-identity',
                          'cloudlab-gateway-public', 'cloudlab-gateway-private'):
            api.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace,
                'labels': {'istio-injection': 'disabled'}}})
        archive, values = self.pinned_chart('platform/secrets/external-secrets', 'external-secrets')
        for component in (values, values['webhook'], values['certController']):
            component['resources'] = {'requests': {'cpu': '10m', 'memory': '64Mi'}, 'limits': {'cpu': '200m', 'memory': '256Mi'}}
        external_secrets = helm(str(archive.relative_to(ROOT)), values, 'external-secrets', 'external-secrets')
        lock = json.loads((ROOT / 'platform/secrets/external-secrets/artifact.lock.json').read_text())
        pinned_images(external_secrets, {name + '@' + digest for name, digest in lock['images'].items()})
        self.apply_all(external_secrets, 'external-secrets')
        self.wait(lambda: all(api.request('/apis/apps/v1/namespaces/external-secrets/deployments/' + name)
            .get('status', {}).get('readyReplicas') == 1 for name in
            ('external-secrets', 'external-secrets-webhook', 'external-secrets-cert-controller')), 'genuine ESO controller/webhook readiness', 600)
        gateway = ROOT / 'platform/connectivity/gateway-api'
        lock = json.loads((gateway / 'artifact.lock.json').read_text())
        raw = (gateway / 'upstream.yaml').read_bytes()
        require(hashlib.sha256(raw).hexdigest() == lock['sha256'] and lock['version'] == '1.6.1', 'Gateway API pin changed')
        self.apply_all([o for o in yaml.safe_load_all(raw) if o], 'istio-system')
        for component in ('base', 'istiod', 'cni', 'ztunnel'):
            path = 'platform/connectivity/istio/' + component
            self.pinned_chart(path, 'istio-system')
            values = fixture_mesh_values(component)
            mesh = helm(path, values, 'istio-system', component)
            allowed = set(json.loads((ROOT / 'platform/connectivity/istio/images.lock.json').read_text()).values())
            pinned_images(mesh, allowed)
            self.apply_all(mesh, 'istio-system')
            if component == 'istiod':
                self.wait(lambda: api.request('/apis/apps/v1/namespaces/istio-system/deployments/istiod')
                    .get('status', {}).get('readyReplicas') == 1, 'pinned Istiod readiness', 600)
            elif component in ('cni', 'ztunnel'):
                name = 'istio-cni-node' if component == 'cni' else 'ztunnel'
                self.wait(lambda name=name: api.request('/apis/apps/v1/namespaces/istio-system/daemonsets/' + name)
                    .get('status', {}).get('numberReady') == 1, 'pinned ' + component + ' readiness', 600)
        data = [{'key': 'grafana-emergency', 'value': json.dumps({'username': 'fixture-admin',
                    'password': 'fixture-only-password-never-real', 'secret_key': 'fixture-only-' + 'a' * 51})},
                {'key': 'kiali-signing-key', 'value': json.dumps({'key': 'fixture-only-' + 'b' * 19})},
                {'key': 'keycloak-client-secrets', 'value': json.dumps({'client_secrets': json.dumps({
                    'platform': {'grafana': 'fixture-grafana', 'kiali': 'fixture-kiali'}})})},
                {'key': 'cascade-fixture', 'value': 'synthetic-owner-cascade'}]
        store = {'apiVersion': 'external-secrets.io/v1', 'kind': 'ClusterSecretStore', 'metadata': {'name': 'cloudlab'},
            'spec': {'conditions': [{'namespaces': [NS]}], 'provider': {'fake': {'data': data}}}}
        self.wait(lambda: api.apply(copy.deepcopy(store)), 'scoped fake-provider admission')
        self.gateway_issuer(directory)

    def generate_pki(self, directory):
        for name in ('ca', 'server'):
            command(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(directory / (name + '.key')),
                '-out', str(directory / (name + ('.crt' if name == 'ca' else '.csr'))),
                '-subj', '/CN=Fixture-only ' + name] + (['-x509', '-days', '2', '-addext',
                    'keyUsage=critical,keyCertSign,cRLSign'] if name == 'ca' else []))
            (directory / (name + '.key')).chmod(0o600)
        extension = directory / 'server.ext'
        extension.write_text('subjectAltName=DNS:' + LOGIN_HOST + ',DNS:*.internal.' + ZONE + '\n')
        command(['openssl', 'x509', '-req', '-in', str(directory / 'server.csr'), '-CA', str(directory / 'ca.crt'),
            '-CAkey', str(directory / 'ca.key'), '-CAcreateserial', '-out', str(directory / 'server.crt'),
            '-days', '2', '-extfile', str(extension)])
        self.ca = (directory / 'ca.crt').read_text()

    def gateway_issuer(self, directory):
        api = self.api
        require(self.ca == (directory / 'ca.crt').read_text(), 'Fixture issuer CA changed after source creation')
        for exposure in ('public', 'private'):
            namespace = 'cloudlab-gateway-' + exposure
            api.apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'cloudlab-gateway-tls', 'namespace': namespace},
                'type': 'kubernetes.io/tls', 'data': {'tls.crt': base64.b64encode((directory / 'server.crt').read_bytes()).decode(),
                                                   'tls.key': base64.b64encode((directory / 'server.key').read_bytes()).decode()}})
        values = json.loads((ROOT / 'platform/connectivity/gateways/values.json').read_text())
        values['zone'] = ZONE
        self.apply_all(helm('platform/connectivity/gateways', values, 'istio-system', 'cloudlab-gateways'), 'istio-system')
        self.wait(lambda: all(self.conditions(api.request('/apis/gateway.networking.k8s.io/v1/namespaces/cloudlab-gateway-'
            + exposure + '/gateways/cloudlab'), ('Accepted', 'Programmed')) for exposure in ('public', 'private')),
            'genuine Gateway Accepted/Programmed', 600)
        for exposure in ('public', 'private'):
            workloads = api.request('/apis/apps/v1/namespaces/cloudlab-gateway-' + exposure + '/deployments')['items']
            require(workloads and list(images(workloads)), 'Generated Gateway workload images are absent')
            pinned_images(workloads, {values['proxyImage']})
        namespace = api.request('/api/v1/namespaces/cloudlab-identity')
        namespace.pop('status', None)
        namespace['metadata']['labels'].update({'cloudlab.io/gateway': 'private', 'istio.io/dataplane-mode': 'ambient'})
        api.request('/api/v1/namespaces/cloudlab-identity', 'PUT', namespace)
        issuer = ISSUER
        code = ('import http.server,json\n'
            'issuer=' + repr(issuer) + '\n'
            'class Handler(http.server.BaseHTTPRequestHandler):\n'
            ' def log_message(self,*args): pass\n'
            ' def do_GET(self):\n'
            '  if self.path=="/realms/platform/.well-known/openid-configuration":\n'
            '   data={"issuer":issuer,"authorization_endpoint":issuer+"/auth","token_endpoint":issuer+"/token",'
            '"jwks_uri":issuer+"/jwks","userinfo_endpoint":issuer+"/userinfo","response_types_supported":["code"],'
            '"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}\n'
            '  elif self.path=="/realms/platform/jwks": data={"keys":[]}\n'
            '  else: self.send_error(404); return\n'
            '  body=json.dumps(data).encode(); self.send_response(200); self.send_header("Content-Type","application/json");'
            'self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)\n'
            'http.server.HTTPServer(("0.0.0.0",8080),Handler).serve_forever()\n')
        compile(code, 'fixture-issuer.py', 'exec')
        api.apply({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'fixture-issuer', 'namespace': 'cloudlab-identity'},
                   'data': {'issuer.py': code}})
        self.python_image = python_image()
        api.apply({'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'fixture-issuer', 'namespace': 'cloudlab-identity'},
            'spec': {'replicas': 1, 'selector': {'matchLabels': {'cloudlab.io/lifecycle-issuer': 'true'}}, 'template': {
                'metadata': {'labels': {'cloudlab.io/lifecycle-issuer': 'true'}}, 'spec': {'automountServiceAccountToken': False,
                    'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'seccompProfile': {'type': 'RuntimeDefault'}},
                    'containers': [{'name': 'issuer', 'image': self.python_image, 'command': ['python', '/fixture/issuer.py'],
                        'ports': [{'containerPort': 8080}], 'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'},
                            'limits': {'cpu': '100m', 'memory': '128Mi'}},
                        'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                        'volumeMounts': [{'name': 'code', 'mountPath': '/fixture', 'readOnly': True}]}],
                    'volumes': [{'name': 'code', 'configMap': {'name': 'fixture-issuer'}}]}}}})
        api.apply({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'fixture-issuer', 'namespace': 'cloudlab-identity'},
            'spec': {'selector': {'cloudlab.io/lifecycle-issuer': 'true'}, 'ports': [{'name': 'http', 'port': 8080, 'targetPort': 8080}]}})
        api.apply({'apiVersion': 'gateway.networking.k8s.io/v1', 'kind': 'HTTPRoute',
            'metadata': {'name': 'fixture-issuer', 'namespace': 'cloudlab-identity'}, 'spec': {
                'parentRefs': [{'name': 'cloudlab', 'namespace': 'cloudlab-gateway-private', 'sectionName': 'https'}],
                'hostnames': [LOGIN_HOST], 'rules': [{'backendRefs': [{'name': 'fixture-issuer', 'port': 8080}]}]}})
        self.wait(lambda: self.route_ready('cloudlab-identity', 'fixture-issuer'), 'genuine issuer route')
        service = self.wait(lambda: api.request('/api/v1/namespaces/cloudlab-gateway-private/services/cloudlab-istio'), 'private Gateway Service')
        core = api.request('/api/v1/namespaces/kube-system/configmaps/coredns')
        require('custom/*.server' in core['data']['Corefile'], 'Pinned K3s CoreDNS lacks its supported custom-server import')
        self.dns_custom = api.apply({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'coredns-custom', 'namespace': 'kube-system'},
            'data': {'lifecycle.server': ZONE + ':53 {\n errors\n hosts {\n  '
                + service['spec']['clusterIP'] + ' ' + LOGIN_HOST + ' ' + KIALI_HOST + '\n  fallthrough\n }\n forward . /etc/resolv.conf\n}\n'}})
        self.dns_applied = time.monotonic()
        self.wait(lambda: api.request('/apis/apps/v1/namespaces/cloudlab-identity/deployments/fixture-issuer')
            .get('status', {}).get('readyReplicas') == 1, 'synthetic issuer backend readiness')
        self.issuer_dns()
        self.issuer_probe('cloudlab-identity', 'fixture-platform-issuer')

    def dns_identity(self):
        api = self.api
        service = api.request('/api/v1/namespaces/kube-system/services/kube-dns')
        endpoint = api.request('/api/v1/namespaces/kube-system/endpoints/kube-dns')
        pods = api.request('/api/v1/namespaces/kube-system/pods')['items']
        selector = service['spec']['selector']
        require(selector == {'k8s-app': 'kube-dns'}, 'CoreDNS Service selector changed')
        selected = [pod for pod in pods if all(pod['metadata'].get('labels', {}).get(key) == value for key, value in selector.items())]
        require(selected and all(any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod.get('status', {}).get('conditions', []))
            for pod in selected), 'CoreDNS readiness is unavailable')
        require({(p['protocol'], p['port']) for p in service['spec']['ports']} >= {('UDP', 53), ('TCP', 53)},
                'kube-dns transport ports changed')
        subsets = endpoint.get('subsets', [])
        require(subsets and all(part.get('addresses') and not part.get('notReadyAddresses') for part in subsets),
                'kube-dns endpoints are not ready')
        require({address.get('targetRef', {}).get('uid') for part in subsets for address in part['addresses']}
            == {pod['metadata']['uid'] for pod in selected}, 'CoreDNS endpoint identity changed')
        custom = api.request('/api/v1/namespaces/kube-system/configmaps/coredns-custom')
        gateway = api.request('/api/v1/namespaces/cloudlab-gateway-private/services/cloudlab-istio')
        cluster = api.request('/api/v1/namespaces/default/services/kubernetes')
        def binding(obj, value):
            return (obj['metadata']['uid'], hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest())
        require(custom['metadata']['uid'] == self.dns_custom['metadata']['uid']
                and custom['metadata']['resourceVersion'] == self.dns_custom['metadata']['resourceVersion']
                and custom['data'] == self.dns_custom['data'], 'Custom DNS declaration changed')
        identity = {'service': binding(service, service['spec']), 'endpoint': binding(endpoint, subsets),
                    'pods': sorted(pod['metadata']['uid'] for pod in selected),
                    'custom': (*binding(custom, custom['data']), custom['metadata']['resourceVersion']),
                    'gateway': binding(gateway, gateway['spec']), 'cluster': binding(cluster, cluster['spec'])}
        return identity, service['spec']['clusterIP'], cluster['spec']['clusterIP'], gateway['spec']['clusterIP']

    def issuer_dns(self):
        ordinary = self.api.request('/api/v1/namespaces/external-secrets')
        labels = ordinary['metadata'].get('labels', {})
        require(labels.get('istio.io/dataplane-mode') != 'ambient' and labels.get('istio-injection') == 'disabled',
                'Ordinary DNS control namespace changed')
        policies = self.api.request('/apis/networking.k8s.io/v1/namespaces/external-secrets/networkpolicies')['items']
        require(not any('Egress' in policy['spec'].get('policyTypes', []) or 'egress' in policy['spec'] for policy in policies),
                'Ordinary DNS policy needs separate qualification')
        before, resolver, cluster, issuer = self.dns_identity()
        matrices = []
        for control, namespace in (('ordinary', 'external-secrets'), ('ambient', 'cloudlab-identity')):
            rows = self.issuer_probe(namespace, 'fixture-issuer-dns', dns={
                'control': control, 'resolver': resolver, 'cluster': cluster, 'issuer': issuer,
                'applied_at': self.dns_applied})
            matrices.append(rows)
        require(self.dns_identity()[0] == before, 'DNS prerequisite identity changed during comparison')
        for rows in matrices:
            print(json.dumps({'dns': rows}, sort_keys=True), flush=True)
        require(matrix_ready(matrices[0]), 'ordinary-dns-readiness-failed')
        require(matrix_ready(matrices[1]), 'ambient-dns-readiness-failed')

    def dns_enrollment(self, namespace, control):
        """Read two boundary snapshots; do not claim continuous enrollment."""
        api = self.api
        source = api.request('/api/v1/namespaces/' + namespace)
        labels = source['metadata'].get('labels', {})
        require(labels.get('istio.io/dataplane-mode') == 'ambient' if control == 'ambient' else
                labels.get('istio.io/dataplane-mode') is None, 'DNS namespace enrollment intent changed')
        result = {'namespace': (source['metadata']['uid'], dns_digest(labels)), 'mesh': {}}
        for name in ('istio-cni-node', 'ztunnel'):
            daemon = api.request('/apis/apps/v1/namespaces/istio-system/daemonsets/' + name)
            generation = daemon['metadata']['generation']
            status = daemon.get('status', {})
            require(status.get('observedGeneration') == generation and all(status.get(key) == 1 for key in
                ('desiredNumberScheduled', 'currentNumberScheduled', 'updatedNumberScheduled', 'numberReady', 'numberAvailable'))
                and status.get('numberMisscheduled', 0) == 0 and status.get('numberUnavailable', 0) == 0,
                'DNS mesh prerequisite is not current and ready')
            pods = api.request('/api/v1/namespaces/istio-system/pods')['items']
            pods = [pod for pod in pods if any(owner.get('uid') == daemon['metadata']['uid'] and owner.get('controller') is True
                and owner.get('kind') == 'DaemonSet' for owner in pod['metadata'].get('ownerReferences', []))]
            require(len(pods) == 1 and pods[0].get('status', {}).get('phase') == 'Running'
                and any(c['type'] == 'Ready' and c['status'] == 'True' for c in pods[0]['status'].get('conditions', [])),
                'DNS mesh Pod identity is unavailable')
            containers = []
            for field in ('initContainerStatuses', 'containerStatuses'):
                for item in pods[0]['status'].get(field, []):
                    state = item.get('state', {})
                    require(type(item.get('restartCount')) is int and item['restartCount'] >= 0
                        and item.get('containerID') and (state.get('running') or state.get('terminated', {}).get('exitCode') == 0)
                        and (field != 'containerStatuses' or item.get('ready') is True), 'DNS mesh container is not ready')
                    containers.append((item['name'], item['containerID'], item['restartCount'], state, item.get('imageID')))
            require(containers, 'DNS mesh container identity is absent')
            template = daemon['spec']['template']['spec']
            references = {v['configMap']['name'] for v in template.get('volumes', []) if 'configMap' in v}
            for volume in template.get('volumes', []):
                references.update(row['configMap']['name'] for row in volume.get('projected', {}).get('sources', []) if 'configMap' in row)
            for container in template.get('containers', []) + template.get('initContainers', []):
                references.update(row['configMapRef']['name'] for row in container.get('envFrom', []) if 'configMapRef' in row)
                references.update(row['valueFrom']['configMapKeyRef']['name'] for row in container.get('env', [])
                    if 'configMapKeyRef' in row.get('valueFrom', {}))
            require(len(references) <= 8 and all(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', value) for value in references),
                    'DNS mesh config references exceed scope')
            configs = {}
            for reference in sorted(references):
                value = api.request('/api/v1/namespaces/istio-system/configmaps/' + reference)
                configs[reference] = (value['metadata']['uid'], value['metadata']['resourceVersion'],
                    dns_digest({'data': value.get('data', {}), 'binaryData': value.get('binaryData', {})}))
            result['mesh'][name] = (daemon['metadata']['uid'], generation, dns_digest(daemon['spec']),
                                    pods[0]['metadata']['uid'], containers, configs)
        return result

    def running_dns(self, namespace, name, control, job, gate, gate_path, nonce, config_hash, deadline):
        api = self.api
        job_path = '/apis/batch/v1/namespaces/' + namespace + '/jobs/' + name
        expected_spec = job['spec']['template']['spec']
        job_uid = job['metadata']['uid']
        bound_uid = None

        def selected_pod():
            require(api.request(job_path)['metadata']['uid'] == job_uid, 'DNS Job was recreated')
            pods = api.request('/api/v1/namespaces/' + namespace + '/pods')['items']
            pods = [pod for pod in pods if any(owner.get('uid') == job_uid and owner.get('kind') == 'Job'
                and owner.get('controller') is True for owner in pod['metadata'].get('ownerReferences', []))]
            require(len(pods) <= 1, 'DNS Pod identity is ambiguous')
            if not pods:
                require(bound_uid is None, 'Bound DNS Pod disappeared')
                return None
            require(bound_uid is None or pods[0]['metadata']['uid'] == bound_uid, 'DNS Pod was replaced')
            return pods[0]

        def records(pod):
            return log_records(read_logs(api, namespace, pod['metadata']['name'], deadline),
                pod_uid=pod['metadata']['uid'], job_uid=job_uid, nonce=nonce, config_hash=config_hash, control=control)

        def waiting():
            pod = selected_pod()
            if pod is None: return False
            identity = pod_identity(pod, job_uid, expected_spec, control)
            if identity is None: return False
            lines = records(pod)
            require(len(lines) <= 1, 'DNS queries ran before release')
            return (identity, lines[0]['binding']) if lines else False

        initial, binding = self.wait(waiting, 'running ' + control + ' DNS hold', max(0, deadline - time.monotonic()), fatal=True)
        bound_uid = initial['podUID']
        before = self.dns_enrollment(namespace, control)
        require(pod_identity(selected_pod(), job_uid, expected_spec, control) == initial, 'DNS process changed before release')
        require(time.monotonic() < deadline, 'DNS operation deadline exceeded')
        gate = update_gate(api, gate_path, gate, 'run', binding)

        def observed():
            pod = selected_pod()
            require(pod_identity(pod, job_uid, expected_spec, control) == initial, 'DNS process changed during queries')
            lines = records(pod)
            require(lines and lines[0]['binding'] == binding, 'DNS process binding changed')
            return lines[1] if len(lines) == 2 else False

        result = self.wait(observed, 'held ' + control + ' DNS result', max(0, deadline - time.monotonic()), fatal=True)
        require(self.dns_enrollment(namespace, control) == before, 'DNS enrollment snapshot changed during queries')
        pod = selected_pod()
        require(pod_identity(pod, job_uid, expected_spec, control) == initial and records(pod)[1] == result,
                'DNS process or result changed before finish')
        require(time.monotonic() < deadline, 'DNS operation deadline exceeded')
        gate = update_gate(api, gate_path, gate, 'finish', binding, result=result, verified=True)

        def terminated():
            pod = selected_pod()
            require(pod_identity(pod, job_uid, expected_spec, control, terminal=True) == initial,
                    'DNS container identity changed at termination')
            final = pod['status']['containerStatuses'][0].get('state', {}).get('terminated')
            if final is None: return False
            require(final.get('exitCode') == result['exitCode'] and final.get('reason') ==
                ('Completed' if result['exitCode'] == 0 else 'Error'), 'DNS exit does not match verified matrix')
            current = api.request(job_path)
            require(current['metadata']['uid'] == job_uid, 'DNS Job changed at termination')
            expected = 'Complete' if result['exitCode'] == 0 else 'Failed'
            if not any(c['type'] == expected and c['status'] == 'True' for c in current.get('status', {}).get('conditions', [])):
                return False
            annotation = pod['metadata'].get('annotations', {}).get('ambient.istio.io/redirection')
            dns_capture = pod['metadata'].get('annotations', {}).get('ambient.istio.io/dns-capture')
            print(json.dumps({'dnsTerminal': control, 'capture': 'absent' if annotation is None else
                'enabled' if annotation == 'enabled' else 'other', 'dnsCapture': 'absent' if dns_capture is None else
                'enabled' if dns_capture == 'true' else 'disabled' if dns_capture == 'false' else 'other',
                'exitCode': result['exitCode']}), flush=True)
            return pod

        final_pod = self.wait(terminated, 'verified ' + control + ' DNS termination', max(0, deadline - time.monotonic()), fatal=True)
        pod_path = '/api/v1/namespaces/' + namespace + '/pods/' + final_pod['metadata']['name']
        try:
            require(time.monotonic() < deadline, 'DNS fixture cleanup remains pending')
            api.request(job_path, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                'propagationPolicy': 'Foreground', 'preconditions': {'uid': job_uid}})
            self.wait(lambda: api.absent(job_path) and api.absent(pod_path), 'DNS Job cleanup',
                      max(0, deadline - time.monotonic()), fatal=True)
            api.request(gate_path, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                'preconditions': {'uid': gate['metadata']['uid']}})
            self.wait(lambda: api.absent(gate_path), 'DNS gate cleanup', max(0, deadline - time.monotonic()), fatal=True)
        except RuntimeError:
            print(json.dumps({'dnsCleanup': control, 'status': 'pending'}), flush=True)
            raise
        print(json.dumps({'dnsCleanup': control, 'status': 'complete'}), flush=True)
        return result['dns']

    @staticmethod
    def conditions(obj, names):
        conditions = obj.get('status', {}).get('conditions', [])
        generation = obj['metadata']['generation']
        return all(any(c['type'] == name and c['status'] == 'True' and c.get('observedGeneration') == generation
                       for c in conditions) for name in names)

    def route_ready(self, namespace, name):
        obj = self.api.request('/apis/gateway.networking.k8s.io/v1/namespaces/' + namespace + '/httproutes/' + name)
        for parent in obj.get('status', {}).get('parents', []):
            if parent.get('controllerName') == 'istio.io/gateway-controller':
                return self.conditions({'metadata': obj['metadata'], 'status': parent}, ('Accepted', 'ResolvedRefs'))
        return False

    def issuer_probe(self, namespace, name, dns=None, *, kiali=False):
        require(not kiali or (dns is None and namespace == NS and name == 'fixture-kiali-openid'),
                'Kiali probe scope changed')
        self.api.apply({'apiVersion': 'v1', 'kind': 'ServiceAccount',
            'metadata': {'name': 'fixture-issuer-probe', 'namespace': namespace}, 'automountServiceAccountToken': False})
        deadline = min(self.deadline, time.monotonic() + 240)
        gate_name = name + '-gate'
        gate_path = '/api/v1/namespaces/' + namespace + '/configmaps/' + gate_name
        if dns is not None:
            nonce = secrets.token_hex(32)
            config_hash = dns_digest(diagnostic_config(**dns))
            require(self.api.absent(gate_path) and self.api.absent('/apis/batch/v1/namespaces/' + namespace + '/jobs/' + name),
                    'DNS operation already exists')
            gate = self.api.apply({'apiVersion': 'v1', 'kind': 'ConfigMap',
                'metadata': {'name': gate_name, 'namespace': namespace, 'labels': {'cloudlab.io/lifecycle-probe': 'true'}},
                'data': {'gate.json': json.dumps({'phase': 'hold', 'nonce': nonce, 'configHash': config_hash,
                    'podUID': '', 'jobUID': '', 'resultDigest': ''}, sort_keys=True, separators=(',', ':'))}})
        if dns is None:
            self.api.apply({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': name, 'namespace': namespace},
                            'data': {'ca.crt': self.ca}})
        code = (kiali_probe_code() if kiali else issuer_probe_code()) if dns is None else diagnostic_code(**dns, nonce=nonce)
        compile(code, 'fixture-issuer-probe.py', 'exec')
        definition = {'apiVersion': 'batch/v1', 'kind': 'Job', 'metadata': {'name': name, 'namespace': namespace},
            'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': 240, 'template': {'metadata': {
                'labels': {'cloudlab.io/lifecycle-probe': 'true'}}, 'spec': {'restartPolicy': 'Never',
                    'serviceAccountName': 'fixture-issuer-probe', 'automountServiceAccountToken': False,
                    'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000,
                        'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': [{'name': 'probe', 'image': self.python_image,
                        'command': ['python', '-c', code], 'securityContext': {'readOnlyRootFilesystem': True,
                            'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                        'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '128Mi'}},
                        'volumeMounts': [{'name': 'trust', 'mountPath': '/fixture', 'readOnly': True}] if dns is None else
                            [{'name': 'gate', 'mountPath': '/fixture-gate', 'readOnly': True}]}],
                    'volumes': [{'name': 'trust', 'configMap': {'name': name, 'defaultMode': 420, 'optional': False}}] if dns is None else
                        [{'name': 'gate', 'configMap': {'name': gate_name, 'defaultMode': 420, 'optional': False}}]}}}}
        if dns is not None:
            definition['spec']['template']['spec']['containers'][0]['env'] = [
                {'name': 'FIXTURE_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}},
                {'name': 'FIXTURE_JOB_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1',
                    'fieldPath': "metadata.labels['batch.kubernetes.io/controller-uid']"}}}]
        job = self.api.apply(definition)
        wanted = definition['spec']['template']['spec']
        accepted = job['spec']['template']['spec']
        require(same_execution_source(accepted, wanted), 'Probe Job source changed during admission')
        if dns is not None:
            return self.running_dns(namespace, name, dns['control'], job, gate, gate_path, nonce, config_hash, deadline)
        job_path = '/apis/batch/v1/namespaces/' + namespace + '/jobs/' + name
        job_uid = job['metadata'].get('uid', '')
        require(re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', job_uid)
                and job['metadata'].get('name') == name and job['metadata'].get('namespace') == namespace,
                'Probe admitted Job identity refused')
        bound_pod = None

        def completed():
            nonlocal bound_pod
            current = self.api.request(job_path)
            require(current['metadata'].get('uid') == job_uid and current['metadata'].get('name') == name
                    and current['metadata'].get('namespace') == namespace
                    and same_execution_source(current['spec']['template']['spec'], wanted),
                    'Probe Job identity or source changed')
            require(not any(c.get('type') == 'Failed' and c.get('status') == 'True'
                            for c in current.get('status', {}).get('conditions', [])), 'Probe Job failed')
            pods = self.api.request('/api/v1/namespaces/' + namespace + '/pods?labelSelector='
                                    'batch.kubernetes.io/controller-uid=' + job_uid)['items']
            require(len(pods) <= 1, 'Probe Pod ownership is ambiguous')
            if not pods:
                require(bound_pod is None, 'Bound probe Pod disappeared')
                return False
            pod = pods[0]
            metadata, spec, status = pod['metadata'], pod['spec'], pod.get('status', {})
            owners = metadata.get('ownerReferences', [])
            require(metadata.get('namespace') == namespace
                    and re.fullmatch(re.escape(name) + r'-[a-z0-9]{5}', metadata.get('name', ''))
                    and metadata.get('labels', {}).get('batch.kubernetes.io/controller-uid') == job_uid
                    and metadata.get('labels', {}).get('batch.kubernetes.io/job-name') == name
                    and len(owners) == 1 and owners[0].get('name') == name
                    and owners[0].get('apiVersion') == 'batch/v1' and owners[0].get('kind') == 'Job'
                    and owners[0].get('uid') == job_uid and owners[0].get('controller') is True
                    and same_execution_source(spec, wanted), 'Probe Pod source or ownership refused')
            identity = (metadata.get('uid'), metadata['name'])
            require(bound_pod is None or identity == bound_pod, 'Probe Pod was replaced')
            bound_pod = identity
            containers = status.get('containerStatuses', [])
            if not containers and status.get('phase') == 'Pending': return False
            require(len(containers) == 1 and containers[0].get('restartCount') == 0,
                    'Probe container restarted or is ambiguous')
            require(status.get('phase') in ('Pending', 'Running', 'Succeeded'), 'Probe did not exit successfully')
            terminal = containers[0].get('state', {}).get('terminated')
            if terminal is None:
                require(status.get('phase') in ('Pending', 'Running'), 'Probe exited without terminal evidence')
                return False
            pod_identity(pod, job_uid, wanted, 'ambient', terminal=True)
            require(type(terminal.get('exitCode')) is int and terminal['exitCode'] == 0,
                    'Probe did not exit successfully')
            if not (status.get('phase') == 'Succeeded' and terminal.get('reason') == 'Completed'
                    and terminal.get('finishedAt')):
                return False
            complete = current.get('status', {})
            if not (complete.get('succeeded') == 1 and not complete.get('active', 0) and not complete.get('failed', 0)
                    and any(c.get('type') == 'Complete' and c.get('status') == 'True' for c in complete.get('conditions', []))):
                return False
            require(isinstance(current['metadata'].get('resourceVersion'), str)
                    and current['metadata']['resourceVersion'], 'Probe Job cleanup identity unavailable')
            return current

        qualified = self.wait(completed,
            'verified native Kiali OIDC redirect' if kiali else 'verified canonical issuer TLS from ' + namespace,
            max(0, deadline - time.monotonic()), fatal=True)
        require(time.monotonic() < deadline, 'Probe cleanup deadline exceeded')
        self.api.request(job_path, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions',
            'propagationPolicy': 'Foreground', 'preconditions': {'uid': job_uid,
                'resourceVersion': qualified['metadata']['resourceVersion']}})

    def external_secret_records(self):
        expected = {'grafana-emergency': 'grafana-emergency', 'kiali-signing-key': 'kiali-signing-key',
                    'grafana-oidc': 'grafana-oidc', 'kiali-oidc': 'kiali'}
        records = {}
        for external, secret in expected.items():
            obj = self.wait(lambda external=external: self.api.request('/apis/external-secrets.io/v1/namespaces/' + NS
                + '/externalsecrets/' + external), 'real ESO declaration ' + external)
            require(obj['metadata']['annotations']['argocd.argoproj.io/sync-options'] == 'Prune=false,Delete=false',
                    'Shared ESO declaration is not retained')
            es_uid = obj['metadata']['uid']
            def owned():
                target = self.api.request('/api/v1/namespaces/' + NS + '/secrets/' + secret)
                return any(r.get('controller') is True and r['kind'] == 'ExternalSecret' and r['uid'] == es_uid
                           for r in target['metadata'].get('ownerReferences', [])) and target
            target = self.wait(owned, 'genuine ESO Secret ownerReference ' + external)
            records[external] = {'external': es_uid, 'secretName': secret, 'secret': target['metadata']['uid'],
                'dataDigest': hashlib.sha256(json.dumps(target['data'], sort_keys=True).encode()).hexdigest()}
        return records

    def retention(self, public, private, parent, records, files):
        api = self.api
        original = files['platform/observability/templates/credentials.yaml']
        public.commit({'platform/observability/templates/credentials.yaml': None})
        removal, _ = parent_objects(public.revision, private.revision)
        self.owner.commit({'parent/application.yaml': yaml.safe_dump(removal)})

        def terminal_parent():
            current = api.request(APPS + PARENT)
            source_guard(current, public.revision, private.revision)
            status = current.get('status', {})
            operation = status.get('operationState', {})
            return (not current.get('operation') and operation.get('phase') in ('Failed', 'Error')
                and bool(operation.get('finishedAt'))
                and status.get('sync', {}).get('revisions') == [public.revision, private.revision]
                and status.get('sync', {}).get('comparedTo', {}).get('sources') == current['spec']['sources']
                and status.get('sync', {}).get('comparedTo', {}).get('destination') == current['spec']['destination']
                and operation.get('syncResult', {}).get('revisions') == [public.revision, private.revision]
                and status.get('health', {}).get('status') == 'Degraded' and current)

        self.wait(terminal_parent, 'retention blocker terminates native parent operation without intervention', 600)
        config = api.request(APPS + 'cloudlab-observability')
        status = config.get('status', {})
        operation = status.get('operationState', {})
        require(status.get('sync', {}).get('status') == 'OutOfSync' and operation.get('phase') == 'Succeeded'
                and status.get('sync', {}).get('revision') == public.revision
                and status.get('sync', {}).get('comparedTo', {}).get('source') == config['spec']['source']
                and status.get('sync', {}).get('comparedTo', {}).get('destination') == config['spec']['destination']
                and bool(operation.get('finishedAt')) and operation.get('syncResult', {}).get('source') == config['spec']['source']
                and operation.get('syncResult', {}).get('revision') == public.revision,
                'Retained child is not current completed nonconvergence')
        skipped = {r['name'] for r in operation.get('syncResult', {}).get('resources', [])
                   if r['kind'] == 'ExternalSecret' and r.get('status') == 'PruneSkipped'}
        require(skipped == set(records), 'Actual shared ESO declarations were not prune-skipped')
        require(self.external_secret_records() == records, 'Retained shared ESO/Secret identities or data changed')
        # Only accepted synthetic Git commits restore intent; no parent/child patch or refresh.
        public.commit({'platform/observability/templates/credentials.yaml': original})
        restored, _ = parent_objects(public.revision, private.revision)
        marker = 'restored-' + public.revision[:12]
        restored['metadata'].setdefault('annotations', {})['cloudlab.io/lifecycle-marker'] = marker
        self.owner.commit({'parent/application.yaml': yaml.safe_dump(restored)})

        def recovered():
            subject = api.request(APPS + PARENT)
            return (subject['metadata'].get('annotations', {}).get('cloudlab.io/lifecycle-marker') == marker
                and self.app_ready(PARENT, public.revision, private.revision)
                and all(self.app_ready(name, public.revision, private.revision) for name in CHILDREN))

        self.wait(recovered, 'Git-only restoration marker and current parent plus six children converge', 900)
        require(self.external_secret_records() == records, 'Git restoration replaced shared credentials')
        require(api.request(APPS + 'fixture-observability-owner')['status']['sync']['revision'] == self.owner.revision,
                'Restoration owner Git revision is stale')
        self.persistent_retention_records()
        dummy = {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret',
            'metadata': {'name': 'fixture-owner-cascade', 'namespace': NS}, 'spec': {
                'refreshInterval': '5s', 'secretStoreRef': {'name': 'cloudlab', 'kind': 'ClusterSecretStore'},
                'target': {'name': 'fixture-owner-cascade', 'creationPolicy': 'Owner', 'deletionPolicy': 'Retain'},
                'data': [{'secretKey': 'dummy', 'remoteRef': {'key': 'cascade-fixture'}}]}}
        external = api.apply(dummy)
        path = '/api/v1/namespaces/' + NS + '/secrets/fixture-owner-cascade'
        def owned_dummy():
            secret = api.request(path)
            return any(r['uid'] == external['metadata']['uid'] and r.get('controller') is True
                for r in secret['metadata'].get('ownerReferences', [])) and secret
        self.wait(owned_dummy, 'real ESO dummy Owner Secret')
        api.request('/apis/external-secrets.io/v1/namespaces/' + NS + '/externalsecrets/fixture-owner-cascade',
            'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': external['metadata']['uid']}})
        self.wait(lambda: api.absent(path), 'explicit dummy Owner deletion cascades despite deletionPolicy Retain')
        require(self.external_secret_records() == records, 'Dummy cascade affected shared credentials')
        print(json.dumps({'retention': 'passed', 'sharedESO': 'same four ExternalSecret/Secret UIDs and data',
            'blocker': 'current completed prune-skipped OutOfSync; parent failed and operation cleared',
            'recovery': 'owner Git only; new marker and current parent plus six children Synced+Healthy',
            'dummyCascade': 'Owner Secret deleted despite deletionPolicy Retain',
            'storage': 'bound static local PV/PVC identities and retention policy only; NON-CSI'}), flush=True)

    def persistent_retention_records(self):
        claims = self.api.request('/api/v1/namespaces/' + NS + '/persistentvolumeclaims')['items']
        require(len(claims) == 5, 'Persistent claim inventory changed')
        for claim in claims:
            require(claim['status']['phase'] == 'Bound', 'Native persistent claim is not bound')
            pv = self.api.request('/api/v1/persistentvolumes/' + claim['spec']['volumeName'])
            require(pv['metadata']['uid'] == self.pvs[claim['metadata']['name']]
                and pv['spec']['claimRef']['uid'] == claim['metadata']['uid']
                and pv['spec']['persistentVolumeReclaimPolicy'] == 'Retain' and 'local' in pv['spec'] and 'csi' not in pv['spec'],
                'Static local volume identity or Retain policy changed')
            require(not any(r['kind'] in ('StatefulSet', 'Pod') for r in claim['metadata'].get('ownerReferences', [])),
                    'Retained claim still has StatefulSet/Pod cascade ownership')
            if claim['metadata']['name'] == 'cloudlab-grafana':
                require(claim['metadata']['annotations']['argocd.argoproj.io/sync-options'] == 'Prune=false,Delete=false',
                        'Grafana direct PVC retention missing')
        for name in ('cloudlab-loki', 'cloudlab-tempo'):
            statefulset = self.api.request('/apis/apps/v1/namespaces/' + NS + '/statefulsets/' + name)
            policy = statefulset['spec'].get('persistentVolumeClaimRetentionPolicy', {})
            require(policy.get('whenDeleted', 'Retain') == 'Retain' and policy.get('whenScaled', 'Retain') == 'Retain',
                    'Loki/Tempo claim auto-deletion is enabled')


if __name__ == '__main__':
    try:
        Qualification().run()
    except Exception as error:
        # All sources/credentials are synthetic; still never print API or subprocess bodies.
        print(str(error) if isinstance(error, RuntimeError) else 'Stack fixture failed: ' + type(error).__name__, flush=True)
        raise SystemExit(1) from None
