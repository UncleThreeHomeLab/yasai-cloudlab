"""In-memory provider for access reconciliation and identity tests."""
import copy


class Provider:
    def __init__(self):
        self.objects = {}
        self.config = {'config': {'ingress': [{'service': 'http_status:404'}]}}
        self.writes = []
        self.interrupt_create = False

    def collection(self, path):
        return [copy.deepcopy(v) for k, v in self.objects.items() if k.rsplit('/', 1)[0] == path]

    def request(self, method, path, document=None):
        if method != 'GET':
            self.writes.append((method, path))
        if path.endswith('/configurations'):
            if method == 'PUT':
                self.config = copy.deepcopy(document)
            return copy.deepcopy(self.config)
        if method == 'POST':
            identity = str(len(self.objects) + 1)
            value = dict(copy.deepcopy(document), id=identity)
            if path.endswith('/apps'):
                value['aud'] = 'fixture-audience'
            self.objects[path + '/' + identity] = value
            if self.interrupt_create:
                self.interrupt_create = False
                raise RuntimeError('connection lost after server committed creation')
            return copy.deepcopy(value)
        if method == 'PUT':
            self.objects[path].update(copy.deepcopy(document))
        return copy.deepcopy(self.objects[path])


def native_access(stage='native', bound=True):
    import base64
    import hashlib
    import json
    from pathlib import Path
    from unittest.mock import Mock, patch
    import yaml
    from playbooks.access.files import inputs, initial_bootstrap, native
    public = yaml.safe_load((Path(__file__).resolve().parents[4] / 'gitops/roots/public/values.yaml').read_text())
    public['repository'] = 'https://github.com/example/platform.git'
    private = 'https://github.com/example/private.git'
    target = {'valuesRepository': private, 'valuesRevision': 'b' * 40}
    raw = b'administrator: admin@example.invalid\n'
    client = Mock(request=Mock(return_value={'type': 'file', 'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()}))
    with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=lambda v, read: read(client, 'c' * 40)):
        contract = inputs.prepare({'PRIVATE_CONFIG_REPOSITORY': private}, public, target, 'd' * 40)
    payload = {'repository': public['repository'], 'private_repository': private, 'branch': 'main', 'revision': 'd' * 40,
        'access_observation': inputs.observation(public, private)}
    state = {'phase': 'configured', 'administrator': hashlib.sha256(b'admin@example.invalid').hexdigest(),
        'application_uid': 'access-app', 'identities': {}}
    objects = {}
    root = {'metadata': {'uid': 'root'}, 'spec': {'project': 'cloudlab-root', 'source': {
        'repoURL': public['repository'], 'targetRevision': 'main', 'path': 'gitops/roots/public',
        'helm': {'valuesObject': {'identity': {'argo': target}} if bound else {}}},
        'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}},
        'status': {'sync': {'status': 'Synced', 'revision': 'd' * 40}, 'health': {'status': 'Healthy'}}}
    objects['application.argoproj.io', 'cloudlab-public-root', 'argocd'] = root
    for kind, name, uid in [('statefulset', 'argocd-application-controller', 'controller'), ('appproject.argoproj.io', 'cloudlab-root', 'root-project')]:
        objects[kind, name, 'argocd'] = {'metadata': {'uid': uid}}
    objects['application.argoproj.io', 'cloudlab-tailscale-operator', 'argocd'] = {
        'status': {'sync': {'status': 'Synced', 'revision': 'd' * 40}, 'health': {'status': 'Healthy'}}}
    for kind, name, namespace in [('proxygroup', 'cloudlab-ingress', None), ('proxygroup', 'cloudlab-api', None),
            ('service', 'cloudlab-tailnet', 'cloudlab-gateway-private'),
            ('secret', 'operator-oauth', 'tailscale'), ('secret', 'cloudflared-runtime', 'cloudlab-connectors')]:
        state['identities'][kind + '/' + name] = name + '-uid'
        obj = {'metadata': {'uid': name + '-uid', 'generation': 1}}
        if kind == 'proxygroup': obj['status'] = {'conditions': [{'type': 'ProxyGroupReady', 'status': 'True', 'observedGeneration': 1}]}
        if kind == 'service': obj['spec'] = {'type': 'LoadBalancer', 'loadBalancerClass': 'tailscale', 'allocateLoadBalancerNodePorts': False,
            'selector': {'gateway.networking.k8s.io/gateway-name': 'cloudlab'}, 'ports': [{'port': 443, 'targetPort': 443}]}
        if kind == 'secret':
            obj['metadata']['ownerReferences'] = [{'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'name': name,
                'uid': name + '-eso', 'controller': True}]
            obj['data'] = {'token': 'c3ludGhldGlj'}
            objects['externalsecret.external-secrets.io', name, namespace] = {'metadata': {'uid': name + '-eso', 'generation': 1},
                'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        objects[kind, name, namespace] = obj
    if stage == 'legacy':
        app = initial_bootstrap.application(payload | {'administrator': 'admin@example.invalid'})
        app['metadata']['managedFields'] = [{'manager': 'cloudlab-access-bootstrap', 'fieldsV1': {'f:spec': {}}}]
        app['status'] = {'sync': {'status': 'Synced', 'revision': 'd' * 40}, 'health': {'status': 'Healthy'}}
    else:
        app = copy.deepcopy(contract['application']); app['spec'].pop('source')
        app['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = native.TRACKING
        app['status'] = {'sync': {'status': 'Synced', 'revisions': [contract['configuration_revision'], 'b' * 40]}, 'health': {'status': 'Healthy'}}
        external = copy.deepcopy(contract['reader']); external['metadata'].update(uid='reader-eso', generation=1)
        external['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'cloudlab-public-root:external-secrets.io/ExternalSecret:argocd/' + native.APP + '-source'
        external['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
        objects['externalsecret.external-secrets.io', native.APP + '-source', 'argocd'] = external
        data = {'type': 'git', 'url': private, 'project': native.APP, 'githubAppID': '1', 'githubAppInstallationID': '2', 'githubAppPrivateKey': 'synthetic-key'}
        objects['secret', native.APP + '-source', 'argocd'] = {'metadata': {'uid': 'reader-secret', 'labels': {'argocd.argoproj.io/secret-type': 'repository'},
            'ownerReferences': [{'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'name': native.APP + '-source', 'uid': 'reader-eso', 'controller': True}]},
            'data': {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}}
    app['metadata']['uid'] = 'access-app'; objects['application.argoproj.io', native.APP, 'argocd'] = app
    project = copy.deepcopy(contract['project']); project['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/AppProject:argocd/' + native.APP}
    if stage == 'legacy': project['spec']['sourceRepos'] = [public['repository']]
    objects['appproject.argoproj.io', native.APP, 'argocd'] = project
    objects['clusterrolebinding.rbac.authorization.k8s.io', native.authority.BINDING, 'argocd'] = {
        'metadata': {'uid': 'administrator-binding', 'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-access:rbac.authorization.k8s.io/ClusterRoleBinding:tailscale/' + native.authority.BINDING}},
        'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'cluster-admin'},
        'subjects': [{'kind': 'User', 'apiGroup': 'rbac.authorization.k8s.io', 'name': 'admin@example.invalid'}]}
    binding_receipt = {'phase': 'accepted', 'target': target, 'root_uid': 'root', 'project_uid': 'root-project', 'controller_uid': 'controller'}
    return contract, payload, state, objects, binding_receipt, client
