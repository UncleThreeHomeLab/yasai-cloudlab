"""Platform-controlled preview project, chart, policies and private route."""
import json
from pathlib import Path

try:
    from .contract import OWNER, IMAGE, ANONYMOUS_INTERVAL, approval, canonical, digest, names, runtime_catalog
except ImportError:
    from contract import OWNER, IMAGE, ANONYMOUS_INTERVAL, approval, canonical, digest, names, runtime_catalog


def metadata(row, state_uid, name, namespace=None):
    return {'name': name, **({'namespace': namespace} if namespace else {}),
        'labels': {'cloudlab.io/owner': OWNER, 'cloudlab.io/preview-instance': row['instance']},
        'annotations': {'cloudlab.io/approval-digest': digest(canonical(row)),
                        'cloudlab.io/runtime-state-uid': state_uid}}


def workload(row, settings, state_uid='render-only'):
    approval(row)
    definition = row['definition']
    n = names(row)
    fixture = definition['profile'] == 'synthetic'
    environment = {} if fixture else definition['environment']
    result = {'name': 'preview', 'owner': OWNER, 'image': row['image'],
        'replicas': 1, 'command': [], 'initCommand': [], 'previewWaypoint': True,
        'previewIdentity': {'instance': row['instance'], 'approvalDigest': digest(canonical(row)), 'runtimeStateUID': state_uid},
        'ports': [{'name': 'http', 'port': 8080 if fixture else definition['port']}],
        'health': {kind: {'path': '/healthz', 'port': 'http'} for kind in ('readiness', 'liveness')},
        'resources': {'requests': {'cpu': '50m', 'memory': '32Mi'}, 'limits': {'cpu': '200m', 'memory': '128Mi'}} if fixture else definition['resources'],
        'environment': dict(environment, CLOUDLAB_SOURCE_SHA=row['sourceSha'],
            CLOUDLAB_PREVIEW_PATH=n['path'], OIDC_CALLBACK_PATH=n['path'] + 'callback',
            OIDC_REDIRECT_URI='https://' + settings['hostname'] + n['path'] + 'callback',
            OIDC_ISSUER=settings['issuer'], OIDC_CLIENT_ID=n['client'], OIDC_AUDIENCE=n['client']),
        'secrets': [], 'configMaps': [], 'data': {}, 'persistence': {'enabled': False, 'size': '1Gi', 'mountPath': '/data', 'retention': 'retain'},
        'exposure': {'class': 'none'}, 'additionalExposures': [], 'oidc': {'enabled': False},
        'monitoring': {'enabled': False}, 'rollouts': {'enabled': False},
        'artifactPolicyHash': digest(canonical({'definition': definition, 'source': row['sourceSha'],
            'trust': settings['artifacts'].get(row['image'].split('@')[0])}))}
    if fixture:
        result['environment']['PREVIEW_MESSAGE'] = definition['message']
        result['command'] = ['python', '-c', '''import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/healthz': value = {'ready': True}
        elif path == os.environ['OIDC_CALLBACK_PATH']: value = {'callback': True}
        else: value = {'message': os.environ['PREVIEW_MESSAGE'], 'source': os.environ['CLOUDLAB_SOURCE_SHA']}
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()''']
    return result


def resources(row, settings, platform_repository, state_uid):
    runtime_catalog(settings)
    approval(row)
    n = names(row)
    ns = n['namespace']
    port = 8080 if row['definition']['profile'] == 'synthetic' else row['definition']['port']
    objects = []
    def add(version, kind, name, spec=None, namespace=ns, **fields):
        obj = {'apiVersion': version, 'kind': kind, 'metadata': metadata(row, state_uid, name, namespace), **fields}
        if spec is not None:
            obj['spec'] = spec
        objects.append(obj)
        return obj
    namespace = add('v1', 'Namespace', ns, namespace=None)
    namespace['metadata']['labels'].update({'pod-security.kubernetes.io/enforce': 'restricted',
        'pod-security.kubernetes.io/enforce-version': 'v1.36', 'istio.io/dataplane-mode': 'ambient',
        'istio.io/use-waypoint': 'preview-waypoint', 'cloudlab.io/gateway': 'private'})
    add('rbac.authorization.k8s.io/v1', 'RoleBinding', 'preview-inventory',
        roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'cloudlab-preview-inventory'},
        subjects=[{'kind': 'ServiceAccount', 'name': OWNER, 'namespace': 'argocd'}])
    add('v1', 'ResourceQuota', 'budget', {'hard': {'pods': '4', 'requests.cpu': '500m', 'requests.memory': '768Mi',
        'limits.cpu': '1', 'limits.memory': '1Gi', 'persistentvolumeclaims': '0',
        'services.loadbalancers': '0', 'services.nodeports': '0', 'count/secrets': '0'}})
    add('v1', 'LimitRange', 'budget', {'limits': [{'type': 'Container',
        'max': {'cpu': '250m', 'memory': '256Mi'}, 'default': {'cpu': '250m', 'memory': '256Mi'},
        'defaultRequest': {'cpu': '50m', 'memory': '128Mi'}}]})
    add('networking.k8s.io/v1', 'NetworkPolicy', 'default-deny', {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']})
    dns = {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                   'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
           'ports': [{'protocol': p, 'port': 53} for p in ('UDP', 'TCP')]}
    gateway_selector = {'matchLabels': {'gateway.networking.k8s.io/gateway-name': 'preview-waypoint'}}
    add('networking.k8s.io/v1', 'NetworkPolicy', 'waypoint', {'podSelector': gateway_selector,
        'policyTypes': ['Ingress', 'Egress'],
        'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'cloudlab-gateway-private'}}}],
                     'ports': [{'port': 15008, 'protocol': 'TCP'}]},
                    {'from': [{'ipBlock': {'cidr': '169.254.7.127/32'}}], 'ports': [{'port': 15021, 'protocol': 'TCP'}]}],
        'egress': [dns, {'to': [{'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'preview'}}}],
                         'ports': [{'port': port, 'protocol': 'TCP'}]},
                   {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'istio-system'}},
                            'podSelector': {'matchLabels': {'app': 'istiod'}}}],
                    'ports': [{'port': 15012, 'protocol': 'TCP'}]}]})
    add('networking.k8s.io/v1', 'NetworkPolicy', 'application', {
        'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'preview'}}, 'policyTypes': ['Ingress', 'Egress'],
        'ingress': [{'from': [{'podSelector': gateway_selector}], 'ports': [{'port': port, 'protocol': 'TCP'}]},
                    {'from': [{'ipBlock': {'cidr': '169.254.7.127/32'}}], 'ports': [{'port': port, 'protocol': 'TCP'}]}],
        'egress': [dns]})
    add('security.istio.io/v1', 'PeerAuthentication', 'strict', {'mtls': {'mode': 'STRICT'}})
    add('security.istio.io/v1', 'AuthorizationPolicy', 'waypoint-only', {
        'selector': {'matchLabels': {'app.kubernetes.io/name': 'preview'}}, 'action': 'ALLOW',
        'rules': [{'from': [{'source': {'principals': ['cluster.local/ns/' + ns + '/sa/preview-waypoint']}}]}]})
    target = [{'group': '', 'kind': 'Service', 'name': 'preview'}]
    add('security.istio.io/v1', 'RequestAuthentication', 'identity', {'targetRefs': target,
        'jwtRules': [{'issuer': settings['issuer'], 'jwksUri': settings['issuer'] + '/protocol/openid-connect/certs',
                      'audiences': [n['client']], 'forwardOriginalToken': True}]})
    add('security.istio.io/v1', 'AuthorizationPolicy', 'identity', {'targetRefs': target, 'action': 'ALLOW',
        'rules': [{'to': [{'operation': {'paths': ['/healthz', n['path'] + 'callback']}}]},
                  {'from': [{'source': {'requestPrincipals': [settings['issuer'] + '/*']}}],
                   'when': [{'key': 'request.auth.claims[aud]', 'values': [n['client']]},
                            {'key': 'request.auth.claims[azp]', 'values': [n['client']]}]}]})
    images = json.loads(Path(__file__).with_name('images.lock.json').read_text())
    proxy = images['proxyv2']
    patch = '''spec:
  replicas: 1
  strategy:
    rollingUpdate: {maxSurge: 1, maxUnavailable: 0}
  template:
    spec:
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: istio-proxy
          image: %s
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
          resources:
            requests: {cpu: 50m, memory: 128Mi}
            limits: {cpu: 250m, memory: 256Mi}
''' % proxy
    add('v1', 'ConfigMap', 'preview-waypoint-options', data={'deployment': patch})
    add('gateway.networking.k8s.io/v1', 'Gateway', 'preview-waypoint', {
        'gatewayClassName': 'istio-waypoint',
        'infrastructure': {'parametersRef': {'group': '', 'kind': 'ConfigMap', 'name': 'preview-waypoint-options'}},
        'listeners': [{'name': 'mesh', 'port': 15008, 'protocol': 'HBONE', 'allowedRoutes': {'namespaces': {'from': 'Same'}}}]})['metadata']['labels']['istio.io/waypoint-for'] = 'service'
    definition = workload(row, settings, state_uid)
    policy = add('kyverno.io/v1', 'Policy', 'preview-artifacts', {'background': False, 'validationFailureAction': 'Enforce',
        'webhookConfiguration': {'failurePolicy': 'Fail', 'timeoutSeconds': 30}, 'rules': [{
            'name': 'exact-images', 'match': {'any': [{'resources': {'kinds': ['Pod']}}]},
            'validate': {'message': 'Only immutable approved preview and waypoint images are permitted.',
                'foreach': [{'list': 'request.object.spec.[initContainers, ephemeralContainers, containers][]',
                    'deny': {'conditions': {'all': [{'key': '{{ element.image }}', 'operator': 'NotIn',
                                                   'value': [definition['image'], proxy]}]}}}]}}]})
    policy['metadata']['annotations']['pod-policies.kyverno.io/autogen-controllers'] = 'none'
    if row['definition']['profile'] == 'application':
        trust = settings['artifacts'][row['image'].split('@')[0]]
        policy['spec']['rules'].append({'name': 'exact-signed-revision',
            'match': {'any': [{'resources': {'kinds': ['Pod'], 'selector': {'matchLabels': {'app.kubernetes.io/name': 'preview'}}}}]},
            'verifyImages': [{'imageReferences': [definition['image']], 'type': 'Cosign', 'mutateDigest': False,
                'verifyDigest': True, 'required': True, 'attestors': [{'count': 1, 'entries': [{'keyless': {
                    'issuer': trust['issuer'], 'subject': trust['subject'],
                    'roots': Path(__file__).with_name('sigstore-fulcio.crt').read_text(),
                    'additionalExtensions': {'githubWorkflowRepository': row['repository'], 'githubWorkflowSha': row['sourceSha']},
                    'rekor': {'url': 'https://rekor.sigstore.dev'}}}]}]}]})
    add('argoproj.io/v1alpha1', 'AppProject', n['name'], {'sourceRepos': [platform_repository],
        'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': ns}],
        'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [
            {'group': group, 'kind': kind} for group, kind in (('', 'ServiceAccount'), ('', 'Service'), ('apps', 'Deployment'))]}, namespace='argocd')
    template_meta = metadata(row, state_uid, n['name'])
    add('argoproj.io/v1alpha1', 'ApplicationSet', n['name'], {
        'goTemplate': True, 'goTemplateOptions': ['missingkey=error'],
        'generators': [{'pullRequest': {'github': dict(zip(('owner', 'repo'), row['repository'].split('/')),
            **({'tokenRef': {'secretName': 'github-preview-discovery', 'key': 'TOKEN'}} if settings['privateDiscovery'] else {})),
            'requeueAfterSeconds': 60 if settings['privateDiscovery'] else ANONYMOUS_INTERVAL, 'continueOnRepoNotFoundError': False},
            'selector': {'matchLabels': {'number': str(row['pullRequest']), 'head_sha': row['sourceSha']}}}],
        'syncPolicy': {'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True},
        'template': {'metadata': template_meta, 'spec': {'project': n['name'],
            'source': {'repoURL': platform_repository, 'targetRevision': row['platformRevision'], 'path': 'charts/service',
                       'helm': {'releaseName': n['name'], 'valuesObject': definition}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': ns},
            'syncPolicy': {'automated': {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': False},
                           'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}}, namespace='argocd')
    return objects


def private_route(row, settings, state_uid):
    approval(row)
    n = names(row)
    port = 8080 if row['definition']['profile'] == 'synthetic' else row['definition']['port']
    return {'apiVersion': 'gateway.networking.k8s.io/v1', 'kind': 'HTTPRoute',
        'metadata': metadata(row, state_uid, 'preview', n['namespace']),
        'spec': {'parentRefs': [{'name': 'cloudlab', 'namespace': 'cloudlab-gateway-private', 'sectionName': 'https'}],
                 'hostnames': [settings['hostname']], 'rules': [{'matches': [{'path': {'type': 'PathPrefix', 'value': n['path']}}],
                    'backendRefs': [{'name': 'preview', 'port': port}]}]}}


def workload_keys(row):
    namespace = names(row)['namespace']
    return [(version, kind, namespace, 'preview') for version, kind in (
        ('v1', 'ServiceAccount'), ('v1', 'Service'), ('apps/v1', 'Deployment'))]
