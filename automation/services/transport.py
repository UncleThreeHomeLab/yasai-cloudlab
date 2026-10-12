"""Cross-node callers prove workload identity policy separately from JWTs."""
import uuid

from automation.mesh.kube import condition, get, kube, wait


def policy(entry):
    definition, approval = entry['definition'], entry['approval']
    namespace = approval['namespace']
    accounts = ['notes-web', 'notes-api'] if approval.get('chartPath') == 'apps/notes' else [definition['name']]
    classes = sorted({exposure['class'] for exposure in [definition['exposure']] +
                      definition.get('additionalExposures', []) if exposure['class'] != 'none'})
    expected = ['cluster.local/ns/' + namespace + '/sa/' + account for account in accounts]
    expected += ['cluster.local/ns/cloudlab-gateway-' + exposure + '/sa/cloudlab-istio' for exposure in classes]
    actual = get('authorizationpolicy.security.istio.io', 'platform-workloads', namespace)
    if (not actual or not actual['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-services:') or
            actual['spec'] != {'selector': {}, 'action': 'ALLOW', 'rules': [{'from': [{'source': {'principals': expected}}]}]}):
        raise RuntimeError('Workload policy differs from its exact platform-owned identities')
    return accounts[0]


def run(entry, image):
    definition, namespace = entry['definition'], entry['approval']['namespace']
    account = policy(entry)
    backend = next((pod for pod in get('pods', namespace=namespace)['items'] if
                    pod['metadata'].get('labels', {}).get('app.kubernetes.io/name') == account and condition(pod, 'Ready')), None)
    nodes = get('nodes')['items']
    other = next((node['metadata']['name'] for node in nodes if condition(node, 'Ready') and
                  node['metadata']['name'] != backend['spec']['nodeName']), None) if backend else None
    if not other: raise RuntimeError('Identity proof requires a ready backend and another ready node')
    port = next(value['port'] for value in definition['ports'] if value['name'] == definition['health']['readiness']['port'])
    url = 'http://' + backend['status']['podIP'] + ':' + str(port) + definition['health']['readiness']['path']
    for allowed in (True, False):
        nonce = uuid.uuid4().hex[:12]
        name = 'identity-proof-' + nonce
        code = """import urllib.request,time
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
success=False
for attempt in range(10):
 try:
  with opener.open(URL,timeout=3) as response: success=response.status==200
 except Exception: pass
 if success: break
 time.sleep(1)
print('allowed' if success else 'denied')
""".replace('URL', repr(url))
        obj = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace,
               'labels': {'cloudlab.io/fixture': nonce}}, 'spec': {'restartPolicy': 'Never',
               'nodeSelector': {'kubernetes.io/hostname': other}, 'serviceAccountName': account if allowed else 'default',
               'automountServiceAccountToken': False, 'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001,
               'runAsGroup': 10001, 'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': [{'name': 'proof',
               'image': image, 'command': ['python', '-c', code],
               'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'cpu': '50m', 'memory': '32Mi'}},
               'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                   'capabilities': {'drop': ['ALL']}}}]}}
        kube('create', '-f', '-', document=obj)
        uid = get('pod', name, namespace)['metadata']['uid']
        try:
            wait(lambda: get('pod', name, namespace).get('status', {}).get('phase') in ('Succeeded', 'Failed'),
                 'application workload identity proof', timeout=120)
            actual = get('pod', name, namespace)
            if (actual['status']['phase'] != 'Succeeded' or actual['metadata'].get('annotations', {}).get('ambient.istio.io/redirection') != 'enabled' or
                    kube('logs', name, '-n', namespace).strip() != ('allowed' if allowed else 'denied')):
                raise RuntimeError('Authorized or unauthorized workload identity behavior failed')
        finally:
            actual = get('pod', name, namespace)
            if actual and (actual['metadata']['uid'] != uid or actual['metadata'].get('labels', {}).get('cloudlab.io/fixture') != nonce):
                raise RuntimeError('Workload proof ownership changed; cleanup refused')
            if actual: kube('delete', 'pod', name, '-n', namespace, '--wait=true')
    return {'cross_node_workload_identity': True, 'unapproved_identity_denied': True}
