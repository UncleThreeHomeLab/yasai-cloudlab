"""Observe composition callers or use bounded fixtures for ordinary workload identity."""
import hashlib
import ipaddress
import uuid

from playbooks.istio.files.kube import condition, get, kube, wait


def composition(entry):
    from playbooks.services.files.composition_verify import authority, owned_pods
    from playbooks.services.files.compositions import backend
    definition, approval = entry['definition'], entry['approval']
    namespace, value = approval['namespace'], approval['composition']
    backend(definition, approval, get, condition)
    images = authority(entry, get)
    pods = owned_pods(entry, images, get, condition)
    accounts = list(dict.fromkeys(row['podSpec'].get('serviceAccountName', 'default') for row in value['workloads']))
    expected = {'platform-workloads': {'action': 'ALLOW', 'rules': [{'from': [{'source': {
        'principals': ['cluster.local/ns/' + namespace + '/sa/' + name for name in accounts]}}]}]}}
    networks = {'platform-deny': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}}
    exposures = [definition['exposure']] + definition.get('additionalExposures', [])
    for host, selected in value['backends'].items():
        classes = list(dict.fromkeys(row['class'] for row in exposures if row.get('hostname') == host and row['class'] != 'none'))
        suffix = hashlib.sha256(host.encode()).hexdigest()[:12]
        expected['platform-gateway-' + suffix] = {'selector': {'matchLabels': selected['selector']}, 'action': 'ALLOW',
            'rules': [{'from': [{'source': {'principals': ['cluster.local/ns/cloudlab-gateway-' + name +
                '/sa/cloudlab-istio' for name in classes]}}], 'to': [{'operation': {'ports': [str(selected['port'])]}}]}]}
        networks['platform-ingress-' + suffix] = {'podSelector': {'matchLabels': selected['selector']},
            'policyTypes': ['Ingress'], 'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {
                'kubernetes.io/metadata.name': 'cloudlab-gateway-' + name}}}], 'ports': [
                    {'protocol': 'TCP', 'port': selected['port']}, {'protocol': 'TCP', 'port': 15008}]} for name in classes]}
        service = get('service', selected['service'], namespace) or {}
        spec = service.get('spec', {})
        if (spec.get('type') != 'ClusterIP' or spec.get('externalIPs') or spec.get('externalName') or
                spec.get('selector') != selected['selector'] or not any(row['port'] == selected['port'] and
                row.get('protocol', 'TCP') == 'TCP' for row in spec.get('ports', []))):
            raise RuntimeError('Composition Service differs from its approved private backend')
    policies = (get('authorizationpolicies.security.istio.io', namespace=namespace) or {}).get('items', [])
    if len(policies) != len(expected) or any(row['metadata']['name'] not in expected or
            row['spec'] != expected[row['metadata']['name']] or not row['metadata'].get('annotations', {}).get(
                'argocd.argoproj.io/tracking-id', '').startswith('cloudlab-services:') for row in policies):
        raise RuntimeError('Composition identities differ from their exact platform-owned policies')
    actual_networks = (get('networkpolicies', namespace=namespace) or {}).get('items', [])
    found = set()
    for row in actual_networks:
        name = row['metadata']['name']
        tracking = row['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '')
        if name in networks:
            spec = dict(row['spec'])
            for key in ('ingress', 'egress'):
                if key in networks[name]: spec.setdefault(key, [])
            if spec != networks[name] or not tracking.startswith('cloudlab-services:'):
                raise RuntimeError('Composition platform network boundary differs from its reviewed owner')
            found.add(name)
        elif not tracking.startswith(approval['name'] + '-' + definition['name'] + ':'):
            raise RuntimeError('Composition network policy has an unapproved controller')
    if found != set(networks):
        raise RuntimeError('Composition platform network boundary is incomplete')
    selected = value['backends'].get(definition['exposure'].get('hostname'))
    if not selected:
        raise RuntimeError('Composition network proof needs its approved primary health backend')
    target = next((pod for pod in pods if all(pod['metadata'].get('labels', {}).get(key) == label
                  for key, label in selected['selector'].items())), None)
    if not target: raise RuntimeError('Composition health backend has no owned ready Pod')
    def python_container(pod):
        for container in pod['spec']['containers']:
            for argument in container.get('command', []) + container.get('args', []):
                if argument in ('python', 'python3'):
                    return container['name'], argument
        return None
    candidates = []
    namespaces = (get('namespace') or {}).get('items', [])
    if len(namespaces) > 128: raise RuntimeError('Composition caller inventory exceeds its bound')
    for row in namespaces:
        labels = row['metadata'].get('labels', {})
        other = row['metadata']['name']
        if other == namespace or labels.get('cloudlab.io/owner') != 'service-platform' or labels.get(
                'pod-security.kubernetes.io/enforce') != 'restricted': continue
        for pod in (get('pods', namespace=other) or {}).get('items', []):
            if condition(pod, 'Ready') and pod.get('status', {}).get('phase') == 'Running' and python_container(pod):
                candidates.append((other, pod))
    if not candidates or not python_container(target):
        raise RuntimeError('Composition network proof requires existing ready Python callers')
    candidates.sort(key=lambda pair: pair[1]['spec'].get('nodeName') == target['spec'].get('nodeName'))
    other_namespace, foreign = candidates[0]
    address = ipaddress.ip_address(target['status']['podIP'])
    host = '[' + str(address) + ']' if address.version == 6 else str(address)
    url = 'http://' + host + ':' + str(selected['port']) + definition['health']['readiness']['path']
    code = """import urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
 with opener.open(URL,timeout=5) as response: allowed=response.status==200
except Exception: allowed=False
print('allowed' if allowed else 'denied')
""".replace('URL', repr(url))
    for source_namespace, pod, required in ((namespace, target, 'allowed'), (other_namespace, foreign, 'denied'),
                                             (namespace, target, 'allowed')):
        container, executable = python_container(pod)
        if kube('exec', '-n', source_namespace, pod['metadata']['name'], '-c', container, '--', executable,
                '-I', '-S', '-c', code).strip() != required:
            raise RuntimeError('Composition real-caller health or network denial was not proved')
    return {'owned_pods': len(pods), 'ambient_capture': True, 'scoped_identity_and_network': True,
            'existing_caller_denied': True, 'cross_node_caller': foreign['spec'].get('nodeName') != target['spec'].get('nodeName'),
            'probe_pods_created': 0}


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
            actual['spec'] != {'selector': {'matchLabels': {'cloudlab.io/owner': definition['owner']}},
                               'action': 'ALLOW', 'rules': [{'from': [{'source': {'principals': expected}}]}]}):
        raise RuntimeError('Workload policy differs from its exact platform-owned identities')
    return accounts[0]


def run(entry, image):
    if entry['approval'].get('composition'):
        return composition(entry)
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
               'image': image, 'command': ['sleep', '3600'],
               'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'cpu': '50m', 'memory': '32Mi'}},
               'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                   'capabilities': {'drop': ['ALL']}}}]}}
        kube('create', '-f', '-', document=obj)
        uid = get('pod', name, namespace)['metadata']['uid']
        try:
            wait(lambda: condition(get('pod', name, namespace), 'Ready') and
                 get('pod', name, namespace)['metadata'].get('annotations', {}).get('ambient.istio.io/redirection') == 'enabled',
                 'live application workload identity capture', timeout=120)
            actual = get('pod', name, namespace)
            if (actual['status']['phase'] != 'Running' or actual['metadata'].get('annotations', {}).get('ambient.istio.io/redirection') != 'enabled' or
                    kube('exec', '-n', namespace, name, '--', 'python', '-c', code).strip() != ('allowed' if allowed else 'denied')):
                raise RuntimeError('Authorized or unauthorized workload identity behavior failed')
        finally:
            actual = get('pod', name, namespace)
            if actual and (actual['metadata']['uid'] != uid or actual['metadata'].get('labels', {}).get('cloudlab.io/fixture') != nonce):
                raise RuntimeError('Workload proof ownership changed; cleanup refused')
            if actual: kube('delete', 'pod', name, '-n', namespace, '--wait=true')
    return {'cross_node_workload_identity': True, 'unapproved_identity_denied': True}
