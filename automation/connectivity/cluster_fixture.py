"""Disposable real routes for outside access checks; never modify application data."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mesh'))
import fixtures
from kube import condition, get, kube, wait

OWNER = 'cloudlab-access-verify'
NAMES = ['cloudlab-access-proof-public', 'cloudlab-access-proof-private']
PROOF_PATH = '/__cloudlab_access_proof'


def owned(namespace):
    existing = get('namespace', namespace)
    if existing and existing['metadata'].get('labels', {}).get('app.kubernetes.io/managed-by') != OWNER:
        raise RuntimeError('Access fixture namespace has a different owner')
    return existing


def cleanup():
    for namespace in NAMES:
        if owned(namespace):
            kube('delete', 'namespace', namespace, '--wait=true', '--timeout=120s', timeout=150)


def prepare(payload):
    certificate = get('certificate.cert-manager.io', 'cloudlab-gateway', 'cloudlab-gateway-public')
    if not condition(certificate, 'Ready'):
        raise RuntimeError('Public gateway certificate is not ready')
    names = certificate['spec']['dnsNames']
    if len(names) != 1 or not names[0].startswith('*.'):
        raise RuntimeError('Public certificate wildcard contract changed')
    zone = names[0][2:]
    cleanup()
    for namespace, exposure in zip(NAMES, ('public', 'private')):
        ns = fixtures.namespace(namespace, exposure, ambient=True)
        ns['metadata']['labels']['app.kubernetes.io/managed-by'] = OWNER
        pod = fixtures.pod(namespace, 'backend', payload['smoke_image'], 'backend', server=True)
        spec = pod['spec']
        spec.pop('activeDeadlineSeconds')
        spec['restartPolicy'] = 'Always'
        spec['topologySpreadConstraints'] = [{'maxSkew': 1, 'topologyKey': 'kubernetes.io/hostname',
            'whenUnsatisfiable': 'DoNotSchedule', 'labelSelector': {'matchLabels': {'app': 'backend'}}}]
        deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
            'metadata': {'name': 'backend', 'namespace': namespace},
            'spec': {'replicas': 2, 'selector': {'matchLabels': {'app': 'backend'}},
                     'template': {'metadata': {'labels': pod['metadata']['labels']}, 'spec': spec}}}
        objects = [ns, fixtures.account(namespace, 'backend'), fixtures.service(namespace), deployment]
        objects += fixtures.identity_policy(namespace, ['cluster.local/ns/cloudlab-gateway-' + exposure + '/sa/cloudlab-istio'])
        objects += [fixtures.network_policy(namespace)]
        labels = [rule['name'] for rule in payload['public']] if exposure == 'public' else payload['private']
        for label in labels:
            hostname = label + ('.internal.' if exposure == 'private' else '.') + zone
            route = fixtures.route(namespace, label, exposure, hostname)
            route['spec']['rules'][0]['matches'] = [{'path': {'type': 'Exact', 'value': PROOF_PATH}}]
            objects.append(route)
        kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=fixtures.document(objects))
        kube('rollout', 'status', 'deployment/backend', '-n', namespace, '--timeout=180s', timeout=210)
        for label in labels:
            def accepted():
                route = get('httproute.gateway.networking.k8s.io', label, namespace)
                return any(all(any(c.get('type') == name and c.get('status') == 'True'
                                   and c.get('observedGeneration') == route['metadata']['generation']
                                   for c in p.get('conditions', [])) for name in ('Accepted', 'ResolvedRefs'))
                           for p in route.get('status', {}).get('parents', []))
            wait(accepted, 'access fixture route readiness', timeout=120)
    return {'fixture_ready': True}


def snapshot():
    result = {}
    for namespace, selector in [('cloudlab-connectors', 'app=cloudflared'),
                                ('cloudlab-gateway-public', 'gateway.networking.k8s.io/gateway-name=cloudlab'),
                                ('cloudlab-gateway-private', 'gateway.networking.k8s.io/gateway-name=cloudlab'),
                                ('tailscale', 'cloudlab.io/proxy=cloudlab-ingress'),
                                ('tailscale', 'cloudlab.io/proxy=cloudlab-api')]:
        pods = json.loads(kube('get', 'pods', '-n', namespace, '-l', selector, '-o', 'json'))['items']
        if len(pods) != 2 or len({p['spec']['nodeName'] for p in pods}) != 2 or not all(condition(p, 'Ready') for p in pods):
            raise RuntimeError('Access replicas are not ready on two distinct nodes')
        if any(not all(c.get(probe) for probe in ('startupProbe', 'readinessProbe', 'livenessProbe'))
               for p in pods for c in p['spec']['containers']):
            raise RuntimeError('An access replica lacks its required health probes')
        budgets = get('poddisruptionbudgets', namespace=namespace)['items']
        selected = [b for b in budgets if b['spec'].get('selector', {}).get('matchLabels')
                    and all(all(p['metadata'].get('labels', {}).get(k) == v
                        for k, v in b['spec']['selector']['matchLabels'].items()) for p in pods)]
        if not any(b['spec'].get('minAvailable') == 1 and b.get('status', {}).get('currentHealthy') == 2
                   and b.get('status', {}).get('disruptionsAllowed') == 1 for b in selected):
            raise RuntimeError('Access replicas lack a ready one-at-a-time disruption budget')
        result[namespace + '/' + selector] = [{'name': p['metadata']['name'], 'uid': p['metadata']['uid'],
            'containers': [c['containerID'].removeprefix('containerd://') for c in p['status']['containerStatuses']]} for p in pods]
    return result


def identities():
    import hashlib
    retained = {}
    for group in ('cloudlab-api', 'cloudlab-ingress'):
        retained[group] = get('proxygroup', group)['metadata']['uid']
        for index in range(2):
            name = group + '-' + str(index)
            secret = get('secret', name, 'tailscale')
            data = secret.get('data', {})
            if not data.get('device_id') or not data.get('_machinekey'):
                raise RuntimeError('Proxy device identity is not persisted')
            retained[name] = {'uid': secret['metadata']['uid'],
                'identity': hashlib.sha256(json.dumps({key: data[key] for key in ('device_id', '_machinekey')}, sort_keys=True).encode()).hexdigest()}
    service = get('service', 'cloudlab-tailnet', 'cloudlab-gateway-private')
    retained['private-service'] = {'uid': service['metadata']['uid'], 'addresses': service['status']['loadBalancer']}
    return retained


def runtime():
    from dns_inputs import read
    private = read()
    group = get('proxygroup', 'cloudlab-api')
    if not condition(group, 'ProxyGroupReady'):
        raise RuntimeError('API proxy group is not ready')
    identity = get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', 'cloudlab-identity') if get(
        'customresourcedefinition', 'keycloaks.k8s.keycloak.org') else None
    return {'private': private, 'zone': private['zone'].removeprefix('internal.'),
            'api_url': group['status']['url'], 'identity_server_present': bool(identity)}


def dns_proof(payload):
    import socket
    settings = runtime()['private']
    hostname = payload['private'][0] + '.' + settings['zone']
    if socket.gethostbyname(hostname) != settings['cluster_gateway']:
        raise RuntimeError('Host default resolver did not use private DNS')
    pods = get('pods', namespace=NAMES[1])['items']
    if len(pods) != 2:
        raise RuntimeError('Both private backend fixtures are required for DNS proof')
    for pod in pods:
        answer = kube('exec', '-n', NAMES[1], pod['metadata']['name'], '--', 'nslookup', hostname)
        if settings['cluster_gateway'] not in answer:
            raise RuntimeError('Pod default resolver did not return the internal gateway address')
        denied = kube('exec', '-n', NAMES[1], pod['metadata']['name'], '--', 'nslookup',
                      'nonexistent-cloudlab-proof.' + settings['zone'], allow_failure=True)
        if denied.returncode == 0 or 'NXDOMAIN' not in denied.stdout + denied.stderr:
            raise RuntimeError('Unknown private name did not fail closed from a Pod')
    return {'server_default_dns': True, 'pod_default_dns_both_nodes': True, 'pod_unknown_private_denied': True}


def fail_one(payload):
    allowed = snapshot()
    key = payload['component']
    if key not in allowed:
        raise RuntimeError('Failure target is outside the disposable access components')
    namespace = key.split('/')[0]
    target = allowed[key][0]
    if namespace == 'tailscale':
        pod = get('pod', target['name'], namespace)
        containers = pod['status']['containerStatuses']
        if len(containers) != 1 or not containers[0].get('ready'):
            raise RuntimeError('Proxy crash fixture requires one healthy container')
        return {'crash_target': {'name': target['name'], 'uid': target['uid'],
            'container_id': containers[0]['containerID'].removeprefix('containerd://')},
            'node': pod['spec']['nodeName'], 'component': key}
    kube('delete', 'pod', target['name'], '-n', namespace, '--grace-period=0', '--force', '--wait=false')
    return {'deleted_uid': target['uid'], 'component': key}


if __name__ == '__main__':
    try:
        payload = json.load(sys.stdin)
        action = payload['action']
        if action == 'prepare':
            result = prepare(payload)
        elif action == 'cleanup':
            cleanup()
            result = {'fixtures_removed': True}
        elif action == 'snapshot':
            result = snapshot()
        elif action == 'identities':
            result = identities()
        elif action == 'runtime':
            result = runtime()
        elif action == 'dns-proof':
            result = dns_proof(payload)
        elif action == 'fail-one':
            result = fail_one(payload)
        else:
            raise ValueError('Unknown access fixture action')
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Access fixture operation failed; production data and management paths retained.') from None
