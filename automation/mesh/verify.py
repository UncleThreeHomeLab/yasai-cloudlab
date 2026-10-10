"""Real traffic proves ambient identity, network isolation and gateway routing."""
import fcntl
import json
import re
import shlex
import sys
import time
import uuid

from configuration import BASE, component_identities, gateway_api, selected_zone
import fixtures
from kube import application_ready, condition, get, kube, wait


def execute(ns, pod, *command):
    return kube('exec', '-n', ns, pod, '--', *command, allow_failure=True, timeout=45)


def http(ns, pod, target):
    if not condition(get('pod', pod, ns), 'Ready'):
        raise RuntimeError('Traffic fixture is not ready; network denial is unproven')
    result = execute(ns, pod, 'wget', '-qO-', '-T', '5', 'http://' + target + ':8080/')
    return result.returncode == 0 and result.stdout.strip() == 'mesh-ok'


def deny(predicate, label):
    wait(lambda: not predicate(), label, timeout=120)
    for _ in range(3):
        if predicate():
            raise RuntimeError('Denied mesh traffic unexpectedly succeeded: ' + label)
        time.sleep(2)


def mtls_connections(namespace):
    total = 0.0
    pods = get('pods', namespace='istio-system')['items']
    for pod in pods:
        if pod['metadata'].get('labels', {}).get('app') != 'ztunnel':
            continue
        raw = kube('get', '--raw', '/api/v1/namespaces/istio-system/pods/' + pod['metadata']['name'] + ':15020/proxy/metrics')
        for line in raw.splitlines():
            if not line.startswith('istio_tcp_connections_opened_total{'):
                continue
            labels = dict(re.findall(r'([a-z_]+)="([^"\\]*)"', line))
            if (labels.get('connection_security_policy') == 'mutual_tls'
                    and labels.get('source_principal') == 'spiffe://cluster.local/ns/' + namespace + '/sa/allowed'
                    and labels.get('destination_principal') == 'spiffe://cluster.local/ns/' + namespace + '/sa/backend'):
                total += float(line.rsplit(' ', 1)[1])
    return total


def route_status(ns, name, accepted):
    obj = get('httproute.gateway.networking.k8s.io', name, ns)
    for parent in (obj or {}).get('status', {}).get('parents', []):
        if parent.get('controllerName') != 'istio.io/gateway-controller':
            continue
        conditions = {c['type']: c for c in parent.get('conditions', [])}
        current = conditions.get('Accepted', {})
        if current.get('observedGeneration') != obj['metadata']['generation']:
            continue
        if accepted:
            return current.get('status') == 'True' and conditions.get('ResolvedRefs', {}).get('status') == 'True'
        return current.get('status') == 'False' and current.get('reason') == 'NotAllowedByListeners'
    return False


def tls(ns, pod, exposure, sni, host=None):
    endpoint = 'cloudlab-istio.cloudlab-gateway-' + exposure + '.svc.cluster.local:443'
    request = 'GET / HTTP/1.1\r\nHost: ' + (host or sni) + '\r\nConnection: close\r\n\r\n'
    command = ('printf %s ' + shlex.quote(request) + ' | timeout 12 openssl s_client -quiet '
               '-verify_return_error -verify_hostname ' + shlex.quote(sni)
               + ' -servername ' + shlex.quote(sni) + ' -connect ' + shlex.quote(endpoint)
               + ' -ignore_unexpected_eof')
    return execute(ns, pod, 'sh', '-c', command)


def successful_tls(result):
    return result.returncode == 0 and bool(re.search(r'^HTTP/1\.[01] 200\b', result.stdout)) and 'mesh-ok' in result.stdout


def controller_snapshot():
    result = {}
    for namespace in ('istio-system', 'cloudlab-gateway-public', 'cloudlab-gateway-private'):
        pods = get('pods', namespace=namespace)['items']
        for pod in pods:
            if not condition(pod, 'Ready'):
                raise RuntimeError('Mesh controller or gateway pod is not ready')
            key = namespace + '/' + pod['metadata']['name']
            result[key] = (pod['metadata']['uid'], [x.get('restartCount', 0) for x in pod.get('status', {}).get('containerStatuses', [])])
    return result


def check_gateways(zone):
    accounts = []
    for exposure in ('public', 'private'):
        ns = 'cloudlab-gateway-' + exposure
        obj = get('gateway.gateway.networking.k8s.io', 'cloudlab', ns)
        if not condition(obj, 'Programmed') or not condition(obj, 'Accepted'):
            raise RuntimeError('Gateway conditions are not ready')
        listeners = obj['spec']['listeners']
        expected = {'https': '*.' + ('internal.' if exposure == 'private' else '') + zone}
        if exposure == 'private':
            expected['identity-account'] = 'login.' + zone
        if (len(listeners) != len(expected) or
                {item.get('name'): item.get('hostname') for item in listeners} != expected):
            raise RuntimeError('Gateway listener inventory or hostname changed')
        for listener in listeners:
            if (listener['protocol'] != 'HTTPS' or listener['port'] != 443 or
                    listener['tls'] != {'mode': 'Terminate', 'certificateRefs': [
                        {'group': '', 'kind': 'Secret', 'name': 'cloudlab-gateway-tls'}]}):
                raise RuntimeError('Gateway listener exposes an unreviewed protocol or certificate')
            if listener['allowedRoutes'] != {
                    'namespaces': {'from': 'Selector', 'selector': {'matchLabels': {'cloudlab.io/gateway': exposure}}},
                    'kinds': [{'group': 'gateway.networking.k8s.io', 'kind': 'HTTPRoute'}]}:
                raise RuntimeError('Gateway route attachment restriction changed')
        service = get('service', 'cloudlab-istio', ns)
        if service['spec']['type'] != 'ClusterIP' or service['spec'].get('externalIPs') or any(p.get('nodePort') for p in service['spec']['ports']):
            raise RuntimeError('Gateway has external service exposure')
        deployment = get('deployment', 'cloudlab-istio', ns)
        if deployment['spec']['replicas'] != 2 or deployment.get('status', {}).get('availableReplicas') != 2:
            raise RuntimeError('Gateway replicas are not ready')
        accounts.append(ns + '/' + deployment['spec']['template']['spec']['serviceAccountName'])
    if len(set(accounts)) != 2:
        raise RuntimeError('Public and private gateways share an identity')


def verify(payload):
    with (BASE / 'ownership.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads((BASE / 'ownership.json').read_text())
        if state['phase'] != 'accepted' or gateway_api(payload['gateway_api']) != state['gateway_api']:
            raise RuntimeError('Gateway API ownership receipt is not accepted or preserved')
        if component_identities(payload) != state['components']:
            raise RuntimeError('Istio object identities changed')
        wait(lambda: application_ready('cloudlab-gateways', payload['revision']), 'gateway Application convergence')
        zone = selected_zone()
        check_gateways(zone)
        ns = 'cloudlab-gateway-public'
        kube('patch', 'configmap', 'cloudlab-gateway-options', '-n', ns, '--type=merge',
             '-p', json.dumps({'metadata': {'annotations': {'cloudlab.io/ownership-proof': 'drift-fixture'}}}))
        wait(lambda: get('configmap', 'cloudlab-gateway-options', ns)['metadata'].get('annotations', {}).get(
            'cloudlab.io/ownership-proof') == 'argocd', 'gateway declaration drift repair', timeout=600)
        # One drift fixture proves this Application's writer. Wait for its full
        # operation to finish before traffic checks or another verification run.
        wait(lambda: application_ready('cloudlab-gateways', payload['revision']), 'post-drift gateway convergence')
        suffix = uuid.uuid4().hex[:10]
        public, private, plain = ['cloudlab-mesh-' + role + '-' + suffix for role in ('public', 'private', 'plain')]
        created = {}
        try:
            for ns, exposure, ambient in [(public, 'public', True), (private, 'private', True), (plain, None, False)]:
                kube('create', '-f', '-', document=fixtures.namespace(ns, exposure, ambient))
                created[ns] = get('namespace', ns)['metadata']['uid']
            objects = []
            for ns in (public, private):
                objects.extend([fixtures.account(ns, 'backend'), fixtures.service(ns),
                                fixtures.pod(ns, 'backend', payload['smoke_image'], 'backend', server=True)])
            # A bounded fixture override proves baseline reachability before
            # restoring STRICT in this disposable namespace. Mesh default stays STRICT.
            baseline_policy = fixtures.identity_policy(public, [])[0]
            baseline_policy['spec']['mtls']['mode'] = 'PERMISSIVE'
            objects.append(baseline_policy)
            for account in ('allowed', 'denied'):
                objects.append(fixtures.account(public, account))
            objects.extend([fixtures.pod(public, 'allowed', payload['smoke_image'], 'allowed'),
                            fixtures.pod(public, 'denied', payload['smoke_image'], 'denied'),
                            fixtures.pod(public, 'network-baseline', payload['smoke_image'], 'allowed', network=False),
                            fixtures.account(plain, 'plain'), fixtures.service(plain),
                            fixtures.pod(plain, 'plain', payload['smoke_image'], 'plain'),
                            fixtures.pod(plain, 'tls', payload['probe_image'], 'plain')])
            nodes = sorted(node['metadata']['labels']['kubernetes.io/hostname']
                           for node in get('nodes')['items'] if condition(node, 'Ready'))
            if len(nodes) != 2:
                raise RuntimeError('Cross-node ambient proof requires both existing nodes ready')
            for obj in objects:
                if obj['kind'] == 'Pod':
                    obj['spec']['nodeSelector'] = {'kubernetes.io/hostname': nodes[0 if obj['metadata']['name'] == 'backend' else 1]}
            kube('create', '-f', '-', document=fixtures.document(objects))
            for ns in created:
                kube('wait', '--for=condition=Ready', 'pods', '--all', '-n', ns, '--timeout=180s', timeout=210)
            for ns in (public, private):
                for pod in get('pods', namespace=ns)['items']:
                    if (len(pod['spec']['containers']) != 1 or pod['metadata'].get('annotations', {}).get('ambient.istio.io/redirection') != 'enabled'):
                        raise RuntimeError('Fixture is not captured by ambient without a sidecar')
            target = 'backend.' + public + '.svc.cluster.local'
            # Positive baselines distinguish policy denial from DNS or broken networking.
            for ns, pod in [(public, 'allowed'), (public, 'denied'), (public, 'network-baseline'), (plain, 'plain')]:
                wait(lambda ns=ns, pod=pod: http(ns, pod, target), 'pre-policy traffic', timeout=120)
            policies = fixtures.identity_policy(public, [
                'cluster.local/ns/' + public + '/sa/allowed',
                'cluster.local/ns/cloudlab-gateway-public/sa/cloudlab-istio'])
            policies += fixtures.identity_policy(private, ['cluster.local/ns/cloudlab-gateway-private/sa/cloudlab-istio'])
            kube('apply', '-f', '-', document=fixtures.document(policies))
            deny(lambda: http(plain, 'plain', target), 'plaintext denied by STRICT mTLS')
            deny(lambda: http(public, 'denied', target), 'unauthorized service account')
            before = mtls_connections(public)
            wait(lambda: http(public, 'allowed', target), 'authorized identity traffic', timeout=120)
            wait(lambda: mtls_connections(public) > before, 'mutual TLS traffic metrics', timeout=90)
            wait(lambda: http(public, 'network-baseline', target), 'same authorized identity before network policy')
            kube('create', '-f', '-', document=fixtures.network_policy(public, allow_hbone=False))
            # NetworkPolicy may retain established connections. Fresh pods force
            # new HBONE connections for both the allowed and denied network cases.
            for name, allowed in [('network-denied', False), ('network-allowed', True)]:
                if allowed:
                    kube('apply', '-f', '-', document=fixtures.network_policy(public, allow_hbone=True))
                pod = fixtures.pod(public, name, payload['smoke_image'], 'allowed', network=allowed)
                pod['spec']['nodeSelector'] = {'kubernetes.io/hostname': nodes[1]}
                kube('create', '-f', '-', document=pod)
                kube('wait', '--for=condition=Ready', 'pod/' + name, '-n', public, '--timeout=180s', timeout=210)
                if not allowed:
                    deny(lambda: http(public, 'network-denied', target), 'network policy with authorized identity')
            wait(lambda: http(public, 'network-allowed', target), 'HBONE network policy allow', timeout=120)
            hosts = {'public': 'verify-' + suffix + '.' + zone, 'private': 'verify-' + suffix + '.internal.' + zone}
            routes = [fixtures.route(public, 'accepted', 'public', hosts['public']),
                      fixtures.route(private, 'accepted', 'private', hosts['private']),
                      fixtures.route(public, 'wrong-gateway', 'private', hosts['private']),
                      fixtures.route(plain, 'unapproved-namespace', 'public', hosts['public'])]
            kube('create', '-f', '-', document=fixtures.document(routes))
            for ns in (public, private):
                wait(lambda ns=ns: route_status(ns, 'accepted', True), 'accepted route references')
            wait(lambda: route_status(public, 'wrong-gateway', False), 'cross-gateway route denial')
            wait(lambda: route_status(plain, 'unapproved-namespace', False), 'unapproved namespace route denial')
            for exposure in ('public', 'private'):
                wait(lambda exposure=exposure: successful_tls(tls(plain, 'tls', exposure, hosts[exposure])),
                     'trusted gateway TLS and backend response', timeout=120)
                unknown = tls(plain, 'tls', exposure, hosts[exposure], 'unknown-' + hosts[exposure])
                if unknown.returncode != 0 or not re.search(r'^HTTP/1\.[01] 404\b', unknown.stdout):
                    raise RuntimeError('Unknown gateway host did not return a trusted TLS route rejection')
                wrong_sni = tls(plain, 'tls', exposure, 'unknown.invalid')
                if wrong_sni.returncode == 0 or re.search(r'^HTTP/', wrong_sni.stdout):
                    raise RuntimeError('Unknown SNI unexpectedly reached a gateway route')
            cross = tls(plain, 'tls', 'public', hosts['private'])
            if successful_tls(cross):
                raise RuntimeError('Private route leaked through the public gateway')
        finally:
            for ns, uid in created.items():
                current = get('namespace', ns)
                if current and current['metadata']['uid'] == uid and current['metadata'].get('labels', {}).get('app.kubernetes.io/managed-by') == 'cloudlab-mesh-verify':
                    kube('delete', 'namespace', ns, '--wait=true', '--timeout=120s', timeout=150)
        baseline = controller_snapshot()
        started = time.monotonic()
        while time.monotonic() - started < 60:
            time.sleep(10)
            if controller_snapshot() != baseline:
                raise RuntimeError('Mesh controllers changed during stability observation')
            for app in ['cloudlab-gateways'] + ['cloudlab-istio-' + c for c in payload['mesh_objects']]:
                if not application_ready(app, payload['revision']):
                    raise RuntimeError('Mesh GitOps convergence changed during stability observation')
        if gateway_api(payload['gateway_api']) != state['gateway_api']:
            raise RuntimeError('Gateway API identity changed during verification')
        check_gateways()
        return {'ambient_without_sidecars': True, 'cross_node_mutual_tls_traffic_observed': True,
                'authorized_identity_allowed': True, 'plaintext_and_unauthorized_identity_denied': True,
                'network_policy_separately_proven': True, 'trusted_gateway_tls': True,
                'hbone_port_denied_then_allowed': True,
                'unknown_hosts_and_sni_denied': True, 'cross_gateway_and_namespace_attachment_denied': True,
                'gateways_internal_and_separate': True, 'gateway_api_owner_preserved': True,
                'gateway_declaration_drift_repaired': True,
                'stability_seconds': round(time.monotonic() - started, 1), 'fixtures_removed': True}


if __name__ == '__main__':
    try:
        print(json.dumps(verify(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Mesh verification failed; private diagnostics withheld') from None
