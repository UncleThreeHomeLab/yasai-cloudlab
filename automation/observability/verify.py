"""Read actual telemetry ownership, retained storage and one correlated request."""
import base64
import json
from pathlib import Path
import secrets
import sys
import urllib.parse
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from automation.mesh.kube import get, kube, application_ready, condition, wait
from automation.identity.health import direct_https

NAMESPACE = 'cloudlab-observability'


def healthy_scrapes(rows):
    if not rows or any(float(row['value'][1]) != 1 for row in rows):
        return False
    jobs = {row['metric'].get('job') for row in rows}
    kubelets = {row['metric'].get('instance') for row in rows if row['metric'].get('job') == 'kubelet'}
    return {'apiserver', 'cloudlab-prometheus', 'kubelet'} <= jobs and len(kubelets - {None}) == 2


def kiali_control_plane_permissions():
    for namespace in ('istio-system', NAMESPACE, 'cloudlab-app-notes',
                      'cloudlab-gateway-public', 'cloudlab-gateway-private', 'argocd'):
        result = kube('auth', 'can-i', 'create', 'pods', '--subresource=portforward', '-n', namespace,
                      '--as=system:serviceaccount:' + NAMESPACE + ':cloudlab-kiali', allow_failure=True)
        permitted = namespace == 'istio-system'
        if result.returncode != (0 if permitted else 1) or result.stdout.strip() != ('yes' if permitted else 'no'):
            raise RuntimeError('Kiali control-plane transport permission is missing or exceeds its namespace')


def kiali_configuration_references(namespaces):
    for namespace in namespaces:
        result = kube('auth', 'can-i', 'list', 'services', '-n', namespace,
                      '--as=system:serviceaccount:' + NAMESPACE + ':cloudlab-kiali', allow_failure=True)
        if result.returncode or result.stdout.strip() != 'yes':
            raise RuntimeError('Kiali cannot read a required service namespace')
        for route in (get('httproutes.gateway.networking.k8s.io', namespace=namespace) or {}).get('items', []):
            parents = route['spec'].get('parentRefs', [])
            backends = [backend for rule in route['spec'].get('rules', []) for backend in rule.get('backendRefs', [])]
            for kind, refs in (('gateway.gateway.networking.k8s.io', parents), ('service', backends)):
                for ref in refs:
                    target_namespace = ref.get('namespace', namespace)
                    if target_namespace not in namespaces or not get(kind, ref['name'], target_namespace):
                        raise RuntimeError('Visible route references a backend or gateway outside Kiali discovery')
    result = kube('auth', 'can-i', 'get', 'secrets', '-n', 'argocd',
                  '--as=system:serviceaccount:' + NAMESPACE + ':cloudlab-kiali', allow_failure=True)
    if result.returncode != 1 or result.stdout.strip() != 'no':
        raise RuntimeError('Kiali backend visibility must not grant access to Argo credentials')


def backend_ready(resource):
    if not all(condition(resource, name) for name in ('Available', 'Reconciled')):
        raise RuntimeError('Telemetry backend is unavailable or reconciliation failed')


def storage(claims, volumes):
    if len(claims) != 4 or any(claim.get('status', {}).get('phase') != 'Bound' or
            claim['spec'].get('storageClassName') != 'cloudlab-telemetry' for claim in claims):
        raise RuntimeError('Telemetry requires four bound local claims')
    for claim in claims:
        volume = volumes[claim['spec']['volumeName']]
        labels = volume['metadata'].get('labels', {})
        groups = {key for key, value in labels.items() if key.startswith('recurring-job-group.longhorn.io/') and value == 'enabled'}
        individual = any(key.startswith('recurring-job.longhorn.io/') and value == 'enabled' for key, value in labels.items())
        if groups != {'recurring-job-group.longhorn.io/telemetry-disposable'} or individual:
            raise RuntimeError('Telemetry volume can inherit off-site recurring jobs')


def proxy(origin, gateway, headers, datasource, path):
    if datasource not in ('metrics', 'logs', 'traces'):
        raise ValueError('Telemetry proof requires a native provisioned datasource')
    url = origin + '/api/datasources/proxy/uid/' + datasource + path
    status, raw = direct_https(url, gateway, headers)
    if status != 200: raise urllib.error.HTTPError(url, status, 'Private datasource query failed', {}, None)
    return json.loads(raw)


def run(payload):
    kiali_control_plane_permissions()
    names = ('observability', 'prometheus', 'loki', 'tempo', 'alloy', 'kiali')
    for name in names:
        application = get('application.argoproj.io', 'cloudlab-' + name, 'argocd')
        if (not application or application['metadata'].get('labels', {}).get('cloudlab.io/owner') != 'observability-platform' or
                application['spec']['source']['repoURL'] != payload['repository'] or
                not application_ready('cloudlab-' + name, payload['revision'])):
            raise RuntimeError('Telemetry Applications have not converged at their committed revision')
    kiali_configuration_references(payload['policy']['kiali']['namespaces'])
    for name, ports in payload['service_ports'].items():
        actual = get('service', name, NAMESPACE)['spec']['ports']
        if sorted(actual, key=lambda port: port['name']) != sorted(ports, key=lambda port: port['name']):
            raise RuntimeError('Telemetry service protocols differ from their pinned declarations')
    claims = get('persistentvolumeclaims', namespace=NAMESPACE)['items']
    for kind in ('prometheus', 'alertmanager'):
        backend_ready(get(kind + '.monitoring.coreos.com', 'cloudlab', NAMESPACE))
    volumes = {claim['spec']['volumeName']: get('volumes.longhorn.io', claim['spec']['volumeName'], 'longhorn-system') for claim in claims}
    storage(claims, volumes)
    collector = get('configmap', 'cloudlab-alloy', NAMESPACE)['data']['config.alloy']
    if collector != payload['collector']: raise RuntimeError('Telemetry collector differs from its redacted committed pipeline')
    for configurations in payload['backend_configurations'].values():
        for name, data in configurations.items():
            if get('configmap', name, NAMESPACE)['data'] != data:
                raise RuntimeError('Running backend configuration differs from local retention settings')
    if get('prometheusrule.monitoring.coreos.com', 'notes-user-slo', NAMESPACE)['spec'] != payload['slo']:
        raise RuntimeError('User SLO rules differ from the shared service definition')
    policy = payload['policy']
    prometheus = get('prometheus.monitoring.coreos.com', 'cloudlab', NAMESPACE)['spec']
    if (prometheus.get('retention') != policy['prometheus']['retention'] or
            prometheus.get('retentionSize') != policy['prometheus']['retention_size'] or prometheus.get('remoteWrite')):
        raise RuntimeError('Metrics retention or local-only ownership changed')
    expected = {pin.rsplit('@', 1)[1] for pin in payload['images'].values()}
    for pod in get('pods', namespace=NAMESPACE)['items']:
        if pod['metadata'].get('deletionTimestamp'): continue
        for container in pod['spec'].get('containers', []) + pod['spec'].get('initContainers', []):
            if container['image'].rsplit('@', 1)[-1] not in expected:
                raise RuntimeError('Running telemetry image differs from the pinned inventory')
            if set(container.get('resources', {}).get('limits', {})) != {'cpu', 'memory'}:
                raise RuntimeError('Running telemetry container lacks resource bounds')
    private_gateway = get('service', 'cloudlab-istio', 'cloudlab-gateway-private')['spec']['clusterIP']
    origin = payload['grafana_origin']
    secret = get('secret', 'grafana-emergency', NAMESPACE)['data']
    credentials = ':'.join(base64.b64decode(secret[key], validate=True).decode() for key in ('username', 'password'))
    authorization = 'Basic ' + base64.b64encode(credentials.encode()).decode()
    query_headers = {'Authorization': authorization, 'Accept': 'application/json'}
    trace_id = secrets.token_hex(16)
    headers = {'traceparent': '00-' + trace_id + '-' + secrets.token_hex(8) + '-01',
               'User-Agent': 'CloudLab-Telemetry-Proof/1.0'}
    gateway = get('service', 'cloudlab-istio', 'cloudlab-gateway-public')['spec']['clusterIP']
    status, body = direct_https(payload['notes_origin'] + '/health', gateway, headers)
    if status != 200 or json.loads(body) != {'ready': True}:
        raise RuntimeError('Real cross-service telemetry request failed')
    def observed():
        try:
            trace = proxy(origin, private_gateway, query_headers, 'traces', '/api/traces/' + trace_id)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                error.close()
                return False
            raise
        encoded = json.dumps(trace)
        if not all(name in encoded for name in ('notes-web', 'notes-api', 'notes.database', 'notes.objects')): return False
        query = urllib.parse.urlencode({'query': '{kind="request"} |= "' + trace_id + '"', 'limit': 10})
        logs = proxy(origin, private_gateway, query_headers, 'logs', '/loki/api/v1/query_range?' + query)
        lines = [json.loads(value[1]) for stream in logs['data']['result'] for value in stream['values']]
        if not {'notes-web', 'notes-api'} <= {line.get('service') for line in lines}: return False
        query = urllib.parse.urlencode({'query': 'sum by (service) (cloudlab_http_requests_total{traffic="synthetic",status="200"})'})
        metrics = proxy(origin, private_gateway, query_headers, 'metrics', '/api/v1/query?' + query)['data']['result']
        if not {'notes-web', 'notes-api'} <= {row['metric'].get('service') for row in metrics}: return False
        query = urllib.parse.urlencode({'query': 'sum(istio_tcp_connections_opened_total{connection_security_policy="mutual_tls",source_workload_namespace="cloudlab-app-notes"})'})
        mesh = proxy(origin, private_gateway, query_headers, 'metrics', '/api/v1/query?' + query)['data']['result']
        query = urllib.parse.urlencode({'query': 'up'})
        scrapes = proxy(origin, private_gateway, query_headers, 'metrics', '/api/v1/query?' + query)['data']['result']
        return bool(mesh) and float(mesh[0]['value'][1]) > 0 and healthy_scrapes(scrapes)
    wait(observed, 'real correlated telemetry request', timeout=300)
    status, _ = direct_https(origin + '/api/search', private_gateway, {})
    if status != 401: raise RuntimeError('Grafana dashboard API permits unauthenticated access')
    status, _ = direct_https(payload['notes_origin'] + '/api/health', gateway,
                             {'Host': urllib.parse.urlsplit(origin).hostname})
    if status != 404: raise RuntimeError('Private Grafana route is reachable through the public gateway')
    status, raw = direct_https(payload['kiali_origin'] + '/kiali/api/auth/info', private_gateway, {})
    if status != 200 or json.loads(raw).get('strategy') != 'openid' or json.loads(raw).get('secretMissing'):
        raise RuntimeError('Private Kiali requires its supported confidential OpenID client')
    status, _ = direct_https(payload['kiali_origin'] + '/kiali/api/namespaces', private_gateway, {})
    if status != 401: raise RuntimeError('Kiali dashboard API permits unauthenticated access')
    status, raw = direct_https(origin + '/api/user', private_gateway, {'Authorization': authorization})
    if status != 200 or json.loads(raw).get('isGrafanaAdmin') is not True:
        raise RuntimeError('Independent private Grafana emergency access failed')
    return {'applications_converged': len(names), 'local_bound_claims': len(claims),
            'backup_excluded': True, 'pinned_bounded_containers': True,
            'real_metrics_logs_traces': True, 'scraped_mesh_mtls_metrics': True, 'emergency_access': True,
            'private_dashboard_apis': True, 'kiali_control_plane_permission': True,
            'all_metric_targets_healthy': True,
            'kiali_route_references_visible': True, 'telemetry_service_protocols': True,
            'retention_settings': True, 'elapsed_retention_deletion_proven': False}


if __name__ == '__main__':
    try: print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Telemetry verification incomplete; private evidence withheld') from None
