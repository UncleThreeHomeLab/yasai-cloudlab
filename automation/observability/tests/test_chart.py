import base64
import hashlib
import json
import re
import tarfile
from pathlib import Path
import unittest
import yaml

from automation.observability.chart import check, configuration, render


class ChartTests(unittest.TestCase):
    def test_tempo_protocol_patch_preserves_all_other_pinned_chart_content(self):
        base = Path(__file__).resolve().parents[3] / 'platform/observability/tempo'
        lock = json.loads((base / 'artifact.lock.json').read_text())
        with tarfile.open(base / 'upstream.tgz') as source, tarfile.open(base / lock['archive']) as patched:
            original = {member.name: source.extractfile(member).read() for member in source if member.isfile()}
            result = {member.name: patched.extractfile(member).read() for member in patched if member.isfile()}
        result['tempo/templates/_ports.tpl'] = re.sub(rb'(?m)^  appProtocol: (http|grpc)\n', b'',
                                                     result['tempo/templates/_ports.tpl'])
        self.assertEqual(original, result)

    def test_telemetry_service_protocols_are_explicit_without_changing_ports(self):
        alloy = next(obj for obj in render('alloy') if obj['kind'] == 'Service')
        otlp = next(port for port in alloy['spec']['ports'] if port['port'] == 4318)
        self.assertEqual(otlp['name'], 'otlp-http')
        self.assertEqual(otlp['appProtocol'], 'http')
        services = [obj for obj in render('tempo') if obj['kind'] == 'Service']
        self.assertEqual({obj['metadata']['name'] for obj in services}, {'cloudlab-tempo', 'cloudlab-tempo-headless'})
        for service in services:
            for port in service['spec']['ports']:
                if port['protocol'] == 'UDP':
                    continue
                expected = 'grpc' if port['name'].startswith('grpc-') or port['port'] == 55680 else 'http'
                self.assertEqual(port['appProtocol'], expected)
            ports = {port['name']: (port['port'], port['targetPort']) for port in service['spec']['ports']}
            self.assertEqual(ports['tempo-prom-metrics'], (3200, 3200))
            self.assertEqual(ports['tempo-otlp-http'], (4318, 4318))

    def test_kubelet_tls_and_per_job_scrape_limits_match_supported_monitor_fields(self):
        objects = render('prometheus')
        monitors = {obj['metadata']['name']: obj['spec'] for obj in objects if obj['kind'] == 'ServiceMonitor'}
        for endpoint in monitors['cloudlab-kubelet']['endpoints']:
            self.assertIn('ca', endpoint['tlsConfig'])
            self.assertNotIn('caFile', endpoint['tlsConfig'])
            self.assertFalse(endpoint['tlsConfig']['insecureSkipVerify'])
        main = next(endpoint for endpoint in monitors['cloudlab-kubelet']['endpoints'] if endpoint.get('path', '/metrics') == '/metrics')
        self.assertEqual(main['metricRelabelings'], [
            {'sourceLabels': ['__name__'], 'regex': 'apiserver_.*', 'action': 'drop'}])
        pattern = main['metricRelabelings'][0]['regex']
        self.assertTrue(re.fullmatch(pattern, 'apiserver_request_duration_seconds_bucket'))
        for metric in ('kubelet_volume_stats_available_bytes', 'storage_operation_duration_seconds_bucket',
                       'rest_client_requests_total', 'go_goroutines', 'process_resident_memory_bytes'):
            self.assertIsNone(re.fullmatch(pattern, metric))
        self.assertNotIn('apiserver_.*', json.dumps(monitors['cloudlab-apiserver']['endpoints']))
        self.assertEqual(monitors['cloudlab-apiserver']['sampleLimit'], 100000)
        self.assertEqual(monitors['cloudlab-kubelet']['labelValueLengthLimit'], 512)
        self.assertEqual(monitors['cloudlab-prometheus']['labelValueLengthLimit'], 512)
        prometheus = next(obj['spec'] for obj in objects if obj['kind'] == 'Prometheus')
        self.assertEqual(prometheus['sampleLimit'], 50000)
        self.assertEqual(prometheus['labelValueLengthLimit'], 200)
        deployment = next(obj for obj in render('kiali') if obj['kind'] == 'Deployment')
        self.assertEqual(deployment['spec']['strategy'], {'type': 'Recreate'})

    def test_kiali_control_plane_transport_grants_only_namespaced_portforward(self):
        objects = configuration(True)
        role = next(obj for obj in objects if obj['kind'] == 'Role' and obj['metadata']['name'] == 'cloudlab-kiali-istiod')
        self.assertEqual(role['metadata']['namespace'], 'istio-system')
        self.assertEqual(role['rules'], [{'apiGroups': [''], 'resources': ['pods/portforward'], 'verbs': ['create']}])
        binding = next(obj for obj in objects if obj['kind'] == 'RoleBinding' and obj['metadata']['name'] == role['metadata']['name'])
        self.assertEqual(binding['metadata']['namespace'], role['metadata']['namespace'])
        self.assertEqual(binding['roleRef'], {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': role['metadata']['name']})
        self.assertEqual(binding['subjects'], [{'kind': 'ServiceAccount', 'name': 'cloudlab-kiali', 'namespace': 'cloudlab-observability'}])

    def test_ambient_transport_keeps_decoded_collector_and_scrape_ports_authorized(self):
        objects = configuration(True)
        policies = {obj['metadata']['name']: obj['spec'] for obj in objects if obj['kind'] == 'NetworkPolicy'}
        self.assertEqual({port['port'] for port in policies['application-traces']['ingress'][0]['ports']}, {4318, 15008})
        self.assertEqual({port['port'] for port in policies['prometheus-scrapes']['ingress'][0]['ports']}, {9091, 15008})
        transport = next(rule for rule in policies['telemetry-boundary']['egress']
                         if rule.get('ports') == [{'protocol': 'TCP', 'port': 15008}])
        self.assertEqual(transport['to'], [{'namespaceSelector': {'matchLabels': {
            'kubernetes.io/metadata.name': 'cloudlab-app-notes'}}, 'podSelector': {'matchLabels': {'cloudlab.io/telemetry': 'safe'}}}])
        collector = next(obj['spec'] for obj in objects if obj['kind'] == 'AuthorizationPolicy' and
                         obj['metadata']['name'] == 'application-traces')
        self.assertEqual(collector['rules'][0]['from'][0]['source']['principals'],
                         ['cluster.local/ns/cloudlab-app-notes/sa/notes-web', 'cluster.local/ns/cloudlab-app-notes/sa/notes-api'])
        self.assertEqual(collector['rules'][0]['to'][0]['operation']['ports'], ['4318'])
        self.assertEqual(collector['rules'][1]['to'][0]['operation']['ports'], ['12345'])
        self.assertEqual({port['port'] for port in policies['private-dashboard-ingress']['ingress'][0]['ports']},
                         {3000, 20001, 15008})
        for name, port in (('grafana', '3000'), ('kiali', '20001')):
            dashboard = next(obj['spec'] for obj in objects if obj['kind'] == 'AuthorizationPolicy' and
                             obj['metadata']['name'] == 'private-' + name)
            self.assertEqual(dashboard['selector'], {'matchLabels': {'app.kubernetes.io/name': name}})
            self.assertEqual(dashboard['rules'][0]['from'][0]['source']['principals'],
                             ['cluster.local/ns/cloudlab-gateway-private/sa/cloudlab-istio'])
            self.assertEqual(dashboard['rules'][0]['to'][0]['operation']['ports'], [port])

    def test_rendered_alert_routes_reference_declared_receivers(self):
        secret = next(obj for obj in render('prometheus') if obj['kind'] == 'Secret' and
                      obj['metadata']['name'] == 'alertmanager-cloudlab')
        config = yaml.safe_load(base64.b64decode(secret['data']['alertmanager.yaml'], validate=True))
        receivers = {row['name'] for row in config['receivers']}
        routes = [config['route']]
        while routes:
            route = routes.pop()
            if 'receiver' in route: self.assertIn(route['receiver'], receivers)
            routes.extend(route.get('routes', []))

    def test_private_routes_resolve_to_pinned_backend_services(self):
        services = {obj['metadata']['name']: {port['port'] for port in obj['spec']['ports']}
                    for name in ('prometheus', 'kiali') for obj in render(name) if obj['kind'] == 'Service'}
        for route in (obj for obj in configuration(True) if obj['kind'] == 'HTTPRoute'):
            for rule in route['spec']['rules']:
                for backend in rule['backendRefs']:
                    self.assertIn(backend['port'], services[backend['name']])

    def test_storage_quota_credentials_and_scraping_have_explicit_owners(self):
        self.assertEqual(configuration(), [])
        objects = configuration(True)
        storage = next(obj for obj in objects if obj['kind'] == 'StorageClass')
        self.assertEqual(storage['reclaimPolicy'], 'Retain')
        self.assertEqual(storage['parameters']['numberOfReplicas'], '2')
        self.assertEqual(json.loads(storage['parameters']['recurringJobSelector']),
                         [{'name': 'telemetry-disposable', 'isGroup': True}])
        quota = next(obj for obj in objects if obj['kind'] == 'ResourceQuota')['spec']['hard']
        self.assertEqual(quota['requests.storage'], '70Gi')
        self.assertEqual(quota['limits.cpu'], '3000m')
        self.assertFalse(any(obj['kind'] in ('Secret', 'Job') for obj in objects))
        secrets = [obj for obj in objects if obj['kind'] == 'ExternalSecret']
        self.assertEqual({obj['metadata']['name'] for obj in secrets},
                         {'grafana-emergency', 'grafana-oidc', 'kiali-signing-key', 'kiali-oidc'})
        for obj in secrets:
            self.assertEqual(obj['spec']['target']['deletionPolicy'], 'Retain')
            self.assertEqual(obj['spec']['refreshInterval'], '24h')
            self.assertEqual(len(obj['spec']['dataFrom']), 1)
            self.assertNotIn('data', obj['spec'])
        monitor = next(obj for obj in objects if obj['kind'] == 'PodMonitor')
        self.assertEqual(monitor['spec']['namespaceSelector']['matchNames'], ['cloudlab-app-notes'])
        self.assertEqual(monitor['spec']['selector']['matchLabels'], {'cloudlab.io/telemetry': 'safe'})
        self.assertEqual(monitor['spec']['jobLabel'], 'app.kubernetes.io/name')
        mesh = {obj['metadata']['name']: obj for obj in objects if obj['kind'] == 'PodMonitor' and obj['metadata']['name'].startswith('mesh-')}
        self.assertEqual(set(mesh), {'mesh-control', 'mesh-ambient', 'mesh-gateways'})
        self.assertEqual(mesh['mesh-ambient']['spec']['podMetricsEndpoints'][0]['port'], 'ztunnel-stats')
        self.assertEqual(mesh['mesh-gateways']['spec']['namespaceSelector']['matchNames'],
                         ['cloudlab-gateway-public', 'cloudlab-gateway-private'])
        grafana = next(obj for obj in render('prometheus') if obj['kind'] == 'Deployment' and obj['metadata']['name'] == 'cloudlab-grafana')
        self.assertEqual(grafana['spec']['strategy'], {'type': 'Recreate'})
        container = next(c for c in grafana['spec']['template']['spec']['containers'] if c['name'] == 'grafana')
        self.assertGreaterEqual(int(container['resources']['requests']['memory'].removesuffix('Mi')), 512)
        self.assertGreaterEqual(int(container['resources']['limits']['memory'].removesuffix('Mi')), 750)
        dns = next(obj for obj in objects if obj['kind'] == 'ServiceMonitor' and obj['metadata']['name'] == 'native-dns')
        self.assertEqual(dns['spec']['selector']['matchLabels'], {'k8s-app': 'kube-dns'})
        self.assertFalse(any(obj['kind'] == 'Service' and obj['metadata'].get('namespace') == 'kube-system'
                             for obj in render('prometheus')))

    def test_isolated_native_proof_uses_identical_pins_and_no_external_network(self):
        root = Path(__file__).resolve().parents[3]
        pins = json.loads((root / 'platform/observability/images.lock.json').read_text())
        compose = yaml.safe_load((root / 'automation/observability/compose.proof.yaml').read_text())
        self.assertTrue(compose['networks']['fixture']['internal'])
        for service, pin in (('loki', 'loki'), ('tempo', 'tempo'), ('alloy', 'alloy'), ('promtool', 'prometheus')):
            self.assertEqual(compose['services'][service]['image'], pins[pin])
            self.assertIn('cpus', compose['services'][service])
            self.assertIn('mem_limit', compose['services'][service])
        self.assertEqual(compose['services']['promtool']['network_mode'], 'none')

    def test_pinned_private_bounded_telemetry_and_disjoint_owners(self):
        result = check()
        self.assertEqual(result['crds'], 10)
        self.assertLessEqual(result['cpu_limit_millicores'], 3000)
        self.assertLessEqual(result['memory_limit_mib'], 6144)
        self.assertEqual(result['offsite_backups'], 0)
