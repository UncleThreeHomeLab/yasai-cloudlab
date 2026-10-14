import hashlib
import json
from pathlib import Path
import unittest
import yaml

from automation.observability.chart import check, configuration, render


class ChartTests(unittest.TestCase):
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
