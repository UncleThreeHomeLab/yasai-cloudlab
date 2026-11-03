import unittest
import yaml

from playbooks.observability.files.payload import compile_payload


class PayloadTests(unittest.TestCase):
    def test_verification_uses_same_catalog_snapshot_and_generated_configmap_bytes(self):
        import json
        from unittest.mock import patch
        from playbooks.observability.files.payload import verification_payload
        from playbooks.observability.files.dashboards import projection, generated
        private = {'catalog': [{'publication': 'published',
            'definition': {'name': 'notes', 'exposure': {'class': 'public', 'hostname': 'notes.example.invalid'},
                           'rollouts': {'enabled': True}},
            'approval': {'name': 'notes', 'namespace': 'fixture', 'chartPath': 'apps/notes'}}]}
        metadata = {'loginHost': 'login.example.invalid', 'gatewayIP': '10.43.0.7',
                    'grafanaHost': 'grafana.internal.example.invalid', 'kialiHost': 'kiali.internal.example.invalid'}
        with patch('playbooks.observability.files.payload.committed_payload', return_value={'repository': 'fixture', 'revision': 'a' * 40}), \
                patch('playbooks.observability.files.payload.metadata', return_value=metadata), \
                patch('playbooks.services.files.inputs.catalog', return_value=(private, 'b' * 40)) as catalog, \
                patch('playbooks.observability.files.chart.render', return_value=[]):
            result = verification_payload()
        catalog.assert_called_once_with(required=True, coordinates=True)
        expected = generated(projection(private))
        for name, raw in expected.items():
            self.assertEqual(result['backend_configurations']['prometheus']['cloudlab-dashboards'][name], raw)
            self.assertEqual(result['dashboards'][name], json.loads(raw))
        self.assertEqual(result['service_catalog_revision'], 'b' * 40)

    def test_runtime_payload_contains_only_generated_service_projection_and_catalog_provenance(self):
        import json
        from playbooks.observability.tests.fixtures import service_bindings
        metadata = {'loginHost': 'login.example.invalid', 'gatewayIP': '10.43.0.7',
                    'grafanaHost': 'grafana.internal.example.invalid', 'kialiHost': 'kiali.internal.example.invalid'}
        value = compile_payload({'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40},
                                metadata, service_bindings(), 'b' * 40)
        prometheus = value['components']['prometheus']
        self.assertEqual(set(prometheus['serviceDashboards']), {'service-overview.json', 'svc-example-notes.json', 'svc-example-worker.json'})
        self.assertEqual(prometheus['serviceCatalogRevision'], 'b' * 40)
        self.assertNotIn('secret', json.dumps(prometheus['serviceDashboards']))
        with self.assertRaises(ValueError): compile_payload({'repository': 'fixture', 'revision': 'a' * 40}, metadata, [], 'main')

    def test_identity_https_keeps_issuer_while_using_only_private_gateway_peers(self):
        metadata = {'loginHost': 'login.example.invalid', 'gatewayIP': '10.43.0.7',
            'apiPeers': ['192.0.2.1/32', '192.0.2.2/32'], 'grafanaHost': 'grafana.internal.example.invalid',
            'kialiHost': 'kiali.internal.example.invalid'}
        payload = compile_payload({'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40}, metadata)
        prometheus = payload['components']['prometheus']['kube-prometheus-stack']['grafana']
        self.assertEqual(prometheus['hostAliases'], [{'ip': '10.43.0.7', 'hostnames': ['login.example.invalid']}])
        self.assertTrue(prometheus['grafana.ini']['auth.generic_oauth']['token_url'].startswith('https://login.example.invalid/'))
        self.assertEqual(payload['configuration']['apiPeers'], metadata['apiPeers'])
        kiali = payload['components']['kiali']['kiali-server']
        self.assertFalse(kiali['deployment']['cluster_wide_access'])
        self.assertTrue(kiali['deployment']['view_only_mode'])
        self.assertEqual(kiali['deployment']['host_aliases'], prometheus['hostAliases'])
        self.assertEqual(payload['components']['alloy'], {})
        from playbooks.observability.files.chart import render
        objects = render('kiali', payload['components']['kiali'])
        roles = [obj for obj in objects if obj['kind'] == 'Role']
        self.assertEqual({obj['metadata']['namespace'] for obj in roles},
                         {'cloudlab-app-notes', 'istio-system', 'cloudlab-observability',
                          'cloudlab-gateway-public', 'cloudlab-gateway-private'})
        for role in roles:
            self.assertTrue(all(set(rule['verbs']) <= {'get', 'list', 'watch'} for rule in role['rules']))
            self.assertFalse(any('secrets' in rule['resources'] or 'pods/log' in rule['resources']
                                 or 'pods/portforward' in rule['resources'] for rule in role['rules']))
        config = yaml.safe_load(next(obj for obj in objects if obj['kind'] == 'ConfigMap')['data']['config.yaml'])
        selected = config['deployment']['discovery_selectors']['default'][0]['matchExpressions'][0]['values']
        self.assertEqual(set(selected), {'cloudlab-app-notes', 'istio-system', 'cloudlab-observability',
                                         'cloudlab-gateway-public', 'cloudlab-gateway-private', 'argocd'})
        self.assertFalse(any(obj['kind'] == 'ClusterRole' for obj in objects))
        service = next(obj for obj in objects if obj['kind'] == 'Service')
        self.assertEqual(service['metadata']['name'], 'cloudlab-kiali')
        self.assertEqual(service['metadata']['annotations']['kiali.io/external-url'],
                         'https://kiali.internal.example.invalid:443/kiali')
        kiali['deployment']['discovery_selectors']['default'].append(
            {'matchLabels': {'kubernetes.io/metadata.name': 'unapproved'}})
        with self.assertRaises(ValueError): render('kiali', payload['components']['kiali'])
