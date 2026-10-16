import unittest
import yaml

from automation.observability.payload import compile_payload


class PayloadTests(unittest.TestCase):
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
        from automation.observability.chart import render
        objects = render('kiali', payload['components']['kiali'])
        roles = [obj for obj in objects if obj['kind'] == 'Role']
        self.assertEqual({obj['metadata']['namespace'] for obj in roles},
                         {'cloudlab-app-notes', 'istio-system', 'cloudlab-observability',
                          'cloudlab-gateway-public', 'cloudlab-gateway-private', 'argocd'})
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
