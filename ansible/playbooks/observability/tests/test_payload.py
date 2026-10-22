import unittest
from unittest.mock import patch
import yaml

import json
from pathlib import Path

from playbooks.observability.tests.fixtures import native_application
from playbooks.observability.files.payload import verification_payload


class PayloadTests(unittest.TestCase):
    def test_read_only_expectations_use_native_values_and_require_the_approved_service(self):
        result, value = native_application('kiali')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        inputs = {'source': {'repository': 'https://github.com/fixture/platform.git', 'revision': 'a' * 40},
            'metadata': {'loginHost': 'login.example.invalid', 'grafanaHost': 'grafana.internal.example.invalid',
                         'kialiHost': 'kiali.internal.example.invalid'},
            'kiali_values': value['spec']['source']['helm']['valuesObject']}
        approved = {'publication': 'published', 'definition': {'name': 'notes',
            'exposure': {'class': 'public', 'hostname': 'notes.example.invalid'}}, 'approval': {'chartPath': 'apps/notes'}}
        with patch('playbooks.services.files.inputs.catalog', return_value={'catalog': [approved]}):
            expected = verification_payload(inputs)
        self.assertEqual(expected['revision'], 'a' * 40)
        self.assertEqual(expected['notes_origin'], 'https://notes.example.invalid')
        self.assertIn('login.example.invalid/realms/platform', str(expected['backend_configurations']['kiali']))
        with patch('playbooks.services.files.inputs.catalog', return_value={'catalog': []}):
            with self.assertRaisesRegex(ValueError, 'approved public Notes'):
                verification_payload(inputs)

    def test_identity_https_keeps_issuer_while_using_only_private_gateway_peers(self):
        result, value = native_application('prometheus')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        prometheus = value['spec']['source']['helm']['valuesObject']['kube-prometheus-stack']['grafana']
        self.assertEqual(prometheus['hostAliases'], [{'ip': '10.43.0.7', 'hostnames': ['login.example.invalid']}])
        self.assertTrue(prometheus['grafana.ini']['auth.generic_oauth']['token_url'].startswith('https://login.example.invalid/'))
        result, value = native_application('kiali')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        overrides = value['spec']['source']['helm']['valuesObject']
        static = json.loads((Path(__file__).resolve().parents[4] / 'platform/observability/kiali/values.json').read_text())
        kiali = static['kiali-server']
        self.assertFalse(kiali['deployment']['cluster_wide_access'])
        self.assertTrue(kiali['deployment']['view_only_mode'])
        self.assertEqual(overrides['kiali-server']['deployment']['host_aliases'], prometheus['hostAliases'])
        from playbooks.observability.files.chart import render
        objects = render('kiali', overrides)
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
        overrides['kiali-server']['deployment']['discovery_selectors'] = {
            'default': [{'matchLabels': {'kubernetes.io/metadata.name': 'unapproved'}}]}
        with self.assertRaises(ValueError): render('kiali', overrides)
