"""Existing Gateway API ownership and namespace trust boundaries are mandatory."""
import unittest
from unittest.mock import patch
import json
from pathlib import Path
import tempfile

import configuration
from kube import contains
import verify


class ConfigurationTests(unittest.TestCase):
    def test_api_spec_and_owner_changes_fail_before_writes(self):
        desired = {'metadata': {'name': 'gateways.gateway.networking.k8s.io'}, 'spec': {'group': 'gateway.networking.k8s.io'}}
        actual = {'metadata': {'uid': 'retained', 'annotations': {
            'meta.helm.sh/release-name': 'traefik-crd', 'gateway.networking.k8s.io/bundle-version': 'v1.6.1'}}, 'spec': desired['spec']}
        with patch.object(configuration, 'get', return_value=actual):
            self.assertEqual(list(configuration.gateway_api([desired]).values()), ['retained'])
            actual['metadata']['annotations']['meta.helm.sh/release-name'] = 'competing'
            with self.assertRaisesRegex(RuntimeError, 'owner changed'):
                configuration.gateway_api([desired])

    def test_recursive_contract_allows_defaults_but_not_missing_versions(self):
        self.assertTrue(contains({'versions': [{'name': 'v1', 'served': True}]}, {'versions': [{'name': 'v1'}]}))
        self.assertFalse(contains({'versions': [{'name': 'v1'}]}, {'versions': [{'name': 'v1'}, {'name': 'v1beta1'}]}))

    def test_gateway_application_cannot_prune_or_replace(self):
        obj = configuration.application({'repository': 'https://github.com/example/platform.git', 'branch': 'main'}, 'example.invalid')
        self.assertNotIn('finalizers', obj['metadata'])
        self.assertFalse(obj['spec']['syncPolicy']['automated']['prune'])
        self.assertEqual(obj['spec']['source']['helm']['valuesObject'], {'zone': 'example.invalid'})
        self.assertFalse(any('Force' in s or 'Replace' in s for s in obj['spec']['syncPolicy']['syncOptions']))

    def test_tls_success_requires_trust_success_http_and_backend(self):
        from types import SimpleNamespace
        for code, body in [(1, 'HTTP/1.1 200 OK\r\nmesh-ok'), (0, 'HTTP/1.1 404 Not Found'), (0, 'HTTP/1.1 200 OK\r\nother')]:
            self.assertFalse(verify.successful_tls(SimpleNamespace(returncode=code, stdout=body)))
        self.assertTrue(verify.successful_tls(SimpleNamespace(returncode=0, stdout='HTTP/1.1 200 OK\r\nmesh-ok')))

    def test_unready_fixture_cannot_count_as_network_denial(self):
        with patch.object(verify, 'get', return_value={'metadata': {}, 'status': {}}), patch.object(verify, 'execute') as execute:
            with self.assertRaisesRegex(RuntimeError, 'not ready'):
                verify.http('fixture', 'client', 'backend')
            execute.assert_not_called()

    def test_checkpoint_repeat_preserves_app_and_ca_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            live = {}
            writes = []
            def get(kind, name=None, namespace=None):
                if kind == 'application.argoproj.io':
                    return live.get('app')
                if kind == 'secret':
                    return {'metadata': {'uid': 'ca'}, 'data': {'ca-cert.pem': 'certificate', 'ca-key.pem': 'key'}}
                if kind == 'gateway.gateway.networking.k8s.io':
                    if 'app' not in live:
                        return None
                    return {'metadata': {'uid': namespace, 'generation': 1},
                            'status': {'conditions': [{'type': 'Programmed', 'status': 'True', 'observedGeneration': 1}]}}
                return {'metadata': {'uid': kind + namespace}, 'spec': {'type': 'ClusterIP'}}
            def kube(*args, **kwargs):
                if args[0] == 'apply':
                    writes.append(args)
                    live['app'] = kwargs['document']
                    live['app']['metadata']['uid'] = 'application'
                return ''
            payload = {'repository': 'https://github.com/example/platform.git', 'branch': 'main',
                       'revision': 'reviewed', 'gateway_api': [], 'mesh_objects': {}}
            with patch.object(configuration, 'BASE', Path(directory)), \
                    patch.object(configuration, 'get', side_effect=get), \
                    patch.object(configuration, 'kube', side_effect=kube), \
                    patch.object(configuration, 'wait', side_effect=lambda predicate, *a, **kw: predicate()), \
                    patch.object(configuration, 'application_ready', return_value=True), \
                    patch.object(configuration, 'selected_zone', return_value='example.invalid'), \
                    patch.object(configuration, 'gateway_api', return_value={'crd': 'retained'}), \
                    patch.object(configuration, 'component_identities', return_value={'component': 'retained'}):
                self.assertTrue(configuration.run(payload)['changed'])
                self.assertFalse(configuration.run(payload)['changed'])
                self.assertEqual(len(writes), 1)
                self.assertEqual(json.loads((Path(directory) / 'ownership.json').read_text())['workload_ca']['uid'], 'ca')
                live['app']['metadata']['uid'] = 'replaced'
                with self.assertRaisesRegex(RuntimeError, 'conflicting owner'):
                    configuration.run(payload)
                self.assertEqual(len(writes), 1)


if __name__ == '__main__':
    unittest.main()
