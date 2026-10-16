import unittest
from unittest.mock import patch

from automation.harbor import bootstrap, host_verify


class BootstrapTests(unittest.TestCase):
    def test_application_has_no_prune_and_bounded_destination(self):
        value = bootstrap.application({'repository': 'https://github.com/fixture/platform.git',
            'revision': 'a' * 40, 'configuration': {'enabled': True}, 'server': {'harbor': {}}})
        self.assertFalse(value['spec']['syncPolicy']['automated']['prune'])
        self.assertEqual(value['spec']['destination']['namespace'], 'cloudlab-harbor')
        self.assertEqual(value['spec']['source']['helm']['valueFiles'], ['values.json'])

    def test_foreign_application_is_never_adopted(self):
        payload = {'repository': 'https://github.com/fixture/platform.git', 'revision': 'a' * 40,
                   'configuration': {'enabled': True}, 'server': {'harbor': {}}}
        existing = bootstrap.application(payload)
        existing['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
        with patch.object(bootstrap, 'get', return_value=existing), patch.object(bootstrap, 'kube') as writes:
            with self.assertRaisesRegex(RuntimeError, 'another owner'): bootstrap.seed(payload)
            writes.assert_not_called()

    def test_node_host_uses_actual_dns_and_tls_and_requires_registry_challenge(self):
        host = 'harbor.internal.example.invalid'
        with patch.object(host_verify.socket, 'getaddrinfo', return_value=[object()]) as resolver, \
                patch.object(host_verify.http.client, 'HTTPSConnection') as factory:
            response = factory.return_value.getresponse.return_value
            response.status = 401
            response.getheader.return_value = 'Bearer realm="https://' + host + '/service/token",service="harbor-registry"'
            self.assertTrue(host_verify.run({'configuration': {'harborHost': host}})['trusted_tls'])
            resolver.assert_called_once()
            self.assertEqual(factory.call_args.args[0], host)
            response.status = 200
            with self.assertRaises(RuntimeError): host_verify.run({'configuration': {'harborHost': host}})
