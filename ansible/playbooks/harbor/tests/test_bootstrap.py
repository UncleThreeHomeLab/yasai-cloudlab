import unittest
from unittest.mock import patch

from playbooks.harbor.files import host_verify


class BootstrapTests(unittest.TestCase):
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
