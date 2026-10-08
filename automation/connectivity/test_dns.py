"""Reject DNS injection and forwarding loops before host changes."""
import unittest
from automation.connectivity.dns import configuration


class DNSTests(unittest.TestCase):
    def setUp(self):
        self.payload = dict(zone='internal.example.invalid', names=['app'], tailnet_address='100.64.0.1',
                            host_address='10.44.0.1', cluster_gateway='10.43.0.10', tailnet_gateway='100.100.0.1',
                            nameservers=['100.64.0.1', '100.64.0.2'], upstreams=['1.1.1.1'])

    def test_repeat_is_deterministic_with_distinct_routable_answers(self):
        files = configuration(self.payload)
        self.assertEqual(files, configuration(self.payload))
        self.assertIn('app IN A 100.100.0.1', files['tailnet.zone'])
        self.assertIn('app IN A 10.43.0.10', files['internal.zone'])
        self.assertNotIn('fallthrough', files['Corefile'])
        self.assertNotIn('forward', files['Corefile'].split('.:53')[0])

    def test_labels_cannot_inject_records_or_use_reserved_names(self):
        for name in ['app\nother IN A 1.1.1.1', '*.app', 'ns1', 'app.internal']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                configuration(dict(self.payload, names=[name]))

    def test_local_and_tailnet_upstreams_cannot_create_forwarding_loops(self):
        for upstream in ['127.0.0.1', '100.100.100.100', '10.44.0.2', '10.43.0.10']:
            with self.subTest(upstream=upstream), self.assertRaises(ValueError):
                configuration(dict(self.payload, upstreams=[upstream]))

    def test_public_listener_or_public_gateway_is_rejected(self):
        for key in ['tailnet_address', 'host_address', 'cluster_gateway', 'tailnet_gateway']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                configuration(dict(self.payload, **{key: '1.1.1.1'}))


if __name__ == '__main__':
    unittest.main()
