"""Resolver generation identity covers served content, never host binds."""
import unittest

import dns_host


def _payload(**overrides):
    payload = {'names': ['b', 'a'], 'zone': 'internal.example.test',
               'identity_host': 'login.example.test',
               'cluster_gateway': '10.43.0.1', 'tailnet_gateway': '100.64.0.9',
               'artifact': 'deadbeef', 'tailnet_address': '100.64.0.1',
               'host_address': '10.44.0.1'}
    payload.update(overrides)
    return payload


class DigestTests(unittest.TestCase):
    def test_host_addresses_do_not_change_generation(self):
        first = dns_host.digest_for(_payload())
        second = dns_host.digest_for(_payload(tailnet_address='100.64.0.2',
                                              host_address='10.44.0.2'))
        self.assertEqual(first, second)

    def test_served_content_changes_generation(self):
        first = dns_host.digest_for(_payload())
        self.assertNotEqual(first, dns_host.digest_for(_payload(names=['a'])))
        self.assertNotEqual(first, dns_host.digest_for(
            _payload(cluster_gateway='10.43.0.2')))
        self.assertNotEqual(first, dns_host.digest_for(_payload(artifact='beef')))


if __name__ == '__main__':
    unittest.main()
