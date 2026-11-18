"""Unmanaged tailnet tests survive server changes."""
import unittest

import policy


class ManagedTestRetentionTests(unittest.TestCase):
    servers = ['100.64.0.1', '100.64.0.2']
    rotated = ['100.64.0.3', '100.64.0.4']
    login = 'owner@example.test'

    def declared(self):
        return {'profile': 'operator-private-access', 'administrator': self.login,
                'zone': 'internal.example.test', 'resolvers': ['cloudlab', 'cloudlab-worker'],
                'accessTests': [(self.login, 'dns', 'allow'),
                                ('tag:cloudlab-denied', 'private-gateway', 'deny')],
                'services': [], 'names': [], 'platformNames': []}

    def test_unmanaged_tests_survive_rotation(self):
        unmanaged = {'src': 'owner@example.test', 'deny': ['tag:other:22']}
        external = {'src': 'owner@example.test', 'proto': 'tcp', 'deny': ['8.8.8.8:53']}
        current = {'grants': [], 'tests': [unmanaged, external]}
        rotated = policy.candidate(policy.candidate(current, self.declared(), self.servers),
                                   self.declared(), self.rotated)
        self.assertIn(unmanaged, rotated['tests'])
        self.assertIn(external, rotated['tests'])


class PrivateExposureTests(unittest.TestCase):
    def document(self, services, platform=()):
        return {'tailnet': {'profile': 'operator-private-access',
                            'administratorReference': 'owner@example.test',
                            'splitDNS': {'zone': 'internal.example.test',
                                         'resolvers': ['cloudlab', 'cloudlab-worker']},
                            'accessTests': [{'identity': 'owner@example.test',
                                             'destination': 'dns', 'expected': 'allow'}]},
                'privateDNS': {'services': services, 'platformNames': list(platform)}}

    def entry(self, service='prices', name='prices'):
        return {'service': service, 'name': name, 'backend': 'web', 'path': '/', 'port': 8080}

    def test_services_derive_dns_labels(self):
        declared = policy.validate_policy(self.document([self.entry()]))
        self.assertEqual(declared['names'], ['prices'])
        self.assertEqual(declared['services'][0]['backend'], 'web')

    def test_duplicate_labels_refused(self):
        with self.assertRaisesRegex(ValueError, 'unique'):
            policy.validate_policy(self.document(
                [self.entry(), self.entry(service='shop', name='prices')]))

    def test_reserved_service_label_refused(self):
        with self.assertRaisesRegex(ValueError, 'reserved platform'):
            policy.validate_policy(self.document([self.entry(name='s3')]))

    def test_service_platform_overlap_refused(self):
        with self.assertRaisesRegex(ValueError, 'overlap'):
            policy.validate_policy(self.document([self.entry()], ['prices']))

    def test_retired_names_format_refused(self):
        document = self.document([])
        document['privateDNS'] = {'names': ['prices']}
        with self.assertRaises(Exception):
            policy.validate_policy(document)


class DuplicateKeyTests(unittest.TestCase):
    def test_duplicate_top_level_key_refused_before_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'uplicate key'):
            policy.loads('tailnet: {}\ntailnet: {}\n')

    def test_duplicate_nested_route_key_refused_before_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'uplicate key'):
            policy.loads('privateDNS:\n  services:\n    - service: prices\n      port: 8080\n      port: 9090\n')

    def test_unique_keys_parse(self):
        self.assertEqual(policy.loads('tailnet: {zone: internal.example.test}\n'),
                         {'tailnet': {'zone': 'internal.example.test'}})
