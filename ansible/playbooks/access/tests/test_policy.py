"""Managed tailnet tests converge across server changes; unmanaged tests survive."""
import unittest

import policy


class ManagedTestPruneTests(unittest.TestCase):
    servers = ['100.64.0.1', '100.64.0.2']
    rotated = ['100.64.0.3', '100.64.0.4']
    login = 'owner@example.test'

    def declared(self):
        return {'profile': 'operator-private-access', 'administrator': self.login,
                'zone': 'internal.example.test', 'resolvers': ['cloudlab', 'cloudlab-worker'],
                'accessTests': [(self.login, 'dns', 'allow'),
                                ('tag:cloudlab-denied', 'private-gateway', 'deny')],
                'services': [], 'names': [], 'platformNames': []}

    def test_server_rotation_converges_without_stale_dns_tests(self):
        before = policy.candidate({'grants': []}, self.declared(), self.servers)
        self.assertTrue(any('100.64.0.1:53' in test.get('deny', [])
                            for test in before['tests']))
        after = policy.candidate(before, self.declared(), self.rotated)
        targets = [target for test in after['tests']
                   for target in list(test.get('accept', [])) + list(test.get('deny', []))]
        self.assertNotIn('100.64.0.1:53', targets)
        self.assertNotIn('100.64.0.2:53', targets)
        self.assertIn('100.64.0.3:53', targets)
        names = policy.tags()
        gateway = [names['ingressService'] + ':443', names['apiService'] + ':443']
        self.assertIn({'src': self.login, 'accept': gateway}, after['tests'])
        self.assertEqual(policy.candidate(after, self.declared(), self.rotated), after)

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
