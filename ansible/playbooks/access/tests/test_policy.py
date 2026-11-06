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
                'names': [], 'platformNames': []}

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
