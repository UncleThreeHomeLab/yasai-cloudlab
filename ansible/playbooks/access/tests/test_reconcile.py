"""Host DNS receipts use the configure digest; plan scope and review fail closed."""
import json
import os
import unittest
from unittest.mock import patch

import reconcile


def _cluster():
    return {'private_routes': [], 'public_routes': [], 'services': [],
            'cluster_gateway': '10.43.0.1', 'tailnet_gateway': '100.64.0.9',
            'certificates': {
                'private': {'ready': True,
                            'names': ['*.internal.example.test', 'login.example.test']},
                'public': {'ready': True, 'names': []}}}


class DnsReceiptTests(unittest.TestCase):
    declared = {'zone': 'internal.example.test', 'services': [], 'names': [],
                'platformNames': []}
    servers = ['100.64.0.1', '100.64.0.2']
    mapping = {'cloudlab': '100.64.0.1', 'cloudlab-worker': '100.64.0.2'}
    digest = '9' * 64

    def reconcile(self, fake_ssh):
        with patch.object(reconcile, 'ssh', side_effect=fake_ssh):
            with patch.dict(os.environ, {'VM_HOST': 'vm1', 'VM2_HOST': 'vm2'}):
                return reconcile.reconcile_dns(self.declared, self.servers,
                                               self.mapping, _cluster())

    def test_configure_digest_compared_against_generation_receipt(self):
        def fake_ssh(prefix, host, command, input=None):
            if command.startswith('cat /var/lib/cloudlab/private-dns/inputs.json'):
                raise RuntimeError('no live generation')
            if command.startswith('cat /var/lib/cloudlab/private-dns/generation'):
                return self.digest
            self.assertNotIn('upstreams', json.loads(input))
            return json.dumps({'changed': True, 'dns_ready': True, 'digest': self.digest})

        result = self.reconcile(fake_ssh)
        self.assertTrue(result['ready'])
        self.assertEqual(result['hosts']['cloudlab']['digest'], self.digest)
        self.assertEqual(result['hosts']['cloudlab-worker']['digest'], self.digest)

    def test_receipt_mismatch_blocks_convergence(self):
        def fake_ssh(prefix, host, command, input=None):
            if command.startswith('cat /var/lib/cloudlab/private-dns/inputs.json'):
                raise RuntimeError('no live generation')
            if command.startswith('cat /var/lib/cloudlab/private-dns/generation'):
                return 'observed-other'
            return json.dumps({'changed': False, 'dns_ready': True, 'digest': 'configured'})

        with self.assertRaisesRegex(RuntimeError, 'Resolver drift'):
            self.reconcile(fake_ssh)


class PlanScopeTests(unittest.TestCase):
    def test_retirement_destroy_uses_service_resource(self):
        document = {'resource_changes': [
            {'address': 'cloudflare_zero_trust_access_application.service_application["service_old"]',
             'change': {'actions': ['delete']}},
            {'address': 'cloudflare_zero_trust_tunnel_cloudflared_config.routing',
             'change': {'actions': ['update']}},
            {'address': 'cloudflare_dns_record.service_publication["service_old"]',
             'change': {'actions': ['delete']}},
        ]}
        self.assertTrue(reconcile.plan_owned_scope(document, set(), {'service_old'}))

    def test_base_application_change_refused(self):
        document = {'resource_changes': [
            {'address': 'cloudflare_zero_trust_access_application.application["fixture"]',
             'change': {'actions': ['update']}},
        ]}
        with self.assertRaisesRegex(RuntimeError, 'Unowned'):
            reconcile.plan_owned_scope(document, {'service_new'}, set())


class ReviewGuardTests(unittest.TestCase):
    def test_retired_review_flag_fails_with_migration_error(self):
        with self.assertRaisesRegex(SystemExit, 'retired; approval comes from the merged Git binding'):
            reconcile.main(['once', '--review', '0' * 64])

    def test_unapproved_private_service_blocks_resolvers(self):
        declared = dict(DnsReceiptTests.declared,
                        services=[{'service': 'ghost', 'name': 'ghost', 'backend': 'web',
                                   'path': '/', 'port': 8080}],
                        names=['ghost'])
        with patch.object(reconcile, 'ssh', side_effect=RuntimeError('no SSH in test')):
            with patch.dict(os.environ, {'VM_HOST': 'vm1', 'VM2_HOST': 'vm2'}):
                with self.assertRaisesRegex(RuntimeError, 'lack approved services'):
                    reconcile.reconcile_dns(declared, DnsReceiptTests.servers,
                                            DnsReceiptTests.mapping, _cluster())
