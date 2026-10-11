"""Inventory must preserve exact receipt identities without provider writes."""
import unittest
from unittest.mock import Mock, patch

from automation.infra import snapshot as subject
from automation.infra.snapshot import capture


class SnapshotTests(unittest.TestCase):
    def test_shared_dns_management_credential_rejected_before_backend_reads(self):
        with patch.object(subject, 'dotenv_values', return_value={}), \
                patch.object(subject, 'fields', side_effect=[
                    {'API_TOKEN': 'shared', 'ACCOUNT_ID': 'account', 'ZONE_ID': 'zone'},
                    {'API_TOKEN': 'shared', 'ZONE_ID': 'zone'}]) as fields:
            with self.assertRaises(ValueError):
                subject.credentials()
        self.assertEqual(fields.call_count, 2)

    def test_exact_policy_account_endpoint_failure_is_recorded_without_mutation(self):
        admin, dns = Mock(), Mock()
        def read(method, path):
            self.assertEqual(method, 'GET')
            if '/access/apps/' in path:
                return {'id': 'app-id', 'domain': 'example.invalid', 'aud': 'audience',
                        'policies': [{'id': 'legacy-policy-id'}]}
            if '/access/policies/' in path:
                raise RuntimeError('Cloudflare API GET failed: HTTP 404')
            return {}
        admin.request.side_effect = read
        result = capture(admin, dns, {'objects': {'app:example.invalid': {'id': 'app-id'}}},
                         {'ACCOUNT_ID': 'account', 'ZONE_ID': 'zone'}, {'TUNNEL_ID': 'tunnel'})
        self.assertFalse(result['account_policy_reads']['legacy-policy-id']['supported'])
        self.assertEqual(result['applications']['example.invalid']['aud'], 'audience')
        dns.request.assert_not_called()

    def test_changed_identity_rejected_before_further_reads(self):
        admin, dns = Mock(), Mock()
        admin.request.return_value = {'id': 'replacement', 'domain': 'example.invalid', 'aud': 'audience'}
        with self.assertRaises(ValueError):
            capture(admin, dns, {'objects': {'app:example.invalid': {'id': 'original'}}},
                    {'ACCOUNT_ID': 'account'}, {})
        self.assertEqual(admin.request.call_count, 1)

    def test_pending_or_missing_owner_inventory_rejected_before_network(self):
        admin, dns = Mock(), Mock()
        for state in ({}, {'objects': {'app:example.invalid': {'intent': 'pending'}}}):
            with self.assertRaises(ValueError):
                capture(admin, dns, state, {}, {})
        admin.request.assert_not_called()
        dns.request.assert_not_called()
