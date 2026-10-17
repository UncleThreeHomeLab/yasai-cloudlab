"""Check policy preservation and enrollment isolation without changing a tailnet."""
import unittest
import io
import os
from unittest.mock import Mock, patch
import control
from control import candidate, HOST_TAG, TEST_TAG


class PolicyTests(unittest.TestCase):
    def test_implicit_allow_all_preserves_existing_destinations(self):
        original = {'tagOwners': {'tag:other': ['autogroup:admin']}}
        devices = [{'user': 'owner@example.test'}, {'user': 'other@example.test'}]
        value = candidate(original, 'owner@example.test', [22], devices)
        self.assertEqual(value['grants'][0]['dst'], ['other@example.test', 'owner@example.test', 'tag:other'])
        self.assertNotIn(HOST_TAG, value['grants'][0]['dst'])
        self.assertEqual(value['tagOwners']['tag:other'], original['tagOwners']['tag:other'])
        self.assertEqual(candidate(value, 'owner@example.test', [22], devices), value)
        self.assertEqual(set(original), {'tagOwners'})

    def test_explicit_unrelated_rules_survive_unchanged(self):
        rule = {'src': ['tag:other'], 'dst': ['tag:another'], 'ip': ['tcp:443']}
        value = candidate({'grants': [rule]}, 'owner@example.test', [2222])
        self.assertEqual(value['grants'][0], rule)
        self.assertEqual(value['grants'][1]['ip'], ['tcp:2222'])
        self.assertTrue(any(t['src'] == TEST_TAG and HOST_TAG + ':2222' in t['deny'] for t in value['tests']))

    def test_existing_tag_owner_conflict_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'different owners'):
            candidate({'acls': [], 'tagOwners': {HOST_TAG: ['someone@example.test']}}, 'owner@example.test', [22])


class PolicyWriteTests(unittest.TestCase):
    def request(self, etag):
        api = Mock()
        api.request.side_effect = [({'grants': []}, etag), ({'devices': []}, None), ({}, None), ({}, None)]
        return api

    def test_missing_etag_blocks_write_after_validation(self):
        api = self.request(None)
        with patch.object(control, 'API', return_value=api), patch.dict(os.environ, TAILSCALE_ADMIN_LOGIN='owner@example.test'):
            with self.assertRaisesRegex(RuntimeError, 'no ETag'):
                control.policy(True)
        self.assertEqual(api.request.call_count, 3)

    def test_policy_write_uses_observed_etag_and_propagates_conflict(self):
        api = self.request('observed-version')
        api.request.side_effect = [({'grants': []}, 'observed-version'), ({'devices': []}, None), ({}, None), RuntimeError('HTTP 412')]
        with patch.object(control, 'API', return_value=api), patch.dict(os.environ, TAILSCALE_ADMIN_LOGIN='owner@example.test'):
            with self.assertRaisesRegex(RuntimeError, 'HTTP 412'):
                control.policy(True)
        self.assertEqual(api.request.call_args.args[3], 'observed-version')
        self.assertEqual(api.request.call_count, 4)

    def test_converged_policy_validates_without_write_or_new_identity(self):
        current = candidate({'grants': []}, 'owner@example.test', [22])
        api = Mock()
        api.request.side_effect = [(current, 'version'), ({'devices': []}, None), ({}, None)]
        with patch.object(control, 'API', return_value=api), patch.dict(os.environ, TAILSCALE_ADMIN_LOGIN='owner@example.test', VM_PORT='22', VM2_PORT='22'), patch('sys.stdout', new_callable=io.StringIO) as output:
            control.policy(True)
        self.assertIn('"changed": false', output.getvalue())
        self.assertEqual(api.request.call_count, 3)


if __name__ == '__main__':
    unittest.main()
