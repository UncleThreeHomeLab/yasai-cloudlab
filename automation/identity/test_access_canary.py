import copy
import json
import unittest
from unittest.mock import patch

from automation.identity import access_canary as canary
from automation.connectivity.test_reconcile import Provider


class CanaryTests(unittest.TestCase):
    def fixture(self):
        state = {'binding': 'owned', 'objects': {'dns:public.example.invalid': {'id': 'dns'}},
                 'identity_provider': {'id': 'dedicated', 'intent': {'config': {'client_id': 'cloudflare-access'}}, 'credential_hash': 'current'}}
        api = Provider()
        saved = []
        canary.configure(api, 'account', state, lambda value: saved.append(copy.deepcopy(value)), 'public.example.invalid', 'fixture@example.invalid')
        return api, state, saved

    def test_configure_repeat_preserves_identity_without_real_policy_writes(self):
        api, state, saved = self.fixture()
        before = copy.deepcopy(state); api.writes.clear()
        result = canary.configure(api, 'account', state, lambda value: saved.append(copy.deepcopy(value)), 'public.example.invalid', 'fixture@example.invalid')
        self.assertFalse(result['changed'])
        self.assertEqual(result['real_application_policies_changed'], 0)
        self.assertEqual(api.writes, [])
        self.assertEqual(state, before)
        self.assertEqual(state['identity_canary']['desired']['domain'], 'public.example.invalid' + canary.CANARY_PATH)

    def test_actual_signed_session_backend_and_machine_boundary_gate_proof_no_token_retained(self):
        for responses, passes in (([{'status': 200, 'body': b'mesh-ok'}, {'status': 403, 'body': b''}], True),
                                 ([{'status': 200, 'body': b'login page'}], False),
                                 ([{'status': 200, 'body': b'mesh-ok'}, {'status': 200, 'body': b'mesh-ok'}], False)):
            api, state, saved = self.fixture()
            with self.subTest(passes=passes), patch.object(canary, 'verify_token', return_value=1000) as verify, \
                    patch.object(canary, 'https', side_effect=responses):
                if passes:
                    result = canary.record(api, 'account', state, lambda value: saved.append(copy.deepcopy(value)),
                        'fixture.cloudflareaccess.com', 'fixture@example.invalid', 'private-session-token', ['machine.example.invalid'])
                    self.assertTrue(result['dedicated_provider_browser_and_backchannel_proven'])
                    self.assertTrue(canary.verified(state, now=1001))
                    self.assertFalse(canary.verified(state, now=1901))
                    self.assertNotIn('private-session-token', json.dumps(saved))
                    verify.assert_called_once_with('private-session-token', state['identity_canary']['aud'],
                        'fixture.cloudflareaccess.com', 'fixture@example.invalid')
                else:
                    with self.assertRaises(RuntimeError):
                        canary.record(api, 'account', state, lambda value: saved.append(copy.deepcopy(value)),
                            'fixture.cloudflareaccess.com', 'fixture@example.invalid', 'private-session-token', ['machine.example.invalid'])
                    self.assertEqual(state['identity_canary']['phase'], 'configured')

    def test_rotated_or_foreign_provider_cannot_reuse_old_canary(self):
        for key, value in (('credential_hash', 'old'), ('provider', 'foreign'), ('binding', 'foreign'), ('provider_intent', {})):
            api, state, _ = self.fixture(); state['identity_canary'].update(phase='proven', verified_at=1000)
            state['identity_canary'][key] = value
            self.assertFalse(canary.verified(state, now=1001))
            with patch.object(canary, 'verify_token') as verify, self.assertRaises(RuntimeError):
                canary.record(api, 'account', state, lambda value: None, 'fixture.cloudflareaccess.com',
                    'fixture@example.invalid', 'private-session-token', ['machine.example.invalid'])
            verify.assert_not_called()

    def test_cleanup_exact_owned_path_repeat_safe_unrelated_objects_preserved(self):
        api, state, _ = self.fixture()
        api.objects['accounts/account/access/apps/unrelated'] = {'id': 'unrelated', 'domain': 'other.example.invalid'}
        original = api.request
        def request(method, path, document=None):
            if method == 'DELETE':
                api.writes.append((method, path)); api.objects.pop(path); return {}
            return original(method, path, document)
        api.request = request
        self.assertTrue(canary.remove(api, 'account', state, lambda value: None)['changed'])
        self.assertFalse(canary.remove(api, 'account', state, lambda value: None)['changed'])
        self.assertIn('accounts/account/access/apps/unrelated', api.objects)
        self.assertEqual(state['objects'], {'dns:public.example.invalid': {'id': 'dns'}})

    def test_cleanup_refuses_foreign_policy_without_deletion(self):
        api, state, _ = self.fixture()
        api.objects['accounts/account/access/apps/' + state['identity_canary']['id']]['domain'] = 'other.example.invalid'
        api.writes.clear()
        with self.assertRaises(RuntimeError): canary.remove(api, 'account', state, lambda value: None)
        self.assertEqual(api.writes, [])


if __name__ == '__main__':
    unittest.main()
