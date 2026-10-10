import copy
import json
from pathlib import Path
import unittest
import yaml

from automation.connectivity.test_reconcile import Provider
from automation.identity.session_access import configure, remove


class SessionAccessTests(unittest.TestCase):
    def fixture(self):
        nonce = 'a' * 32
        state = {'binding': 'owned', 'objects': {'dns:public.example.invalid': {'id': 'dns'}},
                 'identity_provider': {'phase': 'accepted', 'id': 'provider', 'binding': {'account': 'account'}},
                 'identity_cutover': {'phase': 'accepted'}}
        values = {'username': 'proof-'+nonce, 'ownership_id': nonce, 'email': 'fixture@example.invalid'}
        return Provider(), state, values, {'nonce': nonce}

    def test_viewer_fixture_is_repeat_safe_and_does_not_change_production(self):
        api, state, values, request = self.fixture()
        production = copy.deepcopy(state['identity_provider'])
        result = configure(api, 'account', state, lambda _: None, 'public.example.invalid', values, request)
        self.assertTrue(result['changed'])
        wanted = state['identity_session_canary']['desired']
        self.assertEqual(wanted['policies'][0]['include'], [{'email': {'email': values['email']}}])
        self.assertEqual(wanted['policies'][0]['require'][1]['oidc']['claim_value'], '/viewer')
        api.writes.clear()
        self.assertFalse(configure(api, 'account', state, lambda _: None, 'public.example.invalid', values, request)['changed'])
        self.assertEqual(api.writes, [])
        self.assertEqual(state['identity_provider'], production)
        before = copy.deepcopy(state)
        with self.assertRaises(RuntimeError):
            configure(api, 'account', state, lambda _: None, 'public.example.invalid', values, {'nonce':'b'*32})
        self.assertEqual(state, before)

    def test_cleanup_refuses_foreign_policy_and_preserves_other_objects(self):
        api, state, values, request = self.fixture()
        configure(api, 'account', state, lambda _: None, 'public.example.invalid', values, request)
        path = 'accounts/account/access/apps/'+state['identity_session_canary']['id']
        api.objects[path]['domain'] = 'foreign.example.invalid'
        with self.assertRaises(RuntimeError):
            remove(api, 'account', state, lambda _: None, request)
        api.objects[path] = dict(state['identity_session_canary']['desired'], id=state['identity_session_canary']['id'],
                                 aud=state['identity_session_canary']['aud'])
        original = api.request
        def provider(method, path, document=None):
            if method == 'DELETE':
                api.objects.pop(path); return {}
            return original(method, path, document)
        api.request = provider
        self.assertTrue(remove(api, 'account', state, lambda _: None, request)['changed'])
        self.assertFalse(remove(api, 'account', state, lambda _: None, request)['changed'])
        self.assertEqual(state['objects'], {'dns:public.example.invalid': {'id':'dns'}})

    def test_browser_sessions_have_no_persistent_profile_or_docker_logs(self):
        root = Path(__file__).resolve().parents[2]
        service = yaml.safe_load((root/'compose.identity-proof.yaml').read_text())['services']['sessions']
        self.assertEqual(service['logging'], {'driver':'none'})
        self.assertTrue(service['read_only'])
        self.assertEqual(service['volumes'], ['.:/workspace:ro'])
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertEqual(service['user'], '1000:1000')
        self.assertIn('live-sessions', service['profiles'])


if __name__ == '__main__':
    unittest.main()
