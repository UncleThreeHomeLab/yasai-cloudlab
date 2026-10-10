import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from automation.identity.access_cutover import approved_email, prepare, selection, gate
from automation.identity import maintenance, emergency
from automation.identity.access_provider import public_provider
from automation.identity.access_provider import prepare as prepare_provider
from automation.identity.integrations import access, argo
from automation.connectivity.cloudflare import access_application


class AccessCutoverTests(unittest.TestCase):
    def test_unchanged_provider_preserves_acceptance_rotation_requires_new_proof(self):
        from automation.connectivity.test_reconcile import Provider
        api = Provider(); state = {'phase': 'configured', 'binding': 'owned'}
        path = 'accounts/' + 'a' * 32 + '/access/identity_providers'
        prior = {'id': 'previous', 'name': 'Prior provider', 'type': 'onetimepin', 'config': {}}
        api.objects[path + '/previous'] = copy.deepcopy(prior)
        contract = access('https://login.example.invalid/realms/platform', 'fixture', 'x' * 64)
        prepare_provider(api, 'a' * 32, 'previous', contract, state, lambda value: None)
        contract['human_email'] = 'fixture@example.invalid'
        self.proven(state)
        prepare(state, 'previous', contract)
        state['identity_provider']['phase'] = state['identity_cutover']['phase'] = 'accepted'
        self.assertFalse(prepare_provider(api, 'a' * 32, 'previous',
            {key: value for key, value in contract.items() if key != 'human_email'}, state, lambda value: None)['changed'])
        self.assertEqual(state['identity_provider']['phase'], 'accepted')
        contract = access('https://login.example.invalid/realms/platform', 'fixture', 'y' * 64)
        self.assertTrue(prepare_provider(api, 'a' * 32, 'previous', contract, state, lambda value: None)['changed'])
        self.assertEqual(state['identity_provider']['phase'], 'configured')
        self.assertEqual(selection(state, 'previous'), (state['identity_provider']['id'], '/platform-admin'))
        self.assertEqual(api.objects[path + '/previous'], prior)

    def test_gate_requires_completed_recovery_and_current_native_mapping_enrolled_active_operator(self):
        values = {'loginHost': 'login.example.invalid', 'adminHost': 'identity-admin.internal.example.invalid',
                  'bootstrapAdminEnabled': False, 'retiredEmergencyItem': 'keycloak-emergency-' + 'a' * 32}
        app = {'metadata': {'uid': 'owned'}, 'spec': {'source': {'helm': {'valuesObject': values}}}}
        expected = argo('https://login.example.invalid/realms/platform', 'https://cd.example.invalid',
                        ['https://cd.internal.example.invalid'])['helm']['argo-cd']['configs']
        retired = {'phase': 'accepted', 'application_uid': 'owned', 'keycloak_uid': 'server', 'nonce': 'a' * 32}
        changes = {}
        def get(kind, name, namespace):
            if kind == 'keycloak.k8s.keycloak.org': return {'metadata': {'uid': 'server'}}
            if kind == 'application.argoproj.io': return app
            return {'data': dict(expected['rbac'] if name == 'argocd-rbac-cm' else expected['cm'], **changes.get('cm', {}))}
        def request(url, **kwargs):
            if url.endswith('/token'): return {'access_token': 'private-token'}
            if '/events?' in url: return changes.get('events', [])
            if '/users?' in url: return [dict({'id': 'primary', 'enabled': True, 'emailVerified': True, 'email': 'fixture@example.invalid',
                'attributes': {'cloudlab-primary-owner': ['owner']}}, **changes.get('user', {}))]
            if url.endswith('/credentials'): return changes.get('credentials', [{'type': 'webauthn'}])
            return changes.get('groups', [{'path': '/platform-admin'}])
        with tempfile.TemporaryDirectory() as directory, patch.object(maintenance, 'BASE', Path(directory)), \
                patch('automation.mesh.kube.get', side_effect=get), \
                patch.object(emergency, 'current_private', return_value='fixture@example.invalid') as private, \
                patch.object(emergency, 'vault_secret', side_effect=lambda name: {'platform_username': 'fixture', 'ownership_id': 'owner', 'email': 'fixture@example.invalid'}
                    if name == 'keycloak-primary-admin' else {'platform_client_secret': 'private-secret'}), \
                patch('automation.identity.configuration.private_request', side_effect=request), \
                patch('automation.identity.access_provider.snapshot', return_value={'contract': 'fixture'}) as snapshot:
            (Path(directory) / 'ownership.json').write_text(json.dumps({'uid': 'owned'}))
            path = Path(directory) / 'retirement.json'; path.write_text(json.dumps(retired))
            self.assertEqual(gate('fixture'), {'contract': 'fixture', 'human_email': 'fixture@example.invalid'})
            now = int(time.time())
            event = {'type': 'CODE_TO_TOKEN', 'clientId': 'cloudflare-access', 'userId': 'primary', 'time': now * 1000}
            for event_change in (None, {'time': (now - 901) * 1000}, {'time': (now + 1) * 1000},
                                 {'clientId': 'argocd'}, {'userId': 'other'}, {'type': 'LOGIN'}, {'error': 'invalid_client'}):
                changes['events'] = [] if event_change is None else [dict(event, **event_change)]
                with self.subTest(event_change=event_change), self.assertRaises(RuntimeError): gate('fixture', since=now - 1000)
            changes['events'] = [event]
            self.assertEqual(gate('fixture', since=now - 1000), {'contract': 'fixture', 'human_email': 'fixture@example.invalid'})
            for change in ({'user': {'enabled': False}}, {'user': {'email': 'other@example.invalid'}}, {'credentials': []}, {'groups': [{'path': '/nested/platform-admin'}]},
                           {'cm': {'users.session.duration': '1h'}}, {'cm': {'url': 'https://other.example.invalid'}}):
                changes.clear(); changes.update(change); snapshot.reset_mock()
                with self.subTest(change=change), self.assertRaises(RuntimeError): gate('fixture')
                snapshot.assert_not_called()
            changes.clear(); retired['phase'] = 'guarded'; path.write_text(json.dumps(retired)); snapshot.reset_mock()
            with self.assertRaises(RuntimeError): gate('fixture')
            snapshot.assert_not_called()
            retired['phase'] = 'accepted'; path.write_text(json.dumps(retired))
            private.side_effect = RuntimeError('Current private membership is revoked')
            with self.assertRaises(RuntimeError): gate('fixture')
            snapshot.assert_not_called()

    def fixture(self):
        contract = access('https://login.example.invalid/realms/platform', 'fixture', 'x' * 64)
        state = {'phase': 'configured', 'binding': 'owned', 'identity_provider': {
            'id': 'dedicated', 'phase': 'prepared', 'binding': {'account': 'a' * 32, 'previous': 'previous'},
            'credential_ready_at': int(time.time()) - 10,
            'intent': public_provider(contract['provider']),
            'credential_hash': hashlib.sha256(('x' * 64).encode()).hexdigest()}}
        self.proven(state)
        contract['human_email'] = 'fixture@example.invalid'
        return state, contract

    def proven(self, state):
        from automation.identity.access_canary import desired
        owner = state['identity_provider']
        state['identity_canary'] = {'phase': 'proven', 'binding': state['binding'], 'provider': owner['id'],
            'credential_hash': owner['credential_hash'], 'provider_intent': copy.deepcopy(owner['intent']),
            'provider_ready_at': owner['credential_ready_at'], 'configured_at': owner['credential_ready_at'],
            'verified_at': int(time.time()), 'hostname': 'public.example.invalid',
            'desired': desired('public.example.invalid', 'fixture@example.invalid', owner['id'])}

    def test_no_real_policy_switch_without_recent_provider_specific_browser_proof(self):
        state, contract = self.fixture()
        for change in ({'phase': 'configured'}, {'verified_at': 0}, {'credential_hash': 'old'}, {'provider': 'foreign'}):
            changed = copy.deepcopy(state); changed['identity_canary'].update(change)
            with self.subTest(change=change), self.assertRaises(RuntimeError): prepare(changed, 'previous', contract)
            self.assertNotIn('identity_cutover', changed)

    def test_repeat_preserves_receipt_and_selection_never_contacts_idp(self):
        state, contract = self.fixture()
        self.assertEqual(selection(state, 'previous'), ('previous', None))
        self.assertTrue(prepare(state, 'previous', contract))
        original = copy.deepcopy(state)
        self.assertFalse(prepare(state, 'previous', contract))
        self.assertEqual(state, original)
        with patch('urllib.request.build_opener') as network:
            self.assertEqual(selection(state, 'previous'), ('dedicated', '/platform-admin'))
            network.assert_not_called()

    def test_bad_receipts_fail_without_falling_back_to_previous_provider(self):
        state, contract = self.fixture(); prepare(state, 'previous', contract)
        for key, value in (('phase', 'unknown'), ('binding', 'foreign'), ('previous', 'other'),
                           ('provider', 'foreign'), ('group', '/nested/platform-admin'), ('human_email', '')):
            changed = copy.deepcopy(state); changed['identity_cutover'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): selection(changed, 'previous')

    def test_platform_email_is_bound_to_canary_and_selection_remains_independent(self):
        state, contract = self.fixture()
        previous = 'personal@example.invalid'
        self.assertEqual(approved_email(state, previous), previous)
        contract['human_email'] = 'homelab@example.invalid'
        with self.assertRaises(RuntimeError): prepare(state, 'previous', contract)
        from automation.identity.access_canary import desired
        state['identity_canary']['desired'] = desired('public.example.invalid', contract['human_email'], 'dedicated')
        self.assertTrue(prepare(state, 'previous', contract))
        with patch('urllib.request.build_opener') as network:
            self.assertEqual(approved_email(state, previous), 'homelab@example.invalid')
            network.assert_not_called()

    def test_drifted_secret_or_provider_cannot_create_cutover_intent(self):
        for key, value in (('credential_hash', 'foreign'), ('intent', {}), ('phase', 'unknown')):
            state, contract = self.fixture(); state['identity_provider'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): prepare(state, 'previous', contract)
            self.assertNotIn('identity_cutover', state)

    def test_human_requires_email_exact_group_and_dedicated_provider_machine_policy_preserved(self):
        human = {'hostname': 'cd.example.invalid', 'access': 'human'}
        actual = access_application(human, human_email='fixture@example.invalid', identity_provider='dedicated', identity_group='/platform-admin')
        self.assertEqual(actual['allowed_idps'], ['dedicated'])
        self.assertEqual(actual['policies'][0]['include'], [{'email': {'email': 'fixture@example.invalid'}}])
        self.assertEqual(actual['policies'][0]['require'], [
            {'login_method': {'id': 'dedicated'}},
            {'oidc': {'claim_name': 'groups', 'claim_value': '/platform-admin', 'identity_provider_id': 'dedicated'}}])
        with self.assertRaises(ValueError): access_application(human, human_email='fixture@example.invalid', identity_provider='dedicated', identity_group='platform-admin')
        machine = {'hostname': 'api.example.invalid', 'access': 'machine'}
        self.assertEqual(access_application(machine, service_token_id='machine'),
                         access_application(machine, service_token_id='machine', identity_group='/platform-admin'))


if __name__ == '__main__':
    unittest.main()
