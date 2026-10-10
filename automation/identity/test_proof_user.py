import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation.identity.configuration import proof_user
from automation.identity.chart import render
from automation.identity.session_fixture import scope, enroll


class ProofUserTests(unittest.TestCase):
    def test_foreign_identity_owner_is_rejected_before_any_resource_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owned', 'revision': 'a' * 40}))
            foreign = {'metadata': {'uid': 'foreign'}, 'spec': {'source': {'helm': {'valuesObject': {}}}}}
            with patch('automation.identity.maintenance.BASE', root), \
                    patch('automation.mesh.kube.get', return_value=foreign), \
                    patch('automation.mesh.kube.kube') as write:
                with self.assertRaises(RuntimeError):
                    enroll({'nonce': 'a' * 32})
                write.assert_not_called()
            self.assertFalse((root / ('proof-' + 'a' * 32 + '.json')).exists())
    def test_fixture_scope_cannot_select_people_realms_or_credentials(self):
        self.assertEqual(scope({'nonce': 'a' * 32}), 'a' * 32)
        for request in ({}, {'nonce': 123}, {'nonce': 'unsafe'}, {'nonce': 'a' * 32, 'realm': 'master'},
                        {'nonce': 'a' * 32, 'username': 'personal-admin'}):
            with self.assertRaises(ValueError):
                scope(request)
    def setUp(self):
        self.nonce = 'a' * 32
        self.values = {'username': 'proof-' + self.nonce, 'ownership_id': self.nonce,
                       'password': 'x' * 48, 'email': 'disposable@example.invalid'}
        self.state = {'realm': 'platform', 'users': [
            {'username': self.values['username'], 'groups': ['/viewer'],
             'email': self.values['email'], 'emailVerified': True}]}

    def test_creation_is_scoped_and_repeat_preserves_disabled_credentials(self):
        original = copy.deepcopy(self.state)
        result = proof_user(self.state, [], self.values, self.nonce)
        self.assertEqual(self.state, original)
        self.assertEqual(set(result), {'realm', 'users'})
        user = result['users'][0]
        self.assertEqual(user['requiredActions'], ['webauthn-register'])
        self.assertEqual(user['credentials'][0]['value'], self.values['password'])
        current = dict(user, enabled=False, id='immutable')
        self.assertEqual(proof_user(self.state, [current], self.values, self.nonce),
                         {'realm': 'platform', 'users': []})
        self.assertFalse(current['enabled'])

    def test_rejects_unowned_account_revocation_privilege_and_incomplete_private_inputs(self):
        with self.assertRaises(ValueError):
            proof_user(self.state, [{'username': self.values['username']}], self.values, self.nonce)
        for changes in ({'enabled': False}, {'groups': ['/platform-admin']}, {'groups': ['/viewer', '/developer']},
                        {'emailVerified': False}, {'email': 'other@example.invalid'}):
            state = copy.deepcopy(self.state); state['users'][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                proof_user(state, [], self.values, self.nonce)
        for values in (dict(self.values, ownership_id='b' * 32), dict(self.values, password='short'),
                       dict(self.values, username='personal-admin')):
            with self.assertRaises(ValueError):
                proof_user(self.state, [], values, self.nonce)

    def test_chart_uses_eso_and_the_same_lease_without_normal_state_tracking(self):
        values = {'enabled': True, 'reconciliationEnabled': True, 'privateStateEnabled': True,
                  'bootstrapAdminEnabled': False, 'trustedProxyAddresses': ['10.0.0.1'],
                  'databaseCA': 'fixture-ca',
                  'operation': {'action': 'initialize-proof', 'realm': 'platform', 'nonce': self.nonce}}
        objects = render(values)
        secret = next(o for o in objects if o['kind'] == 'ExternalSecret' and o['metadata']['name'] == 'keycloak-proof')
        self.assertEqual(secret['spec']['dataFrom'][0]['extract']['key'], 'keycloak-proof-' + self.nonce)
        job = next(o for o in objects if o['kind'] == 'Job')['spec']['template']['spec']
        init = job['initContainers'][0]['args'][0]
        self.assertLess(init.index('acquire_sync();'), init.index("prepare_proof_user('/imports'"))
        self.assertIn('--import.remote-state.enabled=false', job['containers'][0]['args'][0])
        self.assertIn('/imports/proof.json', job['containers'][0]['args'][0])
        self.assertNotIn('prepare_removal(', init)
        self.assertTrue(next(o for o in objects if o['kind'] == 'CronJob' and o['metadata']['name'] == 'identity-reconcile')['spec']['suspend'])
        for operation in (dict(values['operation'], realm='master'), dict(values['operation'], nonce='unsafe'),
                          dict(values['operation'], username='personal-admin')):
            with self.assertRaises(ValueError):
                render(dict(values, operation=operation))


if __name__ == '__main__':
    unittest.main()
