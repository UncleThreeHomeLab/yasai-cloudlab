"""Retained fixture behavior; native publication has no imperative writer."""
import copy
import unittest

from playbooks.access.files.cloudflare import access_application
from playbooks.access.files.reconcile import Reconciler
from playbooks.access.tests.fixtures import Provider


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.api, self.state, self.saved = Provider(), {'binding': 'fixture'}, []
        self.desired = access_application({'hostname': 'canary.example.invalid', 'access': 'human'},
            human_email='admin@example.invalid', identity_provider='otp')

    def ensure(self, desired=None, key='identity-canary'):
        client = Reconciler(self.state, lambda value: self.saved.append(value))
        result = client.ensure(self.api, key, 'accounts/account/access/apps', desired or self.desired,
                               lambda value: value.get('domain') == 'canary.example.invalid')
        return client, result

    def test_repeat_apply_preserves_ids_and_performs_zero_writes(self):
        _, created = self.ensure()
        before = copy.deepcopy(self.state)
        self.api.writes.clear()
        client, repeated = self.ensure()
        self.assertFalse(client.changed)
        self.assertEqual(repeated['id'], created['id'])
        self.assertEqual(self.api.writes, [])
        self.assertEqual(self.state, before)

    def test_interrupted_create_resumes_without_duplicate_identity(self):
        self.api.interrupt_create = True
        with self.assertRaises(RuntimeError):
            self.ensure()
        self.assertEqual(len(self.api.objects), 1)
        self.assertIn('intent', self.saved[-1]['objects']['identity-canary'])
        self.ensure()
        self.assertEqual(len(self.api.objects), 1)

    def test_drift_repair_removes_unauthorized_rules_and_preserves_ids(self):
        _, created = self.ensure()
        path = next(iter(self.api.objects))
        self.api.objects[path]['policies'][0]['include'].append({'everyone': {}})
        client, repaired = self.ensure()
        self.assertTrue(client.changed)
        self.assertEqual(repaired['id'], created['id'])
        self.assertEqual(repaired['aud'], created['aud'])
        self.assertEqual(repaired['policies'], self.desired['policies'])

    def test_external_deletion_does_not_recreate_identity(self):
        self.ensure()
        self.api.objects.clear()
        self.api.writes.clear()
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            self.ensure()
        self.assertEqual(self.api.writes, [])

    def test_unowned_hostname_is_not_adopted(self):
        self.api.objects['accounts/account/access/apps/other'] = {'id': 'other', 'domain': 'canary.example.invalid'}
        with self.assertRaisesRegex(RuntimeError, 'Unowned'):
            self.ensure()
        self.assertEqual(self.api.writes, [])

    def test_transferred_scope_blocks_old_writer_but_preserves_separate_fixtures(self):
        self.state['infra_owner'] = {'phase': 'accepted', 'binding': self.state['binding'],
                                    'objects': {'app:production.example.invalid': {'id': 'native'}}}
        with self.assertRaises(RuntimeError):
            self.ensure(key='app:production.example.invalid')
        self.assertEqual(self.api.writes, [])
        self.ensure()
        self.assertEqual(len(self.api.writes), 1)

    def test_invalid_ownership_marker_never_reactivates_old_writer(self):
        for owner in ({}, None, False):
            self.state = {'infra_owner': owner}
            with self.assertRaises(RuntimeError):
                self.ensure()
        self.assertEqual(self.api.writes, [])

    def test_app_updates_preserve_existing_nested_policy_id(self):
        self.ensure()
        path = next(iter(self.api.objects))
        self.api.objects[path]['policies'][0]['id'] = 'retained-policy'
        desired = copy.deepcopy(self.desired)
        desired['session_duration'] = '15m'
        _, updated = self.ensure(desired)
        self.assertEqual(updated['policies'][0]['id'], 'retained-policy')


if __name__ == '__main__':
    unittest.main()
