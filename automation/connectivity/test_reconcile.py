"""Exercise interruption, drift repair, collisions and stable external identities."""
import copy
import unittest

from automation.connectivity.reconcile import Reconciler


class Provider:
    def __init__(self):
        self.objects = {}
        self.config = {'config': {'ingress': [{'service': 'http_status:404'}]}}
        self.writes = []
        self.interrupt_create = False

    def collection(self, path):
        return [copy.deepcopy(v) for k, v in self.objects.items() if k.rsplit('/', 1)[0] == path]

    def request(self, method, path, document=None):
        if method != 'GET':
            self.writes.append((method, path))
        if path.endswith('/configurations'):
            if method == 'PUT':
                self.config = copy.deepcopy(document)
            return copy.deepcopy(self.config)
        if method == 'POST':
            identity = str(len(self.objects) + 1)
            value = dict(copy.deepcopy(document), id=identity)
            if path.endswith('/apps'):
                value['aud'] = 'fixture-audience'
            self.objects[path + '/' + identity] = value
            if self.interrupt_create:
                self.interrupt_create = False
                raise RuntimeError('connection lost after server committed creation')
            return copy.deepcopy(value)
        if method == 'PUT':
            self.objects[path].update(copy.deepcopy(document))
        return copy.deepcopy(self.objects[path])


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.api, self.state, self.saved = Provider(), {}, []
        self.inputs = dict(account='account', zone_id='zone', zone='example.invalid', tunnel='tunnel',
                           rules=[{'name': 'human', 'access': 'human'}, {'name': 'machine', 'access': 'machine'}],
                           team='fixture', human_email='admin@example.invalid', identity_provider='otp', service_token_id='token')

    def run_apply(self):
        return Reconciler(self.api, self.api, self.state, lambda value: self.saved.append(value)).run(**self.inputs)

    def test_repeat_apply_preserves_ids_and_performs_zero_writes(self):
        self.assertTrue(self.run_apply()['changed'])
        before = copy.deepcopy(self.state)
        self.api.writes.clear()
        self.assertFalse(self.run_apply()['changed'])
        self.assertEqual(self.api.writes, [])
        self.assertEqual(self.state, before)
        self.assertFalse(self.run_apply()['acceptance_passed'])

    def test_unused_api_managed_tunnel_can_have_null_configuration(self):
        self.api.config = {'config': None}
        self.assertTrue(self.run_apply()['configured'])

    def test_interrupted_create_resumes_without_duplicate_identity(self):
        self.api.interrupt_create = True
        with self.assertRaises(RuntimeError):
            self.run_apply()
        self.assertEqual(len(self.api.objects), 1)
        self.assertIn('intent', next(iter(self.saved[-1]['objects'].values())))
        self.run_apply()
        self.assertEqual(len(self.api.objects), 4)

    def test_drift_repair_removes_unauthorized_rules_and_preserves_ids(self):
        self.run_apply()
        path = next(k for k in self.api.objects if '/apps/' in k)
        identity = self.api.objects[path]['id']
        self.api.objects[path]['policies'][0]['include'].append({'everyone': {}})
        self.assertTrue(self.run_apply()['changed'])
        self.assertEqual(self.api.objects[path]['id'], identity)
        self.assertEqual(len(self.api.objects[path]['policies'][0]['include']), 1)

    def test_external_deletion_does_not_recreate_identity(self):
        self.run_apply()
        del self.api.objects[next(k for k in self.api.objects if '/apps/' in k)]
        self.api.writes.clear()
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            self.run_apply()
        self.assertEqual(self.api.writes, [])

    def test_classification_change_does_not_remove_protection(self):
        self.run_apply()
        self.inputs['rules'][0]['access'] = 'public'
        self.api.writes.clear()
        with self.assertRaisesRegex(RuntimeError, 'migration'):
            self.run_apply()
        self.assertEqual(self.api.writes, [])

    def test_unowned_tunnel_routes_are_preserved(self):
        self.api.config['config']['ingress'].insert(0, {'hostname': 'other.example.invalid', 'service': 'http://other'})
        with self.assertRaisesRegex(RuntimeError, 'unowned'):
            self.run_apply()
        self.assertEqual(self.api.writes, [])

    def test_unowned_hostname_is_not_adopted(self):
        self.api.objects['accounts/account/access/apps/other'] = {'id': 'other', 'domain': 'human.example.invalid'}
        with self.assertRaisesRegex(RuntimeError, 'Unowned'):
            self.run_apply()
        self.assertEqual(self.api.writes, [])

    def test_dns_publishes_only_after_protection_and_tunnel(self):
        self.run_apply()
        writes = self.api.writes
        self.assertTrue(all('/apps' in path for _, path in writes[:2]))
        self.assertTrue(writes[2][1].endswith('/configurations'))
        self.assertTrue(all('/dns_records' in path for _, path in writes[3:]))

    def test_invalid_late_rule_prevents_all_mutation(self):
        self.inputs['rules'].append({'name': 'internal', 'access': 'public'})
        with self.assertRaises(ValueError):
            self.run_apply()
        self.assertEqual(self.api.writes, [])


if __name__ == '__main__':
    unittest.main()
