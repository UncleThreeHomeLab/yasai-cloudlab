import copy
import unittest
from adopt_backup_target import adoption_patch


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.desired = {'apiVersion': 'longhorn.io/v1beta2', 'kind': 'BackupTarget',
            'metadata': {'name': 'default', 'namespace': 'longhorn-system'},
            'spec': {'backupTargetURL': 's3://fixture@region/longhorn', 'credentialSecret': 'fixture', 'pollInterval': '0s'}}
        self.current = {'metadata': {'uid': 'retained', 'resourceVersion': '7', 'managedFields': [
            {'manager': 'longhorn-manager', 'fieldsV1': {'f:spec': {'f:backupTargetURL': {}, 'f:credentialSecret': {}, 'f:pollInterval': {}}}}]},
            'spec': {'backupTargetURL': '', 'credentialSecret': '', 'pollInterval': '5m0s', 'syncRequestedAt': None}}

    def test_adoption_is_compare_and_swap_for_exactly_three_fields(self):
        patch = adoption_patch(self.current, self.desired)
        self.assertEqual(patch[0], {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'})
        self.assertEqual({x['path'] for x in patch[1:]}, {'/spec/' + k for k in self.desired['spec']})
        self.assertEqual(self.current['metadata']['uid'], 'retained')

    def test_custom_target_or_foreign_writer_is_not_adopted(self):
        for variant in ('url', 'owner', 'poll'):
            current = copy.deepcopy(self.current)
            if variant == 'url': current['spec']['backupTargetURL'] = 'private-existing'
            if variant == 'owner': current['metadata']['managedFields'][0]['manager'] = 'other-writer'
            if variant == 'poll': current['spec']['pollInterval'] = '1h'
            with self.subTest(variant=variant), self.assertRaises(RuntimeError):
                adoption_patch(current, self.desired)

    def test_repeat_and_existing_owner_leave_normal_reconciliation_in_charge(self):
        self.current['metadata']['managedFields'][0]['manager'] = 'cloudlab'
        self.assertEqual(adoption_patch(self.current, self.desired), [])
        self.current['spec'].update(self.desired['spec'])
        self.assertEqual(adoption_patch(self.current, self.desired), [])

    def test_extra_fields_or_different_destination_fail(self):
        for key in ('extra', 'destination'):
            desired = copy.deepcopy(self.desired)
            if key == 'extra': desired['spec']['syncRequestedAt'] = 'now'
            else: desired['metadata']['namespace'] = 'other'
            with self.assertRaises(RuntimeError): adoption_patch(self.current, desired)
