"""Local recovery may read only the current disposable fixture's source."""
import unittest

from verify import snapshot_parameters


class SnapshotScopeTests(unittest.TestCase):
    def test_foreign_or_unbound_source_is_rejected(self):
        for status in ({}, {'kubernetesStatus': {'namespace': 'other', 'pvcName': 'source'}},
                       {'kubernetesStatus': {'namespace': 'fixture', 'pvcName': 'unrelated'}}):
            with self.subTest(status=status), self.assertRaisesRegex(RuntimeError, 'disposable namespace'):
                snapshot_parameters({'status': status}, 'fixture', 'snapshot', {})

    def test_restore_keeps_replica_policy_and_selects_the_fixed_snapshot(self):
        volume = {'metadata': {'name': 'fixture-volume'},
                  'status': {'kubernetesStatus': {'namespace': 'fixture', 'pvcName': 'source'}}}
        base = {'numberOfReplicas': '2', 'dataEngine': 'v1'}
        actual = snapshot_parameters(volume, 'fixture', 'fixed-point', base)
        self.assertEqual(actual['dataSource'], 'snap://fixture-volume/fixed-point')
        self.assertEqual(actual['numberOfReplicas'], '2')
        self.assertNotIn('dataSource', base)
        self.assertNotIn('fromBackup', actual)
