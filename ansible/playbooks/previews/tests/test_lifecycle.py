import copy
import unittest
from fixtures import approval, pull
from playbooks.previews.files.lifecycle import enroll, retirement, owned, namespace_disposable
from playbooks.previews.files.contract import canonical, digest, names, OWNER


class LifecycleTests(unittest.TestCase):
    def test_outage_is_not_close_and_expiry_is_git_independent(self):
        row = approval()
        self.assertIsNone(retirement(row, row, None, 1500))
        self.assertEqual(retirement(row, row, None, 2000), 'expired')
        self.assertEqual(retirement(row, None, None, 1500), 'orphan')
        changed = pull()
        changed['head']['sha'] = 'e' * 40
        self.assertEqual(retirement(row, row, changed, 1500), 'revision-unapproved')
        closed = pull() | {'state': 'closed'}
        self.assertEqual(retirement(row, row, closed, 1500), 'closed')
        with self.assertRaises(ValueError): retirement(row, row, {}, 1500)

    def test_capacity_counts_retirement_and_tombstone_prevents_replay(self):
        state = {'format': 1, 'entries': {}}
        state = enroll(state, approval(), 1500)
        state = enroll(state, approval('b' * 32), 1500)
        state['entries']['a' * 32]['phase'] = 'retiring'
        with self.assertRaises(ValueError): enroll(state, approval('d' * 32), 1500)
        state['entries']['a' * 32]['phase'] = 'retired'
        row = approval()
        row['sourceSha'] = 'f' * 40
        with self.assertRaises(ValueError): enroll(state, row, 1500)

    def test_prefix_label_is_not_deletion_authority(self):
        row = approval()
        meta = {'name': names(row)['namespace'], 'uid': 'namespace-uid', 'resourceVersion': '4',
                'labels': {'cloudlab.io/owner': OWNER, 'cloudlab.io/preview-instance': row['instance']},
                'annotations': {'cloudlab.io/approval-digest': digest(canonical(row)), 'cloudlab.io/runtime-state-uid': 'state-uid'}}
        obj = {'kind': 'Namespace', 'metadata': meta}
        owned(obj, row, 'state-uid', 'namespace-uid')
        for uid, state in (('replaced-uid', 'state-uid'), ('namespace-uid', 'foreign-state')):
            with self.assertRaises(ValueError): owned(obj, row, state, uid)

    def test_retained_or_foreign_data_blocks_namespace_deletion(self):
        objects = [{'kind': 'Pod', 'metadata': {'name': 'child', 'uid': 'pod', 'ownerReferences': [{'uid': 'replicaset'}]}},
                   {'kind': 'ReplicaSet', 'metadata': {'name': 'replicaset', 'uid': 'replicaset', 'ownerReferences': [{'uid': 'deployment'}]}}]
        self.assertTrue(namespace_disposable(objects, {'deployment'}, 'namespace'))
        for bad in ({'kind': 'PersistentVolumeClaim', 'metadata': {'name': 'data', 'uid': 'data'}},
                    {'kind': 'ConfigMap', 'metadata': {'name': 'foreign', 'uid': 'foreign'}},
                    {'kind': 'ConfigMap', 'metadata': {'name': 'root', 'uid': 'deployment', 'annotations': {'cloudlab.io/retention': 'retain'}}}):
            with self.subTest(kind=bad['kind']), self.assertRaises(ValueError):
                namespace_disposable(objects + [bad], {'deployment'}, 'namespace')

    def test_native_generated_crl_is_disposable_but_retention_still_blocks(self):
        crl = {'kind': 'ConfigMap', 'metadata': {'name': 'istio-ca-crl', 'uid': 'native-crl'}}
        self.assertTrue(namespace_disposable([crl], set(), 'namespace'))
        retained = copy.deepcopy(crl)
        retained['metadata']['annotations'] = {'helm.sh/resource-policy': 'keep'}
        with self.assertRaises(ValueError): namespace_disposable([retained], set(), 'namespace')
        foreign = copy.deepcopy(crl)
        foreign['metadata']['name'] = 'application-data'
        with self.assertRaises(ValueError): namespace_disposable([foreign], set(), 'namespace')
