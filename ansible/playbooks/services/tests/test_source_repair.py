import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import mock_open, patch
from playbooks.services.files import bootstrap, repair_source_owner as repair
from playbooks.services.tests.fixtures import catalog_payload


class SourceRepairTests(unittest.TestCase):
    def setUp(self):
        self.payload = catalog_payload()
        before = dict(self.payload, revision='c' * 40)
        self.current = bootstrap.application(before)
        self.update = {'apiVersion': 'argoproj.io/v1alpha1', 'fieldsType': 'FieldsV1', 'manager': bootstrap.OWNER,
                       'operation': 'Update', 'time': '2026-10-17T23:54:00Z',
                       'fieldsV1': {'f:spec': {'f:sources': {}}}}
        self.apply = dict(self.update, operation='Apply', fieldsV1={'f:spec': {'f:project': {}}})
        self.foreign = dict(self.update, manager='argocd-controller', fieldsV1={'f:status': {}})
        self.current['metadata'].update(uid='original', resourceVersion='42',
                                        managedFields=[self.apply, self.update, self.foreign])
        self.record = {'uid': 'original', 'sources': copy.deepcopy(self.current['spec']['sources']),
                       'entry': copy.deepcopy(self.update)}
        self.calls = []
        self.probe_change = None
        self.refusal = 'Apply failed with 1 conflict: conflict with "service-platform" using argoproj.io/v1alpha1: .spec.sources'

    def kube(self, *args, document, allow_failure=False):
        self.calls.append((args, copy.deepcopy(document)))
        self.assertEqual(document['spec'], bootstrap.application(self.payload)['spec'])
        self.assertEqual(document['metadata']['uid'], 'original')
        self.assertEqual(document['metadata']['resourceVersion'], '42')
        if allow_failure:
            self.assertIn('--dry-run=server', args)
            self.assertNotIn('--force-conflicts', args)
            return SimpleNamespace(returncode=1, stderr=self.refusal)
        self.assertIn('--force-conflicts', args)
        result = copy.deepcopy(self.current)
        result['spec'] = copy.deepcopy(document['spec'])
        owned = copy.deepcopy(self.apply)
        owned['fieldsV1']['f:spec']['f:sources'] = {}
        result['metadata']['managedFields'] = [owned, copy.deepcopy(self.foreign)]
        if self.probe_change:
            self.probe_change(result)
        if '--dry-run=server' not in args:
            self.current = result
        return json.dumps(result)

    def run_repair(self):
        with patch.object(repair.Path, 'open', mock_open()), patch.object(repair.fcntl, 'flock'), \
                patch.object(repair, 'get', side_effect=lambda *a: self.current), \
                patch.object(repair, 'converged', return_value=True), patch.object(repair, 'wait'), \
                patch.object(repair, 'kube', side_effect=self.kube):
            return repair.recover(self.payload, self.record)

    def test_exact_recovery_dry_run_then_complete_apply_and_repeat(self):
        self.assertEqual(self.run_repair(), {'changed': True})
        self.assertEqual(len(self.calls), 3)
        self.assertIn('--dry-run=server', self.calls[1][0])
        self.assertNotIn('--dry-run=server', self.calls[2][0])
        self.assertEqual(self.run_repair(), {'changed': False})
        self.assertEqual(len(self.calls), 3)

    def test_changed_record_identity_ownership_or_sources_refused_before_apply(self):
        for case in ('uid', 'timestamp', 'fieldset', 'manager', 'operation', 'sources', 'owner', 'refs', 'finalizers',
                     'deleting', 'extra-manager', 'unrelated-spec'):
            with self.subTest(case=case):
                self.setUp()
                if case == 'uid': self.current['metadata']['uid'] = 'foreign'
                elif case == 'timestamp': self.current['metadata']['managedFields'][1]['time'] = '2026-10-18T00:00:00Z'
                elif case == 'fieldset': self.record['entry']['fieldsV1']['f:spec']['f:project'] = {}
                elif case == 'manager': self.record['entry']['manager'] = 'foreign'
                elif case == 'operation': self.record['entry']['operation'] = 'Apply'
                elif case == 'sources': self.current['spec']['sources'][1]['targetRevision'] = 'foreign'
                elif case == 'owner': self.current['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
                elif case == 'refs': self.current['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                elif case == 'finalizers': self.current['metadata']['finalizers'] = ['foreign']
                elif case == 'deleting': self.current['metadata']['deletionTimestamp'] = 'now'
                elif case == 'extra-manager': self.current['metadata']['managedFields'].append(self.update)
                elif case == 'unrelated-spec': self.current['spec']['project'] = 'foreign'
                with self.assertRaises((ValueError, RuntimeError)):
                    self.run_repair()
                self.assertEqual(self.calls, [])

    def test_unhealthy_or_active_catalog_refused_before_apply(self):
        with patch.object(repair.Path, 'open', mock_open()), patch.object(repair.fcntl, 'flock'), \
                patch.object(repair, 'get', return_value=self.current), \
                patch.object(repair, 'converged', return_value=False), patch.object(repair, 'kube') as kube:
            with self.assertRaisesRegex(RuntimeError, 'healthy idle'):
                repair.recover(self.payload, self.record)
        kube.assert_not_called()

    def test_different_or_additional_conflict_never_forced(self):
        for refusal in ('unavailable', self.refusal.replace('service-platform', 'foreign'),
                        self.refusal + '\nconflict with "foreign": .spec.project'):
            with self.subTest(refusal=refusal):
                self.refusal = refusal
                self.calls.clear()
                with self.assertRaisesRegex(RuntimeError, 'recorded sources conflict'):
                    self.run_repair()
                self.assertEqual(len(self.calls), 1)

    def test_dry_run_rejects_unrelated_changes_or_incomplete_apply(self):
        def metadata(app): app['metadata']['labels']['foreign'] = 'new'
        def destination(app): app['spec']['destination']['namespace'] = 'foreign'
        def foreign(app): app['metadata']['managedFields'][-1]['fieldsV1'] = {'f:spec': {}}
        def lost_owned_field(app): app['metadata']['managedFields'][0]['fieldsV1']['f:spec'].pop('f:project')
        def update_remains(app): app['metadata']['managedFields'].append(self.update)
        def status(app): app['status'] = {'foreign': True}
        for change in (metadata, destination, foreign, lost_owned_field, update_remains, status):
            with self.subTest(change=change.__name__):
                self.setUp()
                self.probe_change = change
                with self.assertRaisesRegex(RuntimeError, 'dry-run'):
                    self.run_repair()
                self.assertEqual(len(self.calls), 2)

    def test_normal_bootstrap_uses_complete_apply_without_force(self):
        desired = bootstrap.application(self.payload)
        with patch.object(bootstrap.Path, 'open', mock_open()), patch.object(bootstrap.fcntl, 'flock'), \
                patch.object(bootstrap, 'get', return_value=None), patch.object(bootstrap, 'wait'), \
                patch.object(bootstrap, 'kube') as kube:
            self.assertEqual(bootstrap.configure(self.payload), {'changed': True})
        self.assertNotIn('--force-conflicts', kube.call_args.args)
        self.assertEqual(kube.call_args.kwargs['document'], desired)
