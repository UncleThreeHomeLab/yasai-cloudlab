import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import private_retire


class PrivateRetirementTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.path = self.base / 'private-example.json'
        self.state = {'phase': 'accepted', 'owner': 'cloudlab-private-bootstrap',
                      'identities': {kind: kind + '-uid' for kind in private_retire.CHECKPOINT_KINDS}}
        self.path.write_text(json.dumps(self.state))
        self.objects = {kind: {'metadata': {'name': 'cloudlab-private-example', 'uid': kind + '-uid',
            'resourceVersion': '1', 'labels': {'cloudlab.io/owner': 'private-gitops'},
            'managedFields': [{'manager': 'cloudlab-private-bootstrap'}]}} for kind in private_retire.KINDS}
        self.objects['Secret']['metadata']['ownerReferences'] = [{'apiVersion': 'external-secrets.io/v1',
            'kind': 'ExternalSecret', 'name': 'cloudlab-private-example', 'uid': 'ExternalSecret-uid', 'controller': True}]
        self.objects['ExternalSecret']['spec'] = {'target': {'name': 'cloudlab-private-example',
            'creationPolicy': 'Owner', 'deletionPolicy': 'Retain'}}
        self.calls = []

    def delete(self, *args, document):
        self.calls.append((args, copy.deepcopy(document)))
        kind = next(kind for kind, (_, route) in private_retire.KINDS.items() if args[1] == '--raw=' + route + 'cloudlab-private-example')
        self.assertEqual(document['preconditions'], {key: self.objects[kind]['metadata'][key] for key in ('uid', 'resourceVersion')})
        self.assertEqual(json.loads(self.path.read_text())['retirement']['secret_uid'], 'Secret-uid')
        self.objects.pop(kind)

    def run_retirement(self, delete=None):
        with patch.object(private_retire, 'BASE', self.base), \
                patch.object(private_retire, 'current', side_effect=lambda kind, name: copy.deepcopy(self.objects.get(kind))), \
                patch.object(private_retire, 'kube', side_effect=delete or self.delete):
            return private_retire.retire('example')

    def test_scoped_preconditioned_deletion_retains_namespace_and_repeat_is_noop(self):
        namespace = copy.deepcopy(self.objects['Namespace'])
        self.assertTrue(self.run_retirement()['changed'])
        self.assertEqual(self.objects, {'Namespace': namespace})
        self.assertEqual(json.loads(self.path.read_text())['phase'], 'removed')
        self.assertFalse(self.run_retirement()['changed'])
        self.assertEqual(len(self.calls), 4)

    def test_foreign_uid_owner_tracking_finalizer_or_manager_blocks_before_deletion(self):
        baseline = copy.deepcopy(self.objects)
        for kind, change in (('Application', {'uid': 'foreign'}), ('Secret', {'ownerReferences': []}),
                             ('Namespace', {'labels': {}}), ('AppProject', {'managedFields': []}),
                             ('AppProject', {'managedFields': [{'manager': 'cloudlab-private-bootstrap'},
                                 {'manager': 'other', 'fieldsV1': {'f:spec': {}}}]}),
                             ('Application', {'finalizers': ['cascade']}),
                             ('ExternalSecret', {'annotations': {'argocd.argoproj.io/tracking-id': 'new-owner'}})):
            self.objects = copy.deepcopy(baseline)
            self.objects[kind]['metadata'].update(change)
            with self.subTest(kind=kind, change=change), self.assertRaises(RuntimeError):
                self.run_retirement()
            self.assertEqual(self.calls, [])
            self.assertEqual(json.loads(self.path.read_text())['phase'], 'accepted')

    def test_incomplete_checkpoint_or_missing_initial_credential_cannot_authorize_deletion(self):
        self.objects.pop('Secret')
        with self.assertRaises(RuntimeError): self.run_retirement()
        self.state['identities'].pop('Namespace')
        self.path.write_text(json.dumps(self.state))
        with self.assertRaises(RuntimeError): self.run_retirement()
        self.assertEqual(self.calls, [])

    def test_known_eso_finalizer_uses_normal_controller_cleanup_without_stripping(self):
        self.objects['ExternalSecret']['metadata']['finalizers'] = [private_retire.ESO_FINALIZER]
        def delete(*args, document):
            if '/externalsecrets/' in args[1]:
                self.assertEqual(self.objects['ExternalSecret']['metadata']['finalizers'], [private_retire.ESO_FINALIZER])
            self.delete(*args, document=document)
        self.assertTrue(self.run_retirement(delete)['changed'])
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(all(args[0] == 'delete' for args, document in self.calls))

    def test_unknown_or_additional_eso_finalizers_and_expanded_targets_refuse_all_deletes(self):
        baseline = copy.deepcopy(self.objects)
        for finalizers, target_change in ((['foreign'], {}), ([private_retire.ESO_FINALIZER, 'foreign'], {}),
                ([private_retire.ESO_FINALIZER], {'name': 'other'}),
                ([private_retire.ESO_FINALIZER], {'creationPolicy': 'Merge'}),
                ([private_retire.ESO_FINALIZER], {'deletionPolicy': 'Delete'}),
                ([private_retire.ESO_FINALIZER], {'resource': {'kind': 'ConfigMap'}})):
            self.objects = copy.deepcopy(baseline)
            self.objects['ExternalSecret']['metadata']['finalizers'] = finalizers
            self.objects['ExternalSecret']['spec']['target'].update(target_change)
            with self.subTest(finalizers=finalizers, target=target_change), self.assertRaises(RuntimeError):
                self.run_retirement()
            self.assertEqual(self.calls, [])
            self.assertEqual(json.loads(self.path.read_text())['phase'], 'accepted')

    def test_interrupted_delete_resumes_from_durable_secret_identity(self):
        def interrupted(*args, document):
            if len(self.calls) == 1: raise RuntimeError('interrupted')
            self.delete(*args, document=document)
        with self.assertRaisesRegex(RuntimeError, 'interrupted'): self.run_retirement(interrupted)
        self.assertNotIn('Application', self.objects)
        self.assertTrue(self.run_retirement()['changed'])
        self.assertEqual(set(self.objects), {'Namespace'})

    def test_eso_garbage_collection_of_captured_secret_is_safe_on_resume(self):
        self.state.update(phase='retiring', retirement={'secret_uid': 'Secret-uid'})
        self.path.write_text(json.dumps(self.state))
        self.objects.pop('ExternalSecret')
        self.objects.pop('Secret')
        self.assertTrue(self.run_retirement()['changed'])
        self.assertEqual(len(self.calls), 2)

    def test_recreated_secret_and_retired_name_reuse_are_not_deleted(self):
        self.state.update(phase='retiring', retirement={'secret_uid': 'old-uid'})
        self.path.write_text(json.dumps(self.state))
        with self.assertRaises(RuntimeError): self.run_retirement()
        self.state['phase'] = 'removed'
        self.path.write_text(json.dumps(self.state))
        with self.assertRaises(RuntimeError): self.run_retirement()
        self.assertEqual(self.calls, [])

    def test_runtime_cleanup_requires_terminal_checkpoints_and_preserves_files(self):
        with patch.object(private_retire, 'BASE', self.base), self.assertRaises(RuntimeError):
            private_retire.runtime_ready()
        self.state['phase'] = 'removed'
        self.path.write_text(json.dumps(self.state))
        with patch.object(private_retire, 'BASE', self.base):
            self.assertTrue(private_retire.runtime_ready()['legacy_registrations_retired'])
        self.assertTrue(self.path.is_file())

    def test_selector_cannot_escape_ownership_directory(self):
        for name in ('', '../other', 'x/other', '-flag', 'X', 'a' * 31):
            with self.subTest(name=name), self.assertRaises(RuntimeError): private_retire.retire(name)
