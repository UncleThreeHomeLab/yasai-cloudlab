"""Reject conflicting writers and identity loss across storage handoffs."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bootstrap


class StorageOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.patch = patch.object(bootstrap, 'BASE', self.base)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.payload = {'items': [], 'fixture': {}, 'revision': 'reviewed'}

    def state(self, phase):
        bootstrap.record({'phase': phase, 'digest': bootstrap.hashlib.sha256(b'[]').hexdigest(),
            'owner': 'argocd' if phase == 'accepted' else 'awaiting-argocd',
            'identities': {}, 'storage': {}, 'fixture': {'nonce': 'fixture'}})

    def test_no_receipt_cannot_adopt_an_existing_argo_writer(self):
        with patch.object(bootstrap, 'get', return_value={'spec': {}}), patch.object(bootstrap, 'seed') as apply:
            with self.assertRaisesRegex(RuntimeError, 'competing Argo'):
                bootstrap.run(self.payload, 'seed')
            apply.assert_not_called()
        self.assertFalse((self.base / 'ownership.json').exists())

    def test_released_and_accepted_never_reapply_operator(self):
        for phase in ('released', 'accepted'):
            self.state(phase)
            with patch.object(bootstrap, 'seed') as apply, patch.object(bootstrap, 'get') as read:
                result = bootstrap.run(self.payload, 'seed')
                self.assertFalse(result['changed'])
                apply.assert_not_called()
                read.assert_not_called()

    def test_recovery_refuses_active_or_unfinished_argo_sync(self):
        self.state('accepted')
        for app in ({}, {'spec': {'syncPolicy': {'automated': {'enabled': True}}}},
                    {'spec': {'syncPolicy': {'automated': {'enabled': False}}}, 'operation': {'sync': {}}},
                    {'spec': {'syncPolicy': {'automated': {'enabled': False}}},
                     'status': {'operationState': {'phase': 'Running'}}}):
            with self.subTest(app=app), patch.object(bootstrap, 'get', return_value=app), patch.object(bootstrap, 'seed') as apply:
                with self.assertRaisesRegex(RuntimeError, 'Suspend storage'):
                    bootstrap.run(self.payload, 'recover')
                apply.assert_not_called()
                self.assertEqual(json.loads((self.base / 'ownership.json').read_text())['phase'], 'accepted')

    def test_interruption_injection_is_forbidden_after_release(self):
        self.state('released')
        with self.assertRaisesRegex(RuntimeError, 'precede writer release'):
            bootstrap.run(self.payload, 'seed-stop')

    def test_identity_content_and_attachment_loss_fail_closed(self):
        for before, after in (({'pvc': 'original'}, {'pvc': 'replacement'}),
                              ({'secret': {'uid': 'same', 'content': 'old'}}, {'secret': {'uid': 'same', 'content': 'new'}}),
                              ({'volume': {'attached_node': 'first'}}, {'volume': {'attached_node': ''}})):
            with self.subTest(before=before), self.assertRaisesRegex(RuntimeError, 'identity, attachment, or credential'):
                bootstrap.preserve(before, after)

    def test_crd_needs_real_argo_spec_ownership(self):
        obj = {'kind': 'CustomResourceDefinition'}
        self.assertFalse(bootstrap.owned(obj, {'metadata': {'annotations': {
            'argocd.argoproj.io/tracking-id': 'cloudlab-longhorn:forged'}}}))
        self.assertTrue(bootstrap.owned(obj, {'metadata': {'managedFields': [{
            'manager': 'argocd-controller', 'operation': 'Apply', 'fieldsV1': {'f:spec': {}}}]}}))

    def test_seed_interruption_resumes_without_reapplying_then_accepts_once(self):
        obj = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'longhorn-system'}}
        self.payload['items'] = [obj]
        live = {'metadata': {'uid': 'original', 'managedFields': [{'manager': 'cloudlab'}]}}
        fixture = {'nonce': 'fixture', 'pod_uid': 'pod', 'namespace_uid': 'namespace', 'volume': 'volume'}
        with patch.object(bootstrap, 'get', side_effect=lambda item: None if item == bootstrap.APP else live), \
                patch.object(bootstrap, 'storage_receipt', return_value={}), \
                patch.object(bootstrap, 'kube') as kube, patch.object(bootstrap, 'seed') as seed, \
                patch.object(bootstrap.handoff_fixture, 'prepare', return_value=fixture), \
                patch.object(bootstrap.handoff_fixture, 'verify'):
            first = bootstrap.run(self.payload, 'seed-stop')
            self.assertEqual(first['phase'], 'seeded')
            second = bootstrap.run(self.payload, 'seed')
            self.assertEqual(second['phase'], 'released')
            seed.assert_called_once_with([obj])
            self.assertIn('--dry-run=server', kube.call_args.args)
            self.assertNotIn('--force-conflicts', kube.call_args.args)
        app = {'spec': {'syncPolicy': {'automated': {'enabled': True}}},
               'status': {'sync': {'status': 'Synced', 'revision': 'reviewed'}, 'health': {'status': 'Healthy'}}}
        with patch.object(bootstrap, 'get', side_effect=lambda item: app if item == bootstrap.APP else live), \
                patch.object(bootstrap, 'storage_receipt', return_value={}), patch.object(bootstrap, 'owned', return_value=True), \
                patch.object(bootstrap.handoff_fixture, 'verify') as check, \
                patch.object(bootstrap.handoff_fixture, 'cleanup') as cleanup:
            self.assertEqual(bootstrap.run(self.payload, 'accept')['phase'], 'accepted')
            self.assertFalse(bootstrap.run(self.payload, 'accept')['changed'])
            check.assert_called_once()
            cleanup.assert_called_once_with(fixture)

    def test_changed_chart_cannot_resume_a_partial_transition(self):
        self.state('released')
        self.payload['items'] = [{'different': True}]
        with patch.object(bootstrap, 'seed') as seed:
            with self.assertRaisesRegex(RuntimeError, 'before changing chart inputs'):
                bootstrap.run(self.payload, 'seed')
            seed.assert_not_called()

    def test_recovery_reuses_the_unfinished_handoff_fixture(self):
        self.state('released')
        app = {'spec': {'syncPolicy': {'automated': {'enabled': False}}}}
        with patch.object(bootstrap, 'get', return_value=app), \
                patch.object(bootstrap, 'storage_receipt', return_value={}), patch.object(bootstrap, 'seed') as seed, \
                patch.object(bootstrap.handoff_fixture, 'prepare', return_value={'nonce': 'fixture'}) as prepare, \
                patch.object(bootstrap.handoff_fixture, 'verify'):
            result = bootstrap.run(self.payload, 'recover')
            self.assertEqual(result['phase'], 'released')
            self.assertEqual(prepare.call_args.args[1], {'nonce': 'fixture'})
            seed.assert_called_once_with([])
