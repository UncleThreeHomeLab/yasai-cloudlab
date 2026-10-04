"""Ownership boundaries must survive interruption without restarting old writers."""
import hashlib
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('eso_bootstrap', Path(__file__).with_name('bootstrap.py'))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
OBJECTS = [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'external-secrets'}},
           {'apiVersion': 'external-secrets.io/v1', 'kind': 'ClusterSecretStore', 'metadata': {'name': 'cloudlab'}}]
DIGEST = hashlib.sha256(json.dumps(OBJECTS, sort_keys=True).encode()).hexdigest()


class BootstrapTests(unittest.TestCase):
    def test_crds_require_actual_argo_ssa_spec_ownership(self):
        crd = {'kind': 'CustomResourceDefinition'}
        marker_only = {'metadata': {'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-external-secrets:fixture'}}}
        self.assertFalse(bootstrap.argo_owned(crd, marker_only))
        current = {'metadata': {'managedFields': [{'manager': 'argocd-controller', 'operation': 'Apply',
                                                 'fieldsV1': {'f:spec': {}}}]}}
        self.assertTrue(bootstrap.argo_owned(crd, current))
        self.assertFalse(bootstrap.argo_owned({'kind': 'Deployment'}, current))
        self.assertTrue(bootstrap.argo_owned({'kind': 'Deployment'}, marker_only))

    def test_new_seed_interruption_release_and_adoption_preserve_token(self):
        live = {}
        token = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {
            'name': 'onepassword-token', 'namespace': 'external-secrets', 'uid': 'token-uid'},
            'data': {'token': 'unchanged-fixture'}}
        app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {
            'name': 'cloudlab-external-secrets', 'namespace': 'argocd'},
            'spec': {'syncPolicy': {'automated': {'enabled': True}}},
            'status': {'sync': {'status': 'Synced', 'revision': 'reviewed'}, 'health': {'status': 'Healthy'}}}
        def apply(objects):
            for obj in objects:
                identity = bootstrap.key(obj)
                live.setdefault(identity, copy.deepcopy(obj))
                live[identity]['metadata'].setdefault('uid', 'uid-' + str(len(live)))
        with tempfile.TemporaryDirectory() as folder, patch.object(bootstrap, 'BASE', Path(folder)), \
                patch.object(bootstrap, 'get', side_effect=lambda obj: live.get(bootstrap.key(obj))), \
                patch.object(bootstrap, 'apply', side_effect=apply) as writer, patch.object(bootstrap, 'kube'), \
                patch.object(bootstrap, 'consumer_identities', return_value={'consumer': {'uid': 'original', 'content': 'same'}}):
            self.assertEqual(bootstrap.run(OBJECTS, 'seed-stop')['phase'], 'seeded')
            self.assertNotIn(bootstrap.key(OBJECTS[1]), live)
            live[bootstrap.key(token)] = copy.deepcopy(token)
            self.assertEqual(bootstrap.run(OBJECTS, 'release')['phase'], 'released')
            for obj in OBJECTS:
                live[bootstrap.key(obj)]['metadata']['annotations'] = {
                    'argocd.argoproj.io/tracking-id': 'cloudlab-external-secrets:fixture'}
            live[bootstrap.key(app)] = app
            self.assertEqual(bootstrap.run(OBJECTS, 'accept', 'reviewed')['phase'], 'accepted')
            writer.reset_mock()
            self.assertFalse(bootstrap.run(OBJECTS, 'seed')['changed'])
            self.assertFalse(bootstrap.run(OBJECTS, 'release')['changed'])
            writer.assert_not_called()
            self.assertEqual(live[bootstrap.key(token)], token)

    def test_interruption_checkpoint_is_repeatable_before_release(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / bootstrap.CHECKPOINT).write_text(json.dumps(
                dict(phase='seeded', digest=DIGEST, owner='cloudlab-bootstrap', identities={})))
            with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'apply') as apply:
                self.assertTrue(bootstrap.run(OBJECTS, 'seed-stop')['interruption_test_completed'])
                self.assertFalse(bootstrap.run(OBJECTS, 'seed-stop')['changed'])
                apply.assert_not_called()

    def test_released_and_accepted_never_restart_bootstrap_writes(self):
        for phase in ('released', 'accepted'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                (base / bootstrap.CHECKPOINT).write_text(json.dumps(
                    dict(phase=phase, digest=DIGEST, owner='argocd', identities={}, consumers={})))
                with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'apply') as apply:
                    for action in ('seed', 'release'):
                        self.assertFalse(bootstrap.run(OBJECTS, action)['changed'])
                    apply.assert_not_called()

    def test_release_resumes_after_seed_and_preserves_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / bootstrap.CHECKPOINT).write_text(json.dumps(
                dict(phase='seeded', digest=DIGEST, owner='cloudlab-bootstrap', identities={'object': 'original'})))
            with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'apply') as apply, \
                    patch.object(bootstrap, 'get', side_effect=[None, {'metadata': {'uid': 'token'}}, None]), \
                    patch.object(bootstrap, 'kube'), patch.object(bootstrap, 'identities', return_value={'object': 'original'}), \
                    patch.object(bootstrap, 'consumer_identities', return_value={}):
                result = bootstrap.run(OBJECTS, 'release')
            self.assertEqual(result['phase'], 'released')
            apply.assert_called_once_with([OBJECTS[1]])

    def test_changed_chart_blocks_incomplete_transition(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / bootstrap.CHECKPOINT).write_text(json.dumps(dict(phase='released', digest='old')))
            with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'apply') as apply:
                with self.assertRaisesRegex(RuntimeError, 'before changing'):
                    bootstrap.run(OBJECTS, 'seed')
                apply.assert_not_called()

    def test_competing_application_blocks_initial_seed(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(bootstrap, 'BASE', Path(folder)), \
                patch.object(bootstrap, 'get', return_value={'metadata': {'uid': 'existing'}}), \
                patch.object(bootstrap, 'apply') as apply:
            with self.assertRaisesRegex(RuntimeError, 'competing'):
                bootstrap.run(OBJECTS, 'seed')
            apply.assert_not_called()

    def test_partial_install_without_checkpoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(bootstrap, 'BASE', Path(folder)), \
                patch.object(bootstrap, 'get', return_value=None), \
                patch.object(bootstrap, 'identities', return_value={'namespace': 'existing'}), \
                patch.object(bootstrap, 'apply') as apply:
            with self.assertRaisesRegex(RuntimeError, 'Partial'):
                bootstrap.run(OBJECTS, 'seed')
            apply.assert_not_called()

    def test_replaced_object_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            bootstrap.preserved({'secret': 'original'}, {'secret': 'replacement'})
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            bootstrap.preserved({'secret': {'uid': 'same', 'content': 'original'}},
                                {'secret': {'uid': 'same', 'content': 'changed'}})

    def test_reviewed_configuration_advances_recovery_digest_only_after_convergence(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            receipt = base / bootstrap.CHECKPOINT
            receipt.write_text(json.dumps(dict(phase='accepted', owner='argocd', digest='previous', identities={}, consumers={})))
            app = {'spec': {'syncPolicy': {'automated': {'enabled': True}}},
                   'status': {'sync': {'status': 'OutOfSync', 'revision': 'reviewed'},
                              'health': {'status': 'Healthy'}}}
            with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'get', return_value=app), \
                    patch.object(bootstrap, 'identities', return_value={}), \
                    patch.object(bootstrap, 'argo_owned', return_value=True), patch.object(bootstrap, 'apply') as writer:
                with self.assertRaises(bootstrap.PendingConvergence):
                    bootstrap.run(OBJECTS, 'accept', 'reviewed')
                self.assertEqual(json.loads(receipt.read_text())['digest'], 'previous')
                app['status']['sync']['status'] = 'Synced'
                self.assertTrue(bootstrap.run(OBJECTS, 'accept', 'reviewed')['changed'])
                self.assertEqual(json.loads(receipt.read_text())['digest'], DIGEST)
                self.assertFalse(bootstrap.run(OBJECTS, 'accept', 'reviewed')['changed'])
                writer.assert_not_called()

    def test_recovery_refuses_an_active_writer(self):
        for app in ({}, {'spec': {'syncPolicy': {'automated': {'enabled': True}}}},
                    {'spec': {'syncPolicy': {'automated': {'enabled': False}}}, 'operation': {'sync': {}}}):
            with self.subTest(app=app), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                (base / bootstrap.CHECKPOINT).write_text(json.dumps(
                    dict(phase='accepted', digest=DIGEST, owner='argocd', identities={})))
                with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'get', return_value=app), \
                        patch.object(bootstrap, 'apply') as apply:
                    with self.assertRaisesRegex(RuntimeError, 'Suspend'):
                        bootstrap.run(OBJECTS, 'recover')
                    apply.assert_not_called()

    def test_recovery_resumes_only_with_writer_suspended(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / bootstrap.CHECKPOINT).write_text(json.dumps(
                dict(phase='recovering', digest=DIGEST, owner='cloudlab-bootstrap', identities={'object': 'original'})))
            app = {'spec': {'syncPolicy': {'automated': {'enabled': False}}}}
            with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'get', return_value=app), \
                    patch.object(bootstrap, 'identities', return_value={'object': 'original'}), \
                    patch.object(bootstrap, 'seed_operator') as seed, patch.object(bootstrap, 'apply'), \
                    patch.object(bootstrap, 'kube'):
                self.assertEqual(bootstrap.run(OBJECTS, 'recover')['phase'], 'released')
                seed.assert_called_once_with([OBJECTS[0]])


if __name__ == '__main__':
    unittest.main()
