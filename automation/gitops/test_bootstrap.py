import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import bootstrap


class BootstrapTests(unittest.TestCase):
    def test_interrupted_identity_binding_repairs_controller_without_idp_or_replacement(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'identity-values-binding.json').write_text(json.dumps({
                'phase': 'paused', 'root_uid': 'root', 'controller_uid': 'controller', 'project_uid': 'project'}))
            objects = {'application.argoproj.io': {'metadata': {'uid': 'root'}},
                'statefulset': {'metadata': {'uid': 'controller'}, 'spec': {'replicas': 0}},
                'appproject.argoproj.io': {'metadata': {'uid': 'project'}}}
            with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'get', side_effect=lambda kind, name: objects[kind]), \
                    patch.object(bootstrap, 'kube') as repair:
                self.assertTrue(bootstrap.resume_identity_binding())
                self.assertEqual(repair.call_args.args, ('scale', 'statefulset/argocd-application-controller',
                    '-n', 'argocd', '--replicas=1'))
                objects['statefulset']['metadata']['uid'] = 'foreign'
                with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                    bootstrap.resume_identity_binding()
                self.assertEqual(repair.call_count, 1)

    def test_explicit_interruption_stops_before_root_creation_and_is_not_repeated(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'checkpoint.json').write_text(json.dumps({'phase': 'seeded', 'identities': {}}))
            with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'apply') as apply, \
                    patch.object(bootstrap, 'wait_application') as wait, contextlib.redirect_stdout(io.StringIO()) as output:
                bootstrap.run({'operator': [], 'roots': [], 'stop_after_seed': True})
                self.assertTrue(json.loads(output.getvalue())['interrupted_fixture'])
                apply.assert_not_called()
                wait.assert_not_called()
            state = json.loads((base / 'checkpoint.json').read_text())
            self.assertEqual(state['phase'], 'seeded')
            self.assertTrue(state['interruption_test_completed'])

    def test_resume_after_handoff_never_restarts_the_bootstrap_writer(self):
        for phase in ('seeded', 'argo-requested', 'accepted'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                state = {'phase': phase, 'version': 'fixture', 'identities': {'service/f': 'retained'}}
                (base / 'checkpoint.json').write_text(json.dumps(state))
                with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'apply') as apply, \
                        patch.object(bootstrap, 'get', return_value={'metadata': {'uid': 'root'}}), \
                        patch.object(bootstrap, 'wait_application', return_value='revision'), \
                        patch.object(bootstrap, 'identity', return_value=state['identities']), contextlib.redirect_stdout(io.StringIO()):
                    bootstrap.run({'operator': [], 'roots': [], 'version': 'fixture', 'revision': 'revision'})
                    apply.assert_not_called()
                self.assertEqual(json.loads((base / 'checkpoint.json').read_text())['phase'], 'accepted')

    def test_replaced_object_blocks_acceptance_without_reapplying(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'checkpoint.json').write_text(json.dumps({'phase': 'argo-requested', 'identities': {'service/f': 'old'}}))
            with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'apply') as apply, \
                    patch.object(bootstrap, 'wait_application', return_value='revision'), \
                    patch.object(bootstrap, 'identity', return_value={'service/f': 'new'}):
                with self.assertRaisesRegex(RuntimeError, 'replaced'):
                    bootstrap.run({'operator': [], 'roots': [], 'version': 'fixture', 'revision': 'revision'})
                apply.assert_not_called()
            self.assertEqual(json.loads((base / 'checkpoint.json').read_text())['phase'], 'argo-requested')

    def test_foreign_installation_is_not_silently_adopted(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(bootstrap, 'BASE', Path(folder)), \
                patch.object(bootstrap, 'get', return_value={'metadata': {'uid': 'foreign'}}), patch.object(bootstrap, 'apply') as apply:
            with self.assertRaisesRegex(RuntimeError, 'Unowned'):
                bootstrap.run({'operator': [], 'roots': [], 'version': 'fixture'})
            apply.assert_not_called()

    def test_old_synced_revision_is_not_current_convergence(self):
        def app(revision):
            return {'status': {'sync': {'status': 'Synced', 'revision': revision},
                'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
        with patch.object(bootstrap, 'get', side_effect=[app('old'), app('new')]), patch.object(bootstrap.time, 'sleep') as sleep:
            self.assertEqual(bootstrap.wait_application('fixture', 'new'), 'new')
            sleep.assert_called_once()
