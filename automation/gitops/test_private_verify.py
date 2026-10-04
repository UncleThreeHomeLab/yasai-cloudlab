import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'verification/integration'))
from private_verify import healthy, credential_failure


class PrivateConvergenceTests(unittest.TestCase):
    def test_failed_credential_probe_restores_only_fixture_template(self):
        objects = {'externalsecret.external-secrets.io': {'spec': {'target': {'template': {
            'data': {'githubAppPrivateKey': 'original-template'}}}}},
            'secret': {'data': {'githubAppPrivateKey': 'original-secret'}}}
        with patch('private_verify.get', side_effect=lambda kind, name: objects[kind]), \
                patch('private_verify.kube') as kube, patch('private_verify.mutate') as mutate, \
                patch('private_verify.wait', side_effect=[None, RuntimeError('probe failed'), None]):
            with self.assertRaisesRegex(RuntimeError, 'probe failed'):
                credential_failure('fixture', lambda: None, 'retained-uid')
        self.assertEqual(kube.call_count, 2)
        self.assertTrue(all(call.args[:3] == ('patch', 'externalsecret.external-secrets.io', 'fixture')
                            for call in kube.call_args_list))
        self.assertIn('original-template', kube.call_args_list[-1].args[-1])
        self.assertEqual(mutate.call_count, 2)

    def test_retained_resources_can_converge_without_a_new_sync_operation(self):
        app = {'status': {'sync': {'status': 'Synced', 'revision': 'resolved-commit'},
                          'health': {'status': 'Healthy'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(healthy('fixture'))
        for phase in ('Running', 'Failed', 'Error', 'Terminating'):
            changed = copy.deepcopy(app)
            changed['status']['operationState'] = {'phase': phase}
            with self.subTest(phase=phase), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('fixture'))
        for change in ({'sync': {'status': 'Synced'}}, {'conditions': [{'type': 'ComparisonError'}]},
                       {'sync': {'status': 'Unknown', 'revision': 'old'}}):
            changed = copy.deepcopy(app)
            changed['status'].update(change)
            with self.subTest(change=change), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('fixture'))
