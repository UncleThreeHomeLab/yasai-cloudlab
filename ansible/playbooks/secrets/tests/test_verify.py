import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('eso_verify', Path(__file__).parents[1] / 'files/verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class FakeRetirementTests(unittest.TestCase):
    def test_no_synthetic_provider_remains_in_verifier(self):
        source = Path(verify.__file__).read_text()
        self.assertNotIn('fake', source)

    def test_fresh_auth_proof_cleans_its_disposable_store(self):
        store = {'spec': {'provider': {'onepasswordSDK': {'auth': {'serviceAccountSecretRef': {}}}}}}
        ready_doc = {'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        with patch.object(verify, 'kubectl', side_effect=[store, ready_doc, None, ready_doc, None]) as kube, \
                patch.object(verify, 'wait', side_effect=lambda check: check()), \
                contextlib.redirect_stdout(io.StringIO()):
            verify.main('cloudlab')
        self.assertEqual(kube.call_count, 5)
        deleted = kube.call_args_list[-1]
        self.assertEqual(deleted.args[:2], ('delete', 'secretstore'))
        self.assertIn('cloudlab-verify-cloudlab', deleted.args)


class OperatorDriftTests(unittest.TestCase):
    def test_drift_fixture_changes_only_a_declared_metadata_label(self):
        original = {'metadata': {'uid': 'retained', 'labels': {'app.kubernetes.io/version': 'fixture'},
                    'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-external-secrets:fixture'}},
                    'spec': {'replicas': 1}}
        with patch.object(verify, 'kubectl', side_effect=[original, None, original, original]) as kube, \
                patch.object(verify, 'wait', side_effect=lambda check: self.assertTrue(check())), \
                contextlib.redirect_stdout(io.StringIO()):
            verify.operator_drift()
        changed = json.loads(kube.call_args_list[1].args[-1])
        self.assertEqual(changed, {'metadata': {'labels': {'app.kubernetes.io/version': 'drift-fixture'}}})

    def test_replaced_operator_cannot_pass_drift_proof(self):
        original = {'metadata': {'uid': 'retained', 'labels': {'app.kubernetes.io/version': 'fixture'},
                    'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-external-secrets:fixture'}},
                    'spec': {'replicas': 1}}
        replaced = copy.deepcopy(original)
        replaced['metadata']['uid'] = 'replacement'
        with patch.object(verify, 'kubectl', side_effect=[original, None, replaced, replaced]), \
                patch.object(verify, 'wait', side_effect=lambda check: check()), \
                self.assertRaisesRegex(RuntimeError, 'identity or spec'):
            verify.operator_drift()
