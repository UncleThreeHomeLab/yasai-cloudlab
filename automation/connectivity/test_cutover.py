"""Helm release retention is a prerequisite, not an annotation added after removal."""
import copy
from contextlib import nullcontext, redirect_stdout, redirect_stderr
import io
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import yaml

from automation.connectivity.cutover import definitions, retention
from automation.connectivity import cutover, verify
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mesh'))
from automation.connectivity import legacy


class CutoverTests(unittest.TestCase):
    def test_crd_owner_requires_real_ssa_not_a_copied_annotation(self):
        actual = {'metadata': {'annotations': {'cloudlab.io/owner': legacy.APP,
                  'argocd.argoproj.io/tracking-id': legacy.APP + ':copied'}}}
        self.assertFalse(legacy.gitops_owned(actual))
        actual['metadata']['managedFields'] = [{'manager': 'argocd-controller', 'operation': 'Apply', 'fieldsV1': {'f:spec': {}}}]
        actual['metadata']['annotations'].pop('argocd.argoproj.io/tracking-id')
        self.assertTrue(legacy.gitops_owned(actual))
        actual['metadata']['annotations']['meta.helm.sh/release-name'] = 'traefik-crd'
        self.assertFalse(legacy.gitops_owned(actual))

    def test_empty_legacy_inventories_are_successful_removal(self):
        with patch.object(legacy, 'get', return_value=None):
            self.assertTrue(legacy.legacy_removed())

    def test_remaining_chart_service_or_workload_prevents_adoption(self):
        for kind, value in [('helmcharts.helm.cattle.io', {'items': [{'metadata': {'name': 'traefik'}}]}),
                            ('deployment', {'metadata': {'name': 'traefik'}}),
                            ('service', {'metadata': {'name': 'traefik'}}),
                            ('daemonsets', {'items': [{'metadata': {'name': 'svclb-traefik'}}]})]:
            with self.subTest(kind=kind), patch.object(legacy, 'get', side_effect=lambda resource, *args, **kwargs: value if resource == kind else None):
                self.assertFalse(legacy.legacy_removed())

    def test_final_acceptance_requires_adoption_and_both_disabled_components(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / 'cutover.json'
            with patch.object(legacy, 'RECEIPT', receipt), patch.object(legacy, 'finish') as finish, \
                    patch.object(legacy, 'record') as record:
                for phase, disabled in [('prepared', ['traefik', 'servicelb']), ('adopted', ['traefik'])]:
                    receipt.write_text(json.dumps({'phase': phase}))
                    with self.assertRaises(RuntimeError): legacy.accept({'disabled': disabled})
                finish.assert_not_called()
                record.assert_not_called()
                finish.return_value = {'changed': False, 'phase': 'adopted'}
                result = legacy.accept({'disabled': ['traefik', 'servicelb']})
                self.assertEqual(result['phase'], 'accepted')
                self.assertTrue(result['changed'])
                record.assert_called_once_with({'phase': 'accepted'})

    def test_fresh_verification_progress_does_not_corrupt_structured_result(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cutover, 'remote', side_effect=[{'state': None}, {'state': {'phase': 'prepared'}}, {'changed': False}]), \
                patch.object(cutover, 'transaction', return_value=nullcontext()), \
                patch.object(verify, 'run', side_effect=lambda **kwargs: print('progress')), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(cutover.prepare({}), {'changed': False})
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), 'progress\n')

    def test_release_requires_retention_for_every_pinned_crd(self):
        objects = definitions()
        for obj in objects:
            obj['metadata'].setdefault('annotations', {})['helm.sh/resource-policy'] = 'keep'
        retention(yaml.safe_dump_all(objects), definitions())
        objects[-1]['metadata']['annotations'].pop('helm.sh/resource-policy')
        with self.assertRaises(RuntimeError):
            retention(yaml.safe_dump_all(objects), definitions())
        with self.assertRaises(RuntimeError):
            retention(yaml.safe_dump_all(objects[:-1]), definitions())

    def test_missing_or_stale_acceptance_cannot_authorize_removal(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'receipts').mkdir()
            (base / 'receipts/external.json').write_text(json.dumps({'binding': 'fixture'}))
            with patch.object(legacy, 'BASE', base), patch.object(legacy, 'RECEIPT', base / 'cutover.json'), \
                    patch.object(legacy, 'identities', return_value={'crd': 'retained'}), \
                    patch.object(legacy, 'record') as record, patch.object(legacy, 'dependencies') as audit:
                for passed, age, binding in ((False, 0, 'fixture'), (True, 90000, 'fixture'), (True, 0, 'changed')):
                    (base / 'receipts/acceptance.json').write_text(json.dumps({'evidence': {'acceptance_passed': passed},
                        'verified_at': time.time() - age, 'external_binding': binding}))
                    with self.assertRaises(RuntimeError): legacy.prepare({'gateway_api': []})
                record.assert_not_called()
                audit.assert_not_called()

    def test_resume_refuses_crd_recreation(self):
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / 'cutover.json'
            receipt.write_text(json.dumps({'phase': 'prepared', 'crds': {'crd': 'original'}}))
            with patch.object(legacy, 'RECEIPT', receipt), \
                    patch.object(legacy, 'identities', return_value={'crd': 'replacement'}):
                with self.assertRaises(RuntimeError): legacy.prepare({'gateway_api': []})
