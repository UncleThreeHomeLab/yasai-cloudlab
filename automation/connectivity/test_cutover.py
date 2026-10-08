"""Helm release retention is a prerequisite, not an annotation added after removal."""
import copy
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
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mesh'))
from automation.connectivity import legacy


class CutoverTests(unittest.TestCase):
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
