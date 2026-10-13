import json
from pathlib import Path
import tempfile
import unittest

from automation.infra.status import update, validate, evidence, metrics, alerts


class StatusTests(unittest.TestCase):
    def test_failure_keeps_last_success_and_missing_is_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'status.json'
            revision = 'a' * 40
            document = update(path, 'cloudflare', 'apply', revision, 100)
            self.assertEqual(evidence(document, 'drift', 100), 'unavailable')
            self.assertEqual(evidence(document, 'apply', 101), 'running')
            self.assertEqual(evidence(document, 'apply', 4000), 'interrupted')
            update(path, 'cloudflare', 'apply', revision, 102, result='success')
            update(path, 'cloudflare', 'apply', revision, 110)
            document = update(path, 'cloudflare', 'apply', revision, 112, result='failure', failure='backend')
            self.assertEqual(document['actions']['apply']['last_success_at'], 102)
            self.assertEqual(evidence(document, 'apply', 113), 'failure')
            self.assertEqual(evidence(document, 'apply', 90000), 'stale')
            self.assertEqual(evidence(document, 'apply', 99), 'unavailable')
            self.assertEqual(json.loads(path.read_text()), document)
            self.assertIn('last_success_timestamp_seconds', metrics(document, 113))
            self.assertNotIn('backend', metrics(document, 113))

    def test_reject_secret_fields_nonfinite_clock_and_unbound_completion(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'status.json'
            document = update(path, 'github', 'drift', 'b' * 40, 100)
            with self.assertRaises(ValueError): update(path, 'github', 'drift', 'c' * 40, 101, result='success')
            with self.assertRaises(ValueError): update(path, 'github', 'drift', 'b' * 40, float('nan'))
            document['actions']['drift']['provider_output'] = 'secret'
            with self.assertRaises(ValueError): validate(document)

    def test_drift_is_not_success_and_alerts_require_enabled_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'status.json'
            update(path, 'github', 'drift', 'b' * 40, 100)
            document = update(path, 'github', 'drift', 'b' * 40, 101, result='drift', changes=2)
            self.assertEqual(document['actions']['drift']['last_success_at'], 0)
            self.assertEqual(evidence(document, 'drift', 102), 'drift')
            for rule in alerts(): self.assertIn('workflow_enabled', rule['expr'])
            self.assertIn('unless', alerts()[1]['expr'])
