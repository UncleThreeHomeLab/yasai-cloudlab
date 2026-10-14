import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation.observability.baseline import cleanup, result
from automation.observability.slo import definition


class ReleaseEvidenceTests(unittest.TestCase):
    def test_failed_viewer_cleanup_requires_exact_applications_ownership(self):
        nonce = 'a' * 32
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory, 'fixture.json')
            request = {'nonce': nonce, 'realm': 'applications'}
            checkpoint.write_text(json.dumps(request))
            credentials = {'username': 'proof-' + nonce, 'ownership_id': nonce}
            with (patch('automation.observability.baseline.CHECKPOINT', checkpoint),
                  patch('automation.observability.baseline.inputs', return_value=({}, object(), {}, {})),
                  patch('automation.observability.baseline.environment'),
                  patch('automation.observability.baseline.fields', return_value=credentials) as vault,
                  patch('automation.identity.session_acceptance.offboard_inputs') as tombstone,
                  patch('automation.identity.lifecycle.local_offboard') as revoke):
                for invalid in (dict(credentials, ownership_id='b' * 32), dict(credentials, username='primary')):
                    vault.return_value = invalid
                    with self.assertRaises(ValueError): cleanup()
                    tombstone.assert_not_called()
                    revoke.assert_not_called()
                    self.assertTrue(checkpoint.exists())
                vault.return_value = credentials
                checkpoint.write_text(json.dumps(dict(request, realm='platform')))
                with self.assertRaises(ValueError): cleanup()
                tombstone.assert_not_called()
                checkpoint.write_text(json.dumps(request))
                self.assertTrue(cleanup()['disposable_viewer_offboarded'])
                revoke.assert_called_once_with({'realm': 'applications', 'username': 'proof-' + nonce})
                self.assertFalse(checkpoint.exists())

    def test_only_redacted_bounded_measurements_can_pass_release_gate(self):
        policy = definition()['release']
        good = {'scenario': 'notes-release-read', 'passed': True, 'samples': 240,
                'p95_ms': 100, 'maximum_ms': 200, 'failure_rate': 0, 'evaluation_seconds': 120}
        self.assertEqual(result(good, policy), good)
        for change in ({'samples': 229}, {'samples': 9999}, {'p95_ms': 250}, {'maximum_ms': 1000},
                       {'failure_rate': 0.01}, {'p95_ms': float('nan')}, {'maximum_ms': float('inf')},
                       {'evaluation_seconds': 60}, {'passed': False}, {'access_token': 'must-not-export'}):
            invalid = copy.deepcopy(good)
            invalid.update(change)
            with self.assertRaises(ValueError): result(invalid, policy)
