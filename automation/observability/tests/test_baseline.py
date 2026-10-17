import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from automation.observability.baseline import cleanup, prepare, result, retire, wait_private_source
from automation.observability.slo import definition


class ReleaseEvidenceTests(unittest.TestCase):
    def test_failed_viewer_cleanup_requires_exact_applications_ownership(self):
        from playbooks.keycloak.files.lifecycle import offboard_scope
        nonce = 'a' * 32
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory, 'fixture.json')
            request = {'nonce': nonce, 'realm': 'applications'}
            checkpoint.write_text(json.dumps(request))
            credentials = {'username': 'proof-' + nonce, 'ownership_id': nonce}
            identity = {'realm': 'applications', 'username': credentials['username'],
                        'user_id': '12345678-1234-1234-1234-123456789abc', 'email': 'fixture@example.invalid',
                        'enabled': False, 'preservation': 'unchanged'}
            with (patch('automation.observability.baseline.CHECKPOINT', checkpoint),
                  patch('automation.observability.baseline.inputs', return_value=({}, object(), {}, {})),
                  patch('automation.observability.baseline.environment'),
                  patch('automation.observability.baseline.fields', return_value=credentials) as vault,
                  patch('playbooks.keycloak.tests.session_acceptance.remote_state', return_value=identity),
                  patch('playbooks.keycloak.tests.session_acceptance.offboard_inputs') as tombstone,
                  patch('playbooks.keycloak.files.lifecycle.local_offboard', side_effect=offboard_scope) as revoke):
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
                revoke.assert_called_once_with({key: identity[key] for key in ('realm', 'username', 'user_id', 'email')})
                self.assertFalse(checkpoint.exists())

    def test_logout_waits_for_native_disable_and_preserves_checkpoint_on_drift(self):
        from playbooks.keycloak.files.lifecycle import offboard_scope
        active = {'realm': 'applications', 'username': 'proof-' + 'a' * 32,
                  'user_id': '12345678-1234-1234-1234-123456789abc', 'email': 'fixture@example.invalid',
                  'enabled': True, 'preservation': 'unchanged'}
        disabled = dict(active, enabled=False)
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory, 'fixture.json')
            with (patch('automation.observability.baseline.CHECKPOINT', checkpoint),
                  patch('playbooks.keycloak.tests.session_acceptance.remote_state') as state,
                  patch('playbooks.keycloak.tests.session_acceptance.offboard_inputs'),
                  patch('playbooks.keycloak.files.lifecycle.local_offboard', side_effect=offboard_scope) as revoke,
                  patch('automation.observability.baseline.time.sleep') as sleep):
                checkpoint.write_text('{}')
                state.side_effect = [active, dict(disabled, user_id='foreign')]
                with self.assertRaises(RuntimeError): retire(object(), {}, {'nonce': 'a' * 32, 'realm': 'applications'})
                revoke.assert_not_called()
                self.assertTrue(checkpoint.exists())
                state.side_effect = [active, disabled]
                retire(object(), {}, {'nonce': 'a' * 32, 'realm': 'applications'})
                revoke.assert_called_once_with({key: active[key] for key in ('realm', 'username', 'user_id', 'email')})
                self.assertFalse(checkpoint.exists())
                self.assertEqual(sleep.call_count, 2)

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
