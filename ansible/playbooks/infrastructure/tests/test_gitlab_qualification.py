"""Qualification trust boundaries and recovery invocation without cloud access."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.infrastructure.tests import gitlab_qualification as subject

VALUES = {'PROJECT_ID': '123', 'USERNAME': 'fixture', 'TOKEN': 'synthetic-secret'}
NAME = 'qualification-' + 'a' * 32


class QualificationTests(unittest.TestCase):
    def test_async_deletion_waits_for_absence_without_unlock(self):
        with patch.object(subject, 'request', side_effect=[(202, b''), (200, b''), (404, b'')]) as request, \
                patch.object(subject.time, 'sleep'):
            self.assertTrue(subject.delete_state(VALUES, subject.address(VALUES, NAME)))
        self.assertEqual([call.args[2:] for call in request.call_args_list], [('DELETE',), (), ()])

    def test_deletion_refuses_backend_error(self):
        with patch.object(subject, 'request', return_value=(403, b'')) as request:
            self.assertFalse(subject.delete_state(VALUES, subject.address(VALUES, NAME)))
        self.assertEqual(request.call_count, 1)

    def test_production_state_and_external_hosts_are_rejected_before_network(self):
        with patch.object(subject.urllib.request, 'build_opener') as opener:
            for url in ('https://attacker.example',
                        'https://gitlab.com/api/v4/projects/123/terraform/state/cloudflare',
                        'https://gitlab.com/api/v4/projects/123/repository'):
                with self.assertRaises(ValueError):
                    subject.request(VALUES, url, 'DELETE')
            opener.assert_not_called()
        with self.assertRaises(ValueError):
            subject.address(VALUES, 'cloudflare')
        with self.assertRaises(ValueError):
            subject.address(dict(VALUES, PROJECT_ID='../123'), NAME)

    def test_credentials_are_isolated_and_both_encryption_modes_enforced(self):
        with patch.dict(os.environ, {'OP_SERVICE_ACCOUNT_TOKEN': 'must-not-leak'}, clear=True):
            env = subject.environment(VALUES, subject.address(VALUES, NAME), 'synthetic-passphrase')
        self.assertNotIn('OP_SERVICE_ACCOUNT_TOKEN', env)
        self.assertEqual(env['TF_HTTP_PASSWORD'], VALUES['TOKEN'])
        self.assertEqual(env['TF_HTTP_LOCK_METHOD'], 'POST')
        self.assertEqual(env['TF_HTTP_UNLOCK_METHOD'], 'DELETE')
        self.assertEqual(env['TF_ENCRYPTION'].count('enforced = true'), 2)

    def test_recovery_push_flags_precede_path_and_never_force(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(subject.subprocess, 'run',
            return_value=Mock(returncode=0, stdout=b'', stderr=b'')) as run:
            subject.tofu(Path(directory), {}, 'state', 'push', '/protected/errored.tfstate')
        self.assertEqual(run.call_args.args[0], ['tofu', 'state', 'push', '-no-color', '/protected/errored.tfstate'])

    def test_decrypted_input_handles_native_dynamic_type_without_false_acceptance(self):
        self.assertTrue(subject.fixture_input({'input': {'type': 'string', 'value': 'expected'}}, 'expected'))
        self.assertTrue(subject.fixture_input({'input': 'expected'}, 'expected'))
        self.assertFalse(subject.fixture_input({'input': 'foreign'}, 'expected'))

    def test_decrypted_pull_is_not_written_to_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(subject.subprocess, 'run',
            return_value=Mock(returncode=0, stdout=b'private-state', stderr=b'')):
            root = Path(directory)
            subject.tofu(root, {}, 'state', 'pull')
            self.assertEqual((root / 'last-diagnostics.txt').read_bytes(), b'')


if __name__ == '__main__':
    unittest.main()
