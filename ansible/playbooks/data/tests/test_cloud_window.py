"""Acceptance and restore verification cannot create an off-window B2 exception."""
import unittest
import json
from pathlib import Path
import tempfile
import time
from unittest.mock import patch

from playbooks.data.files import backup, control, independent, remote, restore


class CloudWindowTests(unittest.TestCase):
    def test_acceptance_alias_preserves_current_verified_generation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(control, 'BASE', Path(directory)), \
                patch.object(remote, 'seconds_remaining', return_value=86400), \
                patch.object(control, 'settings', return_value={'maintenance': False}), \
                patch.object(backup, 'capture') as capture, patch.object(backup, 'Repository') as repository:
            receipt = {'captured_at': time.time(), 'retention_complete': True, 'explicit_acceptance_exception': True}
            path = Path(directory) / backup.RECEIPT
            path.write_text(json.dumps(receipt))
            before = path.read_bytes()
            result = backup.run('acceptance-export')
            self.assertEqual(result, {'already_verified_this_month': True, 'b2_reads': 0})
            self.assertEqual(path.read_bytes(), before)
            capture.assert_not_called()
            repository.assert_not_called()

    def test_export_and_fixture_restore_refuse_before_credentials_or_lock(self):
        for action in ('monthly', 'acceptance-export', 'restore-offsite'):
            with self.subTest(action=action), patch.object(remote, 'seconds_remaining', return_value=0), \
                    patch.object(control, 'locked') as locked, patch.object(control, 'secret') as secret, \
                    patch.object(backup, 'Repository') as repository:
                with self.assertRaisesRegex(RuntimeError, 'day 1 UTC only'):
                    backup.run(action)
                locked.assert_not_called()
                secret.assert_not_called()
                repository.assert_not_called()

    def test_independent_cloud_verification_refuses_before_vault_or_dotenv(self):
        with patch.object(remote, 'seconds_remaining', return_value=0), \
                patch.object(independent, 'fields') as fields, \
                patch.object(independent, 'dotenv_values') as dotenv, \
                patch.object(independent, 'Repository') as repository:
            with self.assertRaisesRegex(RuntimeError, 'day 1 UTC only'):
                independent.retrieve()
            fields.assert_not_called()
            dotenv.assert_not_called()
            repository.assert_not_called()

    def test_direct_offsite_restore_refuses_before_cluster_or_fixture_creation(self):
        with patch.object(remote, 'seconds_remaining', return_value=0), \
                patch.object(restore, 'verify') as verify, patch.object(restore, 'kube') as kube:
            with self.assertRaisesRegex(RuntimeError, 'day 1 UTC only'):
                restore.run({}, offsite=True)
            verify.assert_not_called()
            kube.assert_not_called()

    def test_repository_reads_refuse_before_network(self):
        values = {'AWS_ENDPOINT': 'https://s3.us-west-004.backblazeb2.com', 'BUCKET': 'example-bucket',
                  'REGION': 'us-west-004', 'AWS_ACCESS_KEY_ID': 'synthetic', 'AWS_SECRET_ACCESS_KEY': 'synthetic'}
        repository = remote.Repository(values)
        with patch.object(remote, 'seconds_remaining', return_value=0), \
                patch.object(repository.client, 'request') as request, \
                patch.object(repository.client, 'objects') as objects:
            with self.assertRaisesRegex(RuntimeError, 'day 1 UTC only'):
                repository.request('GET', 'metadata')
            with self.assertRaisesRegex(RuntimeError, 'day 1 UTC only'):
                repository.manifests()
            request.assert_not_called()
            objects.assert_not_called()
