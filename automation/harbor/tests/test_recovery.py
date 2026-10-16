"""Test fail-closed recovery boundaries and interrupted maintenance behavior."""
import copy
from contextlib import nullcontext
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

from automation.data.remote import require_window
from automation.harbor import recovery, remote, restore
from automation.harbor.tests.fixtures import manifest


class RecoveryTests(unittest.TestCase):
    def test_manifest_rejects_foreign_volume_invalid_digest_and_negative_size(self):
        self.assertEqual(recovery.validate(manifest()), manifest())
        for mutation in (
            lambda value: value['volumes']['database'].update(volume='pvc-' + '-' * 36),
            lambda value: value['volumes']['database'].update(snapshot='foreign'),
            lambda value: value['volumes']['database'].update(claim_uid='foreign'),
            lambda value: value['volumes']['database'].update(actual_bytes=-1),
            lambda value: value['inventory'].update(artifact_digests=['sha256:bad']),
            lambda value: value.update(captured=False)):
            value = manifest()
            mutation(value)
            with self.assertRaises(ValueError): recovery.validate(value)

    def test_streaming_inventory_checks_exit_status_without_exposing_output(self):
        digest = recovery.stream_hash([sys.executable, '-c', "import sys;sys.stdout.buffer.write(b'x'*2097152)"])
        import hashlib
        self.assertEqual(digest, hashlib.sha256(b'x' * 2097152).hexdigest())
        with self.assertRaisesRegex(RuntimeError, 'diagnostic values withheld'):
            recovery.stream_hash([sys.executable, '-c', "import sys;print('private');sys.exit(1)"])

    def test_cleanup_validates_entire_generation_before_any_delete(self):
        value = manifest()
        value['volumes']['redis']['volume'] = 'foreign'
        with patch.object(recovery, 'kube') as writes, patch.object(recovery, 'get') as reads:
            with self.assertRaises(ValueError): recovery.cleanup_snapshots(value)
            writes.assert_not_called()
            reads.assert_not_called()
        with patch.object(recovery, 'get', return_value={'metadata': {'labels': {}}, 'spec': {}}), patch.object(recovery, 'kube') as writes:
            with self.assertRaisesRegex(RuntimeError, 'foreign'): recovery.cleanup_snapshots(manifest())
            writes.assert_not_called()

    def test_failed_boundary_patch_still_resumes_original_applications(self):
        apps = {name: {'metadata': {'uid': name}, 'spec': {'source': {'targetRevision': 'a' * 40,
            'helm': {'valuesObject': {'harbor': {}}}}}} for name in recovery.APPS}
        with tempfile.TemporaryDirectory() as directory, patch.object(recovery, 'BASE', Path(directory)), \
                patch.object(recovery, 'application', side_effect=lambda name: copy.deepcopy(apps[name])), \
                patch.object(recovery, 'application_ready', return_value=True), \
                patch.object(recovery, 'sources', return_value=manifest()['volumes']), \
                patch.object(recovery, 'fingerprints', return_value=manifest()['secrets']), \
                patch.object(recovery, 'patch_values', side_effect=RuntimeError('interrupted')), \
                patch.object(recovery, 'resume') as resumed:
            with self.assertRaisesRegex(RuntimeError, 'interrupted'): recovery.capture()
            resumed.assert_called_once()
            self.assertTrue((Path(directory) / 'maintenance.json').exists())

    def test_every_b2_request_is_blocked_outside_monthly_window(self):
        repo = remote.Repository.__new__(remote.Repository)
        repo.client, repo.values = Mock(), {'BUCKET': 'fixture-bucket'}
        with patch.object(remote, 'require_window', side_effect=RuntimeError('outside window')):
            for method in ('GET', 'PUT', 'DELETE'):
                with self.assertRaisesRegex(RuntimeError, 'outside window'): repo.request(method)
        repo.client.request.assert_not_called()
        for day, hour, reserve, allowed in ((1, 6, 14400, True), (1, 23, 14400, False), (2, 6, 0, False)):
            now = datetime(2026, 10, day, hour, tzinfo=timezone.utc)
            if allowed: require_window(now=now, reserve=reserve)
            else:
                with self.assertRaises(RuntimeError): require_window(now=now, reserve=reserve)

    def test_retention_requires_real_offsite_restore_before_any_remote_operation(self):
        repo = remote.Repository.__new__(remote.Repository)
        with patch.object(repo, 'manifests') as reads, patch.object(repo, 'request') as writes:
            for proof in ({}, {'restored': True}, {'restored': False, 'offsite_reads': True}):
                with self.assertRaises(RuntimeError): repo.accept(manifest(), proof)
            reads.assert_not_called()
            writes.assert_not_called()

    def test_completed_monthly_repeat_has_no_capture_or_cloud_access(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(recovery, 'BASE', Path(directory)), \
                patch.object(recovery, 'locked', return_value=nullcontext()), patch.object(recovery, 'resume'), \
                patch('automation.data.remote.require_window'), patch.object(recovery, 'capture') as capture:
            (Path(directory) / 'monthly-receipt.json').write_text(json.dumps({'captured_at': datetime.now(timezone.utc).timestamp(),
                'retention_complete': True}))
            self.assertEqual(recovery.run('monthly'), {'already_verified_this_month': True, 'b2_reads': 0})
            capture.assert_not_called()

    def test_restore_cleanup_rejects_recreated_namespace(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(recovery, 'BASE', Path(directory)), \
                patch.object(restore, 'get', return_value={'metadata': {'uid': 'different', 'labels': restore.LABEL}}), \
                patch.object(restore, 'kube') as writes:
            (Path(directory) / 'restore-owned.json').write_text(json.dumps({'uid': 'original', 'classes': [], 'volumes': []}))
            with self.assertRaisesRegex(RuntimeError, 'identity changed'): restore.cleanup()
            writes.assert_not_called()

    def test_restore_quarantine_validates_offsite_url_before_creating_namespace(self):
        value = manifest()
        with patch('automation.data.remote.require_window'), patch.object(remote, 'Repository') as factory, \
                patch.object(restore, 'kube') as writes:
            factory.return_value.validate_url.side_effect = ValueError('foreign URL')
            with self.assertRaises(ValueError): restore.run(value, offsite=True)
            writes.assert_not_called()
