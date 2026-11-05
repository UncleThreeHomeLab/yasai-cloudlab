"""Test fail-closed recovery boundaries and interrupted maintenance behavior."""
import copy
from contextlib import nullcontext
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

from playbooks.data.files.remote import require_window
from playbooks.harbor.files import recovery, remote, restore
from playbooks.harbor.tests.fixtures import manifest


class RecoveryTests(unittest.TestCase):
    def test_idle_monthly_handoff_preserves_evidence_and_refuses_mutation_without_effects(self):
        from playbooks.harbor.files import native
        value = manifest(); value.update(operation='monthly', phase='snapshot', captured=True, captured_at=1, capture_seconds=1)
        value['installation']['revision'] = native.REVISION
        document = {'installationRevision': native.REVISION, 'harborHost': 'harbor.internal.example.invalid',
            'loginHost': 'login.example.invalid', 'gatewayIP': '10.43.0.100'}
        apps = {name: {'metadata': {'uid': 'app-' + name}, 'spec': {'source': {'targetRevision': native.REVISION,
            'helm': {'valuesObject': native.values(document, name)}}}} for name in recovery.APPS}
        snapshots = {row['snapshot']: {'metadata': {'uid': 'snapshot-' + component, 'labels': recovery.LABEL},
            'spec': {'volume': row['volume'], 'labels': {'cloudlab-generation': value['generation']}},
            'status': {'readyToUse': True}} for component, row in value['volumes'].items()}
        current = copy.deepcopy(value['volumes']); secrets = copy.deepcopy(value['secrets'])
        def read(kind, name, *args):
            if kind == 'application.argoproj.io': return copy.deepcopy(apps[name])
            if kind == 'snapshots.longhorn.io': return copy.deepcopy(snapshots[name])
            raise AssertionError('Unexpected pending handoff read')
        with tempfile.TemporaryDirectory(dir='/var/lib') as directory, patch.object(recovery, 'BASE', Path(directory)), \
                patch.object(native, 'BASE', Path(directory)), patch.object(recovery, 'get', side_effect=read), \
                patch.object(recovery, 'sources', side_effect=lambda: copy.deepcopy(current)), \
                patch.object(recovery, 'fingerprints', side_effect=lambda: copy.deepcopy(secrets)), \
                patch.object(native, 'guard', side_effect=AssertionError('Lifecycle gate must not enter ordinary guard')) as guard, \
                patch.object(recovery, 'atomic') as write, patch.object(recovery, 'kube') as mutations, \
                patch.object(recovery, 'execute') as commands, patch.object(recovery, 'cleanup_snapshots') as cleanup:
            path = Path(directory) / 'pending-volume.json'
            raw = json.dumps(value, sort_keys=True).encode(); path.write_bytes(raw); path.chmod(0o600)
            original_snapshots = copy.deepcopy(snapshots)
            before = recovery.handoff_pending()
            current['database']['actual_bytes'] += 100
            self.assertEqual(recovery.handoff_pending(expected=before), before)
            self.assertEqual(path.read_bytes(), raw); self.assertEqual(snapshots, original_snapshots)
            for change in ('malformed', 'incomplete', 'operation', 'source', 'secret', 'snapshot', 'ready'):
                candidate = copy.deepcopy(value)
                if change == 'incomplete': candidate['captured'] = False
                if change == 'operation': candidate['operation'] = 'check-local'
                if change == 'source': current['database']['claim_uid'] = 'foreign'
                if change == 'secret': secrets[recovery.SECRETS[0]] = 'e' * 64
                if change == 'snapshot': snapshots[value['volumes']['database']['snapshot']]['spec']['volume'] = 'foreign'
                if change == 'ready': snapshots[value['volumes']['database']['snapshot']]['status']['readyToUse'] = False
                path.write_bytes(b'{invalid' if change == 'malformed' else json.dumps(candidate).encode())
                with self.subTest(change=change), self.assertRaises(RuntimeError): recovery.handoff_pending()
                current = copy.deepcopy(value['volumes']); secrets = copy.deepcopy(value['secrets']); snapshots = copy.deepcopy(original_snapshots)
            path.write_bytes(raw + b'\n')
            with self.assertRaisesRegex(RuntimeError, 'changed during'): recovery.handoff_pending(expected=before)
            path.write_bytes(raw)
            selected = value['volumes']['database']['snapshot']; snapshots[selected]['metadata']['uid'] = 'replaced'
            with self.assertRaisesRegex(RuntimeError, 'changed during'): recovery.handoff_pending(expected=before)
            snapshots = copy.deepcopy(original_snapshots)
            state = {'phase': 'prepared', 'root_uid': 'root', 'project_uid': 'project', 'profile': document,
                'authority': {'root_uid': 'root'}, 'revision': native.REVISION, 'repository': 'private',
                'applications': {name: apps[name]['metadata']['uid'] for name in recovery.APPS}}
            snapshot = {'enabled': False, 'root': {'metadata': {'uid': 'root'}}, 'profile': document,
                'authority': state['authority'], 'targets': [{'valuesRepository': 'private'}]}
            def child(unused, name, **kwargs):
                return copy.deepcopy(apps[name]), native.values(document, name)
            with patch.object(native, 'receipt', return_value=state), patch.object(native, 'context', return_value=snapshot) as context, \
                    patch.object(native, 'get', return_value={'metadata': {'uid': 'project'}}), patch.object(native, 'child', side_effect=child) as children:
                self.assertFalse(native.prepare())
                self.assertEqual(children.call_count, 2)
                def changed_child(unused, name, **kwargs):
                    snapshots[selected]['metadata']['uid'] = 'changed-during-prepare'
                    return child(unused, name, **kwargs)
                children.side_effect = changed_child
                with self.assertRaisesRegex(RuntimeError, 'changed during'): native.prepare()
                snapshots = copy.deepcopy(original_snapshots); context.reset_mock()
                with self.assertRaisesRegex(RuntimeError, 'Fresh Harbor intent refuses pending'): native.prepare(initial=True)
                context.assert_not_called()
            active = Path(directory) / 'maintenance.json'; active.write_text('{}'); active.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, 'active Harbor recovery'): recovery.handoff_pending()
            self.assertEqual(path.read_bytes(), raw); self.assertEqual(snapshots, original_snapshots)
            guard.assert_not_called(); write.assert_not_called(); mutations.assert_not_called(); commands.assert_not_called(); cleanup.assert_not_called()

    def test_stopped_final_writer_can_return_no_pod_list(self):
        for value in (None, {}, {'items': []}):
            with patch.object(recovery, 'get', return_value=value):
                self.assertEqual(recovery.pods('redis'), [])

    def test_capture_accepts_empty_namespace_but_rejects_an_unstopped_writer(self):
        value = manifest()
        server = {'harbor': {name: {'replicas': 1} for name in ('core', 'nginx', 'portal', 'jobservice', 'registry')}}
        server['harbor'].update({name: {'internal': {'replicas': 1}} for name in ('database', 'redis')})
        apps = {name: {'metadata': {'uid': name}, 'spec': {'source': {'targetRevision': 'a' * 40,
                'helm': {'valuesObject': server if name == 'cloudlab-harbor' else {}}}}} for name in recovery.APPS}
        for remaining in (None, {'items': [{'metadata': {'labels': {}}, 'status': {'phase': 'Running'}}]}):
            def resource(kind, name=None, namespace=None):
                if kind == 'pods': return remaining
                if kind == 'volumes.longhorn.io':
                    row = next(row for row in value['volumes'].values() if row['volume'] == name)
                    return {'metadata': {'uid': row['volume_uid']}}
                if kind == 'snapshots.longhorn.io': return {'status': {'readyToUse': True}}
                raise AssertionError('Unexpected resource')
            with tempfile.TemporaryDirectory() as directory, patch.object(recovery, 'BASE', Path(directory)), \
                    patch.object(recovery, 'application', side_effect=lambda name: copy.deepcopy(apps[name])), \
                    patch.object(recovery, 'application_ready', return_value=True), \
                    patch.object(recovery, 'installation', return_value=value['installation']), \
                    patch.object(recovery, 'sources', return_value=copy.deepcopy(value['volumes'])), \
                    patch.object(recovery, 'fingerprints', return_value=value['secrets']), \
                    patch.object(recovery, 'inventory', return_value=value['inventory']), \
                    patch.object(recovery, 'patch_values'), patch.object(recovery, 'resume') as resume, \
                    patch.object(recovery, 'get', side_effect=resource), patch.object(recovery, 'kube') as writes, \
                    patch.object(recovery, 'wait', side_effect=lambda predicate, label, timeout: self.assertTrue(predicate())):
                if remaining:
                    with self.assertRaisesRegex(RuntimeError, 'writers remain'): recovery.capture()
                    writes.assert_not_called()
                else:
                    self.assertTrue(recovery.capture()['captured'])
                    self.assertEqual(writes.call_count, 3)
                resume.assert_called_once()

    def test_manifest_rejects_foreign_volume_invalid_digest_and_negative_size(self):
        self.assertEqual(recovery.validate(manifest()), manifest())
        for mutation in (
            lambda value: value['volumes']['database'].update(volume='pvc-' + '-' * 36),
            lambda value: value['volumes']['database'].update(snapshot='foreign'),
            lambda value: value['volumes']['database'].update(claim_uid='foreign'),
            lambda value: value['volumes']['database'].update(actual_bytes=-1),
            lambda value: value['inventory'].update(artifact_digests=['sha256:bad']),
            lambda value: value['installation']['images'].__setitem__(0, 'unversioned-image'),
            lambda value: value['installation'].update(revision='main'),
            lambda value: value.update(operation='daily'),
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
            for proof in ({}, {'restored': True}, {'restored': False, 'offsite_reads': True},
                          {'restored': 'true', 'offsite_reads': True}, {'restored': True, 'offsite_reads': 1}):
                with self.assertRaises(RuntimeError): repo.accept(manifest(), proof)
            reads.assert_not_called()
            writes.assert_not_called()

    def test_completed_monthly_repeat_has_no_capture_or_cloud_access(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(recovery, 'BASE', Path(directory)), \
                patch.object(recovery, 'locked', return_value=nullcontext()), patch.object(recovery, 'resume'), \
                patch('playbooks.data.files.remote.require_window'), patch.object(recovery, 'capture') as capture:
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
        with patch('playbooks.data.files.remote.require_window'), patch.object(remote, 'Repository') as factory, \
                patch.object(restore, 'kube') as writes:
            factory.return_value.validate_url.side_effect = ValueError('foreign URL')
            with self.assertRaises(ValueError): restore.run(value, offsite=True)
            writes.assert_not_called()

    def test_local_check_preserves_interrupted_monthly_candidate_before_cleanup(self):
        for captured in (False, True):
            value = manifest()
            value['captured'] = captured
            with tempfile.TemporaryDirectory() as directory, patch.object(recovery, 'BASE', Path(directory)), \
                    patch.object(recovery, 'locked', return_value=nullcontext()), patch.object(recovery, 'resume'), \
                    patch.object(recovery, 'cleanup_snapshots') as cleanup, patch.object(recovery, 'capture') as capture:
                pending = Path(directory) / 'pending-volume.json'
                pending.write_text(json.dumps(value))
                with self.assertRaisesRegex(RuntimeError, 'recorded Harbor recovery'): recovery.run('check-local')
                self.assertEqual(json.loads(pending.read_text()), value)
                cleanup.assert_not_called()
                capture.assert_not_called()

    def test_freshness_reads_only_local_receipts_and_reports_missing_stale_or_failed(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(recovery, 'BASE', Path(directory)), \
                patch.object(recovery, 'resume') as resume, patch.object(recovery, 'get') as reads:
            with self.assertRaisesRegex(RuntimeError, 'No successful monthly'): recovery.run('freshness')
            receipt = Path(directory) / 'monthly-receipt.json'
            receipt.write_text(json.dumps({'captured_at': 1000, 'retention_complete': True}))
            self.assertEqual(recovery.freshness(now=4600)['monthly_age_hours'], 1)
            with self.assertRaisesRegex(RuntimeError, 'stale'): recovery.freshness(now=5000000)
            (Path(directory) / 'monthly-attempt.json').write_text('{"success":false}')
            with self.assertRaisesRegex(RuntimeError, 'last attempt failed'): recovery.freshness(now=4600)
            resume.assert_not_called()
            reads.assert_not_called()

    def test_restore_rejects_changed_chart_or_image_pins_before_any_cluster_call(self):
        for change in ('chart_sha256', 'images'):
            value = manifest()
            if change == 'images':
                image = value['installation']['images'][0]
                value['installation']['images'][0] = image[:-1] + ('0' if image[-1] != '0' else '1')
            else: value['installation']['chart_sha256'] = '0' * 64
            with patch.object(restore, 'get') as reads, patch.object(restore, 'kube') as writes:
                with self.assertRaisesRegex(RuntimeError, 'recorded Harbor checkout'): restore.run(value)
                reads.assert_not_called()
                writes.assert_not_called()
