from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from contextlib import ExitStack

from automation.data import backup, capture, chart, control, credentials, remote, s3, rotation


class DataTests(unittest.TestCase):
    def test_rotation_preserves_unrelated_fields_and_original(self):
        old = {'id': 'fixture', 'title': 'cnpg-notes-production', 'fields': [
            {'label': 'username', 'value': 'notes_app'}, {'label': 'password', 'value': 'old-password'},
            {'label': 'database', 'value': 'notes'}]}
        new = rotation.replacement(old, ('password',))
        self.assertEqual(rotation.values(old)['password'], 'old-password')
        self.assertNotEqual(rotation.values(new)['password'], 'old-password')
        self.assertEqual(rotation.values(new)['username'], 'notes_app')
        self.assertEqual(rotation.values(new)['database'], 'notes')
        self.assertEqual(new['id'], old['id'])
        with self.assertRaisesRegex(RuntimeError, 'missing'):
            rotation.replacement(old, ('SECRET_ACCESS_KEY',))

    def test_external_gate_rejects_public_success(self):
        from automation.data import external
        with ExitStack() as stack:
            stack.enter_context(patch.dict(external.os.environ, {'CLOUDFLARE_ACCESS_HOSTS': '[]', 'VM_HOST': 'example.invalid', 'VM2_HOST': 'example.invalid'}))
            stack.enter_context(patch.object(external, 'fields', return_value={'ENDPOINT': 'https://s3.internal.example.invalid', 'BUCKET': 'notes', 'ACCESS_KEY_ID': 'test', 'SECRET_ACCESS_KEY': 'test', 'REGION': 'us-east-1'}))
            stack.enter_context(patch.object(external, 'remote', return_value={'private': {'tailnet_gateway': '100.64.0.1'}, 'zone': 'example.invalid'}))
            stack.enter_context(patch.object(external.socket, 'gethostbyname', return_value='100.64.0.1'))
            stack.enter_context(patch.object(external.socket, 'create_connection', side_effect=ConnectionRefusedError))
            stack.enter_context(patch.object(external, 'query', return_value={'addresses': []}))
            stack.enter_context(patch.object(external, 'S3', return_value=Mock(objects=Mock(return_value=[]))))
            stack.enter_context(patch.object(external, 'host_rules', return_value=[{'hostname': 'public.example.invalid', 'access': 'public'}]))
            probe = stack.enter_context(patch.object(external, 'https', return_value={'public_peer': True, 'headers': {'cf-ray': 'fixture'}, 'status': 404}))
            self.assertTrue(external.run()['public_s3_denied'])
            probe.return_value['status'] = 200
            with self.assertRaisesRegex(RuntimeError, 'not denied'):
                external.run()

    def generation(self, root):
        (root / 'database.dump').write_bytes(b'dump')
        manifest = {'format': 1, 'consistency': 'application-roles-disabled-s3-restarted',
                    'captured_at': 1, 'objects': [], 'files': [
                        {'file': 'database.dump', 'bytes': 4, 'sha256': hashlib.sha256(b'dump').hexdigest()}]}
        (root / 'manifest.json').write_text(json.dumps(manifest))
        return manifest

    def test_generation_detects_corruption_extra_files_and_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.generation(root)
            capture.verify(root)
            (root / 'database.dump').write_bytes(b'FAIL')
            with self.assertRaisesRegex(ValueError, 'integrity'):
                capture.verify(root)
            manifest = self.generation(root)
            (root / 'unexpected').write_text('extra')
            with self.assertRaisesRegex(ValueError, 'boundary'):
                capture.verify(root)
            (root / 'unexpected').unlink()
            manifest['files'][0]['file'] = '../database.dump'
            (root / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'invalid'):
                capture.verify(root)

    def test_failed_capture_releases_application_maintenance(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(capture.shutil, 'disk_usage', return_value=Mock(free=100 * 1024**3)), \
                patch.object(control, 'maintenance', return_value={'database': 'notes'}) as maintenance, \
                patch.object(control, 'sql', side_effect=RuntimeError('database unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                capture.capture(Path(temporary) / 'candidate')
            self.assertEqual([call.args[0] for call in maintenance.call_args_list], [True, False])

    def test_monthly_window_and_explicit_acceptance(self):
        remote.require_window(now=datetime(2026, 10, 1, tzinfo=timezone.utc))
        with self.assertRaisesRegex(RuntimeError, 'day 1'):
            remote.require_window(now=datetime(2026, 10, 8, tzinfo=timezone.utc))
        remote.require_window(True, now=datetime(2026, 10, 8, tzinfo=timezone.utc))

    def test_backup_environment_cannot_escape_its_b2_prefix(self):
        values = {'AWS_ENDPOINT': 'https://s3.us-west-004.backblazeb2.com', 'BUCKET': 'example-bucket',
                  'REGION': 'us-west-004', 'AWS_ACCESS_KEY_ID': 'synthetic', 'AWS_SECRET_ACCESS_KEY': 'synthetic',
                  'RESTIC_PASSWORD': 'synthetic'}
        env = remote.environment(values)
        self.assertTrue(env['RESTIC_REPOSITORY'].endswith('/application-data-restic/'))
        for endpoint in ('http://s3.us-west-004.backblazeb2.com', 'https://evil.example',
                         'https://user@s3.us-west-004.backblazeb2.com', 'https://s3.us-west-004.backblazeb2.com/path'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                remote.environment(dict(values, AWS_ENDPOINT=endpoint))

    def test_restore_failure_never_prunes_previous_generation(self):
        values = {'AWS_ENDPOINT': 'https://s3.us-west-004.backblazeb2.com', 'BUCKET': 'example-bucket',
                  'REGION': 'us-west-004', 'AWS_ACCESS_KEY_ID': 'synthetic', 'AWS_SECRET_ACCESS_KEY': 'synthetic',
                  'RESTIC_PASSWORD': 'synthetic'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.generation(root)
            repository = remote.Repository(values, acceptance=True)
            def command(*args, **kwargs):
                if args[0] == 'backup':
                    return '{"message_type":"summary","snapshot_id":"candidate"}'
                return '{}'
            with patch.object(repository, 'run', side_effect=command) as run, \
                    patch.object(repository, 'snapshots', return_value=[{'id': 'previous', 'tags': ['verified']}]), \
                    patch.object(repository, 'retrieve', return_value=manifest):
                with self.assertRaisesRegex(RuntimeError, 'restore failed'):
                    repository.export(root, Mock(side_effect=RuntimeError('restore failed')))
                self.assertFalse(any(call.args[0] in ('forget', 'prune', 'tag') for call in run.call_args_list))

    def test_freshness_reads_only_local_receipts(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(control, 'BASE', Path(temporary)), \
                patch.object(remote.subprocess, 'run') as run:
            for kind in ('local', 'monthly'):
                (Path(temporary) / (kind + '-receipt.json')).write_text(json.dumps({'captured_at': 100}))
            self.assertEqual(backup.freshness(now=200)['b2_reads'], 0)
            run.assert_not_called()
            (Path(temporary) / 'local-attempt.json').write_text('{"success":false}')
            with self.assertRaisesRegex(RuntimeError, 'failed'):
                backup.freshness(now=200)

    def test_private_clients_refuse_insecure_urls_and_presign_bounds(self):
        for endpoint in ('http://example.invalid', 'https://user:secret@example.invalid', 'https://example.invalid/path'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                s3.S3(endpoint, 'key', 'secret')
        client = s3.S3('https://s3.internal.example.invalid', 'key', 'secret')
        with self.assertRaises(ValueError):
            client.presign('GET', 'bucket', 'key', 301)
        url = client.presign('GET', 'bucket', 'key with spaces/plus+')
        self.assertIn('key%20with%20spaces/plus%2B', url)
        self.assertNotIn('secret', url)
        self.assertIsNone(s3.NoRedirect().redirect_request(None, None, None, None, None, None))

    def test_reserved_sql_identifiers_are_rejected(self):
        for name in ('postgres', 'pg_monitor', 'template1', 'notes; DROP ROLE postgres', 'notes"'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                control.identity(name)

    def test_secret_definitions_do_not_copy_b2_credentials(self):
        definitions = credentials.definitions('https://s3.internal.example.invalid')
        self.assertEqual(set(definitions['monthly-application-data-b2']), {'RESTIC_PASSWORD'})
        for item, fields in definitions.items():
            if 'password' in fields:
                self.assertNotEqual(fields['password'][1](), fields['password'][1]())


class DataChartTests(unittest.TestCase):
    def test_pinned_charts(self):
        result = chart.check()
        self.assertEqual(result['persistent_seaweedfs_claims'], 3)
        self.assertEqual(result['helm_hooks'], 0)

    def test_maintenance_disables_both_application_writers(self):
        objects = chart.render('configuration', {'maintenance': True})
        cluster = next(row for row in objects if row['kind'] == 'Cluster')
        roles = {row['name']: row for row in cluster['spec']['managed']['roles']}
        self.assertFalse(roles['notes_app']['login'])
        self.assertFalse(roles['notes_migration']['login'])
        self.assertTrue(roles['cloudlab_backup']['login'])
        secret = next(row for row in objects if row['kind'] == 'ExternalSecret' and row['metadata']['name'] == 'cloudlab-s3-config')
        self.assertNotIn('"name":"notes"', secret['spec']['target']['template']['data']['seaweedfs_s3_config'])
        self.assertIn('"name":"data-admin"', secret['spec']['target']['template']['data']['seaweedfs_s3_config'])

    def test_role_overlap_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'render failed'):
            chart.render('configuration', {'applicationRole': 'notes_migration'})


if __name__ == '__main__':
    unittest.main()
