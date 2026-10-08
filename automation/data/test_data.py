from datetime import datetime, timezone
import hashlib
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from contextlib import ExitStack

from automation.data import backup, capture, chart, control, credentials, remote, s3, rotation, restore


class DataTests(unittest.TestCase):
    def test_interrupted_capture_cannot_keep_successful_attempt_status(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(control, 'BASE', Path(temporary)), \
                patch.object(control, 'settings', return_value={'maintenance': False}), \
                patch.object(backup, 'capture', side_effect=KeyboardInterrupt):
            path = Path(temporary) / backup.ATTEMPT
            path.write_text('{"success":true}')
            with self.assertRaises(KeyboardInterrupt):
                backup.run('acceptance-export')
            self.assertFalse(json.loads(path.read_text())['success'])

    def test_restore_policy_allows_only_exact_private_host_snat_addresses(self):
        interfaces = [{'ifname': name, 'addr_info': [{'family': 'inet', 'local': value}]} for name, value in (
            ('flannel.1', '10.42.0.0'), ('cni0', '10.42.0.1'), ('eth0', '203.0.113.1'), ('cni0', '10.43.0.1'))]
        with patch.object(restore.subprocess, 'check_output', return_value=json.dumps(interfaces)):
            self.assertEqual(restore.restore_source_cidrs({'spec': {'podCIDR': '10.42.0.0/24'}}, '172.30.0.1'),
                             ['10.42.0.0/32', '10.42.0.1/32', '172.30.0.1/32'])

    def test_restore_readiness_preserves_authentication_and_private_source(self):
        client = Mock()
        client.request.side_effect = RuntimeError('temporarily unavailable')
        self.assertFalse(restore.s3_ready(client, 'notes'))
        client.request.side_effect = s3.S3Error(404)
        self.assertTrue(restore.s3_ready(client, 'notes'))
        client.request.side_effect = s3.S3Error(403)
        with self.assertRaises(s3.S3Error):
            restore.s3_ready(client, 'notes')
        with self.assertRaisesRegex(ValueError, 'source address'):
            s3.S3('https://example.invalid', 'test', 'test', address='10.0.0.1', source_address='8.8.8.8')

    def test_restore_authentication_uses_current_secrets_and_isolated_sql_tls(self):
        from automation.data import verify as checks
        values = {'database': 'notes', 'applicationRole': 'notes_app', 'migrationRole': 'notes_migration', 'backupRole': 'backup'}
        manifest = {'database': 'notes', 'roles': ['notes_app', 'notes_migration', 'backup'], 'notes_probe': []}
        with patch.object(control, 'settings', return_value=values), \
                patch.object(control, 'secret', side_effect=[{'username': role, 'password': "synthetic'quote"} for role in manifest['roles']]), \
                patch.object(restore, 'get', return_value=None), patch.object(restore, 'sql') as sql, \
                patch.object(restore, 'wait'), patch.object(checks, 'sql_client') as client, \
                patch.object(checks, 'pod_query', side_effect=[Mock(returncode=0, stdout='[]'), *[Mock(returncode=1) for _ in range(3)]]), \
                patch.object(rotation, 'cleanup_sql') as cleanup:
            restore.authenticated_sql(manifest)
            client.assert_called_once_with(values, database_namespace=restore.NAMESPACE, cluster='data-restore')
            cleanup.assert_called_once()
            self.assertEqual(len(sql.call_args_list), 3)
            self.assertIn("synthetic''quote", sql.call_args.args[0])
            with self.assertRaisesRegex(RuntimeError, 'credential mapping'):
                restore.authenticated_sql(dict(manifest, database='unrelated'))

    def test_restored_tag_gate_preserves_key_value_pairs(self):
        original = '<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value>2</Value></Tag></TagSet></Tagging>'
        swapped = original.replace('<Value>1', '<Value>x').replace('<Value>2', '<Value>1').replace('<Value>x', '<Value>2')
        self.assertNotEqual(restore.object_tags(original), restore.object_tags(swapped))
        self.assertEqual(restore.object_tags(original), restore.object_tags(original.replace('<Tagging>', '<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">')))

    def test_cleanup_checkpoint_never_deletes_a_rebound_volume(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(control, 'BASE', Path(temporary)), \
                patch.object(restore, 'wait'), patch.object(restore.physical, 'cleanup_classes'), patch.object(restore, 'kube') as kube:
            path = Path(temporary) / 'restore-cleanup.json'
            path.write_text(json.dumps([['fixture-pv', 'expected-uid', 'expected-claim']]))
            rebound = {'metadata': {'uid': 'different-uid'}, 'spec': {'claimRef': {
                'uid': 'different-claim', 'namespace': 'production'}}, 'status': {'phase': 'Released'}}
            with patch.object(restore, 'get', side_effect=lambda kind, *args: None if kind == 'namespace' else rebound):
                with self.assertRaisesRegex(RuntimeError, 'safely released'):
                    restore.cleanup()
            kube.assert_not_called()
            self.assertTrue(path.exists())

    def test_orphan_cleanup_is_scoped_and_tolerates_automatic_pv_deletion(self):
        volume = {'metadata': {'name': 'pvc-claim', 'uid': 'volume'}, 'status': {'phase': 'Released'},
                  'spec': {'storageClassName': 'cloudlab-data', 'claimRef': {
                      'name': 'data-restore-1', 'namespace': restore.NAMESPACE, 'uid': 'claim'}}}
        with tempfile.TemporaryDirectory() as temporary, patch.object(control, 'BASE', Path(temporary)), \
                patch.object(restore, 'wait'), patch.object(restore.physical, 'cleanup_classes'), patch.object(restore, 'kube') as kube:
            def get(kind, name=None):
                return None if kind == 'namespace' else volume if name else {'items': [volume]}
            with patch.object(restore, 'get', side_effect=get):
                restore.cleanup()
                self.assertIn('--ignore-not-found=true', kube.call_args.args)
                self.assertFalse((Path(temporary) / 'restore-cleanup.json').exists())
                kube.reset_mock()
                volume['spec']['claimRef']['name'] = 'unrelated'
                with self.assertRaisesRegex(RuntimeError, 'unexpected identity'):
                    restore.cleanup()
                kube.assert_not_called()

    def test_rotation_preserves_unrelated_fields_and_original(self):
        old = {'id': 'fixture', 'title': 'cnpg-notes-production', 'category': 'SECURE_NOTE', 'tags': ['cloudlab-managed'], 'fields': [
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
        with self.assertRaisesRegex(RuntimeError, 'provisioner-owned'):
            rotation.replacement(dict(old, category='LOGIN'), ('password',))

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

    def generation(self):
        from automation.data.volumes import CLAIMS
        generation = 'data-' + 'a' * 24
        return {'format': 2, 'generation': generation, 'captured_at': 1, 'captured': True,
                'consistency': 'all-writers-stopped', 'database': 'notes',
                'roles': ['notes_app', 'notes_migration', 'backup'], 'objects': [],
                'volumes': {c: {'claim': name, 'volume': 'pvc-' + 'a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12,
                               'snapshot': generation + '-' + c, 'size': '2Gi', 'actual_bytes': 4096}
                            for c, name in CLAIMS.items()}}

    def test_generation_rejects_incomplete_and_foreign_sources(self):
        manifest = self.generation()
        capture.verify(manifest)
        with self.assertRaises(ValueError):
            capture.verify(dict(manifest, captured=False))
        manifest['volumes']['master']['snapshot'] = 'foreign'
        with self.assertRaises(ValueError):
            capture.verify(manifest)

    def test_failed_capture_releases_application_maintenance(self):
        manifest = self.generation()
        values = {'database': 'notes', 'bucket': 'notes', 'applicationRole': 'notes_app',
                  'migrationRole': 'notes_migration', 'backupRole': 'backup'}
        with tempfile.TemporaryDirectory() as temporary, patch.object(control, 'BASE', Path(temporary)), \
                patch.object(capture.volumes, 'inventory', return_value=manifest['volumes']), \
                patch.object(capture.volumes, 'resume') as resume, \
                patch.object(control, 'maintenance', return_value=values), \
                patch.object(control, 'sql', side_effect=RuntimeError('database unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                capture.capture()
            resume.assert_called_once()
            self.assertFalse(json.loads((Path(temporary) / 'pending-volume.json').read_text())['captured'])

    def test_monthly_window_and_explicit_acceptance(self):
        remote.require_window(now=datetime(2026, 10, 1, tzinfo=timezone.utc))
        with self.assertRaisesRegex(RuntimeError, 'day 1'):
            remote.require_window(now=datetime(2026, 10, 8, tzinfo=timezone.utc))
        remote.require_window(True, now=datetime(2026, 10, 8, tzinfo=timezone.utc))
        with self.assertRaises(RuntimeError):
            remote.require_window(now=datetime(2026, 10, 1, 23, tzinfo=timezone.utc), reserve=3600)

    def test_independent_reader_checks_compressed_blocks_without_files(self):
        repository = remote.Repository({'AWS_ENDPOINT': 'https://s3.us-west-004.backblazeb2.com',
            'BUCKET': 'example-bucket', 'REGION': 'us-west-004',
            'AWS_ACCESS_KEY_ID': 'synthetic', 'AWS_SECRET_ACCESS_KEY': 'synthetic'}, acceptance=True)
        manifest = self.generation()
        payload = b'committed fixture'
        checksum = hashlib.sha512(payload).hexdigest()[:64]
        compressed = gzip.compress(payload)
        for row in manifest['volumes'].values():
            row['url'] = 's3://example-bucket@us-west-004/' + remote.storage_policy()['prefix'] + '?backup=' + row['snapshot'] + '&volume=' + row['volume']
        def request(method, key, **kwargs):
            if key.endswith('.cfg'):
                row = next(row for row in manifest['volumes'].values() if row['snapshot'] in key)
                return {'data': json.dumps({'VolumeName': row['volume'], 'SnapshotName': row['snapshot'],
                                           'CompressionMethod': 'gzip', 'Blocks': [{'BlockChecksum': checksum}]}).encode()}
            return {'data': compressed, 'bytes': len(compressed)}
        with patch.object(repository, 'request', side_effect=request):
            self.assertEqual(repository.read_blocks(manifest)['verified_blocks'], 4)
            compressed = gzip.compress(b'corrupted')
            with self.assertRaisesRegex(RuntimeError, 'checksum'):
                repository.read_blocks(manifest)

    def test_temporary_restore_never_uses_cloud_and_removes_snapshots(self):
        manifest = self.generation()
        with tempfile.TemporaryDirectory() as temporary, patch.object(control, 'BASE', Path(temporary)), \
                patch.object(control, 'settings', return_value={'maintenance': False}), \
                patch.object(backup, 'capture', side_effect=lambda: ((Path(temporary) / 'pending-volume.json').write_text(json.dumps(manifest)), manifest)[1]), \
                patch.object(restore, 'run', side_effect=RuntimeError('fixture failed')), \
                patch.object(backup.volumes, 'cleanup_snapshots') as cleanup, \
                patch.object(backup, 'Repository') as repository:
            with self.assertRaisesRegex(RuntimeError, 'fixture failed'):
                backup.run('check-local')
            cleanup.assert_called_once_with(manifest)
            repository.assert_not_called()
            self.assertFalse((Path(temporary) / 'pending-volume.json').exists())

    def test_backup_environment_cannot_escape_its_b2_prefix(self):
        values = {'AWS_ENDPOINT': 'https://s3.us-west-004.backblazeb2.com', 'BUCKET': 'example-bucket',
                  'REGION': 'us-west-004', 'AWS_ACCESS_KEY_ID': 'synthetic', 'AWS_SECRET_ACCESS_KEY': 'synthetic'}
        repository = remote.Repository(values)
        with self.assertRaises(ValueError):
            repository.validate_url({'url': 's3://foreign@us-west-004/prefix/?backup=x&volume=y', 'snapshot': 'x', 'volume': 'y'})
        for endpoint in ('http://s3.us-west-004.backblazeb2.com', 'https://evil.example',
                         'https://user@s3.us-west-004.backblazeb2.com', 'https://s3.us-west-004.backblazeb2.com/path'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                remote.Repository(dict(values, AWS_ENDPOINT=endpoint))

    def test_legacy_cleanup_refuses_links_and_foreign_paths(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(control, 'BASE', Path(temporary)):
            base = Path(temporary) / 'generations'
            base.mkdir()
            foreign = base / 'unrelated'
            foreign.mkdir()
            with self.assertRaises(RuntimeError):
                backup.retire_local()
            self.assertTrue(foreign.exists())
            foreign.rmdir()
            own = base / 'generation-123'
            own.mkdir()
            (own / 'manifest.json').write_text('{"format":1}')
            self.assertEqual(backup.retire_local(), 1)
            self.assertFalse(base.exists())

    def test_restore_failure_never_prunes_previous_generation(self):
        repository = object.__new__(remote.Repository)
        with patch.object(repository, 'request') as request, patch.object(repository, 'manifests') as manifests:
            with self.assertRaisesRegex(RuntimeError, 'Restore gate'):
                repository.accept(self.generation(), {'restored': False})
            request.assert_not_called()
            manifests.assert_not_called()

    def test_freshness_reads_only_local_receipts(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(control, 'BASE', Path(temporary)), \
                patch.object(remote.S3, 'request') as request:
            (Path(temporary) / backup.RECEIPT).write_text(json.dumps({'captured_at': 100, 'retention_complete': True}))
            self.assertEqual(backup.freshness(now=200)['b2_reads'], 0)
            request.assert_not_called()
            (Path(temporary) / backup.ATTEMPT).write_text('{"success":false}')
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
        self.assertNotIn('monthly-application-data-b2', definitions)
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
