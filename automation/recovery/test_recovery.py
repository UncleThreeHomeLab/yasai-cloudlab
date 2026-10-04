"""Disposable SQLite/WAL, archive and retention failure tests; no B2 traffic."""
from datetime import datetime, timezone
from contextlib import closing
import io
import json
import os
from pathlib import Path
import sqlite3
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from capture import DATABASE, SERVER, capture, sqlite_copy, verify_archive
from repository import Repository, require_window
from monthly_window import seconds_remaining
from b2 import S3
from backup import freshness
import runner

POLICY = json.loads(Path(__file__).with_name('policy.json').read_text())


class RecoveryTests(unittest.TestCase):
    def test_independent_retrieval_removes_disposable_plaintext(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository = unittest.mock.Mock()
            repository.snapshots.return_value = [{'id': 'fixture', 'time': '2026-01-01', 'tags': [POLICY['tag'], 'verified']}]
            def restore(snapshot, target, policy):
                target.mkdir()
                (target / 'recovery.tar.gz').write_bytes(b'disposable secret fixture')
                return {'captured_at': 1}, 0.1
            repository.retrieve.side_effect = restore
            usage = type('Usage', (), {'free': 100 * 1024**3})()
            with patch.object(runner, 'shared_credentials', return_value={}), \
                 patch.object(runner, 'Repository', return_value=repository), \
                 patch.object(runner, 'Path', return_value=root), \
                 patch.object(runner.shutil, 'disk_usage', return_value=usage), patch('builtins.print'):
                runner.retrieve()
            self.assertEqual(list(root.iterdir()), [])

    def test_freshness_uses_only_local_receipts_and_reports_failed_attempts(self):
        with tempfile.TemporaryDirectory() as temp, patch('repository.subprocess.run') as cloud:
            base = Path(temp)
            with self.assertRaisesRegex(RuntimeError, 'No verified'):
                freshness(base, now=10000000)
            (base / 'receipt.json').write_text(json.dumps({'captured_at': 9999900,
                'retention_complete': True, 'archive_bytes': 100, 'retrieval_seconds': 2}))
            with patch('builtins.print'):
                freshness(base, now=10000000)
            with self.assertRaisesRegex(RuntimeError, 'stale'):
                freshness(base, now=20000000)
            (base / 'last-attempt.json').write_text('{"success": false}')
            with self.assertRaisesRegex(RuntimeError, 'failed'):
                freshness(base, now=10000000)
            cloud.assert_not_called()

    def test_version_cleanup_preserves_latest_data_and_deletes_old_data_before_markers(self):
        client = S3({'PREFIX': 'k3s-restic/'})
        current = {'key': 'k3s-restic/retained', 'version': 'new', 'latest': True, 'kind': 'Version', 'size': 10}
        old = dict(current, version='old', latest=False)
        marker = {'key': 'k3s-restic/removed', 'version': 'marker', 'latest': True, 'kind': 'DeleteMarker', 'size': 0}
        calls = []
        def request(method, key='', query=None):
            calls.append((method, key, query))
            return b'<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>'
        with patch.object(client, 'versions', side_effect=[[current, old, marker], [current]]), \
             patch.object(client, 'request', side_effect=request):
            self.assertEqual(client.cleanup(), 10)
        deletes = [c for c in calls if c[0] == 'DELETE']
        self.assertEqual([c[2]['versionId'] for c in deletes], ['old', 'marker'])

    def test_online_backup_includes_committed_wal_and_excludes_uncommitted_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            live = sqlite3.connect(root / 'live.db')
            live.execute('PRAGMA journal_mode=WAL')
            live.execute('CREATE TABLE evidence(value)')
            live.execute("INSERT INTO evidence VALUES ('committed')")
            live.commit()
            live.execute("INSERT INTO evidence VALUES ('uncommitted')")
            sqlite_copy(root / 'live.db', root / 'copy.db', 1024 * 1024)
            with closing(sqlite3.connect(root / 'copy.db')) as restored:
                self.assertEqual(restored.execute('SELECT * FROM evidence').fetchall(), [('committed',)])
            live.close()

    def test_capture_and_restore_include_token_ca_and_validate_checksums(self):
        with tempfile.TemporaryDirectory() as temp:
            root, stage = Path(temp) / 'source', Path(temp) / 'staging'
            stage.mkdir()
            for name in [SERVER / 'token', SERVER / 'tls/server-ca.key', SERVER / 'cred/passwd', Path('etc/rancher/k3s/config.yaml')]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('disposable fixture')
            db = root / DATABASE
            db.parent.mkdir()
            with closing(sqlite3.connect(db)) as connection:
                connection.execute('CREATE TABLE kine(id INTEGER PRIMARY KEY, value BLOB)')
            usage = type('Usage', (), {'free': 500 * 1024**3, 'total': 600 * 1024**3})()
            with patch('capture.shutil.disk_usage', return_value=usage):
                manifest = capture(root, stage, POLICY, 'fixture')
            recovered = verify_archive(stage / 'recovery.tar.gz', stage / 'restored', POLICY)
            self.assertEqual(manifest, recovered)
            self.assertFalse((stage / 'generation').exists())
            self.assertEqual((stage / 'restored' / SERVER / 'token').read_text(), 'disposable fixture')
            repository = object.__new__(Repository)
            repository.values = {}
            repository.env = dict(os.environ, RESTIC_REPOSITORY=str(Path(temp) / 'restic'),
                                  RESTIC_PASSWORD='disposable-local-test-password')
            with patch('repository.require_window', return_value=7200), patch('b2.S3') as s3:
                s3.return_value.prefix = 'k3s-restic/'
                s3.return_value.versions.return_value = []
                s3.return_value.cleanup.return_value = 1000
                first = repository.export(stage, POLICY, repository)
                self.assertTrue(first['retention_complete'])
                shutil.rmtree(stage / 'retrieved')
                # Different bytes create another generation; replacement must
                # verify with real restic before removing the previous snapshot.
                shutil.rmtree(stage / 'restored')
                (root / SERVER / 'token').write_text('rotated disposable fixture')
                with patch('capture.shutil.disk_usage', return_value=usage):
                    capture(root, stage, POLICY, 'fixture')
                second = repository.export(stage, POLICY, repository)
                self.assertNotEqual(first['snapshot'], second['snapshot'])
                self.assertEqual([s['id'] for s in repository.snapshots()], [second['snapshot']])

    def test_unsafe_archive_is_rejected_without_path_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with tarfile.open(root / 'unsafe.tgz', 'w:gz') as archive:
                member = tarfile.TarInfo('../escape')
                member.size = 4
                archive.addfile(member, io.BytesIO(b'fail'))
            with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                verify_archive(root / 'unsafe.tgz', root / 'restore', POLICY)
            self.assertFalse((root / 'escape').exists())

    def test_normal_window_has_no_implicit_initial_or_cleanup_exception(self):
        self.assertEqual(seconds_remaining(datetime(2026, 10, 1, tzinfo=timezone.utc)), 86400)
        self.assertEqual(seconds_remaining(datetime(2026, 10, 2, tzinfo=timezone.utc)), 0)
        with patch('write_window.seconds_remaining', return_value=0), patch('write_window._initial', False):
            with self.assertRaisesRegex(RuntimeError, 'require day 1 UTC'):
                require_window()
            repository = object.__new__(Repository)
            with patch('repository.subprocess.run') as command:
                with self.assertRaises(RuntimeError):
                    repository.run('prune', write=True)
                command.assert_not_called()

    def test_failed_retrieval_never_forgets_previous_snapshot(self):
        repository = object.__new__(Repository)
        reader = object.__new__(Repository)
        repository.values = reader.values = {}
        commands = []
        def command(*args, **kwargs):
            commands.append(args[0])
            return '{"message_type":"summary","snapshot_id":"candidate"}'
        def retrieve(snapshot, target, *args):
            if snapshot == 'previous':
                target.mkdir()
                return {}, 0.1
            raise RuntimeError('fixture checksum failed')
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp)
            (stage / 'recovery.tar.gz').write_bytes(b'fixture')
            with patch('repository.require_window', return_value=7200), \
                 patch.object(repository, 'initialize'), \
                 patch.object(repository, 'snapshots', return_value=[{'id': 'previous', 'time': '2026-01-01', 'tags': [POLICY['tag'], 'verified']}]), \
                 patch.object(repository, 'run', side_effect=command), \
                 patch('b2.S3') as s3, \
                 patch.object(reader, 'retrieve', side_effect=retrieve):
                s3.return_value.prefix = 'k3s-restic/'
                s3.return_value.versions.return_value = []
                s3.return_value.cleanup.return_value = 1000
                with self.assertRaisesRegex(RuntimeError, 'checksum'):
                    repository.export(stage, POLICY, reader)
            self.assertIn('backup', commands)
            self.assertNotIn('forget', commands)
            self.assertNotIn('prune', commands)


if __name__ == '__main__':
    unittest.main()
