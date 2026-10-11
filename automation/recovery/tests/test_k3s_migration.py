"""Exercise interruption recovery and refusal of unsafe migration inputs."""
import json
import fcntl
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import k3s_migration as migration


class MigrationTests(unittest.TestCase):
    def test_active_recovery_lock_blocks_shutdown_before_any_command(self):
        policy = json.loads(Path(migration.__file__).with_name('k3s_migration.json').read_text())
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            state = {'phase': 'prepared', 'role': 'server', 'target': policy['target']}
            (base / 'state.json').write_text(json.dumps(state))
            recovery_path = base / 'recovery.lock'
            original_safe_path = migration.safe_path
            def scoped_path(root, relative):
                return recovery_path if relative == 'var/lib/cloudlab/recovery/job.lock' else original_safe_path(root, relative)
            with recovery_path.open('w') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(migration, 'BASE', base), patch.object(migration, 'safe_path', side_effect=scoped_path), patch.object(migration, 'command') as command:
                    with self.assertRaisesRegex(RuntimeError, 'Recovery capture is running'):
                        migration.run('park', 'server', {'version': policy['target']})
                    command.assert_not_called()
            self.assertEqual(json.loads((base / 'state.json').read_text()), state)

    def test_stop_script_rejects_unreviewed_change(self):
        with self.assertRaisesRegex(RuntimeError, 'patch no longer matches'):
            migration.stop_script('unreviewed script')

    def test_stop_script_never_roundtrips_host_rules_or_changes_tailnet_policy(self):
        source = '\n'.join([
            'iptables-save | grep -v KUBE- | grep -v CNI- | grep -iv flannel | iptables-restore',
            'ip6tables-save | grep -v KUBE- | grep -v CNI- | grep -iv flannel | ip6tables-restore',
            '        tailscale set --advertise-routes=',
        ])
        result = migration.stop_script(source)
        self.assertNotIn('iptables-restore', result)
        self.assertNotIn('ip6tables-restore', result)
        self.assertNotIn('tailscale set', result)

    def test_interrupted_parking_resumes_without_replacing_old_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'live'
            old = Path(folder) / 'old'
            for name in ('a', 'b'):
                (root / name).mkdir(parents=True)
                (root / name / 'data').write_text(name)
            migration.park_paths(root, old, ('a',))
            migration.park_paths(root, old, ('a', 'b'))
            self.assertEqual((old / 'a/data').read_text(), 'a')
            self.assertEqual((old / 'b/data').read_text(), 'b')
            self.assertFalse((root / 'a').exists())

    def test_conflicting_live_and_parked_paths_fail_without_data_loss(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'live'
            old = Path(folder) / 'old'
            (root / 'a').mkdir(parents=True)
            (old / 'a').mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, 'Both original'):
                migration.park_paths(root, old, ('a',))
            self.assertTrue((root / 'a').exists())
            self.assertTrue((old / 'a').exists())

    def test_rollback_retains_failed_target_and_resumes(self):
        with tempfile.TemporaryDirectory() as folder:
            root, old, failed = [Path(folder) / name for name in ('live', 'old', 'failed')]
            for base, value in ((root, 'new'), (old, 'original')):
                (base / 'a').mkdir(parents=True)
                (base / 'a/data').write_text(value)
            migration.restore_paths(root, old, failed, ('a',))
            migration.restore_paths(root, old, failed, ('a',))
            self.assertEqual((root / 'a/data').read_text(), 'original')
            self.assertEqual((failed / 'a/data').read_text(), 'new')

    def test_parent_symlink_cannot_redirect_park(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'live'
            root.mkdir()
            external = Path(folder) / 'external'
            external.mkdir()
            (root / 'a').symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                migration.park_paths(root, Path(folder) / 'old', ('a',))
            self.assertTrue(external.is_dir())

    def test_every_data_bearing_resource_blocks_recreation(self):
        for kind in ('pv', 'pvc', 'volumes.longhorn.io', 'replicas.longhorn.io', 'ingresses'):
            def query(args, **kwargs):
                rows = [{'metadata': {'name': 'private-name'}}] if args[3] == kind else []
                return type('Result', (), {'stdout': json.dumps({'items': rows})})()
            with self.subTest(kind=kind), patch.object(migration, 'command', side_effect=query):
                with self.assertRaisesRegex(RuntimeError, 'zero application') as caught:
                    migration.empty_cluster()
                self.assertNotIn('private-name', str(caught.exception))

    def test_unknown_namespace_blocks_recreation(self):
        def query(args, **kwargs):
            rows = [{'metadata': {'name': 'private-app'}}] if args[3] == 'namespaces' else []
            return type('Result', (), {'stdout': json.dumps({'items': rows})})()
        with patch.object(migration, 'command', side_effect=query):
            with self.assertRaisesRegex(RuntimeError, 'Unknown namespace'):
                migration.empty_cluster()

    def test_default_namespace_workload_blocks_recreation(self):
        def query(args, **kwargs):
            rows = [{'metadata': {'namespace': 'default'}}] if args[3].startswith('pods,') else []
            return type('Result', (), {'stdout': json.dumps({'items': rows})})()
        with patch.object(migration, 'command', side_effect=query):
            with self.assertRaisesRegex(RuntimeError, 'Application workload'):
                migration.empty_cluster()

    def test_api_failure_is_not_an_empty_cluster(self):
        with patch.object(migration, 'command', side_effect=RuntimeError('Query failed')):
            with self.assertRaises(RuntimeError):
                migration.empty_cluster()


if __name__ == '__main__':
    unittest.main()
