from pathlib import Path
import sys
import tempfile
import unittest

from playbooks.buildkit.tests import fixtures


@unittest.skipUnless(Path('/.dockerenv').exists(), 'Native orchestration fixture requires Compose')
class NativeProofTests(unittest.TestCase):
    def setUp(self):
        executable = Path('/usr/local/bin/k3s')
        self.assertFalse(executable.exists(), 'Refuse to overwrite a real Kubernetes binary')
        executable.write_text('#!' + sys.executable + '\n' +
                              (fixtures.BASE / 'tests/kube_fixture.py').read_text())
        executable.chmod(0o700)
        self.addCleanup(executable.unlink)

    def test_native_playbook_builds_sequentially_and_deletes_only_its_namespace_uid(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, state = fixtures.prove(Path(temporary), pending_polls=1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state['build_nodes'], ['node-a', 'node-b'])
        self.assertTrue(state['namespace_deleted'])
        dry_runs = [call for call in state['calls'] if '--dry-run=server' in call['args']]
        self.assertEqual(len(dry_runs), 2)
        self.assertTrue(all(row['document']['metadata']['name'] == 'overflow' for row in dry_runs))

    def test_failed_build_cleans_only_this_fixture_and_never_starts_second_node(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, state = fixtures.prove(Path(temporary), fail_build=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('build-failed-fixture', result.stdout)
        self.assertEqual(state['build_nodes'], ['node-a'])
        self.assertTrue(state['namespace_deleted'])

    def test_namespace_replacement_prevents_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, state = fixtures.prove(Path(temporary), replace_namespace=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('namespace_deleted', state)
        self.assertIn('namespace', state)

    def test_credentials_or_existing_data_fail_before_any_cluster_operation(self):
        for field in ('secret', 'projected', 'hostPath', 'persistentVolumeClaim'):
            configuration = fixtures.values()
            configuration['template']['spec']['volumes'].append({'name': 'forbidden', field: {}})
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                result, state = fixtures.prove(Path(temporary), configuration=configuration)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(state['calls'], [])
