"""Keep local validation credential-free and lint scope explicit."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import validate
import yaml


class ValidationTests(unittest.TestCase):
    def test_lint_gates_all_component_files_without_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env.example').write_text('\n'.join(
                prefix + suffix + '=' for prefix in ('VM', 'VM2')
                for suffix in ('_HOST', '_USER', '_PASSWORD')))
            playbooks = root / 'ansible/playbooks'
            playbooks.mkdir(parents=True)
            migrated = playbooks / 'setup.yml'
            migrated.write_text('---\n')
            with patch.object(validate, 'ROOT', root), \
                    patch.object(validate.subprocess, 'run') as run:
                validate.main()
            command = run.call_args_list[1].args[0]
            separator = command.index('--')
            self.assertNotIn('--exclude', command)
            self.assertEqual(command[separator + 1:], [str(migrated)])
            self.assertEqual(run.call_count, 2)

    def test_missing_documented_inputs_fail_before_tool_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env.example').write_text('VM_HOST=\n')
            with patch.object(validate, 'ROOT', root), \
                    patch.object(validate.subprocess, 'run') as run:
                with self.assertRaisesRegex(SystemExit, 'documented VM bootstrap input names'):
                    validate.main()
            run.assert_not_called()

    def test_resolvers_assert_guards_binary_checksum_before_host_changes(self):
        root = Path(validate.__file__).resolve().parents[2]
        tasks = yaml.safe_load(
            (root / 'ansible/playbooks/access/tasks/resolvers.yml').read_text())
        self.assertEqual(tasks[0]['name'], 'Read the pinned independent DNS artifact')
        guards = [task for task in tasks[1:2] if 'ansible.builtin.assert' in task]
        self.assertEqual(len(guards), 1)
        self.assertIn('access_dns_release.binary_sha256', str(guards[0]))

    def test_dns_lock_pins_binary_checksum_for_both_producers(self):
        root = Path(validate.__file__).resolve().parents[2]
        text = (root / 'platform/connectivity/private-dns/artifact.lock.json').read_text()
        lock = json.loads(text)
        for key in ('sha256', 'binary_sha256'):
            self.assertRegex(lock[key], r'^[a-f0-9]{64}$')
        self.assertNotEqual(lock['sha256'], lock['binary_sha256'])
        self.assertEqual(text.count('"binary_sha256"'), 1)
        tasks = yaml.safe_load(
            (root / 'ansible/playbooks/access/tasks/resolvers.yml').read_text())
        payload = next(task for task in tasks
                       if task['name'] == 'Configure and verify each DNS generation before activation')
        stdin = str(payload['ansible.builtin.command']['stdin'])
        self.assertIn('access_dns_release.binary_sha256', stdin)
        self.assertNotIn('access_dns_release.sha256', stdin)
        download = next(task for task in tasks
                        if task['name'] == 'Download the checksum-verified independent DNS binary')
        self.assertIn('access_dns_release.sha256',
                      str(download['ansible.builtin.get_url']['checksum']))
        source = (root / 'ansible/playbooks/access/files/reconcile.py').read_text()
        self.assertIn("['binary_sha256']", source)
