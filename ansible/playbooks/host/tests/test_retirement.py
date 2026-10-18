"""Exercise native retirement refusal in an isolated runner filesystem, never a VM."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(Path('/.dockerenv').exists(), 'Native fixture requires the Compose runner')
class ToolingRetirementTests(unittest.TestCase):
    def setUp(self):
        self.root = Path('/opt/cloudlab')
        self.assertFalse(self.root.exists(), 'Refuse to touch an existing runtime')
        self.root.mkdir()
        self.addCleanup(shutil.rmtree, self.root)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.inventory = Path(self.temporary.name) / 'inventory.yml'
        self.inventory.write_text('k3s_servers:\n  hosts:\n    fixture:\n'
                                  '      ansible_connection: local\n'
                                  '      ansible_python_interpreter: ' + sys.executable + '\n')

    def run_playbook(self):
        return subprocess.run(['ansible-playbook', '-i', str(self.inventory),
                               '/workspace/ansible/playbooks/host/020-retire-tooling.yml'],
                              capture_output=True, text=True, timeout=90)

    def test_empty_runtime_repeats_without_changes(self):
        for _ in range(2):
            result = self.run_playbook()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertRegex(result.stdout, r'changed=0\s+')

    def test_changed_executable_and_unknown_data_survive_refusal(self):
        directory = self.root / 'automation/connectivity'
        directory.mkdir(parents=True)
        source = directory / 'contract.py'
        source.write_text('foreign bytes')
        source.chmod(0o600)
        retained = directory / 'retained-data'
        retained.write_bytes(b'never remove unknown content')
        result = self.run_playbook()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no tooling removed', result.stdout)
        self.assertEqual(source.read_text(), 'foreign bytes')
        self.assertEqual(retained.read_bytes(), b'never remove unknown content')

    def test_symlink_ancestor_refuses_without_touching_target(self):
        target = Path(self.temporary.name) / 'retained'
        target.mkdir()
        content = target / 'original'
        content.write_bytes(b'retained')
        (self.root / 'automation').symlink_to(target, target_is_directory=True)
        result = self.run_playbook()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Legacy tooling directory changed', result.stdout)
        self.assertEqual(content.read_bytes(), b'retained')
