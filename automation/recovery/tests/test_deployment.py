"""Independent installed recovery must not depend on the implementation checkout."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from jinja2 import Template
import yaml


ROOT = Path(__file__).resolve().parents[3]
TASKS = yaml.safe_load((ROOT / 'ansible/roles/recovery/tasks/main.yml').read_text())
MODULES = next(task for task in TASKS if task['name'] == 'Install recovery modules from the checkout')
WINDOW = next(task for task in TASKS if task['name'] == 'Install the shared cloud-write window contract')


class DeploymentTests(unittest.TestCase):
    def test_declared_assets_resolve_from_component_entry_point(self):
        for task in (MODULES, WINDOW):
            for item in task.get('loop', [None]):
                with self.subTest(task=task['name'], item=item):
                    source = Template(task['ansible.builtin.copy']['src']).render(
                        playbook_dir='/workspace/ansible/playbooks', item=item)
                    local = ROOT / Path(source).relative_to('/workspace')
                    self.assertTrue(local.is_file(), source)

    def test_installed_runtime_imports_without_checkout_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            installed = base / 'recovery'
            installed.mkdir()
            for name in MODULES['loop']:
                shutil.copyfile(ROOT / 'automation/recovery' / name, installed / name)
            destination = base / Path(WINDOW['ansible.builtin.copy']['dest']).relative_to('/opt/cloudlab')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'ansible/playbooks/longhorn/files/monthly_window.py', destination)
            result = subprocess.run(
                [sys.executable, '-I', '-S', '-c',
                 'import sys; sys.path.insert(0, sys.argv[1]); '
                 'import backup, repository, write_window; assert callable(backup.freshness); '
                 'assert callable(repository.require_window); assert callable(write_window.seconds_remaining)',
                 str(installed)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
