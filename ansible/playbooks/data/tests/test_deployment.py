"""Installed schedules must import only declared host assets, without a checkout."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from jinja2 import Template
import yaml

ROOT = Path(__file__).resolve().parents[4]
TASKS = yaml.safe_load((ROOT / 'ansible/playbooks/data/tasks/runtime.yml').read_text())


class DeploymentTests(unittest.TestCase):
    def test_installed_modules_import_without_checkout_or_pythonpath(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for task in TASKS:
                copy = task.get('ansible.builtin.copy', {})
                if 'src' not in copy or not copy['dest'].startswith('/opt/cloudlab/'):
                    continue
                for item in task.get('loop', [None]):
                    source = Template(copy['src']).render(item=item)
                    target = base / Path(Template(copy['dest']).render(item=item)).relative_to('/opt/cloudlab')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = ROOT / Path(source).relative_to('/workspace')
                    if source.is_dir():
                        shutil.copytree(source, target, dirs_exist_ok=True)
                    else:
                        shutil.copyfile(source, target)
            environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
            result = subprocess.run(
                [sys.executable, '-I', '-c',
                 'import sys; sys.path.insert(0, sys.argv[1]); '
                 'from playbooks.data.files import control, configuration, backup, verify, rotation, public_ca; '
                 'from playbooks.keycloak.files import maintenance, recovery, isolated_restore; '
                 'assert control.ROOT == __import__("pathlib").Path(sys.argv[1]); '
                 'assert callable(configuration.configure); assert callable(backup.freshness)', str(base)],
                cwd=base, env=environment, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_new_repair_dependency_precedes_its_active_timer_consumer(self):
        modules = next(task['loop'] for task in TASKS if task['name'] == 'Install application data automation from its owner')
        self.assertEqual(len(modules), len(set(modules)))
        self.assertLess(modules.index('public_ca.py'), modules.index('control.py'))
        helper = next(index for index, task in enumerate(TASKS)
                      if task['name'] == 'Install the shared Kubernetes helper from its owner')
        consumers = next(index for index, task in enumerate(TASKS)
                         if task['name'] == 'Install application data automation from its owner')
        self.assertLess(helper, consumers)

    def test_schedules_keep_runtime_and_cloud_boundaries(self):
        tasks = yaml.safe_load((ROOT / 'ansible/playbooks/data/tasks/schedules.yml').read_text())
        calendars = next(task['loop'] for task in tasks if task['name'] == 'Install monthly backup and local receipt-check schedules')
        self.assertEqual(next(row['calendar'] for row in calendars if row['name'] == 'reconcile'), '*-*-* *:0/5:00 UTC')
        self.assertEqual(next(row['calendar'] for row in calendars if row['name'] == 'monthly'), '{{ data_policy.monthly_calendar }}')
        unit = (ROOT / 'ansible/playbooks/data/templates/service.j2').read_text()
        self.assertIn('/opt/cloudlab/playbooks/data/files/', unit)
        self.assertNotIn('/workspace', unit)
