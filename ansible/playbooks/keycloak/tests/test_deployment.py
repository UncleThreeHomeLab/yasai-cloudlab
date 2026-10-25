"""Declared host assets preserve identity operations without workstation imports."""
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
OWNER = ROOT / 'ansible/playbooks/keycloak'


class DeploymentTests(unittest.TestCase):
    def test_installed_runtime_imports_without_checkout_or_pythonpath(self):
        tasks = []
        for path in (ROOT / 'ansible/playbooks/data/tasks/runtime.yml',
                     OWNER / 'tasks/runtime.yml', OWNER / 'tasks/converge.yml'):
            tasks.extend(yaml.safe_load(path.read_text()))
        tasks = [nested for task in tasks for nested in (
            yaml.safe_load((ROOT / Path(task['ansible.builtin.import_tasks']).relative_to('/workspace')).read_text())
            if 'ansible.builtin.import_tasks' in task else [task])]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for task in tasks:
                copy = task.get('ansible.builtin.copy', {})
                if not copy.get('dest', '').startswith('/opt/cloudlab/'):
                    continue
                for item in task.get('loop', [None]):
                    source = Template(copy['src']).render(item=item)
                    if not source.startswith('/workspace/'):
                        continue
                    target = base / Path(Template(copy['dest']).render(item=item)).relative_to('/opt/cloudlab')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = ROOT / Path(source).relative_to('/workspace')
                    if source.is_dir():
                        shutil.copytree(source, target, dirs_exist_ok=True)
                    else:
                        shutil.copyfile(source, target)
            environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
            result = subprocess.run([sys.executable, '-I', '-c',
                'import sys, runpy, pathlib; '
                'runpy.run_path(str(pathlib.Path(sys.argv[1]) / "playbooks/keycloak/files/bootstrap.py")); '
                'from playbooks.keycloak.files import bootstrap, ownership, maintenance, recovery, '
                'rotation, lifecycle, argo, verify, emergency, session_fixture, owner_enrollment, isolated_restore; '
                'from playbooks.data.files import capture, restore; '
                'assert bootstrap.ROOT == __import__("pathlib").Path(sys.argv[1]); '
                'assert isolated_restore.CONFIGURATION_SOURCE.read_bytes() == '
                '(__import__("pathlib").Path(sys.argv[1]) / "playbooks/keycloak/files/configuration.py").read_bytes(); '
                'assert callable(recovery.verify_restored); assert callable(bootstrap.run)', str(base)],
                cwd=base, env=environment, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_setup_only_imports_retained_identity_after_data(self):
        plays = yaml.safe_load((ROOT / 'ansible/playbooks/setup.yml').read_text())
        imports = [play['ansible.builtin.import_playbook'] for play in plays]
        self.assertLess(imports.index('data/020-reconcile.yml'), imports.index('keycloak/050-retained.yml'))
        self.assertLess(imports.index('keycloak/050-retained.yml'), imports.index('services/010-bootstrap.yml'))
        self.assertEqual([path for path in imports if path.startswith('keycloak/')],
                         ['keycloak/050-retained.yml', 'keycloak/060-retire-runtime.yml'])
        retained = yaml.safe_load((OWNER / '050-retained.yml').read_text())[0]
        self.assertEqual(retained['vars']['keycloak_phase'], 'retained')

    def test_named_client_operations_reject_different_actions_before_execution(self):
        for filename, action in (('provision-client.yml', 'provision-client'),
                                 ('retire-client.yml', 'retire-client'), ('rotate-client.yml', 'rotate')):
            play = yaml.safe_load((OWNER / filename).read_text())[0]
            self.assertIn(action, play['tasks'][0]['ansible.builtin.assert']['that'])
            self.assertTrue(play['tasks'][0]['no_log'])
            self.assertTrue(play['tasks'][1]['no_log'])


if __name__ == '__main__':
    unittest.main()
