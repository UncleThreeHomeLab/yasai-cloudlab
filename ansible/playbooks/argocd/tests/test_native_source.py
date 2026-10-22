"""Exercise native source binding against disposable Git repositories without credentials."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

TASKS = Path(__file__).resolve().parents[1] / 'tasks/source.yml'


class NativeSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repo = self.directory / 'checkout'
        self.repo.mkdir()
        self.git('init', '-b', 'main')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.settings = self.repo / 'gitops/roots/public/values.yaml'
        self.settings.parent.mkdir(parents=True)
        self.settings.write_text('repository: https://github.com/fixture/platform.git\nrevision: main\n')
        self.git('add', '.')
        self.git('commit', '-m', 'Fixture')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.origin = self.directory / 'origin.git'
        self.git('clone', '--bare', str(self.repo), str(self.origin))

    def git(self, *arguments):
        return subprocess.check_output(['git', '-C', str(self.repo), *arguments], text=True, stderr=subprocess.PIPE)

    def run_native(self):
        task = self.directory / 'source.yml'
        task.write_text(TASKS.read_text().replace('/workspace', str(self.repo)))
        accepted = self.directory / 'accepted.json'
        play = self.directory / 'play.yml'
        play.write_text(yaml.safe_dump([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
            'vars': {'ansible_python_interpreter': sys.executable}, 'tasks': [
                {'ansible.builtin.import_tasks': str(task)},
                {'ansible.builtin.copy': {'content': '{{ gitops_source | to_json }}',
                    'dest': str(accepted), 'mode': '0600'}},
            ]}], sort_keys=False))
        # Keep production HTTPS validation while routing only this synthetic URL to a local bare fixture.
        environment = dict(os.environ, GIT_CONFIG_COUNT='1',
            GIT_CONFIG_KEY_0='url.' + self.origin.as_uri() + '.insteadOf',
            GIT_CONFIG_VALUE_0='https://github.com/fixture/platform.git',
            GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null')
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(play)],
            env=environment, capture_output=True, text=True, timeout=90)
        return result, json.loads(accepted.read_text()) if accepted.exists() else None

    def test_published_clean_source_exposes_only_repository_branch_and_revision(self):
        result, value = self.run_native()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value, {'repository': 'https://github.com/fixture/platform.git',
                                'branch': 'main', 'revision': self.head})

    def test_dirty_deployment_inputs_refuse_before_configuration(self):
        self.settings.write_text(self.settings.read_text() + '# Pending edit\n')
        result, value = self.run_native()
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(value)

    def test_unpublished_commit_refuses_before_configuration(self):
        self.settings.write_text(self.settings.read_text() + '# Not yet published\n')
        self.git('add', '.')
        self.git('commit', '-m', 'Unpublished fixture change')
        result, value = self.run_native()
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(value)

    def test_non_github_source_refuses_before_network_access(self):
        self.settings.write_text('repository: https://example.invalid/platform.git\nrevision: main\n')
        self.git('add', '.')
        self.git('commit', '-m', 'Invalid source fixture')
        result, value = self.run_native()
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(value)


if __name__ == '__main__':
    unittest.main()
