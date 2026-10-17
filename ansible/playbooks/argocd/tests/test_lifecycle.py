"""Exercise actual Ansible import gates without Kubernetes or VM credentials."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


class LifecycleTests(unittest.TestCase):
    def test_interrupted_seed_and_explicit_actions_keep_their_stage_boundaries(self):
        lifecycle = Path(__file__).resolve().parents[2] / 'gitops.yml'
        stages = yaml.safe_load(lifecycle.read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'ansible.cfg').write_text('[defaults]\n')
            for index, stage in enumerate(stages):
                filename = str(index) + '.yml'
                stage['ansible.builtin.import_playbook'] = filename
                (root / filename).write_text(yaml.safe_dump([{
                    'name': 'Observe stage', 'hosts': 'localhost', 'gather_facts': False,
                    'tasks': [{'name': 'Record execution', 'ansible.builtin.debug': {
                        'msg': 'executed-stage-' + str(index)}}]}]))
            (root / 'lifecycle.yml').write_text(yaml.safe_dump(stages))
            cases = [('bootstrap', '1', {0}), ('bootstrap', '0', set(range(7))),
                     ('private-remove', '0', {1}), ('verify', '0', {7, 8})]
            for action, stop, expected in cases:
                with self.subTest(action=action, stop=stop):
                    result = subprocess.run(
                        ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(root / 'lifecycle.yml')],
                        capture_output=True, text=True, timeout=60,
                        env=dict(os.environ, LAB_GITOPS_ACTION=action, LAB_GITOPS_STOP_AFTER_SEED=stop,
                                 ANSIBLE_NOCOLOR='1', ANSIBLE_STDOUT_CALLBACK='default',
                                 ANSIBLE_CONFIG=str(root / 'ansible.cfg')))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    executed = {index for index in range(len(stages))
                                if '"msg": "executed-stage-' + str(index) + '"' in result.stdout}
                    self.assertEqual(executed, expected)
