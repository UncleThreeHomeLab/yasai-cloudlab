"""Exact approved target fails in the real Ansible gate before host effects."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[4]


class DataTargetGateTests(unittest.TestCase):
    def test_exact_target_gate_runs_before_any_runtime_effect(self):
        tasks = yaml.safe_load((ROOT / 'ansible/playbooks/keycloak/argo-login.yml').read_text())[0]['tasks']
        gate = tasks[1]
        target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'a' * 40}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for valid in (False, True):
                marker = base / ('effect-' + str(valid))
                actual = target if valid else dict(target, valuesRevision='b' * 40)
                play = [{'name': 'Exercise existing exact identity gate', 'hosts': 'localhost', 'gather_facts': False,
                    'vars': {'ansible_python_interpreter': sys.executable, 'keycloak_argo_expected_target': target,
                             'identity_public_source': {'stdout': json.dumps({'argo': {'target': actual}})}},
                    'tasks': [copy.deepcopy(gate), {'name': 'Record subsequent host effect',
                        'ansible.builtin.copy': {'content': 'effect', 'dest': str(marker), 'mode': '0600'}}]}]
                filename = base / 'gate.yml'; filename.write_text(yaml.safe_dump(play))
                result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(filename)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode == 0, valid, result.stdout + result.stderr)
                self.assertEqual(marker.exists(), valid)
