"""Native API waits reject stale controller evidence without service credentials."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class NativeReadinessTests(unittest.TestCase):
    def test_component_waits_reject_stale_failed_and_missing_evidence(self):
        sources = [
            ('ansible/playbooks/harbor/native.yml', 'harbor_external_secrets', 'Ready'),
            ('ansible/playbooks/observability/tasks/native-secrets.yml', 'telemetry_external_secrets', 'Ready'),
            ('ansible/playbooks/access/tasks/native-prerequisites.yml', 'access_native_api', 'Established'),
            ('ansible/playbooks/access/tasks/native-prerequisites.yml', 'access_native_credential', 'Ready'),
            ('ansible/playbooks/access/tasks/native-identities.yml', 'access_native_proxy', 'ProxyGroupReady'),
        ]
        tasks = []
        for filename, registered, condition in sources:
            entries = yaml.safe_load((ROOT / filename).read_text())
            entries = entries[0]['tasks'] if filename.endswith('/native.yml') else entries
            gate = next(task['until'] for task in entries if task.get('register') == registered)
            ready = {'resources': [{'metadata': {'generation': 3}, 'status': {'conditions': [
                {'type': condition, 'status': 'True', 'observedGeneration': 3}]}}]}
            for scenario in ('current', 'stale', 'failed', 'unspecified-generation', 'missing'):
                result = copy.deepcopy(ready)
                row = result['resources'][0]['status']['conditions'][0]
                if scenario == 'stale': row['observedGeneration'] = 2
                elif scenario == 'failed': row['status'] = 'False'
                elif scenario == 'unspecified-generation': row.pop('observedGeneration')
                elif scenario == 'missing': result['resources'] = []
                expected = scenario in ('current', 'unspecified-generation')
                tasks.extend([
                    {'name': registered + ' ' + scenario,
                     'ansible.builtin.assert': {'that': gate, 'quiet': True},
                     'vars': {registered: result}, 'register': 'checked', 'ignore_errors': True},
                    {'name': 'Require the expected acceptance or refusal',
                     'ansible.builtin.assert': {'that': ['checked.failed == ' + str(not expected).lower()], 'quiet': True}},
                ])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'play.yml'
            path.write_text(yaml.safe_dump([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                'vars': {'ansible_python_interpreter': sys.executable}, 'tasks': tasks}], sort_keys=False))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
                capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
