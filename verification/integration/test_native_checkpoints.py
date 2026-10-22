"""Execute native transaction blocks against disposable local files, never live resources."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


def task_file(relative):
    return yaml.safe_load((ROOT / relative).read_text())


def named(tasks, name):
    return copy.deepcopy(next(task for task in tasks if task.get('name') == name))


class NativeCheckpointTests(unittest.TestCase):
    def run_native(self, tasks, values, staging=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            if staging is not None:
                (root / 'staging.yml').write_text(yaml.safe_dump(staging, sort_keys=False))
                tasks[0]['ansible.builtin.import_tasks'] = str(root / 'staging.yml')
            values = dict(values, ansible_python_interpreter=sys.executable,
                access_state_path=str(root / 'state.json'), certificates_state_path=str(root / 'state.json'),
                native_marker_path=str(root / 'marker.json'))
            path = root / 'play.yml'
            path.write_text(yaml.safe_dump([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                'vars': values, 'tasks': tasks}], sort_keys=False))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
                capture_output=True, text=True, timeout=60)
            files = {name: json.loads((root / name).read_text()) for name in ('state.json', 'marker.json')
                     if (root / name).exists()}
            return result, files

    def test_access_uid_is_written_after_updating_its_in_memory_state(self):
        source = task_file('ansible/playbooks/access/tasks/native-application.yml')
        tasks = [named(source, 'Select whether the Application UID needs a durable record'),
                 named(source, 'Retain Application UID before waiting for controllers')]
        result, files = self.run_native(tasks, {'access_native_state': {'phase': 'preparing'},
            'access_native_declared': {'resources': [{'metadata': {'uid': 'retained'}}]}})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(files['state.json'], {'phase': 'preparing', 'application_uid': 'retained'})

    def test_access_completion_records_its_observed_identities_durably(self):
        source = task_file('ansible/playbooks/access/tasks/native-identities.yml')
        tasks = [named(source, name) for name in ('Initialize the retained identity comparison',
            'Select only public Kubernetes object identities',
            'Record completed initial access configuration without changing retained state')]
        result, files = self.run_native(tasks, {'access_native_state': {'phase': 'preparing'},
            'access_native_objects': {'results': [{'item': {'key': 'proxygroup/cloudlab-ingress'},
                'resources': [{'metadata': {'uid': 'retained-proxy'}}]}]}})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(files['state.json']['phase'], 'configured')
        self.assertEqual(files['state.json']['identities'], {'proxygroup/cloudlab-ingress': 'retained-proxy'})

    def test_cold_telemetry_enables_and_applies_monitors_without_toggling_ready_installations(self):
        source = task_file('ansible/playbooks/observability/native.yml')[0]['tasks']
        block = named(source, 'Enable monitors after Prometheus installs its APIs')
        block['block'][1] = {'name': 'Observe the native boundary declaration after enabling monitors',
            'ansible.builtin.copy': {'dest': '{{ native_marker_path }}', 'mode': '0600',
                'content': '{{ telemetry_monitoring_enabled | to_json }}'}}
        for installed in (False, True):
            with self.subTest(installed=installed):
                result, files = self.run_native([copy.deepcopy(block)], {
                    'telemetry_monitoring_enabled': installed,
                    'telemetry_monitor_apis': {'results': [{'resources': [{}] if installed else []}] * 2}})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if installed: self.assertNotIn('marker.json', files)
                else: self.assertIs(files['marker.json'], True)

    def test_failed_staging_preserves_intent_and_success_records_production_permission(self):
        source = task_file('ansible/playbooks/certificates/native.yml')[0]['tasks']
        stage = named(source, 'Complete staging before enabling production')
        actual = task_file('ansible/playbooks/certificates/tasks/native-staging.yml')
        for failed in (True, False):
            tasks = copy.deepcopy(actual)
            for task in tasks:
                if 'ansible.builtin.import_tasks' not in task: continue
                certificate = task['ansible.builtin.import_tasks'] == 'native-certificate.yml'
                task.pop('ansible.builtin.import_tasks')
                task['ansible.builtin.fail' if certificate and failed else 'ansible.builtin.debug'] = {
                    'msg': 'Synthetic staging issuance result'}
            result, files = self.run_native([copy.deepcopy(stage)], {
                'certificates_initial_phase': 'staging',
                'certificates_state': {'phase': 'staging', 'application_uid': 'retained'},
                'certificates_observed': {'staging': {'certificate_uid': 'certificate', 'secret_uid': 'secret'}}}, staging=tasks)
            with self.subTest(failed=failed):
                self.assertEqual(result.returncode != 0, failed, result.stdout + result.stderr)
                self.assertEqual(files['state.json']['phase'], 'staging' if failed else 'production')
                if not failed:
                    self.assertEqual(files['state.json']['staging'], {'certificate_uid': 'certificate', 'secret_uid': 'secret'})

    def test_certificate_acceptance_preserves_the_existing_account_hash_format(self):
        source = task_file('ansible/playbooks/certificates/tasks/native-identities.yml')
        tasks = [named(source, name) for name in (
            'Select retained gateway identities and an empty account comparison',
            'Compare account identities and credential hashes without exporting keys',
            'Record accepted issuance only after all retained identities pass')]
        data = {'private-key': 'c3ludGhldGlj', 'additional': 'Zml4dHVyZQ=='}
        result, files = self.run_native(tasks, {'certificates_state': {'phase': 'production'},
            'certificates_observed': {'public': {'certificate_uid': 'public'}, 'private': {'certificate_uid': 'private'}},
            'certificates_account_secrets': {'results': [{'item': 'production',
                'resources': [{'metadata': {'uid': 'retained-account'}, 'data': data}]}]}})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(files['state.json']['phase'], 'accepted')
        self.assertEqual(files['state.json']['accounts']['production'], {'uid': 'retained-account',
            'content': hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()})
