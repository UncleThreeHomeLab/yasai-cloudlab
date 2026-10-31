"""Require explicit migration scope before any host mutation."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


class LifecycleGateTests(unittest.TestCase):
    def test_workload_sysctl_is_optional_exact_and_verified_before_host_mutation(self):
        root = Path('/workspace/ansible/playbooks/k3s')
        validation = yaml.safe_load((root / 'tasks/main.yml').read_text())[:2]
        configure = [task for task in yaml.safe_load((root / 'tasks/configure.yml').read_text())
                     if task['name'] in ('Compose node settings using the encrypted interface',
                                         'Allow only the explicitly reviewed namespaced workload sysctl')]
        check = yaml.safe_load((root / 'tasks/verify.yml').read_text())[1]
        plays = []
        for value in ('omitted', [], ['net.ipv6.conf.all.disable_ipv6'], ['net.*'],
                      ['net.ipv6.conf.all.disable_ipv6'] * 2, ['kernel.shmmax'], 'net.ipv6.conf.all.disable_ipv6'):
            valid = value in ('omitted', [], ['net.ipv6.conf.all.disable_ipv6'])
            variables = dict(k3s_mode='server', k3s_service_name='k3s', k3s_version='fixture',
                             k3s_binaries={}, lab_node_name='fixture', wireguard_address='10.44.0.1',
                             wireguard_interface='wg-lab', k3s_allowed_unsafe_sysctls=value)
            if value == 'omitted':
                del variables['k3s_allowed_unsafe_sysctls']
            if valid:
                tasks = validation + configure + [
                    {'ansible.builtin.set_fact': {'verified_node_config': {
                        'content': '{{ k3s_node_config | to_json | b64encode }}'}}}, check,
                    {'ansible.builtin.set_fact': {'verified_node_config': {'content':
                        '{{ {"kubelet-arg": ["allowed-unsafe-sysctls=net.*"]} | to_json | b64encode }}'}}},
                    {'block': [check, {'name': 'Unexpected installed drift acceptance',
                                      'ansible.builtin.fail': {'msg': 'unsafe drift accepted'}}],
                     'rescue': [{'ansible.builtin.assert': {'that':
                         "ansible_failed_task.name != 'Unexpected installed drift acceptance'"}}]}]
            else:
                tasks = [{'block': validation + [{'name': 'Unexpected unsafe input acceptance',
                          'ansible.builtin.fail': {'msg': 'unsafe input accepted'}}],
                          'rescue': [{'ansible.builtin.assert': {'that':
                              "ansible_failed_task.name != 'Unexpected unsafe input acceptance'"}}]}]
            plays.append(dict(hosts='localhost', connection='local', gather_facts=False,
                              vars=variables, tasks=tasks))
        with tempfile.TemporaryDirectory() as directory:
            playbook = Path(directory) / 'sysctls.yml'
            playbook.write_text(yaml.safe_dump(plays, sort_keys=False))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook)],
                                    capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_action_fails_without_host_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / 'inventory.yml'
            inventory.write_text('all:\n  children:\n    k3s_cluster:\n      hosts:\n        cloudlab:\n          ansible_connection: local\n')
            result = subprocess.run(['ansible-playbook', '-i', str(inventory), '-e', 'ansible_python_interpreter=' + sys.executable,
                '/workspace/ansible/playbooks/k3s/migrate.yml'],
                env=dict(os.environ, LAB_K3S_MIGRATION_ACTION='invalid'),
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('changed=0', result.stdout)
            self.assertIn('Require an explicit reviewed migration action', result.stdout)

    def test_invalid_node_role_fails_native_argument_validation_before_install(self):
        with tempfile.TemporaryDirectory() as directory:
            playbook = Path(directory) / 'invalid-role.yml'
            playbook.write_text("""---
- name: Check component input refusal
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    k3s_mode: invalid
    k3s_service_name: k3s
    k3s_version: pinned-fixture
    k3s_binaries: {}
    lab_node_name: fixture
    wireguard_address: 10.44.0.1
    wireguard_interface: wg-lab
  tasks:
    - name: Enter component through its native validation
      ansible.builtin.import_tasks: /workspace/ansible/playbooks/k3s/tasks/main.yml
""")
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('value of k3s_mode must be one of: server, agent', result.stdout)
            self.assertIn('changed=0', result.stdout)
            self.assertNotIn('TASK [Refuse to turn an existing server', result.stdout)
