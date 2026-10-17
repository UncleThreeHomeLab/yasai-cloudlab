"""Require explicit migration scope before any host mutation."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class LifecycleGateTests(unittest.TestCase):
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
