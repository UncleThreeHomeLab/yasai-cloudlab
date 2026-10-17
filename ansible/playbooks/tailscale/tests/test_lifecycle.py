"""Require explicit host lifecycle scope before any host mutation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class LifecycleGateTests(unittest.TestCase):
    def test_invalid_action_fails_without_host_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / 'inventory.yml'
            inventory.write_text('all:\n  hosts:\n    cloudlab:\n      ansible_connection: local\n')
            result = subprocess.run(['ansible-playbook', '-i', str(inventory),
                '/workspace/ansible/playbooks/tailscale/lifecycle.yml'],
                env=dict(os.environ, LAB_TAILSCALE_TARGET='cloudlab', LAB_TAILSCALE_ACTION='invalid'),
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('changed=0', result.stdout)
            self.assertIn('Require an explicit lifecycle action', result.stdout)
