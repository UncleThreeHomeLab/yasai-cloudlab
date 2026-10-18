"""Run real native lifecycle refusals without deployment credentials or VM access."""
import os
import subprocess
import sys
import unittest


class LifecycleRefusalTests(unittest.TestCase):
    def test_unspecified_operations_fail_before_mutation(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('VM', 'OP_', 'LAB_'))}
        for action in ('maintenance', 'upgrade', 'recovery', 'nuke'):
            with self.subTest(action=action):
                result = subprocess.run([sys.executable, '/opt/runner/run.py', action],
                                        cwd='/workspace/ansible', capture_output=True,
                                        text=True, env=environment, timeout=45)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('no mutation performed', result.stdout.lower())
                self.assertNotIn('Missing .env', result.stdout + result.stderr)
                self.assertRegex(result.stdout, r'changed=0\s+')
