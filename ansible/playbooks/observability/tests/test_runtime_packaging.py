"""Scoped runtime proof imports its real owner and keeps workers read only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[4]
COMPONENT = ROOT / 'ansible/playbooks/observability'


class RuntimePackagingTests(unittest.TestCase):
    def test_fixture_imports_existing_server_installer_and_worker_checks_are_read_only(self):
        plays = yaml.safe_load((COMPONENT / 'tests/runtime-proof.yml').read_text())
        server, worker = plays
        self.assertEqual(server['hosts'], 'k3s_servers')
        self.assertEqual(server['tasks'][0]['ansible.builtin.import_tasks'], '../tasks/runtime.yml')
        self.assertEqual(server['tasks'][1]['ansible.builtin.command']['argv'][-1], '--guard-probe')
        self.assertFalse(server['tasks'][1]['changed_when'])
        self.assertTrue(server['tasks'][1]['no_log'])
        self.assertEqual(worker['hosts'], 'k3s_agents')
        self.assertEqual({key for task in worker['tasks'] for key in task if key.startswith('ansible.')},
                         {'ansible.builtin.stat', 'ansible.builtin.assert'})
        tasks = yaml.safe_load((COMPONENT / 'tasks/runtime.yml').read_text())
        self.assertEqual(tasks[1]['loop'], ['bootstrap.py', 'verify.py', 'dashboards.py', 'writer_guard.py'])
        self.assertEqual(tasks[1]['ansible.builtin.copy']['mode'], '0600')
        for name in tasks[1]['loop']:
            compile((COMPONENT / 'files' / name).read_text(), name, 'exec')

    def test_standalone_installed_guard_probe_has_no_checkout_or_mutation_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory) / 'cloudlab/playbooks/observability/files'
            installed.mkdir(parents=True)
            for name in ('bootstrap.py', 'writer_guard.py'):
                shutil.copyfile(COMPONENT / 'files' / name, installed / name)
            kube = Path(directory) / 'cloudlab/playbooks/istio/files'
            kube.mkdir(parents=True)
            # Only Kubernetes I/O is synthetic; run the installed script and guard unchanged.
            (kube / 'kube.py').write_text(
                'def get(kind, name, namespace=None):\n'
                '    assert kind == "application.argoproj.io" and namespace == "argocd"\n'
                '    return None\n'
                'def kube(*args, **kwargs): raise AssertionError("unexpected mutation")\n'
                'contains = application_ready = wait = condition = kube\n')
            result = subprocess.run([sys.executable, str(installed / 'bootstrap.py'), '--guard-probe'],
                                    cwd=directory, env=dict(os.environ, PYTHONPATH=''),
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {'changed': False, 'legacy_writer_authorized': True})


if __name__ == '__main__':
    unittest.main()
