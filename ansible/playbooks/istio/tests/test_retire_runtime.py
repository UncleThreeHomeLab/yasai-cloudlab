"""Exercise scoped file retirement with synthetic local files and no cluster access."""
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[4]


class RuntimeRetirementTests(unittest.TestCase):
    def run_retirement(self, directory, *, attested=True, deferred=False, changed=False, redirected=False):
        path = Path(directory)
        runtime = path / 'runtime'
        runtime.mkdir(exist_ok=True)
        (runtime / '__pycache__').mkdir(exist_ok=True)
        if not (path / 'initialized').exists():
            (runtime / 'configuration.py').write_text('changed' if changed else 'old writer')
            (runtime / '__pycache__/configuration.cpython-313.pyc').write_bytes(b'old bytecode')
            (runtime / 'ownership.json').write_text('retained receipt')
            (runtime / 'initial_bootstrap.py').write_text('active initial seed')
            (path / 'initialized').touch()
        if redirected:
            target = path / 'foreign.pyc'; target.write_bytes(b'foreign')
            (runtime / '__pycache__/configuration.cpython-313.pyc').unlink()
            (runtime / '__pycache__/configuration.cpython-313.pyc').symlink_to(target)
        play = copy.deepcopy(yaml.safe_load((ROOT / 'ansible/playbooks/istio/020-retire-runtime.yml').read_text())[1])
        play['vars']['mesh_runtime_directories'] = [str(runtime)]
        play['vars']['mesh_retired_writer_sha256'] = hashlib.sha256(b'old writer').hexdigest()
        (path / 'playbook.yml').write_text(yaml.safe_dump([play]))
        (path / 'inventory').write_text('[k3s_cluster]\nnode ansible_connection=local ansible_python_interpreter=' + sys.executable + '\n[k3s_servers]\nnode\n'
            '[all:vars]\nmesh_native_handoff_verified=' + str(attested).lower() + '\n'
            'mesh_runtime_retirement_deferred=' + str(deferred).lower() + '\n')
        return subprocess.run(['ansible-playbook', '-i', str(path / 'inventory'), str(path / 'playbook.yml')],
            capture_output=True, text=True, timeout=60), runtime

    def test_owned_writer_and_cache_retire_after_handoff_and_second_apply_changes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            result, runtime = self.run_retirement(directory)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((runtime / 'configuration.py').exists())
            self.assertFalse((runtime / '__pycache__/configuration.cpython-313.pyc').exists())
            self.assertEqual((runtime / 'ownership.json').read_text(), 'retained receipt')
            self.assertTrue((runtime / 'initial_bootstrap.py').exists())
            repeated, _ = self.run_retirement(directory)
            self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
            self.assertRegex(repeated.stdout, r'changed=0\s')

    def test_missing_attestation_or_changed_executable_preserves_all_files(self):
        for attested, changed in ((False, False), (True, True)):
            with tempfile.TemporaryDirectory() as directory:
                result, runtime = self.run_retirement(directory, attested=attested, changed=changed)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue((runtime / 'configuration.py').exists())
                self.assertTrue((runtime / '__pycache__/configuration.cpython-313.pyc').exists())

    def test_accepted_prebinding_upgrade_defers_retirement_until_identity_can_bind(self):
        with tempfile.TemporaryDirectory() as directory:
            result, runtime = self.run_retirement(directory, attested=False, deferred=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((runtime / 'configuration.py').exists())
            self.assertIn('retirement deferred', result.stdout)
        setup = yaml.safe_load((ROOT / 'ansible/playbooks/setup.yml').read_text())
        imports = [stage['ansible.builtin.import_playbook'] for stage in setup]
        self.assertGreater(imports.index('istio/020-retire-runtime.yml'), imports.index('keycloak/050-retained.yml'))

    def test_redirected_obsolete_cache_is_refused_without_removing_source_or_target(self):
        with tempfile.TemporaryDirectory() as directory:
            result, runtime = self.run_retirement(directory, redirected=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((runtime / 'configuration.py').exists())
            self.assertTrue((runtime / '__pycache__/configuration.cpython-313.pyc').is_symlink())
            self.assertEqual((Path(directory) / 'foreign.pyc').read_bytes(), b'foreign')
