"""The scheduled bridge dispatches native tasks and retains shared recovery exclusion."""
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

from playbooks.data.files import control

COMPONENT = Path(__file__).resolve().parents[1]


class NativeCADispatchTests(unittest.TestCase):
    def test_dispatch_inherits_lock_and_uses_private_ephemeral_ansible_paths(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(control, 'BASE', Path(folder)):
            with control.locked() as owner, patch.object(Path, 'resolve', return_value=Path('/native')):
                def run(command, **arguments):
                    self.assertEqual(command, ['/usr/bin/ansible-playbook', '-i', 'localhost,', '/native'])
                    self.assertEqual(arguments['pass_fds'], (owner.fileno(),))
                    environment = arguments['env']
                    self.assertTrue(Path(environment['ANSIBLE_LOCAL_TEMP']).parent.is_dir())
                    self.assertEqual(environment['ANSIBLE_COLLECTIONS_PATH'], '/native')
                    self.assertTrue(arguments['capture_output'])
                    return subprocess.CompletedProcess(command, 0, stdout='localhost : ok=10 changed=1 failed=0')
                with patch.object(control.subprocess, 'run', side_effect=run):
                    self.assertTrue(control.native_repair(owner, 'ca'))
                with patch.object(control.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, 'private-value', 'private-value')):
                    with self.assertRaisesRegex(RuntimeError, '^Native data repair failed; private diagnostics withheld$'):
                        control.native_repair(owner, 'ca')
            with self.assertRaisesRegex(RuntimeError, 'existing data owner lock'):
                control.native_repair(owner, 'ca')
            with self.assertRaisesRegex(ValueError, 'Unknown native data repair stage'):
                control.native_repair(owner, 'unapproved')

    def test_child_keeps_exclusion_after_parent_closes_its_descriptor(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(control, 'BASE', Path(folder)):
            owner = control.locked()
            read_fd, write_fd = os.pipe()
            child = subprocess.Popen(['/bin/cat'], stdin=read_fd, stdout=subprocess.DEVNULL,
                                     pass_fds=(owner.fileno(),))
            os.close(read_fd)
            owner.close()
            try:
                with self.assertRaisesRegex(RuntimeError, 'holds the owner lock'):
                    control.locked()
            finally:
                os.close(write_fd)
                child.wait(timeout=5)
            with control.locked():
                pass

    def test_failed_native_sql_prevents_later_credential_or_bucket_mutations(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(control, 'BASE', Path(folder)), \
                patch.object(control, 'settings', return_value={'maintenance': False}), \
                patch.object(control, 'native_repair', side_effect=RuntimeError('native SQL refused')), \
                patch.object(control, 'reload_s3') as reload, patch.object(control, 's3') as client:
            with control.locked() as owner, self.assertRaisesRegex(RuntimeError, 'native SQL refused'):
                control.reconcile(owner)
            reload.assert_not_called()
            client.assert_not_called()

    def test_native_create_is_bounded_and_never_upserts(self):
        tasks = yaml.safe_load((COMPONENT / 'tasks/ca-write.yml').read_text())
        command = tasks[0]['ansible.builtin.command']['argv']
        self.assertIn('create', command)
        self.assertIn('--request-timeout=30s', command)
        self.assertNotIn('apply', command)

    def test_checked_collection_hides_dotted_private_key_fields(self):
        with patch.object(sys, 'path', ['/usr/share/ansible/collections', *sys.path]):
            from ansible_collections.kubernetes.core.plugins.module_utils.k8s.service import hide_fields
        tasks = yaml.safe_load((COMPONENT / 'tasks/ca-source.yml').read_text())
        secret = next(task['kubernetes.core.k8s_info'] for task in tasks
                      if task.get('kubernetes.core.k8s_info', {}).get('kind') == 'Secret')
        self.assertEqual(hide_fields({'data': {'ca.crt': 'public', 'ca.key': 'private', 'tls.key': 'private'}},
                                     secret['hidden_fields']), {'data': {'ca.crt': 'public'}})

    def test_handoff_qualifies_before_switch_and_refuses_unknown_executables(self):
        for fail_qualification, unknown_dispatch in ((False, False), (True, False), (False, True)):
            with self.subTest(fail_qualification=fail_qualification, unknown_dispatch=unknown_dispatch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                runtime = root / 'runtime'
                stage = runtime / 'ca' / ('a'*40)
                (stage / 'files').mkdir(parents=True)
                (runtime / 'files').mkdir()
                for name in ('control.py', 'rotation.py', 'verify.py', 'requests.py', 'service_proof.py'):
                    source = (COMPONENT / 'files' / name).read_bytes()
                    (stage / 'files' / name).write_bytes(source)
                    (runtime / 'files' / name).write_bytes(source)
                    (runtime / 'files' / name).chmod(0o600)
                if unknown_dispatch:
                    (runtime / 'files/control.py').write_text('unrecognized owner')
                before = (runtime / 'files/control.py').read_bytes()
                (root / 'policy').mkdir()
                (stage / 'contract.json').write_bytes((COMPONENT.parents[2] / 'platform/data/contract.json').read_bytes())
                text = (COMPONENT / 'native-install.yml').read_text().replace('/opt/cloudlab/playbooks/data', str(runtime))
                text = text.replace('/opt/cloudlab/platform/data', str(root / 'policy'))
                (stage / 'install.yml').write_text(text)
                qualify = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False, 'tasks': [
                    {'ansible.builtin.assert': {'that': json.dumps(not fail_qualification)}}]}]
                (stage / 'native-ca.yml').write_text(yaml.safe_dump(qualify))
                (stage / 'native-sql.yml').write_text(yaml.safe_dump(qualify))
                result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(stage / 'install.yml'),
                    '-e', 'ansible_python_interpreter=' + sys.executable],
                    capture_output=True, text=True, timeout=60)
                failed = fail_qualification or unknown_dispatch
                self.assertEqual(result.returncode == 0, not failed, result.stdout + result.stderr)
                self.assertEqual((runtime / 'ca/current').is_symlink(), not failed)
                self.assertEqual((runtime / 'files/control.py').read_bytes(), before)
