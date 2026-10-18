"""Run the real host tasks with a bounded fake sysctl, never change runner limits."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(Path('/.dockerenv').exists(), 'Native fixture requires the Compose runner')
class HostKernelTests(unittest.TestCase):
    def test_apply_repeats_and_repairs_drift_without_touching_unmanaged_settings(self):
        configuration = Path('/etc/sysctl.d/90-cloudlab.conf')
        self.assertFalse(configuration.exists(), 'Refuse to overwrite an existing runner configuration')
        if not configuration.parent.exists():
            configuration.parent.mkdir()
            self.addCleanup(configuration.parent.rmdir)
        self.addCleanup(configuration.unlink, missing_ok=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'state.json'
            initial = {'net.ipv4.ip_forward': 0, 'fs.inotify.max_user_instances': 128,
                       'fs.inotify.max_user_watches': 253014}
            state.write_text(json.dumps(initial))
            executable = root / 'sysctl'
            executable.write_text('#!' + sys.executable + '\n' + '''import json,os,sys
from pathlib import Path
state=Path(os.environ['MOCK_SYSCTL_STATE'])
values=json.loads(state.read_text())
action,key=sys.argv[1:]
if action=='-n':
 print(values[key])
elif action=='-w':
 key,value=key.split('=')
 assert key in ('net.ipv4.ip_forward','fs.inotify.max_user_instances')
 values[key]=int(value)
 state.write_text(json.dumps(values))
 print(key+' = '+value)
else:raise SystemExit(2)
''')
            executable.chmod(0o700)
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps({'all': {'hosts': {'fixture': {
                'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable}}}}))
            playbook = root / 'playbook.json'
            playbook.write_text(json.dumps([{'name': 'Exercise host kernel tasks', 'hosts': 'all',
                'gather_facts': False,
                'vars_files': ['/workspace/ansible/group_vars/all/host.yml'],
                'environment': {'PATH': str(root) + ':' + os.environ['PATH'],
                                'MOCK_SYSCTL_STATE': str(state)},
                'tasks': [{'ansible.builtin.import_tasks':
                           '/workspace/ansible/playbooks/host/tasks/sysctl.yml'}]}]))

            def apply():
                result = subprocess.run(['ansible-playbook', '-i', str(inventory), str(playbook)],
                                        capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result.stdout

            self.assertRegex(apply(), r'changed=2\s+')
            expected = dict(initial, **{'net.ipv4.ip_forward': 1, 'fs.inotify.max_user_instances': 1024})
            self.assertEqual(json.loads(state.read_text()), expected)
            persisted = configuration.read_bytes()
            self.assertIn(b'fs.inotify.max_user_instances = 1024\n', persisted)
            self.assertRegex(apply(), r'changed=0\s+')
            self.assertEqual(configuration.read_bytes(), persisted)
            state.write_text(json.dumps(dict(expected, **{'fs.inotify.max_user_instances': 128})))
            self.assertRegex(apply(), r'changed=1\s+')
            self.assertEqual(json.loads(state.read_text()), expected)
