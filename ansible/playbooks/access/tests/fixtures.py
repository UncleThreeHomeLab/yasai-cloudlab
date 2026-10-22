"""In-memory provider for access reconciliation and identity tests."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import yaml


def native_application(*, current=None, state=None, receipt=True):
    """Run native ownership checks before rendering the actual access template."""
    component = Path(__file__).resolve().parents[1]
    if current is None:
        current = {'metadata': {'uid': 'retained-access', 'labels': {'cloudlab.io/owner': 'cloudlab-access-bootstrap'}},
            'spec': {'project': 'cloudlab-access', 'destination': {
                'server': 'https://kubernetes.default.svc', 'namespace': 'tailscale'},
                'source': {'repoURL': 'https://github.com/fixture/platform.git', 'path': 'platform/connectivity/access'}}}
    if state is None:
        state = {'phase': 'configured', 'administrator': hashlib.sha256(b'admin@example.invalid').hexdigest(),
                 'application_uid': 'retained-access'}
    values = {'ansible_python_interpreter': sys.executable,
        'access_state_file': {'stat': {'exists': receipt}}, 'access_native_state': state,
        'access_administrator': 'admin@example.invalid', 'access_native_current': current,
        'access_native_source': {'repository': 'https://github.com/fixture/platform.git',
                                 'branch': 'main', 'revision': 'a' * 40}}
    with tempfile.TemporaryDirectory() as folder:
        directory = Path(folder)
        output = directory / 'application.json'
        play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False, 'vars': values,
            'tasks': [{'ansible.builtin.import_tasks': str(component / 'tasks/native-owner-check.yml')},
                {'ansible.builtin.copy': {'content': "{{ lookup('ansible.builtin.template', '" +
                    str(component / 'templates/access-application.yml.j2') + "') | from_yaml | to_json }}",
                    'dest': str(output), 'mode': '0600'}}]}]
        play_path = directory / 'play.yml'
        play_path.write_text(yaml.safe_dump(play, sort_keys=False))
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(play_path)],
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, ANSIBLE_CONFIG=str(component.parent / 'host/files/ansible.cfg')))
        return result, json.loads(output.read_text()) if output.exists() else None


class Provider:
    def __init__(self):
        self.objects = {}
        self.config = {'config': {'ingress': [{'service': 'http_status:404'}]}}
        self.writes = []
        self.interrupt_create = False

    def collection(self, path):
        return [copy.deepcopy(v) for k, v in self.objects.items() if k.rsplit('/', 1)[0] == path]

    def request(self, method, path, document=None):
        if method != 'GET':
            self.writes.append((method, path))
        if path.endswith('/configurations'):
            if method == 'PUT':
                self.config = copy.deepcopy(document)
            return copy.deepcopy(self.config)
        if method == 'POST':
            identity = str(len(self.objects) + 1)
            value = dict(copy.deepcopy(document), id=identity)
            if path.endswith('/apps'):
                value['aud'] = 'fixture-audience'
            self.objects[path + '/' + identity] = value
            if self.interrupt_create:
                self.interrupt_create = False
                raise RuntimeError('connection lost after server committed creation')
            return copy.deepcopy(value)
        if method == 'PUT':
            self.objects[path].update(copy.deepcopy(document))
        return copy.deepcopy(self.objects[path])
