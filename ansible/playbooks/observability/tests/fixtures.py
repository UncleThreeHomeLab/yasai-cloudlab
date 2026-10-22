"""Synthetic independent account and monitor responses."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import yaml

from playbooks.observability.files.uptimerobot import desired


def native_application(component='configuration', *, current=None, monitoring=True):
    """Render the real native declaration only after its ownership guard passes."""
    owner = Path(__file__).resolve().parents[1]
    policy = json.loads((owner.parents[2] / 'platform/observability/policy.json').read_text())
    name = 'cloudlab-observability' if component == 'configuration' else 'cloudlab-' + component
    path = 'platform/observability' + ('' if component == 'configuration' else '/' + component)
    if current is None:
        current = {'metadata': {'uid': 'retained-application', 'labels': {'cloudlab.io/owner': policy['owner']}},
            'spec': {'project': 'cloudlab-observability', 'destination': {
                'server': 'https://kubernetes.default.svc', 'namespace': policy['namespace']},
                'source': {'repoURL': 'https://github.com/fixture/platform.git', 'path': path}}}
    values = {'telemetry_policy': policy, 'telemetry_source': {
            'repository': 'https://github.com/fixture/platform.git', 'revision': 'a' * 40},
        'telemetry_component': component, 'telemetry_current': current,
        'telemetry_application_name': name, 'telemetry_application_path': path,
        'telemetry_monitoring_enabled': monitoring, 'telemetry_template_dir': str(owner / 'templates'),
        'telemetry_login_host': 'login.example.invalid', 'telemetry_gateway': '10.43.0.7',
        'telemetry_grafana_host': 'grafana.internal.example.invalid',
        'telemetry_grafana_origin': 'https://grafana.internal.example.invalid',
        'telemetry_kiali_host': 'kiali.internal.example.invalid',
        'telemetry_api_peers': ['192.0.2.2/32', '192.0.2.1/32'],
        'telemetry_oidc_protocol': 'https://login.example.invalid/realms/platform/protocol/openid-connect',
        'telemetry_logout_query': "{{ {'post_logout_redirect_uri': telemetry_grafana_origin ~ '/login'} | urlencode }}",
        'ansible_python_interpreter': sys.executable}
    with tempfile.TemporaryDirectory() as folder:
        directory = Path(folder)
        output = directory / 'application.json'
        play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False, 'vars': values,
            'tasks': [{'ansible.builtin.import_tasks': str(owner / 'tasks/native-owner-check.yml')},
                {'ansible.builtin.copy': {'content': "{{ lookup('ansible.builtin.template', '" +
                    str(owner / 'templates/application.yml.j2') + "') | from_yaml | to_json }}",
                    'dest': str(output), 'mode': '0600'}}]}]
        play_path = directory / 'play.yml'
        play_path.write_text(yaml.safe_dump(play, sort_keys=False))
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(play_path)],
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, ANSIBLE_CONFIG=str(owner.parent / 'host/files/ansible.cfg')))
        return result, json.loads(output.read_text()) if output.exists() else None


class FakeAPI:
    def __init__(self):
        self.user = {'email': 'operator@example.com', 'monitorLimit': 50,
                     'activeSubscription': {'plan': 'FREE'}}
        self.contacts = [{'id': 7, 'type': 'Email', 'value': 'operator@example.com', 'status': 'Active'}]
        self.rows = []
        self.writes = []
        self.next_link = None
        self.next_id = 12

    def request(self, method, path, value=None):
        if method == 'GET':
            if path == 'user/me': return copy.deepcopy(self.user)
            if path == 'user/alert-contacts': return copy.deepcopy(self.contacts)
            if path == 'monitors?limit=50': return {'data': copy.deepcopy(self.rows), 'nextLink': self.next_link}
            raise AssertionError('Unexpected fixture read')
        self.writes.append((method, path, copy.deepcopy(value)))
        if method == 'POST':
            while any(row.get('id') == self.next_id for row in self.rows): self.next_id += 1
            self.rows.append(dict(value, id=self.next_id, status='STARTED'))
        elif method == 'PATCH':
            identifier = int(path.split('/')[-1])
            next(row for row in self.rows if row['id'] == identifier).update(value)
        elif method == 'DELETE':
            identifier = int(path.split('/')[-1])
            self.rows = [row for row in self.rows if row['id'] != identifier]
        else: raise AssertionError('Unexpected fixture mutation')


def existing(key='notes-health', url='https://notes.example.com/health', **overrides):
    return dict(desired(key, url, 7), id=12, status='UP', **overrides)
