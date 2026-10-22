"""Credential-free native certificate ownership and template fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

COMPONENT = Path(__file__).resolve().parents[1]


def native_application(*, state=None, current=None, receipt=True, production=True):
    if state is None:
        state = {'phase': 'accepted', 'zone_hash': hashlib.sha256(b'example.invalid').hexdigest(),
            'application_uid': 'retained-application',
            'staging': {'certificate_uid': 'retained-staging', 'secret_uid': 'retained-staging-secret'}}
    if current is None:
        current = {'metadata': {'uid': 'retained-application', 'labels': {'cloudlab.io/owner': 'cloudlab-certificates-bootstrap'}},
            'spec': {'project': 'cloudlab-certificates', 'destination': {
                'server': 'https://kubernetes.default.svc', 'namespace': 'cert-manager'},
                'source': {'repoURL': 'https://github.com/fixture/platform.git', 'path': 'platform/certificates/configuration'}}}
    owner = yaml.safe_load((COMPONENT / 'native.yml').read_text())[0]['vars']['certificates_owner']
    values = {'ansible_python_interpreter': sys.executable, 'certificates_owner': owner,
        'certificates_state': state, 'certificates_current': current,
        'certificates_checkpoint': {'stat': {'exists': receipt}}, 'certificates_zone': 'example.invalid',
        'certificates_source': {'repository': 'https://github.com/fixture/platform.git', 'branch': 'main', 'revision': 'a'*40},
        'certificates_production': production}
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        output = root / 'application.json'
        tasks = [{'ansible.builtin.import_tasks': str(COMPONENT / 'tasks/native-owner-check.yml')},
            {'ansible.builtin.copy': {'content': "{{ lookup('ansible.builtin.template', '" +
                str(COMPONENT / 'templates/application.yml.j2') + "') | from_yaml | to_json }}",
                'dest': str(output), 'mode': '0600'}}]
        path = root / 'play.yml'
        path.write_text(yaml.safe_dump([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
            'vars': values, 'tasks': tasks}], sort_keys=False))
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, ANSIBLE_CONFIG=str(COMPONENT.parent / 'host/files/ansible.cfg')))
        return result, json.loads(output.read_text()) if output.exists() else None
