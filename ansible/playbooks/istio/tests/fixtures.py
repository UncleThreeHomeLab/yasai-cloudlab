"""Credential-free native mesh declarations and native file dispatch."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

COMPONENT = Path(__file__).resolve().parents[1]


def run_native(tasks, values):
    """Use the production native file interface against disposable local files."""
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        output = root / 'accepted.json'
        values = dict(values, ansible_python_interpreter=sys.executable, fixture_output_path=str(output))
        path = root / 'play.yml'
        path.write_text(yaml.safe_dump([{'hosts': 'localhost', 'connection': 'local',
            'gather_facts': False, 'tasks': tasks}], sort_keys=False))
        inputs = root / 'inputs.json'
        inputs.write_text(json.dumps(values))
        inputs.chmod(0o600)
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '--extra-vars', '@' + str(inputs), str(path)],
            capture_output=True, text=True, timeout=90,
            env=dict(os.environ, ANSIBLE_CONFIG=str(COMPONENT.parent / 'host/files/ansible.cfg')))
        return result, json.loads(output.read_text()) if output.exists() else None


def retained():
    owner = yaml.safe_load((COMPONENT / 'native.yml').read_text())[0]['vars']['mesh_native_owner']
    crds, components = {'gateways.gateway.networking.k8s.io': 'retained-crd'}, {'Deployment.apps/istio-system/istiod': 'retained-component'}
    ca = {'uid': 'retained-ca', 'content': 'c' * 64}
    return {'mesh_native_owner': owner, 'mesh_native_zone': 'example.invalid',
        'mesh_native_crd_ids': crds, 'mesh_native_component_ids': components, 'mesh_native_ca': ca,
        'mesh_native_source': {'repository': 'https://github.com/fixture/platform.git', 'branch': 'main', 'revision': 'a'*40},
        'mesh_native_checkpoint': {'stat': {'exists': True}},
        'mesh_native_state': {'phase': 'accepted', 'application_uid': 'retained-application',
            'zone_hash': hashlib.sha256(b'example.invalid').hexdigest(), 'gateway_api': copy.deepcopy(crds),
            'components': copy.deepcopy(components), 'workload_ca': copy.deepcopy(ca)},
        'mesh_native_current': {'metadata': {'uid': 'retained-application', 'labels': {'cloudlab.io/owner': owner}},
            'spec': {'project': 'cloudlab-gateways', 'destination': {
                'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-gateway-public'},
                'source': {'repoURL': 'https://github.com/fixture/platform.git', 'path': 'platform/connectivity/gateways'}}},
        'mesh_argo_routes': {'public': 'console.example.invalid', 'private': 'cd.internal.example.invalid'}}


def native_application(values=None):
    tasks = [{'ansible.builtin.import_tasks': str(COMPONENT / 'tasks/native-owner-check.yml')},
        {'ansible.builtin.copy': {'content': "{{ lookup('ansible.builtin.template', '" +
            str(COMPONENT / 'templates/application.yml.j2') + "') | from_yaml | to_json }}",
            'dest': '{{ fixture_output_path }}', 'mode': '0600'}}]
    return run_native(tasks, values or retained())
