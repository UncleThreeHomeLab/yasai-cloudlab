"""Load the native runner values and render fixtures through Ansible itself."""
import json
import os
from pathlib import Path
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / 'ansible/playbooks/buildkit'
VALUES = ROOT / 'platform/delivery/ci/runner.values.yaml'


def values():
    return yaml.safe_load(VALUES.read_text())


def render(directory):
    configuration = values()
    variables = {'ansible_python_interpreter': sys.executable,
                 'buildkit_namespace': 'cloudlab-buildkit-proof-test',
                 'buildkit_values': configuration,
                 'buildkit_container': next(row for row in configuration['template']['spec']['containers']
                                            if row['name'] == 'builder'),
                 'buildkit_node': {'metadata': {'name': 'node-a'}}}
    play = [{'name': 'Render native rootless proof inputs', 'hosts': 'localhost', 'gather_facts': False,
             'vars': variables, 'tasks': [{'name': 'Render the bounded fixture', 'ansible.builtin.copy': {
                 'content': "{{ lookup('template', '" + str(BASE / 'templates') + "/' + item + '.json.j2') }}",
                 'dest': str(directory) + '/{{ item }}.json', 'mode': '0600'},
                 'loop': ['namespace', 'resources', 'job']}]}]
    path = directory / 'play.json'
    path.write_text(json.dumps(play))
    result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(path)],
                            capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return {name: json.loads((directory / (name + '.json')).read_text()) for name in ('namespace', 'resources', 'job')}


def prove(directory, **scenario):
    state = directory / 'state.json'
    state.write_text(json.dumps({'calls': [], 'build_nodes': [], **scenario}))
    inventory = directory / 'inventory.json'
    inventory.write_text(json.dumps({'all': {'children': {'k3s_cluster': {'children': {
        'k3s_servers': {'hosts': {'localhost': {'ansible_connection': 'local',
                                             'ansible_python_interpreter': sys.executable}}}}}}}}))
    result = subprocess.run(['ansible-playbook', '-i', str(inventory), str(BASE / 'verify.yml'),
                             '--start-at-task', 'Read the existing Linux nodes'],
                            env=dict(os.environ, BUILDKIT_TEST_STATE=str(state)),
                            capture_output=True, text=True, timeout=120)
    return result, json.loads(state.read_text())
