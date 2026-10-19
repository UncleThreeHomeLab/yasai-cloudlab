"""Public, unreachable inputs for native CI chart checks."""
import json
import subprocess
import sys

from playbooks.ci.files.chart import POOL
from playbooks.ci.files.qualification import ansible_inputs


def pool_values():
    values = json.loads((POOL / 'values.json').read_text())
    values['arc']['githubConfigUrl'] = 'https://github.com/example/private-fixture'
    spec = values['arc']['template']['spec']
    for kind, containers in (('runner', spec['containers']), ('builder', spec['initContainers'])):
        containers[0]['image'] = 'registry.example.invalid/cloudlab-public/ci-' + kind + '@sha256:' + 'a' * 64
    values['eligibility'] = [{
        'repository_id': '123', 'repository': 'example/private-fixture',
        'workflow_ref': 'example/private-fixture/.github/workflows/publish.yaml@refs/heads/main',
        'workflow_sha': 'b' * 40, 'sha': 'b' * 40, 'ref': 'refs/heads/main',
        'event_name': 'workflow_dispatch', 'job': 'publish'}]
    return values


def bootstrap_document():
    return {'revision': 'b' * 40, 'images': {
        kind: 'harbor.internal.example.invalid/cloudlab-public/ci-' + kind + '@sha256:' + 'a' * 64
        for kind in ('controller', 'runner', 'builder')}}


def render_resources(directory, configuration):
    output = directory / 'resources.json'
    playbook = directory / 'render.json'
    playbook.write_text(json.dumps([{'name': 'Render qualification without credentials', 'hosts': 'localhost',
        'gather_facts': False, 'vars': {'ansible_python_interpreter': sys.executable, 'ci_fixture': ansible_inputs(configuration)},
        'tasks': [{'name': 'Preserve controller templates', 'ansible.builtin.copy': {
            'content': '{{ ci_fixture.resources_b64 | b64decode }}', 'dest': str(output), 'mode': '0600'}}]}]))
    result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return json.loads(output.read_text())
