"""Public, unreachable inputs for native CI chart checks."""
import json
import subprocess
import sys
import yaml

from playbooks.ci.files.chart import POOL, ROOT
from playbooks.ci.files.qualification import ansible_inputs, profile_fingerprint


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


def qualified_tools():
    return {'images': bootstrap_document()['images'], 'image_revision': 'b' * 40, 'revision': 'c' * 40,
            'nodes_verified': 2, 'max_build_pods': 1, 'workload_api_writes_denied': True,
            'health_access_loss_shutdown_bound_seconds': 90,
            'github_or_signing_credentials_provisioned': False, 'profile_sha256': profile_fingerprint()}


def fixture_repository():
    return {'id': 123, 'html_url': 'https://github.com/example/private-fixture',
            'full_name': 'example/private-fixture', 'private': True, 'fork': False, 'archived': False,
            'default_branch': 'main', 'description': 'Managed by CloudLab repository setup: private-fixture'}


def release_request():
    environment = {'RELEASE_SCOPE': 'private', 'RELEASE_ACTOR': 'release-private[bot]',
                   'GITHUB_REPOSITORY': 'example/gitops', 'RUNNER_ENVIRONMENT': 'github-hosted',
                   'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                   'GITHUB_ACTOR': 'release-private[bot]'}
    event = {'sender': {'login': environment['RELEASE_ACTOR'], 'type': 'Bot'},
             'repository': {'full_name': environment['GITHUB_REPOSITORY'], 'private': True, 'fork': False},
             'inputs': {'digest': 'sha256:' + 'a' * 64, 'source_revision': 'b' * 40, 'workflow_run_id': '123'}}
    return event, environment


def workflow_permissions():
    desired = {'owner': 'example', 'repositories': {
        'public_platform': {'name': 'public-gitops', 'id': 100, 'node_id': 'R_public'},
        'private_config': {'name': 'private-gitops', 'id': 101, 'node_id': 'R_private'}}}
    observed = {key: {'default_workflow_permissions': 'read', 'can_approve_pull_request_reviews': False}
                for key in desired['repositories']}
    return desired, observed


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


def render_root(*, pool=False, private=True):
    values = {'ci': {'enabled': True, 'poolEnabled': pool}}
    if private:
        values['identity'] = {'enabled': True, 'argo': {
            'valuesRepository': 'https://github.com/example/private-config.git', 'valuesRevision': 'b' * 40}}
    result = subprocess.run(['helm', 'template', 'cloudlab-root', str(ROOT / 'gitops/roots/public'),
                             '--namespace', 'argocd', '-f', str(ROOT / 'gitops/roots/public/values.yaml'), '-f', '-'],
                            input=yaml.safe_dump(values), capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise AssertionError(result.stderr)
    return [row for row in yaml.safe_load_all(result.stdout) if row]
