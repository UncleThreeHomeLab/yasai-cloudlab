"""Synthetic policy inputs; no service credentials or cluster access."""
import copy
import json

from playbooks.ci.files.chart import POOL, render


def runner():
    values = json.loads((POOL / 'values.json').read_text())
    values['arc']['githubConfigUrl'] = 'https://github.com/example/fixture'
    values['eligibility'] = [{'repository_id': '1', 'repository': 'example/fixture',
        'workflow_ref': 'example/fixture/.github/workflows/ci.yaml@refs/heads/main',
        'workflow_sha': 'a' * 40, 'sha': 'a' * 40, 'ref': 'refs/heads/main',
        'event_name': 'push', 'job': 'test'}]
    for kind, field in (('runner', 'containers'), ('builder', 'initContainers')):
        values['arc']['template']['spec'][field][0]['image'] = (
            'registry.example.invalid/cloudlab-public/ci-' + kind + '@sha256:' + 'a' * 64)
    objects = render(values, chart=POOL)
    profile = next(row for row in objects if row['kind'] == 'ConfigMap' and
                   row['metadata']['name'] == 'cloudlab-ci-eligibility')
    document = {'apiVersion': 'v1', 'kind': 'Pod',
                'metadata': {'name': 'accepted', 'namespace': 'cloudlab-ci-private'},
                'spec': copy.deepcopy(json.loads(profile['data']['admission.json'])['spec'])}
    document['spec']['containers'][0]['env'] += [
        {'name': 'ACTIONS_RUNNER_INPUT_JITCONFIG', 'valueFrom': {
            'secretKeyRef': {'name': 'accepted', 'key': 'jitToken'}}},
        {'name': 'GITHUB_ACTIONS_RUNNER_EXTRA_USER_AGENT', 'value': 'actions-runner-controller/0.15.0'},
        {'name': 'ACTIONS_RUNNER_RETURN_VERSION_DEPRECATED_EXIT_CODE', 'value': '1'}]
    return document, profile


def pod(name='accepted'):
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': 'cloudlab-app-proof'},
            'spec': {'automountServiceAccountToken': False, 'containers': [{
                'name': 'app', 'image': 'example.invalid/public/app@sha256:' + 'a' * 64,
                'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                              'limits': {'cpu': '100m', 'memory': '64Mi'}}}]}}
