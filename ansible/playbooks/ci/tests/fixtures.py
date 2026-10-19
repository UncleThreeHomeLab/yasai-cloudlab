"""Public, unreachable inputs for native CI chart checks."""
import json

from playbooks.ci.files.chart import POOL


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
