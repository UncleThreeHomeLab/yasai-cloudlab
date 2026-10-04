"""Publish only a synthetic fixture to the explicitly designated private test repo."""
import base64
import json
from pathlib import Path

from github_setup import inputs, inspect, repository


def prepare(api, values):
    repo = repository(values.get('PRIVATE_TEST_REPOSITORY'))
    if inspect(api, 'private-fixture', repo, True) is None:
        raise RuntimeError('Designated private fixture repository is missing')
    path = 'repos/' + repo + '/contents/gitops/configmap.yaml'
    expected = (Path(__file__).resolve().parents[2] / 'gitops/fixtures/private/configmap.yaml').read_bytes()
    current = api.request('GET', path, missing=True)
    if current:
        if base64.b64decode(current.get('content', '')) != expected:
            raise RuntimeError('Existing private fixture differs; overwrite refused')
        return {'fixture_published': False, 'unchanged': True}
    api.request('PUT', path, {'message': 'Add isolated GitOps verification fixture',
                            'content': base64.b64encode(expected).decode()})
    return {'fixture_published': True}


if __name__ == '__main__':
    try:
        values, api = inputs()
        print(json.dumps(prepare(api, values)))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Private fixture preparation failed; diagnostics withheld') from None
