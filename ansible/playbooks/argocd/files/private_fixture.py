"""Publish only a synthetic fixture to the explicitly designated private test repo."""
import base64
import json
from pathlib import Path

try:
    from .github_setup import inputs, inspect, repository
except ImportError:
    from github_setup import inputs, inspect, repository


def prepare(api, values):
    repo = repository(values.get('PRIVATE_TEST_REPOSITORY'))
    if inspect(api, 'private-fixture', repo, True) is None:
        raise RuntimeError('Designated private fixture repository is missing')
    path = 'repos/' + repo + '/contents/gitops/configmap.yaml'
    expected = (Path(__file__).resolve().parents[4] / 'gitops/fixtures/private/configmap.yaml').read_bytes()
    current = api.request('GET', path, missing=True)
    if current:
        if base64.b64decode(current.get('content', '')) != expected:
            raise RuntimeError('Existing private fixture differs; overwrite refused')
        return {'fixture_published': False, 'unchanged': True}
    api.request('PUT', path, {'message': 'Add isolated GitOps verification fixture',
                            'content': base64.b64encode(expected).decode()})
    return {'fixture_published': True}


def prepare_service(api, values, definition):
    """Create only one validated synthetic values file in the designated fixture repo."""
    import yaml
    from playbooks.services.files.contract import validate
    definition = validate(definition)
    if not definition['name'].startswith('fixture-'):
        raise ValueError('Service fixture requires its explicit disposable name')
    repo = repository(values.get('PRIVATE_TEST_REPOSITORY'))
    if inspect(api, 'private-fixture', repo, True) is None:
        raise RuntimeError('Designated private service fixture repository is missing')
    filename = 'apps/' + definition['name'] + '.yaml'
    path = 'repos/' + repo + '/contents/' + filename
    expected = yaml.safe_dump(definition, sort_keys=True).encode()
    current = api.request('GET', path, missing=True)
    if current:
        if base64.b64decode(current.get('content', '')) != expected:
            raise RuntimeError('Existing service fixture differs; overwrite refused')
    else:
        api.request('PUT', path, {'message': 'Add scoped disposable service definition',
                                 'content': base64.b64encode(expected).decode(), 'branch': 'main'})
    revision = api.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
    return {'fixture_published': current is None, 'revision': revision, 'values_path': filename}


if __name__ == '__main__':
    try:
        values, api = inputs()
        print(json.dumps(prepare(api, values)))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Private fixture preparation failed; diagnostics withheld') from None
