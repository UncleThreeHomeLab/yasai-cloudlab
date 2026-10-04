"""Compare backup declarations with their existing templates using fake inputs."""
import json
from jinja2 import Environment, StrictUndefined
import yaml
from backup_chart import REPOSITORY, render
from backup_policy import load_policy


def verify():
    policy = load_policy()
    values = {'store': 'cloudlab', 'bucket': 'parity-fixture', 'region': 'fixture-region'}
    environment = Environment(undefined=StrictUndefined)
    environment.filters['to_json'] = json.dumps
    inputs = {'longhorn_backup_policy': policy, 'external_secrets_store': values['store'],
              'longhorn_backup_secret_name': policy['secret_name'], 'longhorn_backup_bucket': values['bucket'],
              'longhorn_backup_region': values['region']}
    expected = []
    for name in ('resources.yml.j2', 'external-secret.yml.j2'):
        source = (REPOSITORY / 'ansible/roles/longhorn_backup/templates' / name).read_text()
        expected.extend(obj for obj in yaml.safe_load_all(environment.from_string(source).render(**inputs)) if obj)
    actual = render(values)[0]
    canonical = lambda objects: sorted(json.dumps(obj, sort_keys=True) for obj in objects)
    if canonical(actual) != canonical(expected):
        raise ValueError('Backup chart differs from existing declaration semantics')
    if render({'store': values['store']}, True)[0] != [next(obj for obj in actual if obj['kind'] == 'ExternalSecret')]:
        raise ValueError('Credential-only seed differs from the final Argo declaration')
    print(json.dumps({'backup_chart_parity': True, 'objects': len(actual), 'real_private_inputs_used': False}))


if __name__ == '__main__':
    verify()
