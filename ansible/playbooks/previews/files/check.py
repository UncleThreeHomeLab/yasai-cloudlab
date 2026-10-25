"""Credential-free packaging, immutable templates and ordinary service regression checks."""
import json
from pathlib import Path
import subprocess
import yaml

from playbooks.previews.files.contract import IMAGE, SOURCE_PATH, canonical, digest
from playbooks.previews.files.resources import resources, workload
from playbooks.previews.files.package import check, ROOT


def example():
    definition = {'profile': 'synthetic', 'message': 'synthetic preview'}
    row = {'instance': 'a' * 32, 'repository': 'example/platform', 'repositoryId': 123, 'pullRequest': 7,
        'sourceSha': 'b' * 40, 'sourcePath': SOURCE_PATH, 'sourceDigest': digest(canonical(definition)),
        'definition': definition, 'image': IMAGE, 'platformRevision': 'c' * 40, 'createdAt': 1000, 'expiresAt': 2000}
    return {'hostname': 'preview.internal.example.invalid', 'issuer': 'https://login.example.invalid/realms/applications',
        'privateDiscovery': False, 'approvals': [row], 'artifacts': {},
        'ownership': {'cloudlab-preview-' + row['instance']: row['instance'] + ':' + digest(canonical(row))}}


def render(values):
    result = subprocess.run(['helm', 'template', 'previews', str(ROOT / 'platform/delivery/previews'), '-n', 'argocd', '-f', '-'],
        input=json.dumps(values), capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError('Preview chart render failed')
    return [obj for obj in yaml.safe_load_all(result.stdout) if obj]


def run():
    check()
    if render({}):
        raise ValueError('Optional previews must remain disabled by default')
    settings = example()
    staged = render({'enabled': True, 'catalog': settings})
    objects = render({'enabled': True, 'permissionsEnabled': True, 'catalog': settings})
    if len([o for o in objects if o['kind'] == 'ValidatingAdmissionPolicy']) != 3:
        raise ValueError('Preview ownership admission inventory differs')
    for obj in objects:
        if obj['kind'] == 'ValidatingAdmissionPolicy':
            authorization = [row['expression'] for row in obj['spec']['variables'] if row['name'] == 'authorization']
            if 'paramKind' in obj['spec'] or len(authorization) != 1 or json.loads(authorization[0]) != settings['ownership']:
                raise ValueError('Preview admission must embed exact administrator authorization')
        if obj['kind'] == 'ValidatingAdmissionPolicyBinding' and 'paramRef' in obj['spec']:
            raise ValueError('Preview admission cannot depend on parameter discovery')
    cron = next(o for o in staged if o['kind'] == 'CronJob')
    if cron['spec']['suspend'] is not True or next(o for o in staged if o['kind'] == 'ClusterRole' and o['metadata']['name'] == 'cloudlab-previews')['rules']:
        raise ValueError('Preview controller privileges precede native admission qualification')
    inventory = next(o for o in objects if o['kind'] == 'ClusterRole' and o['metadata']['name'] == 'cloudlab-preview-inventory')
    if inventory['rules'][0] != {'apiGroups': ['*'], 'resources': ['*'], 'verbs': ['list']}:
        raise ValueError('Preview collection inventory must remain namespaced LIST-only')
    from playbooks.services.files.contract import render as service_render
    service = service_render(workload(settings['approvals'][0], settings))
    account = next(o for o in service if o['kind'] == 'ServiceAccount')
    if account['automountServiceAccountToken'] is not False or any(o['kind'] == 'PersistentVolumeClaim' for o in service):
        raise ValueError('Preview workload credential or storage boundary differs')
    plain = service_render(yaml.safe_load((ROOT / 'apps/synthetic.yaml').read_text()))
    if any('istio.io/ingress-use-waypoint' in o.get('metadata', {}).get('labels', {}) for o in plain):
        raise ValueError('Ordinary service routing changed')
    return {'runtime_packaged': True, 'admission_policies': 3, 'ordinary_service_routing_retained': True,
            'native_admission_verification_required': True}


if __name__ == '__main__':
    print(json.dumps(run(), sort_keys=True))
