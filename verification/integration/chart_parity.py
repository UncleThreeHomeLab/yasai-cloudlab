"""Check active chart semantics against the reviewed migration baseline.

Legacy renderers are retired. Artifact/image validation remains with each module;
this contract detects any semantic change that needs review and a new live proof.
"""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULES = [('secrets/external-secrets', 'external_secrets'), ('storage/longhorn', 'longhorn')]


def identity(item):
    return (item['apiVersion'], item['kind'],
            item['metadata'].get('namespace', ''), item['metadata']['name'])


def index(items):
    result = {}
    for item in items:
        key = identity(item)
        if key in result:
            raise ValueError(f'Duplicate object: {key}')
        result[key] = item
    return result


def normalize(item, module):
    item = copy.deepcopy(item)
    if module in ('external_secrets', 'longhorn') and item['kind'] == 'CustomResourceDefinition':
        annotations = item['metadata'].get('annotations', {})
        option = annotations.pop('argocd.argoproj.io/sync-options', None)
        if option not in (None, 'ServerSideApply=true,Prune=false,Delete=false'):
            raise ValueError('Unreviewed CRD ownership options')
    if module == 'longhorn':
        # These two labels do not participate in existing selectors.
        for metadata in (item['metadata'], item.get('spec', {}).get('template', {}).get('metadata', {})):
            labels = metadata.get('labels', {})
            for key, expected in [('app.kubernetes.io/managed-by', 'Helm'), ('helm.sh/chart', 'longhorn-1.13.0')]:
                if key in labels:
                    if labels[key] != expected:
                        raise ValueError(f'Unexpected packaging label: {key}')
                    del labels[key]
    if item['kind'] == 'ConfigMap' and item['metadata']['name'] in ('longhorn-default-setting', 'longhorn-storageclass'):
        for key, value in item['data'].items():
            parsed = yaml.safe_load(value) or {}
            if key == 'default-setting.yaml':
                parsed = {k: str(v).lower() if isinstance(v, bool) else v for k, v in parsed.items()}
            item['data'][key] = parsed
    return item


def differences(a, b, path=''):
    if a == b:
        return []
    if isinstance(a, dict) and isinstance(b, dict):
        return [p for key in sorted(a.keys() | b.keys())
                for p in differences(a.get(key), b.get(key), path + '/' + key)]
    return [path]


def container_images(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ('containers', 'initContainers', 'ephemeralContainers'):
                for container in child:
                    yield container['image']
            else:
                yield from container_images(child)
    elif isinstance(value, list):
        for child in value:
            yield from container_images(child)


def semantic_digest(objects, module):
    actual = index([normalize(obj, module) for obj in objects])
    canonical = json.dumps([actual[key] for key in sorted(actual)], sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify(module, owner):
    folder = ROOT / 'platform' / module
    lock = json.loads((folder / 'artifact.lock.json').read_text())
    subprocess.run(['helm', 'lint', str(folder), '--strict', '--kube-version', lock['kube_version'],
                    '-f', str(folder / 'values.json')], check=True, capture_output=True, timeout=90)
    # Each module verifies its archive, vendor patch, all images, hooks and identity
    # boundaries before returning the same declarations used for bootstrap.
    payload = json.loads(subprocess.check_output(
        [sys.executable, str(ROOT / 'automation' / owner / 'chart.py')], timeout=180))
    objects = payload['items'] + payload.get('generated', [])
    digest = semantic_digest(objects, owner)
    if digest != lock['semantic_sha256']:
        raise ValueError(module + ': reviewed chart semantics changed; review the diff and rerun full proof')
    if owner == 'longhorn':
        source = (folder / 'storageclass.yaml').read_text()
        config = next(obj for obj in objects if obj['kind'] == 'ConfigMap'
                      and obj['metadata']['name'] == 'longhorn-storageclass')
        if config['data']['storageclass.yaml'] != source:
            raise ValueError('StorageClass generator bytes changed; its controller could replace the object')
        policy = json.loads((folder / 'policy.json').read_text())
        settings = {obj['metadata']['name']: obj['value'] for obj in objects if obj['kind'] == 'Setting'}
        if settings != policy['settings'] or yaml.safe_load(source)['metadata']['name'] != policy['storage_class']:
            raise ValueError('Chart and verification storage policies differ')
    return dict(module=module, objects=len(objects), semantic_sha256=digest,
                reviewed_semantics_preserved=True, resources_applied=False)


if __name__ == '__main__':
    print(json.dumps([verify(*module) for module in MODULES], indent=2))
