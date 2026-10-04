"""Render the checked upstream release with the lab policy and locked images.

Runs in the Compose runner. Normal applies never resolve mutable tags or fetch
manifests. Dependency updates explicitly update release.json and upstream.yaml.
"""

import hashlib
import json
from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parent
IMAGE = re.compile(r'docker\.io/longhornio/[a-z0-9-]+:[a-zA-Z0-9_.-]+')


def render():
    lock = json.loads((ROOT / 'release.json').read_text())
    policy = json.loads((ROOT / 'policy.json').read_text())
    upstream = (ROOT / 'upstream.yaml').read_bytes()
    if hashlib.sha256(upstream).hexdigest() != lock['sha256']:
        raise ValueError('Longhorn upstream manifest checksum mismatch')
    source = upstream.decode()
    if set(IMAGE.findall(source)) != set(lock['images']):
        raise ValueError('Longhorn image lock does not match the upstream manifest')
    for image, digest in lock['images'].items():
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('Invalid image digest')
    source = IMAGE.sub(lambda match: match[0] + '@' + lock['images'][match[0]], source)
    documents = [item for item in yaml.safe_load_all(source) if item]
    storage_class = None
    for item in documents:
        name = item['metadata']['name']
        if item['kind'] == 'Namespace':
            item['metadata'].setdefault('labels', {})['pod-security.kubernetes.io/enforce'] = 'privileged'
        if item['kind'] == 'ConfigMap' and name == 'longhorn-default-setting':
            settings = yaml.safe_load(item['data']['default-setting.yaml'])
            settings.update(policy['settings'])
            item['data']['default-setting.yaml'] = yaml.safe_dump(settings)
        if item['kind'] == 'ConfigMap' and name == 'longhorn-storageclass':
            storage_class = yaml.safe_load(item['data']['storageclass.yaml'])
            storage_class['metadata']['name'] = policy['storage_class']
            # Opt in explicitly. Existing local-path volumes and defaults stay intact.
            storage_class['metadata']['annotations']['storageclass.kubernetes.io/is-default-class'] = 'false'
            storage_class['parameters']['numberOfReplicas'] = '2'
            storage_class['parameters']['dataLocality'] = 'best-effort'
            item['data']['storageclass.yaml'] = yaml.safe_dump(storage_class)
        if item['kind'] == 'Deployment' and name in ('longhorn-ui', 'longhorn-global-manager'):
            item['spec']['replicas'] = 2
    if storage_class is None:
        raise ValueError('Upstream storage class is missing')
    settings = [dict(apiVersion='longhorn.io/v1beta2', kind='Setting',
                     metadata=dict(name=name, namespace='longhorn-system'), value=value)
                for name, value in policy['settings'].items()]
    return {
        'namespace': [item for item in documents if item['kind'] == 'Namespace'],
        'crds': [item for item in documents if item['kind'] == 'CustomResourceDefinition'],
        'system': [item for item in documents if item['kind'] not in ('CustomResourceDefinition', 'Namespace')],
        'policy': settings + [storage_class],
    }


if __name__ == '__main__':
    group = sys.argv[1]
    print(json.dumps(dict(apiVersion='v1', kind='List', items=render()[group])))
