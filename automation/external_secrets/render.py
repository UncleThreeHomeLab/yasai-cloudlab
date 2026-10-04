"""Render the vendored ESO release; no network or Helm needed during apply."""

import hashlib
import json
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parent
IMAGE = re.compile(r'ghcr\.io/external-secrets/external-secrets:v[0-9.]+')


def render():
    lock = json.loads((ROOT / 'release.json').read_text())
    upstream = (ROOT / 'upstream.yaml').read_bytes()
    if hashlib.sha256(upstream).hexdigest() != lock['sha256']:
        raise ValueError('ESO upstream manifest checksum mismatch')
    source = upstream.decode()
    if set(IMAGE.findall(source)) != set(lock['images']):
        raise ValueError('ESO image lock does not match the manifest')
    for digest in lock['images'].values():
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('Invalid ESO image digest')
    source = IMAGE.sub(lambda match: match[0] + '@' + lock['images'][match[0]], source)
    documents = [item for item in yaml.safe_load_all(source) if item]
    return {
        'namespace': [dict(apiVersion='v1', kind='Namespace', metadata=dict(name='external-secrets'))],
        'crds': [item for item in documents if item['kind'] == 'CustomResourceDefinition'],
        'system': [item for item in documents if item['kind'] != 'CustomResourceDefinition'],
    }


if __name__ == '__main__':
    print(json.dumps(dict(apiVersion='v1', kind='List', items=render()[sys.argv[1]])))
