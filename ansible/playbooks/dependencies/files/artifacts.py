"""Maintain the two fixed raw network artifacts without changing ownership policy."""
import json
import base64
from pathlib import Path
import re

import yaml

from .inputs import baseline
from .security import archive_files, digest, download, owned_path
from .tools import write_json

OWNERS = {'connectivity/gateway-api': ('kubernetes-sigs/gateway-api', 'standard-install.yaml'),
          'connectivity/private-dns': ('coredns/coredns', 'coredns_{version}_linux_amd64.tgz')}


def update(root, name, version, *, fetch=download):
    if name not in OWNERS or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Unsupported raw artifact or release')
    relative = 'platform/' + name + '/artifact.lock.json'
    target = owned_path(root, relative)
    lock = json.loads(target.read_bytes())
    original = json.loads(baseline(root, relative))
    if version.split('.')[:2] != original['version'].split('.')[:2]:
        raise ValueError('Raw network artifact minor changes require compatibility review')
    repository, asset = OWNERS[name]
    prefix = 'https://github.com/' + repository + '/releases/download/'
    url = prefix + 'v' + version + '/' + asset.format(version=version)
    raw = fetch(url, prefix=prefix)
    if name == 'connectivity/gateway-api':
        objects = [row for row in yaml.safe_load_all(raw) if row]
        crds = [row for row in objects if row.get('kind') == 'CustomResourceDefinition']
        policies = [row for row in objects if row.get('kind') != 'CustomResourceDefinition']
        if (len(objects) != 12 or len(crds) != 10 or
                any(row.get('spec', {}).get('group') != 'gateway.networking.k8s.io' for row in crds) or
                {row.get('kind') for row in policies} != {'ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding'} or
                any(row.get('metadata', {}).get('name') != 'safe-upgrades.gateway.networking.k8s.io' for row in policies)):
            raise ValueError('Gateway API artifact contains unexpected resources')
        owned_path(root, 'platform/' + name + '/upstream.yaml').write_bytes(raw)
    elif 'coredns' not in archive_files(raw):
        raise ValueError('CoreDNS archive lacks its expected executable')
    lock.update(version=version, url=url, sha256=digest(raw))
    write_json(target, lock)
    return {'owner': 'chart:' + name, 'status': 'pending-verification', 'artifactChecksumUpdated': True}


def provenance(root, plan, *, fetch=download):
    for name, (repository, asset) in OWNERS.items():
        relative = 'platform/' + name + '/artifact.lock.json'
        if relative not in plan['baseFiles']:
            continue
        original = json.loads(base64.b64decode(plan['baseFiles'][relative], validate=True))
        lock = json.loads(owned_path(root, relative).read_bytes())
        from .compatibility import minor
        minor(original['version'], lock['version'])
        prefix = 'https://github.com/' + repository + '/releases/download/'
        expected = prefix + 'v' + lock['version'] + '/' + asset.format(version=lock['version'])
        if lock['url'] != expected:
            raise ValueError('Raw artifact origin differs from its exact approved release')
        gateway = name == 'connectivity/gateway-api'
        raw = owned_path(root, 'platform/' + name + '/upstream.yaml').read_bytes() if gateway else None
        if lock == original and (not gateway or digest(raw) == original['sha256']):
            continue
        official = fetch(expected, prefix=prefix)
        if digest(official) != lock['sha256'] or (gateway and raw != official):
            raise ValueError('Raw artifact differs from its exact official release')
