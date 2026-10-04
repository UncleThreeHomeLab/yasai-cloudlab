"""Render the locked ESO module for bounded bootstrap and ownership review."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[2] / 'platform/secrets/external-secrets'


def images(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'image' and isinstance(child, str):
                yield child
            else:
                yield from images(child)
    elif isinstance(value, list):
        for child in value:
            yield from images(child)


def render():
    lock = json.loads((ROOT / 'artifact.lock.json').read_text())
    archive = (ROOT / lock['archive']).resolve()
    if not archive.is_relative_to(ROOT.resolve()):
        raise ValueError('ESO chart archive escapes its module')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['sha256']:
        raise ValueError('ESO chart checksum mismatch')
    if subprocess.check_output(['helm', 'version', '--short'], text=True).strip() != lock['helm_version']:
        raise ValueError('ESO rendering requires the pinned Helm tool')
    command = ['helm', 'template', lock['release_name'], str(ROOT),
               '--namespace', lock['namespace'], '--kube-version', lock['kube_version'],
               '--include-crds', '--values', str(ROOT / 'values.json')]
    rendered = subprocess.check_output(command, stderr=subprocess.PIPE, timeout=90)
    if rendered != subprocess.check_output(command, stderr=subprocess.PIPE, timeout=90):
        raise ValueError('ESO chart render is nondeterministic')
    objects = [item for item in yaml.safe_load_all(rendered) if item]
    expected = {name + '@' + digest for name, digest in lock['images'].items()}
    if not all(re.fullmatch(r'sha256:[0-9a-f]{64}', digest) for digest in lock['images'].values()):
        raise ValueError('ESO image lock contains an invalid digest')
    if set(images(objects)) != expected:
        raise ValueError('ESO chart images differ from the lock')
    identities = set()
    for item in objects:
        metadata = item['metadata']
        identity = (item['apiVersion'], item['kind'], metadata.get('namespace', ''), metadata['name'])
        if identity in identities:
            raise ValueError('ESO chart contains duplicate objects')
        identities.add(identity)
        annotations = metadata.get('annotations', {})
        if 'helm.sh/hook' in annotations:
            raise ValueError('ESO chart contains an unreviewed hook')
        options = annotations.get('argocd.argoproj.io/sync-options')
        expected_options = 'ServerSideApply=true,Prune=false,Delete=false'
        if options and (item['kind'] != 'CustomResourceDefinition' or options != expected_options):
            raise ValueError('ESO chart contains unreviewed sync options')
        if item['kind'] == 'Secret' and (metadata['name'] != 'external-secrets-webhook'
                or metadata.get('namespace') != 'external-secrets'
                or set(item) != {'apiVersion', 'kind', 'metadata'}):
            # The empty webhook Secret is initialized by the chart; its contents
            # belong to the ESO certificate controller. No credentials are rendered.
            raise ValueError('ESO chart must not own the bootstrap credential or generated Secret data')
    return objects


if __name__ == '__main__':
    try:
        objects = render()
        if sys.argv[1:] == ['check']:
            print(json.dumps({'objects': len(objects), 'images': len(set(images(objects))),
                              'deterministic': True, 'bootstrap_secret_excluded': True}))
        else:
            revision = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
            print(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects, 'revision': revision}))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        raise SystemExit('Locked ESO chart validation failed; no resources applied') from None
