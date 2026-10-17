"""Validate and render the same storage chart for bootstrap and Argo."""
import json
import re
import subprocess
import sys

import yaml

from vendor_chart import ROOT, verify


def generated():
    """Longhorn alone creates the immutable class from its byte-stable ConfigMap."""
    return [yaml.safe_load((ROOT / 'storageclass.yaml').read_text())]


def container_images(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ('containers', 'initContainers', 'ephemeralContainers'):
                yield from (container['image'] for container in child)
            else:
                yield from container_images(child)
    elif isinstance(value, list):
        for child in value:
            yield from container_images(child)


def render():
    verify()
    lock = json.loads((ROOT / 'artifact.lock.json').read_text())
    if subprocess.check_output(['helm', 'version', '--short'], text=True).strip() != lock['helm_version']:
        raise ValueError('Longhorn rendering requires the pinned Helm tool')
    command = ['helm', 'template', lock['release_name'], str(ROOT), '--namespace', lock['namespace'],
               '--kube-version', lock['kube_version'], '--include-crds', '-f', str(ROOT / 'values.json')]
    rendered = subprocess.check_output(command, stderr=subprocess.PIPE, timeout=90)
    if rendered != subprocess.check_output(command, stderr=subprocess.PIPE, timeout=90):
        raise ValueError('Longhorn chart render is nondeterministic')
    objects = [obj for obj in yaml.safe_load_all(rendered) if obj]
    expected = {tag + '@' + digest for tag, digest in lock['images'].items()}
    references = set(re.findall(r'docker.io/longhornio/[a-zA-Z0-9_./:@-]+', json.dumps(objects)))
    if references != expected or not set(container_images(objects)) <= expected:
        raise ValueError('Longhorn runtime image references differ from the lock')
    identities = set()
    for obj in objects:
        metadata = obj['metadata']
        identity = (obj['apiVersion'], obj['kind'], metadata.get('namespace', ''), metadata['name'])
        if identity in identities:
            raise ValueError('Duplicate Longhorn chart object')
        identities.add(identity)
        annotations = metadata.get('annotations', {})
        if 'helm.sh/hook' in annotations or obj['kind'] in ('Job', 'Secret', 'PersistentVolume', 'PersistentVolumeClaim'):
            raise ValueError('Longhorn chart contains a lifecycle hook, credential, or data object')
        options = annotations.get('argocd.argoproj.io/sync-options')
        if obj['kind'] == 'CustomResourceDefinition':
            if options != 'ServerSideApply=true,Prune=false,Delete=false':
                raise ValueError('Longhorn CRD retention or ownership options differ')
        elif options:
            raise ValueError('Unreviewed Longhorn sync options')
        if obj['kind'] == 'Service' and obj['spec'].get('type', 'ClusterIP') != 'ClusterIP':
            raise ValueError('Longhorn services must remain private')
    return objects


if __name__ == '__main__':
    try:
        objects = render()
        if sys.argv[1:] == ['check']:
            print(json.dumps({'objects': len(objects), 'lifecycle_hooks': 0, 'deterministic': True}))
        else:
            revision = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
            print(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects,
                              'generated': generated(), 'revision': revision}))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        raise SystemExit('Locked Longhorn chart validation failed; no resources applied') from None
