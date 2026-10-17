"""Check certificate packaging before publishing it for Argo reconciliation."""
import json
import re
import subprocess

import yaml

from vendor_chart import ROOT, verify


def render():
    lock = verify()
    if subprocess.check_output(['helm', 'version', '--short'], text=True).strip() != lock['helm_version']:
        raise ValueError('Certificate checks require the pinned Helm tool')
    command = ['helm', 'template', lock['release_name'], str(ROOT), '--namespace', lock['namespace'],
               '--kube-version', lock['kube_version'], '--include-crds', '-f', str(ROOT / 'values.json')]
    first = subprocess.check_output(command, stderr=subprocess.PIPE, timeout=90)
    if first != subprocess.check_output(command, stderr=subprocess.PIPE, timeout=90):
        raise ValueError('Certificate chart is nondeterministic')
    objects = [obj for obj in yaml.safe_load_all(first) if obj]
    expected = {name + '@' + digest for name, digest in lock['images'].items()}
    actual = set(re.findall(r'quay.io/jetstack/[a-zA-Z0-9_./:@-]+', json.dumps(objects)))
    if actual != expected:
        raise ValueError('Certificate image references differ from their lock')
    identities = set()
    for obj in objects:
        metadata = obj['metadata']
        identity = (obj['apiVersion'], obj['kind'], metadata.get('namespace', ''), metadata['name'])
        if identity in identities:
            raise ValueError('Duplicate certificate object')
        identities.add(identity)
        annotations = metadata.get('annotations', {})
        if 'helm.sh/hook' in annotations or obj['kind'] in ('Job', 'Secret', 'Certificate', 'Issuer', 'ClusterIssuer'):
            raise ValueError('Operator chart must not contain hooks, private inputs or issued credentials')
        if obj['kind'] == 'CustomResourceDefinition':
            if annotations.get('argocd.argoproj.io/sync-options') != 'ServerSideApply=true,Prune=false,Delete=false':
                raise ValueError('Certificate CRD retention changed')
        elif annotations.get('argocd.argoproj.io/sync-options'):
            raise ValueError('Unreviewed certificate sync options')
        if obj['kind'] == 'Service' and obj['spec'].get('type', 'ClusterIP') != 'ClusterIP':
            raise ValueError('Certificate services must remain private')
        if obj['kind'] == 'Deployment':
            for container in obj['spec']['template']['spec']['containers']:
                if container['image'] not in expected or not container.get('resources', {}).get('limits'):
                    raise ValueError('Certificate controller needs a pinned image and resource limits')
                if container['name'] == 'cert-manager-controller' and not {
                        '--dns01-recursive-nameservers=1.1.1.1:53,8.8.8.8:53',
                        '--dns01-recursive-nameservers-only'} <= set(container.get('args', [])):
                    raise ValueError('Public DNS-01 checks must not use the private split DNS view')
    if sum(obj['kind'] == 'CustomResourceDefinition' for obj in objects) != 6:
        raise ValueError('Certificate API inventory changed')
    return objects


def configuration_render(zone='example.invalid', production=False):
    command = ['helm', 'template', 'cloudlab-certificates', str(ROOT.parent / 'configuration'), '--values', '-']
    result = subprocess.run(command, input=json.dumps({'zone': zone, 'production': production}),
                            capture_output=True, text=True, timeout=90, check=True)
    objects = [obj for obj in yaml.safe_load_all(result.stdout) if obj]
    if len(objects) != (7 if production else 4):
        raise ValueError('Certificate configuration inventory changed')
    for obj in objects:
        if obj['kind'] == 'ClusterIssuer':
            for solver in obj['spec']['acme']['solvers']:
                if 'http01' in solver or 'dns01' not in solver or solver['selector']['dnsZones'] != [zone]:
                    raise ValueError('Certificate solver must remain DNS-only and restricted to the selected zone')
        elif obj['kind'] == 'Certificate':
            if obj['spec']['privateKey']['rotationPolicy'] != 'Always':
                raise ValueError('Certificate private keys must rotate during renewal')
        elif obj['kind'] != 'Namespace':
            raise ValueError('Unexpected certificate configuration resource')
    return objects


if __name__ == '__main__':
    try:
        objects = render()
        configuration_render()
        configuration_render(production=True)
        print(json.dumps({'certificate_objects': len(objects), 'deterministic': True, 'resources_applied': False}))
    except Exception:
        raise SystemExit('Certificate chart checks failed; no resources applied') from None
