"""Validate immutable Istio charts, private services and disjoint ownership."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import yaml

from vendor_charts import ROOT, PATHS, verify


def render(component):
    lock = verify(component)
    if subprocess.check_output(['helm', 'version', '--short'], text=True).strip() != lock['helm_version']:
        raise ValueError('Mesh checks require the pinned Helm tool')
    root = ROOT / component
    command = ['helm', 'template', component, str(root), '-n', lock['namespace'],
               '--kube-version', lock['kube_version'], '--include-crds', '-f', str(root / 'values.json')]
    first = subprocess.check_output(command, stderr=subprocess.PIPE, timeout=90)
    if first != subprocess.check_output(command, stderr=subprocess.PIPE, timeout=90):
        raise ValueError('Mesh chart render is nondeterministic')
    return [obj for obj in yaml.safe_load_all(first) if obj]


def image_refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'image' and isinstance(child, str):
                yield child
            else:
                yield from image_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from image_refs(child)


def validate(groups):
    lock = json.loads((ROOT / 'images.lock.json').read_text())
    expected = set(lock.values())
    identities = set()
    policies = [obj for objects in groups.values() for obj in objects if obj['kind'] == 'PeerAuthentication']
    if len(policies) != 1 or policies[0]['metadata']['namespace'] != 'istio-system' or policies[0]['spec'] != {'mtls': {'mode': 'STRICT'}}:
        raise ValueError('Mesh default must require STRICT mutual TLS')
    for component, objects in groups.items():
        for obj in objects:
            meta = obj['metadata']
            identity = (obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else '',
                        obj['kind'], meta.get('namespace', ''), meta['name'])
            if identity in identities:
                raise ValueError('Mesh Applications have competing object owners')
            identities.add(identity)
            annotations = meta.get('annotations', {})
            if 'helm.sh/hook' in annotations or obj['kind'] in ('Job', 'Secret'):
                raise ValueError('Mesh charts cannot contain hooks or generated credentials')
            if obj['kind'] == 'CustomResourceDefinition':
                if component != 'base' or annotations.get('argocd.argoproj.io/sync-options') != 'ServerSideApply=true,Prune=false,Delete=false':
                    raise ValueError('Mesh API ownership or retention changed')
                if obj['spec']['group'] == 'gateway.networking.k8s.io':
                    raise ValueError('Gateway API retains its existing Traefik owner until cutover')
            if obj['kind'] == 'Service' and obj['spec'].get('type', 'ClusterIP') != 'ClusterIP':
                raise ValueError('Mesh services must remain internal')
            if obj['kind'] in ('Deployment', 'DaemonSet'):
                pod = obj['spec']['template']['spec']
                for container in pod.get('containers', []) + pod.get('initContainers', []):
                    if container['image'] not in expected or not container.get('resources', {}).get('limits'):
                        raise ValueError('Mesh containers need pinned images and limits')
    if not set(image_refs(groups)) <= expected:
        raise ValueError('Mesh contains an unpinned image')
    return len(identities)


def gateway_api():
    root = ROOT.parent / 'gateway-api'
    lock = json.loads((root / 'artifact.lock.json').read_text())
    raw = (root / 'upstream.yaml').read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock['sha256']:
        raise ValueError('Gateway API checksum mismatch')
    objects = [obj for obj in yaml.safe_load_all(raw) if obj]
    crds = [obj for obj in objects if obj['kind'] == 'CustomResourceDefinition']
    if len(objects) != 12 or len(crds) != 10 or {obj['kind'] for obj in objects} != {
            'CustomResourceDefinition', 'ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding'}:
        raise ValueError('Gateway API standard inventory changed')
    return crds


def gateways(zone='example.invalid'):
    root = ROOT.parent / 'gateways'
    result = subprocess.run(['helm', 'template', 'cloudlab-gateways', str(root), '-f', str(root / 'values.json'),
                             '--values', '-'], input=json.dumps({'zone': zone}), capture_output=True,
                            text=True, timeout=90, check=True)
    objects = [obj for obj in yaml.safe_load_all(result.stdout) if obj]
    if len(objects) != 4 or {obj['kind'] for obj in objects} != {'Gateway', 'ConfigMap'}:
        raise ValueError('Gateway chart must not compete with generated workloads or certificate namespaces')
    image = json.loads((ROOT / 'images.lock.json').read_text())['proxyv2']
    for obj in objects:
        if obj['kind'] == 'ConfigMap':
            service = yaml.safe_load(obj['data']['service'])
            deployment = yaml.safe_load(obj['data']['deployment'])
            if service['spec']['type'] != 'ClusterIP' or deployment['spec']['replicas'] != 2:
                raise ValueError('Gateway service exposure or replica policy changed')
            if deployment['spec']['template']['spec']['containers'][0]['image'] != image:
                raise ValueError('Gateway image differs from its lock')
        else:
            exposure = obj['metadata']['namespace'].removeprefix('cloudlab-gateway-')
            listeners = obj['spec']['listeners']
            if len(listeners) != (2 if exposure == 'private' else 1):
                raise ValueError('Gateway listener inventory changed')
            for listener in listeners:
                if listener['protocol'] != 'HTTPS' or listener['tls']['mode'] != 'Terminate':
                    raise ValueError('Gateway requires terminating HTTPS listeners')
                if listener['allowedRoutes']['namespaces'] != {
                        'from': 'Selector', 'selector': {'matchLabels': {'cloudlab.io/gateway': exposure}}}:
                    raise ValueError('Gateway route attachment must be restricted by exposure')
            if exposure == 'private' and (listeners[1]['name'] != 'identity-account' or
                    listeners[1]['hostname'] != 'login.' + zone):
                raise ValueError('Private identity listener must use the exact canonical issuer hostname')
    return objects


if __name__ == '__main__':
    groups = {name: render(name) for name in PATHS}
    count = validate(groups)
    definitions = gateway_api()
    gateways()
    if sys.argv[1:] == ['payload']:
        print(json.dumps({'mesh_objects': groups, 'gateway_api': definitions}))
    else:
        print(json.dumps({'mesh_objects': count, 'gateway_api_definitions': len(definitions),
                          'gateway_api_existing_owner_retained': True, 'resources_applied': False}))
