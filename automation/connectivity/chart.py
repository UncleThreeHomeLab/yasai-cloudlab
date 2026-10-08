"""Offline checks for inactive access charts and the exact selected proxy APIs."""
import json
from pathlib import Path
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.connectivity.vendor_operator import verify


def render(path, administrator=None):
    command = ['helm', 'template', 'cloudlab-access', str(path), '--namespace', 'tailscale',
               '--kube-version', '1.36.5', '--include-crds']
    if administrator:
        command += ['--set-string', 'administrator=' + administrator]
    first = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=90)
    second = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=90)
    if first.returncode or second.returncode or first.stdout != second.stdout:
        raise ValueError('Access chart render failed or was nondeterministic')
    return [value for value in yaml.safe_load_all(first.stdout) if value]


def validate(operator, access):
    lock = verify()
    identities = set()
    for value in operator + access:
        meta = value['metadata']
        identity = (value['apiVersion'].split('/')[0] if '/' in value['apiVersion'] else '',
                    value['kind'], meta.get('namespace', ''), meta['name'])
        if identity in identities:
            raise ValueError('Access charts have competing resource owners')
        identities.add(identity)
        if value['kind'] == 'Secret' or 'helm.sh/hook' in meta.get('annotations', {}):
            raise ValueError('Access charts must not render generated credentials or Helm hooks')
    crds = [value for value in operator if value['kind'] == 'CustomResourceDefinition']
    if len(crds) != 8 or any(value['metadata'].get('annotations', {}).get('argocd.argoproj.io/sync-options') !=
                            'ServerSideApply=true,Prune=false,Delete=false' for value in crds):
        raise ValueError('Tailscale CRD retention contract changed')
    schemas = {value['metadata']['name']: value['spec']['versions'][0]['schema']['openAPIV3Schema'] for value in crds}
    pg_schema = schemas['proxygroups.tailscale.com']['properties']['spec']['properties']
    if not {'ingress', 'kube-apiserver'} <= set(pg_schema['type']['enum']) or 'auth' not in pg_schema['kubeAPIServer']['properties']['mode']['enum']:
        raise ValueError('Pinned operator does not support the selected ProxyGroup modes')
    classes = {value['metadata']['name']: value for value in access if value['kind'] == 'ProxyClass'}
    proxy_pod_fields = schemas['proxyclasses.tailscale.com']['properties']['spec']['properties']['statefulSet']['properties']['pod']['properties']
    for name, mode in [('cloudlab-ingress', 'ingress'), ('cloudlab-api', 'api')]:
        pod = classes[name]['spec']['statefulSet']['pod']
        if not set(pod) <= set(proxy_pod_fields):
            raise ValueError('ProxyClass uses unsupported Pod fields')
        if pod['tailscaleContainer']['image'] != lock['images'][mode]:
            raise ValueError('ProxyClass image differs from its lock')
        if not pod['tailscaleContainer']['resources'].get('limits') or not pod.get('topologySpreadConstraints'):
            raise ValueError('ProxyClass requires bounded resources and node placement')
    groups = {value['metadata']['name']: value for value in access if value['kind'] == 'ProxyGroup'}
    if groups['cloudlab-ingress']['spec']['type'] != 'ingress' or groups['cloudlab-api']['spec']['type'] != 'kube-apiserver':
        raise ValueError('Selected L3 ingress or dedicated API mode changed')
    if groups['cloudlab-api']['spec']['kubeAPIServer']['mode'] != 'auth' or any(
            value['spec']['replicas'] != 2 for value in groups.values()):
        raise ValueError('Both dedicated proxy modes need two replicas; API must enforce tailnet identity')
    deployments = {value['metadata']['name']: value for value in operator + access if value['kind'] == 'Deployment'}
    op = deployments['operator']
    container = op['spec']['template']['spec']['containers'][0]
    env = {value['name']: value.get('value') for value in container['env']}
    if op['spec']['replicas'] != 1 or env.get('APISERVER_PROXY') != 'false' or container['image'] != lock['images']['operator']:
        raise ValueError('Operator must retain its supported single replica and disable its in-process API proxy')
    connector = deployments['cloudflared']
    cloudflared = connector['spec']['template']['spec']['containers'][0]
    if connector['spec']['replicas'] != 2 or any(not cloudflared.get(key) for key in ('startupProbe', 'readinessProbe', 'livenessProbe')):
        raise ValueError('Cloudflared needs two replicas and explicit health probes')
    image_lock = json.loads((ROOT / 'platform/connectivity/access/images.lock.json').read_text())['images']
    if cloudflared['image'] != image_lock['cloudflared']:
        raise ValueError('Cloudflared image differs from its lock')
    if connector['spec']['template']['spec']['topologySpreadConstraints'][0].get('matchLabelKeys') != ['pod-template-hash']:
        raise ValueError('Connector spread must remain balanced across rollout revisions')
    services = [value for value in access if value['kind'] == 'Service']
    if len(services) != 1 or services[0]['spec'].get('loadBalancerClass') != 'tailscale' or services[0]['spec'].get('allocateLoadBalancerNodePorts') is not False or services[0]['spec']['ports'] != [{'name': 'https', 'protocol': 'TCP', 'port': 443, 'targetPort': 443}]:
        raise ValueError('Private L3 service must preserve Istio HTTPS without NodePorts or public listener')
    bindings = [value for value in access if value['kind'] == 'ClusterRoleBinding']
    if len(bindings) != 1 or bindings[0]['subjects'] != [{'kind': 'User', 'apiGroup': 'rbac.authorization.k8s.io', 'name': 'admin@example.invalid'}]:
        raise ValueError('API RBAC must bind only the explicitly selected human identity')
    admission = [value for value in access if value['kind'] == 'MutatingAdmissionPolicy']
    if len(admission) != 1:
        raise ValueError('Exactly one admission owner must add the proxy health probes')
    constraints = admission[0]['spec']['matchConstraints']
    if constraints['namespaceSelector'] != {'matchLabels': {'kubernetes.io/metadata.name': 'tailscale'}} or constraints['resourceRules'] != [
            {'apiGroups': [''], 'apiVersions': ['v1'], 'operations': ['CREATE'], 'resources': ['pods']}]:
        raise ValueError('Proxy admission must affect only new Pods in tailscale')
    if constraints['objectSelector'] != {'matchExpressions': [{'key': 'cloudlab.io/proxy', 'operator': 'In', 'values': ['cloudlab-ingress', 'cloudlab-api']}]}:
        raise ValueError('Proxy admission must select only the declared proxy groups')
    return {'operator_objects': len(operator), 'access_objects': len(access), 'crds': len(crds),
            'proxygroup_modes': ['ingress', 'kube-apiserver/auth'], 'proxygroup_replicas': 2,
            'operator_replicas': 1, 'resources_applied': False, 'proxy_probe_support': False,
            'pod_probe_owner': 'MutatingAdmissionPolicy/v1'}


def check():
    verify()
    operator = render(ROOT / 'platform/connectivity/tailscale-operator')
    access = render(ROOT / 'platform/connectivity/access', 'admin@example.invalid')
    result = validate(operator, access)
    dns = render(ROOT / 'platform/connectivity/private-dns')
    if len(dns) != 1 or dns[0]['kind'] != 'ConfigMap' or dns[0]['metadata']['name'] != 'coredns-custom' or dns[0]['metadata']['namespace'] != 'kube-system':
        raise ValueError('Private DNS chart must own only the custom forwarding ConfigMap')
    if 'forward . 10.44.0.1 10.44.0.2' not in dns[0]['data']['cloudlab-private.server']:
        raise ValueError('Cluster private DNS must use both independent private resolvers')
    from automation.connectivity.cutover import definitions
    expected = {obj['metadata']['name']: obj['spec'] for obj in definitions()}
    retained = render(ROOT / 'platform/connectivity/gateway-api')
    if len(retained) != 10 or {obj['metadata']['name']: obj['spec'] for obj in retained} != expected:
        raise ValueError('Gateway API handoff changes the pinned CRD contract')
    for obj in retained:
        annotations = obj['metadata']['annotations']
        if annotations.get('argocd.argoproj.io/sync-options') != 'ServerSideApply=true,Prune=false,Delete=false' or annotations.get('helm.sh/resource-policy') != 'keep':
            raise ValueError('Gateway API handoff must preserve deletion protection')
    return result


if __name__ == '__main__':
    try:
        print(json.dumps(check()))
    except ValueError as error:
        raise SystemExit(str(error)) from None
