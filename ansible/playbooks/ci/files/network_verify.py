"""Exercise shared CI network policies with bounded, credential-free cross-node pods."""
import copy
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time


LABELS = {'cloudlab.io/owner': 'ci-platform', 'cloudlab.io/fixture': 'ci-network'}
NAME = re.compile(r'cloudlab-ci-proof-[a-f0-9]{12}')


def kubectl(*arguments, document=None):
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=20s', *arguments],
        input=json.dumps(document) if document is not None else None, capture_output=True, text=True, timeout=60)
    if result.returncode:
        try:
            with open('/var/lib/cloudlab/ci-network-check-failure.json') as stream:
                previous = json.load(stream)
            if not isinstance(previous, list):
                previous = [previous]
        except FileNotFoundError:
            previous = []
        descriptor = os.open('/var/lib/cloudlab/ci-network-check-failure.json',
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump((previous + [{'operation': arguments[0], 'stdout': result.stdout, 'stderr': result.stderr}])[-8:], stream)
        raise RuntimeError('CI network check failed; private diagnostics withheld')
    return result.stdout


def get(kind, *arguments):
    return json.loads(kubectl('get', kind, *arguments, '-o', 'json'))


def validate(policy):
    spec = policy['spec']
    if (set(spec) not in ({'podSelector', 'policyTypes', 'ingress', 'egress'}, {'podSelector', 'policyTypes', 'egress'}) or
            spec.get('podSelector') != {} or set(spec.get('policyTypes', [])) != {'Ingress', 'Egress'} or spec.get('ingress', []) != []):
        raise ValueError('CI networking must isolate every pod in both directions')
    rules = spec.get('egress', [])
    if len(rules) not in (4, 6):
        raise ValueError('CI networking has unexpected exceptions')
    dns = rules[0]
    if dns != {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                      'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
               'ports': [{'protocol': 'UDP', 'port': 53}, {'protocol': 'TCP', 'port': 53}]}:
        raise ValueError('CI DNS scope differs')
    public = rules[1]
    block = public['to'][0]['ipBlock']
    required = {'0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
                '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4'}
    if (len(public['to']) != 1 or block.get('cidr') != '0.0.0.0/0' or set(block.get('except', [])) != required or
            public['ports'] != [{'protocol': 'TCP', 'port': 443}]):
        raise ValueError('Public network access exceeds HTTPS outside private ranges')
    if len(rules) == 6 and rules[-1] != {'to': [{'namespaceSelector': {'matchLabels': {
            'kubernetes.io/metadata.name': 'cloudlab-gateway-private'}}, 'podSelector': {'matchLabels': {
            'gateway.networking.k8s.io/gateway-name': 'cloudlab'}}}], 'ports': [{'protocol': 'TCP', 'port': 443}]}:
        raise ValueError('Harbor gateway exception exceeds its private TLS workload')
    for rule in rules[2:4 if len(rules) == 4 else 5]:
        if rule.get('ports') not in ([{'protocol': 'TCP', 'port': 443}], [{'protocol': 'TCP', 'port': 6443}]):
            raise ValueError('CI internal ports exceed their reviewed scope')
        if set(rule) != {'to', 'ports'} or not 1 <= len(rule['to']) <= 4:
            raise ValueError('CI internal peers exceed their reviewed scope')
        for peer in rule['to']:
            address = ipaddress.ip_network(peer['ipBlock']['cidr'])
            if (set(peer) != {'ipBlock'} or set(peer['ipBlock']) != {'cidr'} or address.version != 4 or
                    address.prefixlen != 32 or not any(address.subnet_of(ipaddress.ip_network(network))
                    for network in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'))):
                raise ValueError('CI internal peers must be exact private hosts')


def retire(namespace, uid):
    if not NAME.fullmatch(namespace):
        raise ValueError('Network fixture deletion scope refused')
    current = get('namespace', namespace)
    if current['metadata']['uid'] != uid or any(current['metadata'].get('labels', {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError('Network fixture identity changed; preserve for inspection')
    kubectl('delete', '--raw', '/api/v1/namespaces/' + namespace, '-f', '-', document={
        'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}})
    deadline = time.monotonic() + 120
    while kubectl('get', 'namespace', namespace, '--ignore-not-found', '-o', 'json').strip():
        if time.monotonic() >= deadline:
            raise RuntimeError('Network fixture deletion remains pending; preserve its identity')
        time.sleep(1)


def probe(namespace, code, *arguments):
    return kubectl('exec', '-n', namespace, 'probe', '--', 'python3', '-I', '-S', '-c', code, *arguments)


CONNECT = '''import socket,sys
try:
 with socket.create_connection((sys.argv[1],18080),timeout=3): pass
except (TimeoutError, OSError):
 print('blocked')
else: print('connected')
'''
ALLOWED = '''import socket,sys,urllib.request,urllib.error
socket.getaddrinfo('api.github.com',443)
for label,url in (('GitHub','https://api.github.com/meta'),('Harbor','https://'+sys.argv[1]+'/v2/'),('API','https://kubernetes.default.svc/readyz')):
 try:
  context=None
  if 'kubernetes.default.svc' in url:
   import ssl
   context=ssl.create_default_context(cafile='/run/kubernetes/ca.crt')
  with urllib.request.urlopen(url,timeout=20,context=context) as response:
   assert response.status==200
 except urllib.error.HTTPError as error:
  assert 'api.github.com' not in url and error.code in (401,403)
 except Exception as error:
  raise RuntimeError('Required '+label+' access failed: '+type(getattr(error,'reason',error)).__name__) from None
print('allowed')
'''


def fixture(namespace, node, image, secret):
    return [
        {'apiVersion': 'v1', 'kind': 'ResourceQuota', 'metadata': {'name': 'budget', 'namespace': namespace},
         'spec': {'hard': {'pods': '1', 'limits.cpu': '100m', 'limits.memory': '128Mi',
                           'limits.ephemeral-storage': '128Mi', 'persistentvolumeclaims': '0', 'secrets': '1'}}},
        {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret',
         'metadata': {'name': 'harbor-tools-pull', 'namespace': namespace}, 'spec': copy.deepcopy(secret['spec'])},
        {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'probe', 'namespace': namespace, 'labels': LABELS},
         'spec': {'nodeName': node, 'activeDeadlineSeconds': 600, 'restartPolicy': 'Never',
                  'hostUsers': False, 'automountServiceAccountToken': False,
                  'volumes': [{'name': 'ca', 'configMap': {'name': 'kube-root-ca.crt'}}],
                  'imagePullSecrets': [{'name': 'harbor-tools-pull'}],
                  'securityContext': {'runAsNonRoot': True, 'runAsUser': 1001, 'runAsGroup': 1001,
                                      'seccompProfile': {'type': 'RuntimeDefault'}},
                  'containers': [{'name': 'probe', 'image': image, 'imagePullPolicy': 'Always',
                      'command': ['python3', '-I', '-S', '-c',
                          'import socket; s=socket.socket(); s.bind(("0.0.0.0",18080)); s.listen();\nwhile True:\n c,a=s.accept(); c.close()'],
                      'volumeMounts': [{'name': 'ca', 'mountPath': '/run/kubernetes', 'readOnly': True}],
                      'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                          'capabilities': {'drop': ['ALL']}},
                      'resources': {'requests': {'cpu': '10m', 'memory': '32Mi', 'ephemeral-storage': '16Mi'},
                                    'limits': {'cpu': '100m', 'memory': '128Mi', 'ephemeral-storage': '128Mi'}}}]}}]


def prove(policy, image, secret):
    validate(policy)
    if not re.fullmatch(r'[^/]+/cloudlab-public/ci-runner@sha256:[a-f0-9]{64}', image):
        raise ValueError('Network proof requires the qualified public runner digest')
    sources = secret['spec'].get('dataFrom', [])
    if (len(sources) != 1 or sources[0].get('extract', {}).get('key') != 'harbor-cloudlab-public-pull' or
            secret['spec'].get('data')):
        raise ValueError('Network proof cannot receive private or write credentials')
    nodes = get('nodes')['items']
    if len(nodes) != 2:
        raise ValueError('Network proof requires exactly two existing nodes')
    created = []
    try:
        for node in nodes:
            namespace = 'cloudlab-ci-proof-' + secrets.token_hex(6)
            document = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace,
                'labels': dict(LABELS, **{'cloudlab.io/ci-role': 'qualification', 'cloudlab.io/service-secrets': 'approved',
                    'pod-security.kubernetes.io/enforce': 'baseline', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
                    'pod-security.kubernetes.io/audit': 'restricted', 'pod-security.kubernetes.io/warn': 'restricted'})}}
            result = json.loads(kubectl('create', '-f', '-', '-o', 'json', document=document))
            created.append((namespace, result['metadata']['uid']))
            resources = fixture(namespace, node['metadata']['name'], image, secret)
            kubectl('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'List', 'items': resources[:2]})
            kubectl('wait', 'externalsecret/harbor-tools-pull', '-n', namespace, '--for=condition=Ready', '--timeout=45s')
            deadline = time.monotonic() + 30
            while not get('resourcequota', 'budget', '-n', namespace).get('status', {}).get('hard'):
                if time.monotonic() >= deadline:
                    raise RuntimeError('Network fixture quota did not become ready')
                time.sleep(1)
            kubectl('create', '-f', '-', document=resources[2])
            kubectl('wait', 'pod/probe', '-n', namespace, '--for=condition=Ready', '--timeout=45s')
        first, second = [entry[0] for entry in created]
        addresses = [get('pod', 'probe', '-n', namespace)['status']['podIP'] for namespace in (first, second)]
        if probe(first, ALLOWED, image.split('/')[0]).strip() != 'allowed':
            raise RuntimeError('Required service baseline failed before network enforcement')
        for target, other, target_ip, other_ip in ((first, second, *addresses), (second, first, *reversed(addresses))):
            for client, address in ((target, other_ip), (other, target_ip)):
                deadline = time.monotonic() + 15
                while probe(client, CONNECT, address).strip() != 'connected':
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Network fixture lacks a working cross-node baseline')
                    time.sleep(1)
            selected = copy.deepcopy(policy)
            selected['metadata'] = {'name': 'cloudlab-ci-boundary', 'namespace': target}
            kubectl('create', '-f', '-', document=selected)
            deadline = time.monotonic() + 30
            while True:
                denied = [probe(target, CONNECT, other_ip).strip(), probe(other, CONNECT, target_ip).strip()]
                if denied == ['blocked', 'blocked']:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('Network policy failed to block actual ingress or private egress')
                time.sleep(1)
            if probe(target, ALLOWED, image.split('/')[0]).strip() != 'allowed':
                raise RuntimeError('Required DNS, GitHub, Harbor or Kubernetes API access failed')
            kubectl('delete', 'networkpolicy', 'cloudlab-ci-boundary', '-n', target)
        return {'nodes_verified': 2, 'cross_node_baselines': 4, 'ingress_denials': 2, 'private_egress_denials': 2, 'ingress_denied': True,
                'private_egress_denied': True, 'required_https_and_dns': True, 'github_or_signing_credentials': False}
    finally:
        failures = []
        for namespace, uid in reversed(created):
            try:
                retire(namespace, uid)
            except Exception as error:
                failures.append(error)
        if failures:
            raise RuntimeError('Network fixture cleanup incomplete; scoped identities preserved') from None


def main():
    prior = get('namespaces', '-l', 'cloudlab.io/owner=ci-platform,cloudlab.io/fixture=ci-network')['items']
    for namespace in prior:
        name = namespace['metadata']['name']
        pods = get('pods', '-n', name)['items']
        if any(pod['metadata']['name'] != 'probe' or pod.get('status', {}).get('phase') not in ('Failed', 'Succeeded') for pod in pods):
            raise RuntimeError('Prior network fixture is still active; preserve it until its deadline')
        retire(name, namespace['metadata']['uid'])
    namespaces = [row['metadata']['name'] for row in get('namespaces', '-l', 'cloudlab.io/owner=ci-platform')['items']
                  if row['metadata'].get('labels', {}).get('cloudlab.io/ci-role') in ('runner', 'controller')]
    policies = []
    for namespace in namespaces:
        rows = get('networkpolicies', '-n', namespace)['items']
        if len(rows) != 1 or rows[0]['metadata']['name'] != 'cloudlab-ci-boundary':
            raise ValueError('CI namespace has missing or additional network grants')
        policies.extend(rows)
    if not namespaces or 'cloudlab-ci-system' not in namespaces:
        raise ValueError('CI namespace inventory is incomplete')
    for policy in policies:
        validate(policy)
    pools = get('autoscalingrunnersets.actions.github.com', '-A')['items']
    reference = next(row['spec']['template']['spec']['containers'][0]['image'] for row in pools
                     if '/cloudlab-public/ci-runner@sha256:' in row['spec']['template']['spec']['containers'][0]['image'])
    service = get('service', 'kubernetes', '-n', 'default')['spec']['clusterIP']
    endpoints = get('endpoints', 'kubernetes', '-n', 'default')['subsets']
    required = {(service + '/32', 443)} | {(address['ip'] + '/32', 6443)
        for subset in endpoints for address in subset.get('addresses', [])}
    registry = {(row[4][0] + '/32', 443) for row in socket.getaddrinfo(reference.split('/')[0], 443, socket.AF_INET, socket.SOCK_STREAM)}
    for policy in policies:
        actual = {(peer['ipBlock']['cidr'], port['port']) for rule in policy['spec']['egress'][2:]
                  for peer in rule['to'] if 'ipBlock' in peer for port in rule['ports']}
        expected = required if policy['metadata']['namespace'] == 'cloudlab-ci-system' else required | registry
        if actual != expected:
            raise ValueError('CI internal exceptions differ from the existing API and Harbor endpoints')
    policy = next(row for row in policies if row['metadata']['namespace'] != 'cloudlab-ci-system')
    secret = get('externalsecret', 'harbor-tools-pull', '-n', policy['metadata']['namespace'])
    print(json.dumps(dict(prove(policy, reference, secret), namespaces_isolated=len(namespaces))))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('CI network verification incomplete; private diagnostics withheld') from None
