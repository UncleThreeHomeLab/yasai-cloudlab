"""Derive narrow CI network exceptions from the existing cluster and registry."""
import ipaddress
import json
import os
import shlex

from playbooks.access.files.preflight import ssh
from playbooks.harbor.files.transport import hostname


def configuration(document, *, enforce=True):
    keys = {'apiServiceCIDRs', 'apiEndpointCIDRs', 'registryCIDRs'}
    if set(document) != keys or type(enforce) is not bool:
        raise ValueError('CI networking requires exactly the existing API and registry endpoints')
    result = {'enforce': enforce}
    private = [ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10')]
    for key in sorted(keys):
        rows = document[key]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 4:
            raise ValueError('CI endpoint inventory is empty or exceeds its bounded scope')
        addresses = [ipaddress.IPv4Address(value) for value in rows]
        if len(set(addresses)) != len(addresses) or any(not any(address in network for network in private) for address in addresses):
            raise ValueError('CI exceptions must be unique private IPv4 hosts')
        result[key] = [str(address) + '/32' for address in sorted(addresses)]
    return result


def discover(values, registry):
    registry = hostname(registry)
    script = '''import json,socket,subprocess,sys
def get(resource,name,namespace='default'):
 result=subprocess.run(['/usr/local/bin/k3s','kubectl','--request-timeout=15s','get',resource,name,'-n',namespace,'-o','json'],capture_output=True,text=True,check=True)
 return json.loads(result.stdout)
service=get('service','kubernetes')
endpoints=get('endpoints','kubernetes')
gateway=get('service','cloudlab-istio','cloudlab-gateway-private')
addresses=sorted({row[4][0] for row in socket.getaddrinfo(sys.argv[1],443,socket.AF_INET,socket.SOCK_STREAM)})
if (addresses!=[gateway['spec']['clusterIP']] or gateway['spec']['selector']!={'gateway.networking.k8s.io/gateway-name':'cloudlab'} or
 not any(port['port']==443 and port['targetPort']==443 for port in gateway['spec']['ports'])):
 raise RuntimeError('Harbor gateway route differs from its accepted private TLS service')
print(json.dumps({'apiServiceCIDRs':[service['spec']['clusterIP']],
 'apiEndpointCIDRs':sorted({address['ip'] for subset in endpoints['subsets'] for address in subset.get('addresses',[])}),
 'registryCIDRs':addresses}))
'''
    selected = {key: values[key] for key in ('VM_USER', 'VM_PASSWORD', 'VM_PORT') if values.get(key)}
    original = {key: os.environ.get(key) for key in selected}
    try:
        os.environ.update(selected)
        raw = ssh('VM', values['VM_HOST'], 'sudo python3 -c ' + shlex.quote(script) + ' ' + shlex.quote(registry), timeout=60)
        return configuration(json.loads(raw))
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
