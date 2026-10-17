"""Read private DNS inputs through ready certificate and Service public interfaces."""
import json
import sys
sys.path.insert(0, '/var/lib/cloudlab/mesh')
from kube import condition, get


def read():
    certificate = get('certificate.cert-manager.io', 'cloudlab-gateway', 'cloudlab-gateway-private')
    service = get('service', 'cloudlab-istio', 'cloudlab-gateway-private')
    tailnet = get('service', 'cloudlab-tailnet', 'cloudlab-gateway-private')
    if not condition(certificate, 'Ready'):
        raise RuntimeError('Private certificate is not ready')
    names = certificate['spec']['dnsNames']
    if (len(names) != 2 or not names[0].startswith('*.internal.') or
            names[1] != 'login.' + names[0][11:]):
        raise RuntimeError('Private certificate contract changed')
    addresses = [x['ip'] for x in tailnet.get('status', {}).get('loadBalancer', {}).get('ingress', [])
                 if x.get('ip') and ':' not in x['ip']]
    if len(addresses) != 1:
        raise RuntimeError('Private L3 Service has no unique ready IPv4 address')
    return {'zone': names[0][2:], 'identity_host': names[1],
            'cluster_gateway': service['spec']['clusterIP'], 'tailnet_gateway': addresses[0]}


if __name__ == '__main__':
    try:
        print(json.dumps(read()))
    except Exception:
        raise SystemExit('Private DNS input discovery failed; existing resolvers retained.') from None
