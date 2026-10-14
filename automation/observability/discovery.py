"""Read current identity/gateway peers without exporting credentials or private names."""
import ipaddress

from automation.mesh.kube import get, condition


def run():
    identity = get('application.argoproj.io', 'cloudlab-identity', 'argocd')
    if not identity: raise RuntimeError('Accepted identity Application required')
    values = identity['spec']['source']['helm']['valuesObject']
    login = values['loginHost']
    if not login.startswith('login.') or values.get('maintenance') or not values.get('reconciliationEnabled'):
        raise RuntimeError('Converged active identity writer required')
    gateway = get('service', 'cloudlab-istio', 'cloudlab-gateway-public')
    peers = []
    for node in get('nodes')['items']:
        if not condition(node, 'Ready'): raise RuntimeError('Both existing telemetry nodes must be ready')
        for address in node['status']['addresses']:
            if address['type'] == 'InternalIP':
                peer = ipaddress.ip_address(address['address'])
                peers.append(str(peer) + '/' + str(peer.max_prefixlen))
    if len(peers) != 2: raise RuntimeError('Telemetry requires exactly two existing node peers')
    ipaddress.ip_address(gateway['spec']['clusterIP'])
    return {'loginHost': login, 'gatewayIP': gateway['spec']['clusterIP'], 'apiPeers': sorted(peers),
            'grafanaHost': 'grafana.internal.' + login[6:], 'kialiHost': 'kiali.internal.' + login[6:]}
