"""Read current identity/gateway peers without exporting credentials or private names."""
import ipaddress

from playbooks.istio.files.kube import get, condition


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


def metadata():
    import json
    import os
    from pathlib import Path
    import shlex
    from playbooks.access.files.preflight import ssh
    ROOT = Path(__file__).resolve().parents[4]
    # Inspection uses the versioned module through stdin, without configuring the VM.
    script = (ROOT / 'ansible/playbooks/observability/files/discovery.py').read_text()
    script = "import sys,json;sys.path.insert(0,'/opt/cloudlab');\n" + script + '\nprint(json.dumps(run()))'
    return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(script), timeout=60))
