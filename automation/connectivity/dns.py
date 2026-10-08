"""Deterministic independent host DNS configuration; private zones never recurse."""
import hashlib
import ipaddress
import json
import re


def address(value, network):
    ip = ipaddress.IPv4Address(value)
    if ip not in ipaddress.IPv4Network(network):
        raise ValueError('DNS address lies outside its declared network')
    return str(ip)


def configuration(payload):
    zone = payload['zone']
    if not zone.startswith('internal.') or len(zone) > 253 or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in zone.split('.')):
        raise ValueError('Private DNS requires a canonical internal subdomain')
    names = payload['names']
    if not names or len(names) != len(set(names)) or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', n) for n in names):
        raise ValueError('Private DNS labels are invalid or ambiguous')
    if {'ns1', 'ns2'} & set(names):
        raise ValueError('Private DNS nameserver labels are reserved')
    tailnet = address(payload['tailnet_address'], '100.64.0.0/10')
    host = address(payload['host_address'], '10.44.0.0/30')
    gateway = address(payload['cluster_gateway'], '10.43.0.0/16')
    vip = address(payload['tailnet_gateway'], '100.64.0.0/10')
    servers = [address(x, '100.64.0.0/10') for x in payload['nameservers']]
    if len(servers) != 2 or len(set(servers)) != 2:
        raise ValueError('Private DNS requires two distinct host nameservers')
    upstreams = payload['upstreams']
    if not upstreams or len(upstreams) > 3:
        raise ValueError('Retained upstream resolvers are required')
    for value in upstreams:
        # A local/tailnet/cluster resolver would create a bootstrap loop.
        if not ipaddress.ip_address(value).is_global:
            raise ValueError('Retained upstream resolver is not independent of the lab')
    record_data = {'zone': zone, 'names': sorted(names), 'gateway': gateway, 'vip': vip, 'servers': servers}
    serial = int(hashlib.sha256(json.dumps(record_data, sort_keys=True).encode()).hexdigest()[:8], 16) or 1
    header = f'$ORIGIN {zone}.\n$TTL 30\n@ IN SOA ns1.{zone}. hostmaster.{zone}. {serial} 60 30 86400 30\n@ IN NS ns1.{zone}.\n@ IN NS ns2.{zone}.\n'
    files = {}
    for view, target in [('tailnet', vip), ('internal', gateway)]:
        ns = servers if view == 'tailnet' else ['10.44.0.1', '10.44.0.2']
        files[view + '.zone'] = header + ''.join(f'ns{i+1} IN A {value}\n' for i, value in enumerate(ns)) + ''.join(
            f'{name} IN A {target}\n' for name in sorted(names))
    # Files are relative to the service WorkingDirectory; validation uses the same bytes.
    files['Corefile'] = f'''{zone}:53 {{
    bind {tailnet}
    acl {{
        allow net 100.64.0.0/10
        block
    }}
    file tailnet.zone {zone} {{
        reload 0
    }}
}}
{zone}:53 {{
    bind 127.0.0.1 {host}
    acl {{
        allow net 127.0.0.1/32 10.44.0.0/30 10.42.0.0/16
        block
    }}
    file internal.zone {zone} {{
        reload 0
    }}
}}
.:53 {{
    bind 127.0.0.1 {host}
    acl {{
        allow net 127.0.0.1/32 10.44.0.0/30 10.42.0.0/16
        block
    }}
    forward . {' '.join(upstreams)}
    cache 30
    loop
    health 127.0.0.1:18053
}}
'''
    return files


if __name__ == '__main__':
    import sys
    try:
        print(json.dumps(configuration(json.load(sys.stdin))))
    except (ValueError, KeyError, TypeError):
        raise SystemExit('Private DNS configuration rejected; existing resolver retained.') from None
