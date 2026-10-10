"""Add only private-zone DNS and administrator DNS grants; retain unrelated policy."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'automation/tailscale'))
from control import API
from automation.connectivity.tailnet import split_dns


def dns_policy(current, login, servers, others=()):
    import copy
    # Reuse canonical resolver validation; the synthetic zone is never published.
    split_dns({}, 'internal.example.invalid', servers)
    if not login or '@' not in login:
        raise ValueError('An explicit administrator is required')
    result = copy.deepcopy(current)
    desired = {'src': [login], 'dst': sorted(servers), 'ip': ['tcp:53', 'udp:53']}
    grants = result.setdefault('grants', [])
    conflicts = [g for g in grants if sorted(g.get('dst', [])) == sorted(servers)]
    if conflicts and conflicts != [desired]:
        raise ValueError('DNS addresses already have conflicting grant ownership')
    if desired not in grants:
        grants.append(desired)
    tests = result.setdefault('tests', [])
    for protocol in ('tcp', 'udp'):
        for user in sorted(set(others) | {login, 'tag:cloudlab-denied'}):
            test = {'src': user, 'proto': protocol,
                    'accept' if user == login else 'deny': [s + ':53' for s in sorted(servers)]}
            if test not in tests:
                tests.append(test)
    return result


def run(payload):
    api = API('tailscale-policy')
    zone, servers = payload['zone'], payload['nameservers']
    before, _ = api.request('GET', 'tailnet/-/dns/split-dns')
    desired_dns = split_dns(before, zone, servers)
    identity_host = payload['identity_host']
    if identity_host != 'login.' + zone.removeprefix('internal.'):
        raise ValueError('Identity split DNS must retain the canonical realm hostname')
    desired_dns = split_dns(desired_dns, identity_host, servers)
    policy, etag = api.request('GET', 'tailnet/-/acl')
    devices, _ = api.request('GET', 'tailnet/-/devices')
    others = {d['user'] for d in devices.get('devices', []) if d.get('user')}
    desired = dns_policy(policy, os.environ.get('TAILSCALE_ADMIN_LOGIN', ''), servers, others)
    if api.request('POST', 'tailnet/-/acl/validate', desired)[0]:
        raise RuntimeError('DNS policy validation failed')
    if desired != policy:
        if not etag:
            raise RuntimeError('Policy API supplied no concurrency guard')
        api.request('POST', 'tailnet/-/acl', desired, etag)
    if api.request('GET', 'tailnet/-/acl')[0] != desired:
        raise RuntimeError('DNS grants did not converge')
    if before != desired_dns:
        # PATCH changes only the two owned domains; retain unrelated split DNS.
        api.request('PATCH', 'tailnet/-/dns/split-dns', {name: desired_dns[name] for name in (zone, identity_host)})
    actual, _ = api.request('GET', 'tailnet/-/dns/split-dns')
    if (any(actual.get(name) != desired_dns[name] for name in (zone, identity_host)) or
            any(actual.get(k) != v for k, v in before.items() if k not in (zone, identity_host))):
        raise RuntimeError('Split DNS did not converge or unrelated configuration changed')
    print(json.dumps({'changed': desired != policy or desired_dns != before, 'split_dns_configured': True}))


if __name__ == '__main__':
    try:
        run(json.load(sys.stdin))
    except Exception:
        raise SystemExit('Tailnet DNS reconciliation failed; host SSH policy retained.') from None
