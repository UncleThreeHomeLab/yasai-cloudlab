"""Validate private tailnet/DNS declarations and derive fixed-template policy.

Only bounded intent is accepted: the declared administrator, two inventory
resolvers, one internal zone, and allow/deny tests over two fixed destinations.
Grants always follow the fixed templates below; unrelated policy is preserved.
"""
import copy
import ipaddress
import json
from pathlib import Path
import re

import yaml
from jsonschema import validate

ROOT = Path(__file__).resolve().parents[4]
SCHEMA = ROOT / 'platform/connectivity/access/policy.schema.json'
CONTRACT = ROOT / 'platform/connectivity/access/contract.json'
INVENTORY = ROOT / 'ansible/inventory.yml'

PROFILE = 'operator-private-access'
TEST_TAG = 'tag:cloudlab-denied'
RESERVED_NAMES = {'ns1', 'ns2', 's3', 'identity-admin', 'cd', 'api'}


def dns_label(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value))


def zone_name(value):
    if not isinstance(value, str) or len(value) > 253 or '.' not in value or not all(
            dns_label(part) for part in value.split('.')):
        raise ValueError('Access zone must be a canonical lowercase DNS name')
    return value


def inventory_hosts():
    """Hostnames of the two lab machines from the static inventory."""
    document = yaml.safe_load(INVENTORY.read_text())
    hosts = set()
    for group in ('k3s_servers', 'k3s_agents'):
        hosts.update((document['all']['children']['k3s_cluster']['children']
                      [group]['hosts']))
    if len(hosts) != 2:
        raise ValueError('Private DNS requires exactly two inventory resolvers')
    return hosts


def tags():
    return json.loads(CONTRACT.read_text())['tags']


def validate_policy(document):
    """Schema plus semantic checks; returns the normalized declaration."""
    validate(document, json.loads(SCHEMA.read_text()))
    tailnet, private = document['tailnet'], document['privateDNS']
    login = tailnet['administratorReference']
    zone = zone_name(tailnet['splitDNS']['zone'])
    if not zone.startswith('internal.'):
        raise ValueError('Tailnet split DNS requires a canonical internal subdomain')
    if set(tailnet['splitDNS']['resolvers']) != inventory_hosts():
        raise ValueError('Split-DNS resolvers must be exactly the inventory hosts')
    seen = set()
    for test in tailnet['accessTests']:
        identity = test['identity']
        tagged = identity.startswith('tag:')
        if tagged:
            if not re.fullmatch(r'tag:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', identity):
                raise ValueError('Access test identity must be a login or tag')
        elif not re.fullmatch(r'[^\s@]+@[^\s@]+', identity):
            raise ValueError('Access test identity must be a login or tag')
        if test['expected'] == 'allow' and identity != login:
            raise ValueError('Only the declared administrator may expect allow')
        key = (identity, test['destination'], test['expected'])
        if key in seen:
            raise ValueError('Access tests must be unique')
        seen.add(key)
    services = private['services']
    # Platform records are operator-declared per owning area; service names can
    # never take them over, and nameserver labels stay reserved everywhere.
    labels = [entry['name'] for entry in services]
    if len(set(labels)) != len(labels):
        raise ValueError('Private DNS service names must be unique')
    platform = private.get('platformNames', [])
    if RESERVED_NAMES & set(labels):
        raise ValueError('Private DNS names include reserved platform labels')
    if {'ns1', 'ns2'} & (set(labels) | set(platform)):
        raise ValueError('Private DNS nameserver labels are reserved')
    if set(labels) & set(platform):
        raise ValueError('Private DNS service and platform names overlap')
    if len(services) + len(platform) > 20:
        raise ValueError('Private DNS names exceed their bound')
    return {'profile': PROFILE, 'administrator': login, 'zone': zone,
            'resolvers': sorted(tailnet['splitDNS']['resolvers']),
            'accessTests': sorted(seen),
            'services': sorted(services, key=lambda entry: (entry['service'], entry['name'])),
            'names': sorted(labels), 'platformNames': sorted(platform)}


def split_dns(current, zone, nameservers):
    """Preserve every unrelated split-DNS domain; reject silent takeover."""
    zone_name(zone)
    if len(nameservers) != 2 or len(set(nameservers)) != 2 or any(
            ipaddress.ip_address(value) not in ipaddress.ip_network('100.64.0.0/10')
            for value in nameservers):
        raise ValueError('Split DNS requires both distinct host Tailscale IPv4 addresses')
    result = copy.deepcopy(current)
    wanted = sorted(nameservers)
    if result.get(zone) is not None and sorted(result[zone]) != wanted:
        raise ValueError('Private split-DNS domain already selects different resolvers')
    result[zone] = wanted
    return result


def cluster_policy(current, login):
    """Additive cluster tags, service approvals and fixed administrator grants."""
    if 'grants' not in current and 'acls' not in current:
        raise ValueError('Host policy must be established before adding cluster access')
    names = tags()
    result = copy.deepcopy(current)
    owners = result.setdefault('tagOwners', {})
    for name, tag in names.items():
        wanted = [login] if name == 'operator' else [names['operator']]
        if tag in owners and owners[tag] != wanted:
            raise ValueError('An access tag already has a different owner')
        owners[tag] = wanted
    services = result.setdefault('autoApprovers', {}).setdefault('services', {})
    for service, device in [('ingressService', 'ingressDevice'), ('apiService', 'apiDevice')]:
        tag, wanted = names[service], [names[device]]
        if tag in services and services[tag] != wanted:
            raise ValueError('A service approval already has different advertisers')
        services[tag] = wanted
    grants = result.setdefault('grants', [])
    for tag in (names['ingressService'], names['apiService']):
        wanted = {'src': [login], 'dst': [tag], 'ip': ['tcp:443']}
        matches = [g for g in grants if g.get('dst') == [tag]]
        if matches and matches != [wanted]:
            raise ValueError('An access grant has a different owner or permission set')
        if wanted not in grants:
            grants.append(wanted)
    return result


def _targets(test):
    """Accept/deny targets of a single-verdict test; None is never managed."""
    if test.get('accept') and test.get('deny') or 'src' not in test:
        return None
    return list(test.get('accept') or []) + list(test.get('deny') or [])


def _dns_shape(test):
    """Managed tests point only at tailnet DNS; external and mixed tests never match."""
    targets = _targets(test)
    if not targets:
        return False
    for target in targets:
        host, separator, port = target.rpartition(':')
        try:
            if not (separator and port == '53'
                    and ipaddress.ip_address(host) in ipaddress.ip_network('100.64.0.0/10')):
                return False
        except ValueError:
            return False
    return True


def _gateway_shape(test, gateway):
    targets = _targets(test)
    return bool(targets) and all(target in gateway for target in targets)


def dns_grants(current, login, servers, others=()):
    """Administrator-only DNS grants plus allow/deny tests; retain the rest."""
    split_dns({}, 'internal.example.invalid', servers)
    result = copy.deepcopy(current)
    desired = {'src': [login], 'dst': sorted(servers), 'ip': ['tcp:53', 'udp:53']}
    grants = result.setdefault('grants', [])
    conflicts = [g for g in grants if sorted(g.get('dst', [])) == sorted(servers)]
    if conflicts and conflicts != [desired]:
        raise ValueError('DNS addresses already have conflicting grant ownership')
    if desired not in grants:
        grants.append(desired)
    tests = result.setdefault('tests', [])
    # Stale server addresses would mismatch the new grants; drop managed DNS
    # tests before appending the current ones.
    tests[:] = [test for test in tests if not _dns_shape(test)]
    for protocol in ('tcp', 'udp'):
        for user in sorted(set(others) | {login, TEST_TAG}):
            test = {'src': user, 'proto': protocol,
                    'accept' if user == login else 'deny': [s + ':53' for s in sorted(servers)]}
            if test not in tests:
                tests.append(test)
    return result


def declared_tests(policy, login, servers):
    """Map declared access tests onto managed destinations; deny by default."""
    names = tags()
    servers = sorted(servers)
    entries = []
    for identity, destination, expected in policy['accessTests']:
        if destination == 'private-gateway':
            targets = [names['ingressService'] + ':443']
        else:
            targets = [server + ':53' for server in servers]
        # Declarations say allow/deny; the native policy tests accept/deny.
        entries.append({'src': identity, 'accept' if expected == 'allow' else 'deny': targets})
    return entries


def candidate(current, policy, servers, other_users=()):
    """Full managed tailnet state: cluster access, DNS grants and tests."""
    login = policy['administrator']
    result = dns_grants(cluster_policy(current, login), login, servers, other_users)
    tests = result.setdefault('tests', [])
    names = tags()
    gateway = [names['ingressService'] + ':443', names['apiService'] + ':443']
    tests[:] = [test for test in tests if not _gateway_shape(test, set(gateway))]
    for test in [{'src': login, 'accept': gateway}] + [
            {'src': user, 'deny': gateway}
            for user in sorted(set(other_users) | {TEST_TAG}) if user != login]:
        if test not in tests:
            tests.append(test)
    for test in declared_tests(policy, login, servers):
        if test not in tests:
            tests.append(test)
    return result
