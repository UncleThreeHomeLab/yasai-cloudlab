"""Narrow additive tailnet policy for separately tagged service and device identities."""
import copy

from automation.connectivity.contract import policy, zone_name


def tag_owners(current, login):
    settings = policy()
    tags = settings['tags']
    if not isinstance(login, str) or '@' not in login or any(c.isspace() for c in login):
        raise ValueError('TAILSCALE_ADMIN_LOGIN must identify the approved administrator')
    if 'grants' not in current and 'acls' not in current:
        raise ValueError('Host policy must be established before adding cluster access')
    result = copy.deepcopy(current)
    owners = result.setdefault('tagOwners', {})
    for name, tag in tags.items():
        wanted = [login] if name == 'operator' else [tags['operator']]
        if tag in owners and owners[tag] != wanted:
            raise ValueError('An access tag already has a different owner')
        owners[tag] = wanted
    return result


def candidate(current, login, other_users=()):
    tags = policy()['tags']
    result = tag_owners(current, login)
    services = result.setdefault('autoApprovers', {}).setdefault('services', {})
    for service, device in [('ingressService', 'ingressDevice'), ('apiService', 'apiDevice')]:
        tag = tags[service]
        wanted = [tags[device]]
        if tag in services and services[tag] != wanted:
            raise ValueError('A service approval already has different advertisers')
        services[tag] = wanted
    grants = result.setdefault('grants', [])
    for tag in (tags['ingressService'], tags['apiService']):
        wanted = {'src': [login], 'dst': [tag], 'ip': ['tcp:443']}
        matches = [g for g in grants if g.get('dst') == [tag]]
        if matches and matches != [wanted]:
            raise ValueError('An access grant has a different owner or permission set')
        if wanted not in grants:
            grants.append(wanted)
    tests = result.setdefault('tests', [])
    destination = [tags['ingressService'] + ':443', tags['apiService'] + ':443']
    for test in [{'src': login, 'accept': destination}] + [
            {'src': user, 'deny': destination} for user in sorted(set(other_users) | {'tag:cloudlab-denied'})
            if user != login]:
        if test not in tests:
            tests.append(test)
    return result


def split_dns(current, zone, nameservers):
    """Preserve every unrelated split-DNS domain; reject silent takeover."""
    import ipaddress
    zone_name(zone)
    if len(nameservers) != 2 or len(set(nameservers)) != 2 or any(
            ipaddress.ip_address(value) not in ipaddress.ip_network('100.64.0.0/10') for value in nameservers):
        raise ValueError('Split DNS requires both distinct host Tailscale IPv4 addresses')
    result = copy.deepcopy(current)
    existing = result.get(zone)
    wanted = sorted(nameservers)
    if existing is not None and sorted(existing) != wanted:
        raise ValueError('Private split-DNS domain already selects different resolvers')
    result[zone] = wanted
    return result
