"""Native external adapter; no provider CRUD or additional service state engine."""
import copy
import json

from playbooks.services.files.contract import external_route, exposure_request


def declarations(definition, desired, *, operation, origin, application=None):
    if operation not in ('ready', 'route', 'publish', 'withdraw-dns', 'withdraw-route'):
        raise ValueError('Unsupported service exposure operation')
    exposure = exposure_request(definition)
    route = external_route(definition, origin, application)
    key = 'service_' + definition['name'].replace('-', '_')
    result = copy.deepcopy(desired)
    entries = result.setdefault('service_exposures', {})
    previous = entries.get(key)
    binding = {'exposure': exposure, 'origin': origin, 'application': route['application']}
    if previous and any(previous.get(field) != value for field, value in binding.items()):
        raise ValueError('Exposure change requires explicit withdrawal and migration')
    if any(item['hostname'] == exposure['hostname'] for item in desired['routes'].values()) or any(
            other != key and value['exposure']['hostname'] == exposure['hostname'] for other, value in entries.items()):
        raise ValueError('Service exposure cannot take over a shared or unrelated hostname')
    value = dict(binding, routed=previous['routed'] if previous else False,
                 published=previous['published'] if previous else False)
    if operation == 'route': value['routed'] = True
    if operation == 'publish':
        if not value['routed']:
            raise ValueError('DNS publication requires verified routing first')
        value['published'] = True
    if operation == 'withdraw-dns': value['published'] = False
    if operation == 'withdraw-route':
        if value['published']:
            raise ValueError('Withdraw DNS before tunnel routing')
        value['routed'] = False
    entries[key] = value
    return result


def guarded_plan(document, definition, operation):
    """Lifecycle may change only its DNS and selected tunnel entries."""
    key = 'service_' + definition['name'].replace('-', '_')
    dns_address = 'cloudflare_dns_record.service_publication[' + json.dumps(key) + ']'
    for resource in document.get('resource_changes', []):
        if resource.get('previous_address') or resource.get('change', {}).get('importing'):
            raise ValueError('Service lifecycle cannot import or move native ownership')
        if resource.get('mode') != 'managed' or resource['change']['actions'] == ['no-op']:
            continue
        address, change = resource['address'], resource['change']
        if address == dns_address:
            expected = ['create'] if operation == 'publish' else ['delete'] if operation == 'withdraw-dns' else []
            if change['actions'] != expected:
                raise ValueError('Service lifecycle proposed unexpected DNS mutation')
            value = change.get('after') or change.get('before') or {}
            if value.get('name') != definition['exposure']['hostname']:
                raise ValueError('DNS plan differs from reviewed exposure')
        elif address == 'cloudflare_zero_trust_tunnel_cloudflared_config.routing':
            if operation not in ('route', 'withdraw-route') or change['actions'] != ['update']:
                raise ValueError('Tunnel mutation is outside this lifecycle operation')
            before, after = change['before'], change['after']
            for field in ('id', 'account_id', 'tunnel_id', 'source'):
                if before.get(field) != after.get(field):
                    raise ValueError('Service lifecycle must preserve shared tunnel identity')
            hostname = definition['exposure']['hostname']
            def unrelated(value):
                configuration = copy.deepcopy(value['config'])
                configuration['ingress'] = [row for row in configuration['ingress'] if row.get('hostname') != hostname]
                return configuration
            if unrelated(before) != unrelated(after):
                raise ValueError('Service lifecycle changed unrelated tunnel routing')
            selected = [row for row in after['config']['ingress'] if row.get('hostname') == hostname]
            if len(selected) != (1 if operation == 'route' else 0):
                raise ValueError('Tunnel plan does not match selected service operation')
            if selected and (not selected[0]['service'].startswith('https://') or selected[0]['origin_request'].get('no_tls_verify') is not False):
                raise ValueError('Service origin requires verified TLS')
            if selected:
                origin = selected[0]['origin_request']
                hostname = definition['exposure']['hostname']
                if origin.get('origin_server_name') != hostname or origin.get('http_host_header') != hostname:
                    raise ValueError('Service origin must preserve exact TLS SNI and hostname')
                protected = definition['exposure']['access'] != 'public'
                access = origin.get('access') or {}
                if protected and (access.get('required') is not True or len(access.get('aud_tag') or []) != 1):
                    raise ValueError('Protected service origin must enforce its exact Access audience')
        else:
            raise ValueError('Service lifecycle cannot mutate shared or unrelated external resources')
