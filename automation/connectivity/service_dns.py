"""Service labels use the existing independent DNS owner, never public DNS."""
import copy

try:
    from .contract import dns_label, zone_name
except ImportError:
    from contract import dns_label, zone_name


def desired(payload, exposure, baseline, *, published):
    if exposure['class'] != 'private' or exposure['access'] != 'tailnet':
        raise ValueError('Private DNS accepts only the private exposure contract')
    hostname = zone_name(exposure['hostname'])
    label, zone = hostname.split('.', 1)
    if (zone != payload['zone'] or not dns_label(label) or label in set(baseline) | {'ns1', 'ns2', 's3', 'identity-admin', 'cd', 'api'}):
        raise ValueError('Service cannot take over shared or foreign private DNS')
    result = copy.deepcopy(payload)
    names = set(payload['names'])
    if published: names.add(label)
    else: names.discard(label)
    result['names'] = sorted(names)
    return result
