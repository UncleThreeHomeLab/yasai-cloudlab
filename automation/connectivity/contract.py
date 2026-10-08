"""Validate access inputs before any account or Kubernetes mutation."""
import base64
import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / 'platform/connectivity/access/contract.json'


def dns_label(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value))


def zone_name(value):
    if not isinstance(value, str) or len(value) > 253 or '.' not in value or not all(
            dns_label(part) for part in value.split('.')):
        raise ValueError('Access zone must be a canonical lowercase DNS name')
    return value


def host_rules(value, zone):
    """Each public name has an explicit classification; private names never enter it."""
    zone_name(zone)
    if not isinstance(value, list) or not value or len(value) > 10:
        raise ValueError('Declare between one and ten public access hostnames')
    seen = set()
    result = []
    for rule in value:
        if not isinstance(rule, dict) or set(rule) != {'name', 'access'}:
            raise ValueError('Hostname rules require only name and access')
        name = rule['name']
        if not dns_label(name) or name == 'internal' or name in seen:
            raise ValueError('Public hostname labels must be unique and outside the private zone')
        if rule['access'] not in ('public', 'human', 'machine'):
            raise ValueError('Each hostname requires public, human or machine classification')
        seen.add(name)
        result.append({'hostname': name + '.' + zone, 'access': rule['access']})
    return sorted(result, key=lambda rule: rule['hostname'])


def private_names(value):
    if not isinstance(value, list) or not value or len(value) > 20 or not all(isinstance(name, str) for name in value) or len(set(value)) != len(value):
        raise ValueError('Declare between one and twenty unique private hostname labels')
    if not all(dns_label(name) for name in value):
        raise ValueError('Private hostname labels must be canonical DNS labels')
    return sorted(value)


def runtime_rule(rule):
    if not isinstance(rule, dict) or set(rule) != {'hostname', 'access'} or rule['access'] not in ('public', 'human', 'machine'):
        raise ValueError('Runtime hostname requires an explicit access classification')
    zone_name(rule['hostname'])
    if 'internal' in rule['hostname'].split('.'):
        raise ValueError('Private hostnames cannot enter public tunnel configuration')
    return rule


def tunnel_identity(token, account, tunnel):
    """Decode only to cross-check selection, never to authenticate or log credentials."""
    try:
        document = json.loads(base64.b64decode(token, validate=True))
    except (ValueError, TypeError, UnicodeDecodeError):
        raise ValueError('Saved tunnel credential has invalid encoding') from None
    if not isinstance(document, dict) or document.get('a') != account or document.get('t') != tunnel or not document.get('s'):
        raise ValueError('Saved tunnel credential does not match the selected account and tunnel')


def gateway_address(value, *, tailnet):
    address = ipaddress.IPv4Address(value)
    network = ipaddress.IPv4Network('100.64.0.0/10' if tailnet else '10.43.0.0/16')
    if address not in network:
        raise ValueError('Private gateway address is outside its declared network')
    return str(address)


def policy():
    return json.loads(POLICY.read_text())
