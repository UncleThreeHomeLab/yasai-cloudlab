"""One service intent; adapters use existing identity, data and exposure owners."""
import copy
import json
from pathlib import Path
import re
import subprocess

import yaml

from playbooks.access.files.contract import runtime_rule, zone_name
from automation.identity.configuration import client

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / 'charts/service'


def render(definition, namespace='cloudlab-service-proof'):
    result = subprocess.run(['helm', 'template', definition.get('name', 'invalid'), str(CHART),
                             '-n', namespace, '--kube-version', '1.36.5', '-f', '-'],
                            input=json.dumps(definition), capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise ValueError('Service definition violates the chart schema or template contract')
    return [obj for obj in yaml.safe_load_all(result.stdout) if obj]


def validate(definition):
    render(definition)
    value = copy.deepcopy(definition)
    ports = value['ports']
    if len({p['name'] for p in ports}) != len(ports) or len({p['port'] for p in ports}) != len(ports):
        raise ValueError('Service ports must be distinct')
    for probe in value['health'].values():
        if probe['port'] not in {p['name'] for p in ports}:
            raise ValueError('Health probe must use a declared port')
    for unit in ('cpu', 'memory'):
        pattern, multiplier = (r'([1-9][0-9]*)m', 1) if unit == 'cpu' else (r'([1-9][0-9]*)Mi', 1)
        amounts = [int(re.fullmatch(pattern, value['resources'][kind][unit])[1]) * multiplier
                   for kind in ('requests', 'limits')]
        if amounts[0] > amounts[1]:
            raise ValueError('Resource request exceeds limit')
        copies = value['replicas'] + (0 if value['persistence']['enabled'] else 1)
        if amounts[0] * copies > 1000 or amounts[1] * copies > 2000:
            raise ValueError('Service exceeds its namespace resource budget')
    mounts = value.get('secrets', []) + value.get('configMaps', [])
    if any(m['name'] in ('temporary', 'dependencies', 'data') for m in mounts):
        raise ValueError('Mount names are reserved for chart-owned volumes')
    if len({m['name'] for m in mounts}) != len(mounts) or len({m['mountPath'] for m in mounts}) != len(mounts):
        raise ValueError('Mount names and paths must be distinct')
    if value['persistence']['enabled'] and int(value['persistence']['size'][:-2]) > 4:
        raise ValueError('Persistence exceeds its namespace storage budget')
    references = [request['credentialReference'] for request in value['data'].values()]
    if len(set(references)) != len(references): raise ValueError('Data credentials must have distinct scopes')
    exposures = [value['exposure']] + value.get('additionalExposures', [])
    if value['exposure']['class'] == 'none' and value.get('additionalExposures'):
        raise ValueError('Private views require an exposed primary service')
    for exposure in exposures:
        if exposure['class'] != 'none':
            zone_name(exposure['hostname'])
            if exposure['port'] not in {p['port'] for p in ports}:
                raise ValueError('Route must use a declared port')
            if exposure['class'] == 'public':
                runtime_rule({key: exposure[key] for key in ('hostname', 'access')})
            elif '.internal.' not in exposure['hostname'] or exposure['access'] != 'tailnet':
                raise ValueError('Private exposure requires private DNS and tailnet protection')
    pairs = [(exposure.get('hostname'), exposure.get('path')) for exposure in exposures if exposure['class'] != 'none']
    if len(set(pairs)) != len(pairs): raise ValueError('Route exposures must be distinct')
    if any(exposure['class'] == 'none' for exposure in value.get('additionalExposures', [])):
        raise ValueError('Additional exposure must select a public or private route')
    oidc = value['oidc']
    if oidc['enabled']:
        if oidc['public'] and 'secretReference' in oidc:
            raise ValueError('Public OIDC clients must not select secrets')
        if oidc.get('secretReference') in references:
            raise ValueError('OIDC and data credentials must have distinct secret owners')
        identity_request(value, {oidc.get('secretReference'): 'x' * 48})
    return value


def identity_request(definition, secrets):
    """The identity module validates and exclusively creates/rotates/removes clients."""
    oidc, exposure = definition['oidc'], definition['exposure']
    if not oidc['enabled']:
        return None
    if exposure['class'] == 'none':
        raise ValueError('OIDC requires an exact approved callback host')
    hosts = list(dict.fromkeys(e['hostname'] for e in [exposure] + definition.get('additionalExposures', []) if e['class'] != 'none'))
    callbacks = ['https://' + host + path for host in hosts for path in oidc['callbackPaths']]
    desired = {'id': oidc['client'], 'callbacks': callbacks, 'audience': oidc['audience'],
               'public': oidc['public'], 'roles': list(oidc['roleMapping']),
               'role_groups': oidc['roleMapping'], 'scopes': oidc['scopes']}
    if oidc['public']:
        desired['web_origins'] = ['https://' + host for host in hosts]
    # Validation has no authority to generate a real secret or write a client.
    credentials = {} if oidc['public'] else {oidc['client']: secrets.get(oidc.get('secretReference'))}
    client(desired, credentials)
    if not oidc['public'] and oidc['secretReference'] not in {s['name'] for s in definition['secrets']}:
        raise ValueError('Confidential OIDC client requires its scoped mounted secret reference')
    return {'realm': oidc['realm'], 'client': desired, 'secretReference': oidc.get('secretReference')}


def exposure_request(definition):
    """Kubernetes routes and external declarations consume this same validated value."""
    value = validate(definition)['exposure']
    if value['class'] == 'none':
        return None
    return copy.deepcopy(value)


def exposure_bindings(definition):
    return [(value.get('class'), value.get('access'), value.get('hostname')) for value in
            [definition['exposure']] + definition.get('additionalExposures', [])]


def external_route(definition, origin, application=None):
    exposure = exposure_request(definition)
    if not exposure or exposure['class'] != 'public':
        raise ValueError('Only public exposure enters the Cloudflare root')
    if not re.fullmatch(r'https://[a-z0-9.-]+(?::443)?', origin):
        raise ValueError('Tunnel origin must use verified TLS')
    if (exposure['access'] == 'public') != (application is None):
        raise ValueError('Protected exposure requires the approved Access application')
    return {'hostname': exposure['hostname'], 'service': origin, 'application': application,
            'dns_comment': 'Managed service exposure'}
