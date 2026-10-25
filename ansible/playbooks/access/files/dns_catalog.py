"""Resolve the optional reserved preview prefix before host DNS changes."""
import json
import re
from pathlib import Path

import yaml

from playbooks.previews.files.contract import hostname


def declaration(settings, names):
    hostname({'instance': '0' * 32}, settings)
    prefix, zone = settings['hostname'].split('.', 1)
    if prefix in ('ns1', 'ns2'):
        raise ValueError('Private DNS nameserver labels are reserved')
    if prefix not in names:
        raise ValueError('Preview DNS prefix must be declared in PRIVATE_ACCESS_HOSTS')
    if any(re.fullmatch(re.escape(prefix) + '-[a-f0-9]{32}', name) for name in names):
        raise ValueError('Preview DNS prefix collides with an ordinary service')
    return {'prefix': prefix, 'zone': zone}


def read():
    root = Path(__file__).resolve().parents[4]
    public = yaml.safe_load((root / 'gitops/roots/public/values.yaml').read_text())
    if not public.get('previews', {}).get('enabled', False):
        return {}
    from playbooks.previews.files.source import read as catalog
    settings, _, values = catalog()
    names = json.loads(values.get('PRIVATE_ACCESS_HOSTS') or '[]')
    result = declaration(settings, names)
    from playbooks.services.files.inputs import private_dns_names
    if result['prefix'] in private_dns_names():
        raise ValueError('Preview DNS prefix collides with an ordinary service')
    return {'preview_dns': result}


if __name__ == '__main__':
    try:
        print(json.dumps(read()))
    except Exception:
        raise SystemExit('Preview DNS inputs rejected; existing resolvers retained') from None
