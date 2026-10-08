"""Local, explicit data credential provisioning; ESO retains its read-only token."""
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import sys

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.credentials.provision import ensure_items
from automation.credentials.vault import fields
from automation.connectivity.cloudflare import API

CONTRACT = json.loads((ROOT / 'platform/data/contract.json').read_text())


def definitions(endpoint):
    from urllib.parse import urlsplit
    parsed = urlsplit(endpoint)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.port not in (None, 443) or parsed.path not in ('', '/') or parsed.query
            or parsed.fragment or not parsed.hostname.startswith('s3.internal.')):
        raise ValueError('Data endpoint must be the selected private HTTPS S3 hostname')
    names = {
        'cnpg-notes-production': {'username': 'notes_app', 'database': 'notes'},
        'cnpg-notes-migration': {'username': 'notes_migration', 'database': 'notes'},
        'cnpg-backup': {'username': 'cloudlab_backup'},
        's3-notes-production': {'BUCKET': 'notes', 'ENDPOINT': endpoint.rstrip('/'), 'REGION': 'us-east-1'},
    }
    result = {}
    for item, schema in CONTRACT['items'].items():
        result[item] = {}
        for field, kind in schema.items():
            if field in names.get(item, {}):
                factory = lambda value=names[item][field]: value
            elif field == 'ACCESS_KEY_ID':
                factory = lambda: secrets.token_hex(16)
            else:
                factory = lambda: secrets.token_urlsafe(48)
            result[item][field] = kind, factory
    return result


def main():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    token = values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    if not token:
        raise RuntimeError('Missing .env input: OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN', '')
    dns = fields('cloudlab-dns01', ('API_TOKEN', 'ZONE_ID'))
    if not re.fullmatch(r'[a-f0-9]{32}', dns['ZONE_ID']):
        raise ValueError('Invalid DNS zone identifier')
    zone = API(dns['API_TOKEN']).request('GET', 'zones/' + dns['ZONE_ID'])
    if zone.get('id') != dns['ZONE_ID'] or zone.get('status') != 'active':
        raise RuntimeError('Data provisioning requires the existing active DNS zone')
    endpoint = 'https://' + CONTRACT['s3_label'] + '.internal.' + zone['name']
    desired = definitions(endpoint)
    # Shared Compose state serializes concurrent runs from this workstation.
    # Cross-workstation provisioning remains one operator at a time.
    with Path('/state/data-vault-provision.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = ensure_items(token, desired)
        # Verify the existing ESO reader can consume each created or retained item.
        for name, schema in CONTRACT['items'].items():
            fields(name, schema)
        result['reader_verified'] = True
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError) as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError))
                         else 'Data credential provisioning unavailable') from None
