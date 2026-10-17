"""Resolve private data identities in the runner without publishing vault contents."""
import json
from pathlib import Path
import sys
import yaml
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from playbooks.secrets.files.vault import fields
from playbooks.argocd.files.render import committed_payload
from playbooks.data.files.chart import check, render


def payload():
    check()
    result = committed_payload()
    app = fields('cnpg-notes-production', ('username', 'database'))
    migration = fields('cnpg-notes-migration', ('username', 'database'))
    backup = fields('cnpg-backup', ('username',))
    s3 = fields('s3-notes-production', ('BUCKET', 'ENDPOINT', 'REGION'))
    endpoint = urlsplit(s3['ENDPOINT'])
    if (endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password
            or endpoint.port not in (None, 443) or endpoint.path not in ('', '/') or endpoint.query or endpoint.fragment
            or not endpoint.hostname.startswith('s3.internal.') or s3['REGION'] != 'us-east-1'):
        raise ValueError('Unexpected data endpoint or region contract')
    if app['database'] != migration['database']:
        raise ValueError('Application and migration identities must target the same database')
    result['values'] = {'s3Host': endpoint.hostname, 'database': app['database'],
                        'applicationRole': app['username'], 'migrationRole': migration['username'],
                        'backupRole': backup['username'], 'bucket': s3['BUCKET'], 'maintenance': False,
                        'hibernated': False}
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    if public.get('identity', {}).get('enabled'):
        keycloak = fields('cnpg-keycloak', ('username', 'database'))
        result['values']['identity'] = {'enabled': True, 'database': keycloak['database'], 'role': keycloak['username']}
    if public.get('services', {}).get('enabled'):
        from automation.services.inputs import catalog
        from playbooks.data.files.requests import request, resolve, protect
        service_catalog = catalog(required=True)
        requests = [request(entry['approval']['name'], entry['definition']['data'], service_catalog['dataApprovals'])
                    for entry in service_catalog['catalog'] if entry['definition']['data']]
        result['values']['serviceConsumers'] = sorted({row['namespace'] for row in requests if 'database' in row})
        resolved = resolve(requests, fields)
        protect(resolved, result['values'])
        # The original notes database/bucket already have their data-module owner.
        for row in resolved:
            if row.get('database', {}).get('name') == app['database']:
                db = row.pop('database')
                if db['applicationRole'] != app['username'] or db['migrationRole'] != migration['username']:
                    raise ValueError('Existing notes database scope differs from the approved service request')
            if row.get('bucket', {}).get('name') == s3['BUCKET']:
                if row.pop('bucket')['item'] != 's3-notes-production':
                    raise ValueError('Existing notes bucket scope differs from the approved service request')
        result['values']['serviceRequests'] = [row for row in resolved if set(row) - {'service', 'namespace'}]
    render('configuration', result['values'])
    return {key: result[key] for key in ('repository', 'branch', 'revision', 'values')}


if __name__ == '__main__':
    try:
        print(json.dumps(payload()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Data input resolution failed') from None
