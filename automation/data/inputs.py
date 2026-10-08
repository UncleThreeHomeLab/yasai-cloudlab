"""Resolve private data identities in the runner without publishing vault contents."""
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.credentials.vault import fields
from automation.gitops.render import committed_payload
from automation.data.chart import check, render


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
                        'backupRole': backup['username'], 'bucket': s3['BUCKET'], 'maintenance': False}
    render('configuration', result['values'])
    return {key: result[key] for key in ('repository', 'branch', 'revision', 'values')}


if __name__ == '__main__':
    try:
        print(json.dumps(payload()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Data input resolution failed') from None
