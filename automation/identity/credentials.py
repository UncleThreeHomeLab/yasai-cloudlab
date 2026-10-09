"""Provision missing identity bootstrap inputs while preserving existing values."""
import fcntl
import json
import os
from pathlib import Path
import secrets
import sys

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.credentials.provision import ensure_items
from automation.credentials.vault import fields


def definitions():
    return {
        'cnpg-keycloak': {
            'username': ('STRING', lambda: 'keycloak'),
            'database': ('STRING', lambda: 'keycloak'),
            'password': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
        },
        'keycloak-bootstrap-admin': {
            'username': ('STRING', lambda: 'temporary-bootstrap'),
            'password': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
        },
        'keycloak-realm-writers': {
            'platform_client_secret': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
            'applications_client_secret': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
        },
        'keycloak-realm-health': {
            'platform_client_secret': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
            'applications_client_secret': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
        },
        'keycloak-client-secrets': {
            'client_secrets': ('CONCEALED', lambda: json.dumps({'platform': {}, 'applications': {}}, sort_keys=True)),
        },
    }


def main():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    with Path('/state/identity-vault-provision.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = ensure_items(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), definitions())
        for title, schema in definitions().items():
            fields(title, schema)
        result['reader_verified'] = True
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError))
                         else 'Identity provisioning failed; private diagnostics withheld') from None
