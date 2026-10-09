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


def primary_definitions(values):
    email = values.get('CLOUDFLARE_HUMAN_EMAIL')
    if not email or '@' not in email:
        raise RuntimeError('Primary provisioning requires the already verified human Access identity')
    return {'keycloak-primary-admin': {
        'master_username': ('STRING', lambda: 'master-' + secrets.token_hex(8)),
        'platform_username': ('STRING', lambda: 'operator-' + secrets.token_hex(8)),
        'master_password': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
        'platform_password': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
        'ownership_id': ('STRING', lambda: secrets.token_hex(16)),
        'email': ('STRING', lambda: email),
        'email_verified': ('STRING', lambda: 'true'),
    }}


def main():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    values['CLOUDFLARE_HUMAN_EMAIL'] = values.get('CLOUDFLARE_HUMAN_EMAIL') or values.get('TAILSCALE_ADMIN_LOGIN')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    selected = definitions()
    if sys.argv[1:] == ['--primary']:
        for key, value in values.items():
            if value is not None:
                os.environ[key] = value
        os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
        from automation.connectivity.human import retained
        if not retained().get('human_policy_matches_signed_proof'):
            raise RuntimeError('Signed existing human Access proof must precede primary provisioning')
        selected = primary_definitions(values)
    elif sys.argv[1:]:
        raise ValueError('Unsupported identity credential provisioning mode')
    with Path('/state/identity-vault-provision.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = ensure_items(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), selected)
        for title, schema in selected.items():
            retrieved = fields(title, schema)
            if title == 'keycloak-primary-admin' and retrieved['email'] != values['CLOUDFLARE_HUMAN_EMAIL']:
                raise RuntimeError('Primary identity differs from the existing verified human; values preserved')
        result['reader_verified'] = True
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError))
                         else 'Identity provisioning failed; private diagnostics withheld') from None
