"""Provision missing identity bootstrap inputs while preserving existing values."""
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
from automation.credentials.provision import ensure_items, command
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


def primary_login_items(token, primary, hosts):
    """Create browser Login copies once; never modify an enrolled passkey item."""
    from automation.identity.configuration import exact_url, name
    if (not re.fullmatch('[a-f0-9]{32}', primary['ownership_id']) or
            any(not isinstance(primary[realm + '_password'], str) or len(primary[realm + '_password']) < 32
                for realm in ('master', 'platform')) or not hosts['loginHost'].startswith('login.') or
            hosts['adminHost'] != 'identity-admin.internal.' + hosts['loginHost'][6:]):
        raise ValueError('Primary Login requires the existing scoped owner and private host contract')
    for realm in ('master', 'platform'):
        name(primary[realm + '_username'])
    desired = {}
    for realm in ('master', 'platform'):
        urls = ([hosts['adminHost'] + '/admin/master/console/'] if realm == 'master'
                else ['cd.internal.' + hosts['loginHost'][6:] + '/', hosts['loginHost'] + '/'])
        desired['keycloak-' + realm + '-admin-login'] = {
            'title': 'keycloak-' + realm + '-admin-login', 'category': 'LOGIN',
            'tags': ['cloudlab-managed'],
            'urls': [{'href': exact_url('https://' + url), 'primary': index == 0}
                     for index, url in enumerate(urls)],
            'fields': [
                {'id': 'username', 'label': 'username', 'type': 'STRING', 'purpose': 'USERNAME',
                 'value': primary[realm + '_username']},
                {'id': 'password', 'label': 'password', 'type': 'CONCEALED', 'purpose': 'PASSWORD',
                 'value': primary[realm + '_password']},
                {'id': 'cloudlab-primary-owner', 'label': 'cloudlab-primary-owner', 'type': 'STRING',
                 'value': primary['ownership_id']},
            ]}
    if not token:
        raise RuntimeError('Missing .env input: OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    existing = command(['item', 'list', '--vault', 'CloudLab'], token)
    found = {}
    for title, document in desired.items():
        rows = [row for row in existing if row.get('title') == title]
        if len(rows) > 1:
            raise RuntimeError('Duplicate primary Login item; values preserved')
        found[title] = bool(rows)
        if rows:
            actual = command(['item', 'get', rows[0]['id'], '--vault', 'CloudLab'], token)
            if actual.get('category') != 'LOGIN':
                raise RuntimeError('Primary Login category conflicts; values preserved')
            for field in document['fields']:
                matches = [row for row in actual.get('fields', []) if row.get('id') == field['id']]
                if len(matches) != 1 or any(matches[0].get(key) != field[key] for key in ('type', 'value')):
                    raise RuntimeError('Primary Login credentials or owner changed; values preserved')
            if not {row['href'] for row in document['urls']} <= {row.get('href') for row in actual.get('urls', [])}:
                raise RuntimeError('Primary Login websites changed; values preserved')
    result = {'created': [], 'preserved': [], 'passkeys_created': False}
    for title, document in desired.items():
        if found[title]:
            result['preserved'].append(title)
            continue
        if any(row.get('title') == title for row in command(['item', 'list', '--vault', 'CloudLab'], token)):
            raise RuntimeError('Primary Login appeared during provisioning; rerun to validate')
        created = command(['item', 'create', '-', '--vault', 'CloudLab'], token, document)
        if not created.get('id') or created.get('title') != title:
            raise RuntimeError('Primary Login creation response incomplete; inspect before retrying')
        result['created'].append(title)
    return result


def main():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    values['CLOUDFLARE_HUMAN_EMAIL'] = values.get('CLOUDFLARE_HUMAN_EMAIL') or values.get('TAILSCALE_ADMIN_LOGIN')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    if sys.argv[1:] == ['--login-items']:
        from automation.connectivity.preflight import ssh
        for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
            os.environ[key] = values[key]
        os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
        hosts = json.loads(ssh('VM', values['VM_HOST'],
            'python3 /opt/cloudlab/automation/identity/bootstrap.py inputs', timeout=60))
        primary = fields('keycloak-primary-admin', ('master_username', 'platform_username',
                         'master_password', 'platform_password', 'ownership_id'))
        with Path('/state/identity-vault-provision.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(primary_login_items(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), primary, hosts)))
        return
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
