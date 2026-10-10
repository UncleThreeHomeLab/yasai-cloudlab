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


def login_guide(token, hosts):
    """Keep instructions in a separate note; CLI JSON cannot preserve passkeys."""
    from automation.identity.configuration import exact_url
    if (not hosts['loginHost'].startswith('login.') or
            hosts['adminHost'] != 'identity-admin.internal.' + hosts['loginHost'][6:]):
        raise ValueError('Login guide requires the existing private host contract')
    master = exact_url('https://' + hosts['adminHost'] + '/admin/master/console/')
    argo = exact_url('https://cd.internal.' + hosts['loginHost'][6:] + '/')
    title = 'keycloak-login-guide'
    begin, end = '[CloudLab managed login instructions]', '[/CloudLab managed login instructions]'
    instructions = '\n'.join([
        begin, 'Connect to Tailscale first. These private pages require private DNS and access.', '',
        'Keycloak master administration: ' + master,
        'Use keycloak-master-admin-login: its generated username, password and enrolled passkey.',
        'The platform account cannot administer the master realm.', '',
        'Platform / Argo CD: ' + argo,
        'Choose Keycloak login. Use keycloak-platform-admin-login: its generated username, password and enrolled passkey.',
        'Email login is disabled. The account email is a profile field, not the login username.',
        'The platform account has application roles, not Keycloak realm-management permissions.', '',
        'The public login hostname is an OIDC issuer, not a homepage. Its root and account page are denied by the gateway.',
        'Platform account self-service is under verification; do not count it as a working login path yet.', '',
        'Keep enrolled passkeys in your personal vault. Do not edit Login items through CLI JSON templates.',
        'Keep keycloak-primary-admin in CloudLab: it is the ESO recovery source. This guide contains no passwords.',
        end])
    rows = [row for row in command(['item', 'list', '--vault', 'CloudLab'], token) if row.get('title') == title]
    if len(rows) > 1:
        raise RuntimeError('Duplicate login guide title; no changes made')
    if rows:
        current = command(['item', 'get', rows[0]['id'], '--vault', 'CloudLab'], token)
        if current.get('category') != 'SECURE_NOTE' or 'cloudlab-managed' not in current.get('tags', []):
            raise RuntimeError('Existing login guide has a conflicting owner; no changes made')
        notes = [field for field in current.get('fields', []) if field.get('id') == 'notesPlain']
        if len(notes) != 1 or notes[0].get('type') != 'STRING':
            raise RuntimeError('Login guide notes are ambiguous; no changes made')
        previous = notes[0].get('value') or ''
        if previous.count(begin) != 1 or previous.count(end) != 1 or previous.index(begin) > previous.index(end):
            raise RuntimeError('Login guide managed section changed; preserve human notes')
        before, rest = previous.split(begin, 1)
        _, after = rest.split(end, 1)
        updated = before + instructions + after
        if updated == previous:
            return {'login_guide_ready': True, 'changed': False, 'login_items_untouched': True}
        notes[0]['value'] = updated
        command(['item', 'edit', current['id'], '--vault', 'CloudLab'], token, current)
    else:
        created = command(['item', 'create', '-', '--vault', 'CloudLab'], token, {
            'title': title, 'category': 'SECURE_NOTE', 'tags': ['cloudlab-managed'],
            'fields': [{'id': 'notesPlain', 'type': 'STRING', 'purpose': 'NOTES', 'value': instructions}]})
        if created.get('title') != title or not created.get('id'):
            raise RuntimeError('Login guide creation response incomplete; inspect before retrying')
    return {'login_guide_ready': True, 'changed': True, 'login_items_untouched': True}


def main():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    values['CLOUDFLARE_HUMAN_EMAIL'] = values.get('CLOUDFLARE_HUMAN_EMAIL') or values.get('TAILSCALE_ADMIN_LOGIN')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    if sys.argv[1:] in (['--login-items'], ['--login-guide']):
        from automation.connectivity.preflight import ssh
        for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
            os.environ[key] = values[key]
        os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
        hosts = json.loads(ssh('VM', values['VM_HOST'],
            'python3 /opt/cloudlab/automation/identity/bootstrap.py inputs', timeout=60))
        with Path('/state/identity-vault-provision.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if sys.argv[1:] == ['--login-guide']:
                result = login_guide(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), hosts)
            else:
                primary = fields('keycloak-primary-admin', ('master_username', 'platform_username',
                                 'master_password', 'platform_password', 'ownership_id'))
                result = primary_login_items(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), primary, hosts)
            print(json.dumps(result))
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
