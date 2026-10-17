"""Enroll the verified lab owner in applications through the existing realm writer."""
import copy
import json
import os
from pathlib import Path
import re
import secrets
import sys

ROOT = Path(__file__).resolve().parents[2]


def membership(source, revoked, values):
    if (set(values) != {'username', 'password', 'email', 'ownership_id'} or
            not re.fullmatch('[a-f0-9]{32}', values.get('ownership_id', '')) or
            len(values.get('password', '')) < 48):
        raise ValueError('Applications owner requires complete independent vault credentials')
    username = values['username']
    if any(username in revoked['realms'].get(realm, {}).get('users', []) for realm in ('platform', 'applications')):
        raise ValueError('Revoked owners cannot be enrolled')
    platform = [row for row in source['realms'].get('platform', {}).get('memberships', [])
                if row['username'] == username]
    if (len(platform) != 1 or 'platform-admin' not in platform[0].get('groups', []) or
            platform[0].get('profile') != {'email': values['email'], 'verified': True}):
        raise ValueError('Applications owner must match the verified private platform owner')
    result = copy.deepcopy(source)
    rows = result['realms'].setdefault('applications', {}).setdefault('memberships', [])
    desired = {'username': username, 'groups': ['platform-admin'], 'profile': platform[0]['profile']}
    existing = [row for row in rows if row['username'] == username]
    if existing and existing != [desired]:
        raise ValueError('Applications owner membership changed; adoption refused')
    if not existing:
        rows.append(desired)
    return result


def inputs():
    from playbooks.argocd.files.github_setup import inputs as github_inputs, repository
    from automation.identity.private_source import decode_contents
    import yaml
    environment, api = github_inputs()
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = environment.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    repo = repository(environment['PRIVATE_CONFIG_REPOSITORY'])
    revision = api.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
    manifest = yaml.safe_load(decode_contents(api.request('GET',
        'repos/' + repo + '/contents/identity/configmap.yaml?ref=' + revision)))
    if (manifest.get('kind') != 'ConfigMap' or manifest.get('metadata', {}).get('name') != 'identity-private-state' or
            manifest.get('metadata', {}).get('namespace') != 'cloudlab-identity' or
            set(manifest.get('data', {})) != {'desired_state', 'revocations'}):
        raise ValueError('Applications enrollment requires the complete private identity inventory')
    return environment, api, json.loads(manifest['data']['desired_state']), json.loads(manifest['data']['revocations'])


def provision():
    import fcntl
    from playbooks.secrets.files.provision import ensure_items
    from playbooks.secrets.files.vault import fields
    environment, _, source, revoked = inputs()
    username = fields('keycloak-primary-admin', ['platform_username'])['platform_username']
    owners = [row for row in source['realms']['platform']['memberships'] if row['username'] == username]
    if len(owners) != 1 or owners[0].get('profile', {}).get('verified') is not True:
        raise ValueError('Existing owner must have a verified private profile')
    email = owners[0]['profile']['email']
    # Validate authorization before creating a secret; no credential is reused.
    membership(source, revoked, {'username': username, 'email': email,
        'password': 'x' * 48, 'ownership_id': 'a' * 32})
    os.umask(0o077)
    with Path('/state/identity-vault-provision.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = ensure_items(environment.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), {
            'keycloak-applications-owner': {
                'username': ('STRING', lambda: username), 'email': ('STRING', lambda: email),
                'password': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
                'ownership_id': ('STRING', lambda: secrets.token_hex(16))}})
        owner = fields('keycloak-applications-owner', ['username', 'password', 'email', 'ownership_id'])
        membership(source, revoked, owner)
        from automation.identity.credentials import ensure_login_items
        from automation.services.inputs import catalog
        notes = [row for row in catalog(required=True)['catalog'] if row['approval']['name'] == 'notes']
        if len(notes) != 1:
            raise ValueError('Applications Login requires the approved notes exposure')
        title = 'keycloak-applications-owner-login'
        ensure_login_items(environment.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), {title: {
            'title': title, 'category': 'LOGIN', 'tags': ['cloudlab-managed'],
            'urls': [{'href': 'https://' + notes[0]['definition']['exposure']['hostname'] + '/', 'primary': True}],
            'fields': [{'id': 'username', 'label': 'username', 'type': 'STRING', 'purpose': 'USERNAME', 'value': owner['username']},
                       {'id': 'password', 'label': 'password', 'type': 'CONCEALED', 'purpose': 'PASSWORD', 'value': owner['password']},
                       {'id': 'cloudlab-primary-owner', 'label': 'cloudlab-primary-owner', 'type': 'STRING', 'value': owner['ownership_id']}]}})
    return {'credentials_ready': True, 'created': bool(result['created']), 'existing_credentials_preserved': True}


def publish():
    from playbooks.secrets.files.vault import fields
    from automation.identity.operations import private_files
    from automation.identity.private_source import publish as private_publish
    environment, api, source, revoked = inputs()
    owner = fields('keycloak-applications-owner', ['username', 'password', 'email', 'ownership_id'])
    desired = membership(source, revoked, owner)
    if desired != source:
        local(stage=True)
    source = desired
    clients = json.loads(fields('keycloak-client-secrets', ['client_secrets'])['client_secrets'])
    # Callback producers have already validated the actual issuer; this is syntax validation only.
    return private_publish(api, environment, private_files(source, revoked, clients, 'validation.invalid'))


def local(stage=False):
    from dotenv import dotenv_values
    from playbooks.secrets.files.vault import fields
    from playbooks.access.files.preflight import ssh
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        os.environ[key] = environment[key]
    os.environ['VM_PORT'] = environment.get('VM_PORT') or '22'
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = environment.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    nonce = fields('keycloak-applications-owner', ['ownership_id'])['ownership_id']
    if not re.fullmatch('[a-f0-9]{32}', nonce):
        raise ValueError('Applications owner marker changed')
    return json.loads(ssh('VM', os.environ['VM_HOST'],
        'python3 /opt/cloudlab/automation/identity/owner_enrollment.py ' + ('stage' if stage else 'enroll'),
        input=json.dumps({'nonce': nonce}), timeout=2400))


if __name__ == '__main__':
    try:
        mode = sys.argv[1:]
        if mode in (['stage'], ['enroll']):
            sys.path.insert(0, str(ROOT))
            from automation.identity.session_fixture import enroll
            result = enroll(json.load(sys.stdin), stage=mode == ['stage'], application_owner=True)
        elif mode == ['provision']: result = provision()
        elif mode == ['publish']: result = publish()
        elif mode == ['local']: result = local()
        elif mode == ['--stage']: result = local(stage=True)
        else: raise ValueError('Unknown applications owner operation')
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Applications enrollment incomplete; preserve its identity owner checkpoint. Diagnostics withheld.') from None
