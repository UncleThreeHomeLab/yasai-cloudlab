"""Move owned human Access policies only after verified recovery and native OIDC."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def selection(state, previous):
    """Pure receipt selection keeps provider reconciliation independent of the IdP."""
    cutover = state.get('identity_cutover')
    if cutover is None:
        return previous, None
    owner = state.get('identity_provider') or {}
    binding = owner.get('binding', {})
    if (cutover.get('phase') not in ('prepared', 'configured', 'accepted') or
            cutover.get('binding') != state.get('binding') or
            cutover.get('previous') != previous or binding.get('previous') != previous or
            cutover.get('provider') != owner.get('id') or
            not re.fullmatch('[A-Za-z0-9-]{1,64}', cutover.get('provider') or '') or
            owner.get('phase') not in ('prepared', 'configured', 'accepted') or
            cutover.get('group') != '/platform-admin'):
        raise RuntimeError('Central Access receipt changed; no fallback or provider mutation permitted')
    return cutover['provider'], cutover['group']


def gate(team, since=None):
    import yaml
    from automation.identity.integrations import argo
    from automation.identity.access_provider import snapshot
    from automation.identity.maintenance import BASE, APP, NAMESPACE
    from automation.identity.emergency import current_private, vault_secret
    from automation.identity.configuration import private_request
    from urllib.parse import urlencode, quote
    from automation.mesh.kube import get
    ownership = json.loads((BASE / 'ownership.json').read_text())
    retired = json.loads((BASE / 'retirement.json').read_text())
    server = get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE)
    app = get('application.argoproj.io', APP, 'argocd')
    values = app['spec']['source']['helm']['valuesObject']
    if (retired.get('phase') != 'accepted' or retired.get('application_uid') != ownership.get('uid') or
            app.get('metadata', {}).get('uid') != ownership.get('uid') or
            retired.get('keycloak_uid') != server['metadata']['uid'] or
            values.get('bootstrapAdminEnabled') is not False or values.get('maintenance') or values.get('operation') or
            values.get('retiredEmergencyItem') != 'keycloak-emergency-' + retired.get('nonce', '')):
        raise RuntimeError('Central Access requires verified real enrollment, custody and completed recovery exercise')
    cm = (get('configmap', 'argocd-cm', 'argocd') or {}).get('data', {})
    rbac = (get('configmap', 'argocd-rbac-cm', 'argocd') or {}).get('data', {})
    expected = argo('https://' + values['loginHost'] + '/realms/platform', 'https://cd.' + values['loginHost'][6:],
                    ['https://cd.internal.' + values['loginHost'][6:]])['helm']['argo-cd']['configs']
    if (cm.get('url') != expected['cm']['url'] or
            any(rbac.get(key) != value for key, value in expected['rbac'].items()) or
            yaml.safe_load(cm.get('oidc.config', '')) != yaml.safe_load(expected['cm']['oidc.config']) or
            cm.get('users.session.duration') != '10m'):
        raise RuntimeError('Central Access requires current exact native Argo OIDC and group mapping')
    primary = vault_secret('keycloak-primary-admin')
    current_private(values, primary)
    writer = vault_secret('keycloak-realm-writers')
    origin = 'https://' + values['loginHost']
    bearer = private_request(origin + '/realms/platform/protocol/openid-connect/token', form={
        'grant_type': 'client_credentials', 'client_id': 'realm-writer',
        'client_secret': writer['platform_client_secret']})['access_token']
    admin = 'https://' + values['adminHost'] + '/admin/realms/platform'
    rows = private_request(admin + '/users?' + urlencode({'username': primary['platform_username'], 'exact': 'true'}), token=bearer)
    if (len(rows) != 1 or rows[0].get('enabled') is not True or rows[0].get('emailVerified') is not True or
            rows[0].get('email', '').lower() != primary['email'].lower() or
            rows[0].get('attributes', {}).get('cloudlab-primary-owner') != [primary['ownership_id']] or
            'webauthn-register' in rows[0].get('requiredActions', [])):
        raise RuntimeError('Central Access requires the current active enrolled primary operator')
    endpoint = admin + '/users/' + quote(rows[0]['id'], safe='')
    if (not any(row.get('type') == 'webauthn' for row in private_request(endpoint + '/credentials', token=bearer)) or
            not any(row.get('path') == '/platform-admin' for row in private_request(endpoint + '/groups', token=bearer))):
        raise RuntimeError('Central Access requires current WebAuthn and exact privileged membership')
    if since is not None:
        if type(since) is not int or not 0 < since <= time.time():
            raise RuntimeError('Fresh Access exchange requires its owned configuration timestamp')
        health = vault_secret('keycloak-realm-health')
        audit_token = private_request(origin + '/realms/platform/protocol/openid-connect/token', form={
            'grant_type': 'client_credentials', 'client_id': 'realm-health',
            'client_secret': health['platform_client_secret']})['access_token']
        events = private_request(admin + '/events?' + urlencode({'user': rows[0]['id'], 'type': 'CODE_TO_TOKEN', 'max': 100}), token=audit_token)
        if not any(row.get('type') == 'CODE_TO_TOKEN' and not row.get('error') and
                   row.get('userId') == rows[0]['id'] and row.get('clientId') == 'cloudflare-access' and
                   type(row.get('time')) is int and row['time'] > since * 1000 and
                   0 <= time.time() * 1000 - row['time'] <= 900000 for row in events):
            raise RuntimeError('Fresh dedicated-client code exchange required; cached Access SSO is insufficient')
    return snapshot(team)


def browser_gate(team, since):
    import shlex
    from automation.connectivity.preflight import ssh
    script = "import sys,json;sys.path.insert(0,'/opt/cloudlab');from automation.identity.access_cutover import gate;gate(**json.load(sys.stdin));print('verified')"
    if ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(script),
           input=json.dumps({'team': team, 'since': since}), timeout=60).strip() != 'verified':
        raise RuntimeError('Fresh dedicated-provider browser exchange was not verified')


def validate_provider(state, previous, contract):
    from automation.identity.access_provider import public_provider
    owner = state.get('identity_provider') or {}
    if (state.get('phase') != 'configured' or not state.get('binding') or
            owner.get('phase') not in ('prepared', 'configured', 'accepted') or not owner.get('id') or
            type(owner.get('credential_ready_at')) is not int or
            owner.get('binding', {}).get('previous') != previous or
            not re.fullmatch('[A-Za-z0-9-]{1,64}', owner.get('id') or '') or
            owner.get('intent') != public_provider(contract['provider']) or
            owner.get('credential_hash') != hashlib.sha256(contract['provider']['config']['client_secret'].encode()).hexdigest()):
        raise RuntimeError('Central Access requires the current dedicated provider and authenticated client')
    return owner


def prepare(state, previous, contract):
    owner = validate_provider(state, previous, contract)
    wanted = {'phase': 'prepared', 'binding': state['binding'], 'provider': owner['id'],
              'previous': previous, 'group': '/platform-admin'}
    if state.get('identity_cutover'):
        selection(state, previous)
        if any(state['identity_cutover'].get(key) != value for key, value in wanted.items() if key != 'phase'):
            raise RuntimeError('Central Access cutover inputs advanced; retain the checkpoint')
        return False
    from automation.identity.access_canary import verified
    if not verified(state):
        raise RuntimeError('Central Access requires a recent signed dedicated-provider canary login before policy cutover')
    state['identity_cutover'] = wanted
    selection(state, previous)
    return True


def local():
    from dotenv import dotenv_values
    from automation.credentials.vault import fields
    from automation.connectivity.cloudflare import API
    from automation.connectivity.checkpoint import transaction
    from automation.connectivity.preflight import ssh
    from automation.connectivity.external import run
    from automation.identity.access_provider import public_provider
    from automation.connectivity.reconcile import matches
    import shlex
    values = dotenv_values(ROOT / '.env', interpolate=False)
    for key, value in values.items():
        if value is not None and key not in ('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', 'GITHUB_PROVISION_TOKEN'):
            os.environ[key] = value
    management = fields('cloudflare-management', ('API_TOKEN', 'ACCOUNT_ID'))
    api = API(management['API_TOKEN'])
    path = 'accounts/' + management['ACCOUNT_ID'] + '/access/identity_providers/'
    previous = values['CLOUDFLARE_IDP_ID']
    if not re.fullmatch('[a-f0-9]{32}', management['ACCOUNT_ID']) or not re.fullmatch('[A-Za-z0-9-]{1,64}', previous):
        raise ValueError('Central Access requires exact existing account/provider identities')
    prior = api.request('GET', path + previous)
    domain = api.request('GET', 'accounts/' + management['ACCOUNT_ID'] + '/access/organizations')['auth_domain']
    if not domain.endswith('.cloudflareaccess.com'):
        raise RuntimeError('Unsupported existing Access organization')
    script = "import sys,json;sys.path.insert(0,'/opt/cloudlab');from automation.identity.access_cutover import gate;print(json.dumps(gate(json.load(sys.stdin))))"
    with transaction() as receipts:
        state = receipts.load('external') or {}
        contract = json.loads(ssh('VM', values['VM_HOST'], 'python3 -c ' + shlex.quote(script),
            input=json.dumps(domain.removesuffix('.cloudflareaccess.com')), timeout=60))
        owner = state.get('identity_provider') or {}
        changed = prepare(state, previous, contract)
        if not matches(public_provider(api.request('GET', path + owner['id'])), owner['intent']):
            raise RuntimeError('Dedicated Access provider drifted before cutover')
        receipts.save('external', state)
    run()
    if api.request('GET', path + previous) != prior:
        raise RuntimeError('Prior Access provider changed during cutover')
    with transaction() as receipts:
        state = receipts.load('external')
        selection(state, previous)
        if state['identity_cutover']['phase'] != 'accepted':
            state['identity_cutover']['phase'] = 'configured'
            state['identity_provider']['phase'] = 'configured'
            receipts.save('external', state)
    return {'changed': changed, 'central_access_policies_configured': True,
            'prior_provider_preserved': True, 'browser_and_session_acceptance': False}


if __name__ == '__main__':
    try:
        print(json.dumps(local()))
    except Exception:
        raise SystemExit('Central Access cutover incomplete; retain the checkpoint and independent repair access.') from None
