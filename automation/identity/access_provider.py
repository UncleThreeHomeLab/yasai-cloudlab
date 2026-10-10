"""Prepare the dedicated Access provider without changing existing applications."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.identity.integrations import access


def public_provider(provider):
    result = copy.deepcopy(provider)
    result.get('config', {}).pop('client_secret', None)
    return result


def prepare(api, account, previous, contract, state, save):
    """The external receipt lock protects creation, drift repair and rotation."""
    from automation.connectivity.reconcile import matches
    if not re.fullmatch('[a-f0-9]{32}', account) or not re.fullmatch('[A-Za-z0-9-]{1,64}', previous):
        raise ValueError('Access provider requires exact existing account/provider identities')
    desired = contract['provider']
    callback = contract['client']['callbacks']
    team = re.fullmatch(r'https://([a-z0-9-]+)\.cloudflareaccess\.com/cdn-cgi/access/callback', callback[0]) if len(callback) == 1 else None
    if not team or contract != access(desired['config']['auth_url'].removesuffix('/protocol/openid-connect/auth'),
                                      team[1], desired['config']['client_secret']):
        raise ValueError('Access provider differs from its scoped OIDC producer')
    secret_hash = hashlib.sha256(desired['config']['client_secret'].encode()).hexdigest()
    public = public_provider(desired)
    path = 'accounts/' + account + '/access/identity_providers'
    prior = api.request('GET', path + '/' + previous)
    if prior.get('id') != previous:
        raise RuntimeError('Prior Access provider identity is unavailable')
    rows = [row for row in api.collection(path) if row.get('name') == desired['name']]
    if len(rows) > 1 or any(row.get('id') == previous for row in rows):
        raise RuntimeError('Dedicated Access provider collides with existing identity')
    owner = state.get('identity_provider')
    binding = {'account': account, 'previous': previous}
    if owner and owner.get('binding') != binding:
        raise RuntimeError('Access provider ownership binding changed')
    if not owner:
        if rows:
            raise RuntimeError('Dedicated Access provider already exists without an owner')
        owner = {'binding': binding, 'intent': public, 'credential_hash': secret_hash}
        state['identity_provider'] = owner
        save(state)
    changed = False
    if not owner.get('id'):
        if rows:
            # Masked secrets cannot establish ownership after a lost POST response.
            raise RuntimeError('Interrupted Access creation requires explicit identity recovery')
        if owner['intent'] != public or owner['credential_hash'] != secret_hash:
            raise RuntimeError('Pending Access provider creation inputs changed')
        actual = api.request('POST', path, desired)
        if not actual.get('id') or actual['id'] == previous:
            raise RuntimeError('Dedicated Access provider creation returned no safe identity')
        owner['id'] = actual['id']
        save(state)
        changed = True
    else:
        if len(rows) != 1 or rows[0].get('id') != owner['id']:
            raise RuntimeError('Dedicated Access provider identity changed; recreation refused')
        actual = api.request('GET', path + '/' + owner['id'])
    if actual.get('read_only'):
        raise RuntimeError('Dedicated Access provider is immutable')
    if not matches(public_provider(actual), public) or owner['credential_hash'] != secret_hash:
        api.request('PUT', path + '/' + owner['id'], desired)
        changed = True
    actual = api.request('GET', path + '/' + owner['id'])
    if not matches(public_provider(actual), public) or api.request('GET', path + '/' + previous) != prior:
        raise RuntimeError('Access provider preparation changed prior identity or did not converge')
    phase = owner.get('phase') if not changed and owner.get('phase') in ('configured', 'accepted') else (
        'configured' if state.get('identity_cutover') else 'prepared')
    if changed or type(owner.get('credential_ready_at')) is not int:
        owner['credential_ready_at'] = int(time.time())
    owner.update(intent=public, credential_hash=secret_hash, phase=phase)
    save(state)
    return {'changed': changed, 'dedicated_provider_prepared': True,
            'prior_provider_preserved': True, 'applications_changed': 0,
            'browser_and_credential_acceptance': False}


def snapshot(team):
    from automation.identity.bootstrap import private_inputs
    from automation.identity.configuration import private_request
    from automation.identity.maintenance import APP, BASE, NAMESPACE, OWNER
    from automation.mesh.kube import application_ready, condition, get
    ownership = json.loads((BASE / 'ownership.json').read_text())
    app = get('application.argoproj.io', APP, 'argocd') or {}
    native = Path('/var/lib/cloudlab/gitops/identity-values-binding.json')
    if (ownership.get('phase') != 'scoped' or app.get('metadata', {}).get('uid') != ownership.get('uid') or
            app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER or
            not application_ready(APP, ownership['revision']) or not native.exists() or
            json.loads(native.read_text()).get('phase') != 'accepted'):
        raise RuntimeError('Access preparation requires converged scoped identity and prior native Argo binding')
    private = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd')
    values = app['spec']['source']['helm']['valuesObject']
    binding = json.loads(native.read_text())
    for key, kind, name in (('root_uid', 'application.argoproj.io', 'cloudlab-public-root'),
                            ('controller_uid', 'statefulset', 'argocd-application-controller'),
                            ('project_uid', 'appproject.argoproj.io', 'cloudlab-root')):
        resource = get(kind, name, 'argocd') or {}
        if resource.get('metadata', {}).get('uid') != binding.get(key):
            raise RuntimeError('Native Argo binding identity changed before Access preparation')
    if not application_ready('cloudlab-argocd', ownership['revision']):
        raise RuntimeError('Native Argo must converge before Access preparation')
    source, revoked, _ = private_inputs({'private_repository': private['spec']['source']['repoURL'], 'values': values})
    external = get('externalsecret.external-secrets.io', 'keycloak-client-secrets', NAMESPACE)
    if not condition(external, 'Ready'):
        raise RuntimeError('Access client secret requires current ready ESO')
    credentials = get('secret', 'keycloak-client-secrets', NAMESPACE)
    secret = json.loads(base64.b64decode(credentials['data']['client_secrets'], validate=True))['platform'].get('cloudflare-access')
    contract = access('https://' + values['loginHost'] + '/realms/platform', team, secret)
    clients = [client for client in source['realms'].get('platform', {}).get('clients', []) if client.get('id') == 'cloudflare-access']
    denied = revoked['realms'].get('platform', {})
    if (clients != [contract['client']] or 'cloudflare-access' in denied.get('clients', []) or
            'cloudflare-access' in denied.get('removed_clients', [])):
        raise RuntimeError('Access preparation requires its active exact scoped client')
    response = private_request('https://' + values['loginHost'] + '/realms/platform/protocol/openid-connect/token',
        form={'grant_type': 'authorization_code', 'client_id': 'cloudflare-access', 'client_secret': secret,
              'code': 'invalid-disposable-access-proof', 'code_verifier': 'x' * 64,
              'redirect_uri': contract['client']['callbacks'][0]}, accepted_statuses=(400,))
    if response.get('error') != 'invalid_grant':
        raise RuntimeError('Access client credentials have not converged through the realm writer')
    return contract


def local():
    from dotenv import dotenv_values
    from automation.credentials.vault import fields
    from automation.connectivity.cloudflare import API
    from automation.connectivity.checkpoint import transaction
    from automation.connectivity.preflight import ssh
    values = dotenv_values(ROOT / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'OP_SERVICE_ACCOUNT_TOKEN'):
        os.environ[key] = values.get(key) or ''
    os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
    management = fields('cloudflare-management', ('API_TOKEN', 'ACCOUNT_ID'))
    api = API(management['API_TOKEN'])
    domain = api.request('GET', 'accounts/' + management['ACCOUNT_ID'] + '/access/organizations')['auth_domain']
    if not domain.endswith('.cloudflareaccess.com'):
        raise RuntimeError('Existing Access organization has an unsupported domain')
    script = "import sys,json;sys.path.insert(0,'/opt/cloudlab');from automation.identity.access_provider import snapshot;print(json.dumps(snapshot(json.load(sys.stdin)['team'])))"
    import shlex
    def current():
        return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(script),
            input=json.dumps({'team': domain.removesuffix('.cloudflareaccess.com')}), timeout=60))
    with transaction() as receipts:
        state = receipts.load('external')
        if not state or state.get('phase') != 'configured':
            raise RuntimeError('Existing external access owner must be configured first')
        contract = current()
        result = prepare(api, management['ACCOUNT_ID'], values['CLOUDFLARE_IDP_ID'],
                         contract, state, lambda value: receipts.save('external', value))
        if current() != contract:
            raise RuntimeError('Access inputs changed during preparation; repeat before any cutover')
        return result


if __name__ == '__main__':
    try:
        print(json.dumps(local()))
    except Exception:
        raise SystemExit('Dedicated Access provider preparation incomplete; retain ownership. Private diagnostics withheld.') from None
