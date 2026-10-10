"""A viewer-only disposable Access app; production policies remain untouched."""
import json
import os
from pathlib import Path
import sys

from automation.connectivity.cluster_fixture import CANARY_PATH
from automation.connectivity.cloudflare import access_application
from automation.connectivity.reconcile import Reconciler, matches
from automation.identity.session_fixture import scope


def configure(api, account, state, save, hostname, values, request):
    nonce = scope(request)
    owner = state.get('identity_provider') or {}
    if (owner.get('phase') != 'accepted' or owner.get('binding', {}).get('account') != account or
            not owner.get('id') or state.get('identity_canary') or
            not state.get('objects', {}).get('dns:' + hostname, {}).get('id') or
            values.get('username') != 'proof-' + nonce or values.get('ownership_id') != nonce):
        raise RuntimeError('Session canary requires an accepted provider and exact disposable vault owner')
    wanted = access_application({'hostname': hostname, 'access': 'human'},
        human_email=values['email'], identity_provider=owner['id'])
    wanted.update(name='cloudlab-identity-session-'+nonce[:12], domain=hostname+CANARY_PATH)
    wanted['policies'][0]['require'] = [
        {'login_method': {'id': owner['id']}},
        {'oidc': {'claim_name': 'groups', 'claim_value': '/viewer', 'identity_provider_id': owner['id']}}]
    prior = state.get('identity_session_canary')
    binding = {'nonce': nonce, 'account': account, 'provider': owner['id'], 'external': state['binding']}
    if prior and (prior.get('binding') != binding or prior.get('desired') != wanted):
        raise RuntimeError('Session canary identity changed; overwrite refused')
    reconciler = Reconciler(api, api, state, save)
    actual = reconciler.ensure(api, 'identity-session-canary', 'accounts/'+account+'/access/apps', wanted,
        lambda row: row.get('domain') == wanted['domain'] or row.get('name') == wanted['name'])
    if not actual.get('aud'):
        raise RuntimeError('Session canary has no exact audience')
    state['identity_session_canary'] = {'binding': binding, 'id': actual['id'], 'aud': actual['aud'],
                                        'desired': wanted, 'hostname': hostname}
    save(state)
    return {'session_canary_configured': True, 'changed': reconciler.changed, 'production_policy_changes': 0}


def remove(api, account, state, save, request):
    nonce = scope(request)
    entry = state.get('identity_session_canary')
    if not entry:
        return {'session_canary_removed': True, 'changed': False}
    if (entry.get('binding', {}).get('nonce') != nonce or entry['binding'].get('account') != account or
            entry.get('id') != state.get('objects', {}).get('identity-session-canary', {}).get('id')):
        raise RuntimeError('Session canary removal requires its exact recorded owner')
    path = 'accounts/'+account+'/access/apps/'+entry['id']
    current = api.request('GET', path) if any(row.get('id') == entry['id']
        for row in api.collection(path.rsplit('/', 1)[0])) else None
    if current:
        if not matches(current, entry['desired']) or current.get('aud') != entry['aud']:
            raise RuntimeError('Session canary changed; foreign deletion refused')
        api.request('DELETE', path)
    if any(row.get('id') == entry['id'] for row in api.collection(path.rsplit('/', 1)[0])):
        raise RuntimeError('Session canary deletion did not converge')
    state['objects'].pop('identity-session-canary')
    state.pop('identity_session_canary')
    save(state)
    return {'session_canary_removed': True, 'changed': bool(current), 'production_policy_changes': 0}


def local(request, *, cleanup=False):
    from dotenv import dotenv_values
    import yaml
    from automation.credentials.vault import fields
    from automation.connectivity.cloudflare import API
    from automation.connectivity.checkpoint import transaction
    from automation.connectivity.contract import host_rules
    from automation.connectivity.verify import remote
    nonce = scope(request)
    root = Path(__file__).resolve().parents[2]
    environment = dotenv_values(root / '.env', interpolate=False)
    for key, value in environment.items():
        if value is not None and key not in ('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', 'GITHUB_PROVISION_TOKEN'):
            os.environ[key] = value
    management = fields('cloudflare-management', ('API_TOKEN', 'ACCOUNT_ID'))
    api = API(management['API_TOKEN'])
    if cleanup:
        with transaction() as receipts:
            result = remove(api, management['ACCOUNT_ID'], receipts.load('external'),
                lambda value: receipts.save('external', value), request)
        remote('cleanup', purpose='identity-canary')
        return result
    values = fields('keycloak-proof-'+nonce, ('username', 'email', 'ownership_id'))
    runtime = remote('runtime')
    public = [row for row in host_rules(json.loads(environment['CLOUDFLARE_ACCESS_HOSTS']), runtime['zone'])
              if row['access'] == 'public' and row['hostname'] != 'login.'+runtime['zone']]
    if not public:
        raise RuntimeError('Session canary requires an owned public smoke hostname')
    hostname = public[0]['hostname']
    with transaction() as receipts:
        state = receipts.load('external')
        if state.get('identity_canary'):
            raise RuntimeError('Remove the accepted original canary before preparing the session fixture')
        remote('prepare', purpose='identity-canary', public=[{'name': hostname.split('.')[0], 'access': 'public'}],
               private=[], smoke_image=yaml.safe_load((root/'ansible/group_vars/all/verification.yml').read_text())['smoke_image'])
        return configure(api, management['ACCOUNT_ID'], state, lambda value: receipts.save('external', value),
                         hostname, values, request)


if __name__ == '__main__':
    try:
        if sys.argv[1:] not in (['prepare'], ['remove']):
            raise ValueError('Unknown disposable session canary operation')
        print(json.dumps(local(json.load(sys.stdin), cleanup=sys.argv[1:] == ['remove'])))
    except Exception:
        raise SystemExit('Disposable session canary incomplete; retain ownership. Private diagnostics withheld.') from None
