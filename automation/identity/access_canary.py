"""Verify the dedicated provider on a disposable path before real policy cutover."""
import copy
import json
import os
import sys
from pathlib import Path
import time

from automation.connectivity.cluster_fixture import CANARY_PATH
from automation.connectivity.cloudflare import access_application
from automation.connectivity.contract import host_rules
from automation.connectivity.reconcile import Reconciler, matches
from automation.connectivity.traffic import https, success, denied
from automation.connectivity.human import verify_token


def desired(hostname, email, provider):
    rule = {'hostname': hostname, 'access': 'human'}
    result = access_application(rule, human_email=email, identity_provider=provider, identity_group='/platform-admin')
    result.update(name='cloudlab-identity-canary', domain=hostname + CANARY_PATH)
    return result


def verified(state, now=None):
    canary, owner = state.get('identity_canary') or {}, state.get('identity_provider') or {}
    now = time.time() if now is None else now
    return (canary.get('phase') == 'proven' and canary.get('binding') == state.get('binding') and
            canary.get('provider') == owner.get('id') and canary.get('credential_hash') == owner.get('credential_hash') and
            canary.get('provider_intent') == owner.get('intent') and
            type(canary.get('verified_at')) is int and 0 <= now - canary['verified_at'] <= 900)


def configure(api, account, state, save, hostname, email):
    owner = state['identity_provider']
    wanted = desired(hostname, email, owner['id'])
    prior = state.get('identity_canary')
    if prior and (prior.get('hostname') != hostname or prior.get('binding') != state['binding']):
        raise RuntimeError('Dispose the previous canary before changing its host or owner')
    if not state.get('objects', {}).get('dns:' + hostname, {}).get('id'):
        raise RuntimeError('Canary must use an already owned public hostname')
    client = Reconciler(api, api, state, save)
    actual = client.ensure(api, 'identity-canary', 'accounts/' + account + '/access/apps', wanted,
                          lambda row: row.get('domain') == wanted['domain'] or row.get('name') == wanted['name'])
    if not actual.get('aud'):
        raise RuntimeError('Canary has no exact Access audience')
    current = {'phase': 'configured', 'binding': state['binding'], 'hostname': hostname,
               'id': actual['id'], 'aud': actual['aud'], 'desired': wanted, 'provider': owner['id'],
               'credential_hash': owner['credential_hash'], 'provider_intent': copy.deepcopy(owner['intent'])}
    if prior and all(prior.get(key) == value for key, value in current.items() if key != 'phase'):
        current = prior
    state['identity_canary'] = current
    save(state)
    return {'changed': client.changed, 'canary_configured': True, 'real_application_policies_changed': 0,
            'browser_path': CANARY_PATH, 'browser_acceptance': verified(state)}


def record(api, account, state, save, organization, email, token, machine_hosts):
    canary = state.get('identity_canary') or {}
    owner = state.get('identity_provider') or {}
    if (canary.get('phase') not in ('configured', 'proven') or canary.get('binding') != state.get('binding') or
            canary.get('provider') != owner.get('id') or canary.get('credential_hash') != owner.get('credential_hash') or
            canary.get('provider_intent') != owner.get('intent') or not machine_hosts):
        raise RuntimeError('Canary proof requires unchanged provider inputs and an independent machine boundary')
    actual = api.request('GET', 'accounts/' + account + '/access/apps/' + canary['id'])
    if actual.get('aud') != canary['aud'] or not matches(actual, canary['desired']):
        raise RuntimeError('Canary policy or audience changed before browser proof')
    now = verify_token(token, canary['aud'], organization, email)
    headers = {'Cookie': 'CF_Authorization=' + token}
    if not success(https(canary['hostname'], headers=headers, path=CANARY_PATH)):
        raise RuntimeError('Signed canary session did not reach its disposable backend')
    from automation.connectivity.cluster_fixture import PROOF_PATH
    if any(not denied(https(host, headers=headers, path=PROOF_PATH)) for host in machine_hosts):
        raise RuntimeError('Canary human session crossed the independent machine boundary')
    canary.update(phase='proven', verified_at=now)
    save(state)
    return {'dedicated_provider_browser_and_backchannel_proven': True, 'machine_boundary_denied': True,
            'session_persisted': False, 'real_application_policies_changed': 0}


def remove(api, account, state, save):
    canary = state.get('identity_canary')
    if not canary:
        return {'changed': False, 'canary_removed': True}
    slot = state.get('objects', {}).get('identity-canary') or {}
    if slot.get('id') != canary['id'] or canary['desired']['domain'] != canary['hostname'] + CANARY_PATH:
        raise RuntimeError('Canary cleanup ownership changed; no deletion permitted')
    path = 'accounts/' + account + '/access/apps/' + canary['id']
    rows = api.collection(path.rsplit('/', 1)[0])
    if any(row.get('id') == canary['id'] for row in rows):
        if not matches(api.request('GET', path), canary['desired']):
            raise RuntimeError('Canary policy changed; cleanup refuses a foreign object')
        api.request('DELETE', path)
    if any(row.get('id') == canary['id'] for row in api.collection(path.rsplit('/', 1)[0])):
        raise RuntimeError('Canary deletion did not converge')
    state['objects'].pop('identity-canary')
    state.pop('identity_canary')
    save(state)
    return {'changed': True, 'canary_removed': True, 'real_application_policies_changed': 0}


def local(action, token=None):
    import shlex
    import yaml
    import re
    from dotenv import dotenv_values
    from automation.credentials.vault import fields
    from automation.connectivity.cloudflare import API
    from automation.connectivity.checkpoint import transaction
    from automation.connectivity.preflight import ssh
    from automation.connectivity.verify import remote
    from automation.identity.access_cutover import validate_provider
    from automation.identity.access_provider import public_provider
    root = Path(__file__).resolve().parents[2]
    values = dotenv_values(root / '.env', interpolate=False)
    for key, value in values.items():
        if value is not None and key not in ('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', 'GITHUB_PROVISION_TOKEN'):
            os.environ[key] = value
    management = fields('cloudflare-management', ('API_TOKEN', 'ACCOUNT_ID'))
    account = management['ACCOUNT_ID']
    if not re.fullmatch('[a-f0-9]{32}', account):
        raise ValueError('Canary requires the exact existing account')
    api = API(management['API_TOKEN'])
    if action == 'remove':
        with transaction() as receipts:
            state = receipts.load('external') or {}
            result = remove(api, account, state, lambda value: receipts.save('external', value))
        remote('cleanup', purpose='identity-canary')
        return result
    domain = api.request('GET', 'accounts/' + account + '/access/organizations')['auth_domain']
    if not re.fullmatch('[a-z0-9-]+[.]cloudflareaccess[.]com', domain):
        raise ValueError('Canary requires the exact existing organization')
    runtime = remote('runtime')
    rules = host_rules(json.loads(values['CLOUDFLARE_ACCESS_HOSTS']), runtime['zone'])
    public = [rule for rule in rules if rule['access'] == 'public' and rule['hostname'] != 'login.' + runtime['zone']]
    if not public:
        raise RuntimeError('Canary requires the existing public smoke hostname')
    hostname = public[0]['hostname']
    with transaction() as receipts:
        state = receipts.load('external') or {}
        script = "import sys,json;sys.path.insert(0,'/opt/cloudlab');from automation.identity.access_cutover import gate;print(json.dumps(gate(json.load(sys.stdin))))"
        contract = json.loads(ssh('VM', values['VM_HOST'], 'python3 -c ' + shlex.quote(script),
            input=json.dumps(domain.removesuffix('.cloudflareaccess.com')), timeout=60))
        validate_provider(state, values['CLOUDFLARE_IDP_ID'], contract)
        if not matches(public_provider(api.request('GET', 'accounts/' + account + '/access/identity_providers/' + state['identity_provider']['id'])), state['identity_provider']['intent']):
            raise RuntimeError('Dedicated provider drifted before canary verification')
        save = lambda value: receipts.save('external', value)
        if action == 'proof':
            return record(api, account, state, save, domain, values['CLOUDFLARE_HUMAN_EMAIL'], token,
                          [rule['hostname'] for rule in rules if rule['access'] == 'machine'])
        if action != 'prepare':
            raise ValueError('Unknown canary action')
        remote('prepare', purpose='identity-canary', public=[{'name': hostname.split('.')[0], 'access': 'public'}],
               private=[], smoke_image=yaml.safe_load((root / 'ansible/group_vars/all/verification.yml').read_text())['smoke_image'])
        return configure(api, account, state, save, hostname, values['CLOUDFLARE_HUMAN_EMAIL'])


if __name__ == '__main__':
    try:
        action = sys.argv[1]
        print(json.dumps(local(action, json.load(sys.stdin)['token'] if action == 'proof' else None)))
    except Exception:
        raise SystemExit('Access canary incomplete; retain ownership. Session and private diagnostics withheld.') from None
