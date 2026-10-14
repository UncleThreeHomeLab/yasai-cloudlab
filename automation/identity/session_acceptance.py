"""Measure real disposable-user sessions; never save credentials or browser tokens."""
import json
import os
import re
from pathlib import Path
import shlex
import socket
import sys
import time

import yaml

from automation.identity.session_fixture import scope

ROOT = Path(__file__).resolve().parents[2]


def network_diagnostics(value):
    """Expose bounded counts and flags, never browser URLs or error messages."""
    value = value if isinstance(value, dict) else {}
    result = {key:min(value[key],1000) for key in (
        'failed_resources','failed_account','failed_protocol','failed_requests')
        if type(value.get(key)) is int and value[key]>=0}
    result.update({key:value.get(key) is True for key in ('iframe_timeout','script_error')})
    return result


REMOTE = '''import sys,json,hashlib
sys.path.insert(0,'/opt/cloudlab')
from automation.identity.session_fixture import scope
from automation.identity.emergency import vault_secret
from automation.identity.configuration import private_request
from automation.identity.maintenance import APP,NAMESPACE,BASE
from automation.mesh.kube import get,wait
from automation.identity.bootstrap import reconciled
from urllib.parse import urlencode
request=json.load(sys.stdin);nonce=scope(request);realm=request.get('realm','platform')
owner=json.loads((BASE/'ownership.json').read_text())
app=get('application.argoproj.io',APP,'argocd');values=app['spec']['source']['helm']['valuesObject']
if owner['phase']!='scoped' or owner['uid']!=app['metadata']['uid'] or values.get('operation') or values.get('maintenance'):
 raise RuntimeError('Session observation requires normal scoped reconciliation')
wait(lambda:reconciled(owner['revision'],owner['uid']),'session observation convergence',timeout=60)
app=get('application.argoproj.io',APP,'argocd');values=app['spec']['source']['helm']['valuesObject']
if json.loads((BASE/'ownership.json').read_text())!=owner or app['metadata']['uid']!=owner['uid'] or values.get('operation') or values.get('maintenance'):
 raise RuntimeError('Session observation ownership changed during convergence')
checkpoint=json.loads((BASE/('proof-'+nonce+'.json')).read_text())
if checkpoint.get('phase')!='enrolled' or checkpoint.get('application_uid')!=owner['uid'] or checkpoint.get('realm','platform')!=realm: raise RuntimeError('Disposable enrollment is incomplete')
origin='https://'+values['adminHost'];root=origin+'/admin/realms/'+realm
token=private_request(origin+'/realms/'+realm+'/protocol/openid-connect/token',form={'grant_type':'client_credentials','client_id':'realm-writer','client_secret':vault_secret('keycloak-realm-writers')[realm+'_client_secret']})['access_token']
rows=private_request(root+'/users?'+urlencode({'username':'proof-'+nonce,'exact':'true','max':2}),token=token)
if len(rows)!=1 or rows[0]['id']!=checkpoint['user_id'] or rows[0].get('username')!='proof-'+nonce or rows[0].get('attributes',{}).get('cloudlab-primary-owner')!=[nonce]: raise RuntimeError('Disposable identity changed')
user=rows[0];other={}
for first in range(0,10000,100):
 batch=private_request(root+'/users?first='+str(first)+'&max=100',token=token)
 for row in batch:
  if row['id']!=user['id']:
   if row['id'] in other: raise RuntimeError('Ambiguous preservation inventory')
   path=root+'/users/'+row['id']
   other[row['id']]={'user':row,'credentials':private_request(path+'/credentials',token=token),'roles':private_request(path+'/role-mappings',token=token)}
 if len(batch)<100:break
else:raise RuntimeError('Preservation inventory exceeds bounds')
keys=private_request('https://'+values['loginHost']+'/realms/'+realm+'/protocol/openid-connect/certs')
fingerprint=hashlib.sha256(json.dumps({'users':other,'keys':keys},sort_keys=True).encode()).hexdigest()
print(json.dumps({'realm':realm,'username':user['username'],'user_id':user['id'],'email':user['email'],'enabled':user['enabled'],'preservation':fingerprint,'groups':[r['path'] for r in private_request(root+'/users/'+user['id']+'/groups',token=token)]}))
'''


def remote_state(request):
    from automation.connectivity.preflight import ssh
    scope(request)
    return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c '+shlex.quote(REMOTE),
                          input=json.dumps(request), timeout=120))


def offboard_inputs(api, values, request, *, resume=False):
    """Review the exact sole-user tombstone before the normal private PR merge."""
    from automation.gitops.github_setup import repository
    from automation.identity.private_source import decode_contents, publish
    from automation.identity.operations import change, private_files
    from automation.credentials.vault import fields
    nonce = scope(request)
    prefix = 'repos/'+repository(values['PRIVATE_CONFIG_REPOSITORY'])
    base = api.request('GET', prefix+'/git/ref/heads/main')['object']['sha']
    def document(revision):
        return yaml.safe_load(decode_contents(api.request('GET', prefix+'/contents/identity/configmap.yaml?ref='+revision)))
    before = document(base)
    source, revoked = [json.loads(before['data'][key]) for key in ('desired_state','revocations')]
    source, revoked = change(source, revoked, {'action':'offboard-user','realm':request.get('realm','platform'),'username':'proof-'+nonce})
    credentials = json.loads(fields('keycloak-client-secrets', ['client_secrets'])['client_secrets'])
    prepared = private_files(source, revoked, credentials, 'validation.invalid')
    expected = yaml.safe_load(prepared['identity/configmap.yaml'])
    if {k:v for k,v in before.items() if k!='data'} != {k:v for k,v in expected.items() if k!='data'}:
        raise RuntimeError('Private source metadata changed; overwrite refused')
    result = publish(api, values, prepared)
    if not result['private_source_changed']:
        if resume: return
        raise RuntimeError('Disposable user was already offboarded; a new baseline is required')
    pull = api.request('GET', prefix+'/pulls/'+str(result['private_pull_request']))
    files = api.request('GET', prefix+'/pulls/'+str(pull['number'])+'/files')
    if (pull['base']['sha'] != base or len(files)!=1 or files[0]['filename']!='identity/configmap.yaml' or
            files[0]['status']!='modified' or document(pull['head']['sha']) != expected or
            api.request('GET', prefix+'/git/ref/heads/main')['object']['sha'] != base):
        raise RuntimeError('Private offboarding review changed; merge refused')
    merged = api.request('PUT', prefix+'/pulls/'+str(pull['number'])+'/merge',
        {'sha':pull['head']['sha'],'merge_method':'squash','commit_title':'Offboard disposable identity acceptance user'})
    if merged.get('merged') is not True:
        raise RuntimeError('Private offboarding merge did not succeed')


def run():
    from automation.gitops.github_setup import inputs
    from automation.credentials.vault import fields
    from automation.connectivity.checkpoint import transaction
    from automation.connectivity.verify import remote
    from automation.identity.lifecycle import local_offboard
    values, api = inputs()
    for key, value in values.items():
        if value is not None and key not in ('OP_PROVISION_SERVICE_ACCOUNT_TOKEN','GITHUB_PROVISION_TOKEN'):
            os.environ[key] = value
    request = json.loads(Path('/recovery/identity-session-fixture.json').read_text())
    nonce = scope(request)
    proof = fields('keycloak-proof-'+nonce, ['username','email','password','ownership_id'])
    before = remote_state(request)
    if (before['enabled'] is not True or before['username'] != proof['username'] or
            before['email'] != proof['email'] or before['groups'] != ['/viewer']):
        raise RuntimeError('Session acceptance requires the active exact disposable viewer')
    runtime = remote('runtime')
    with transaction() as receipts:
        state = receipts.load('external')
        canary = state.get('identity_session_canary') or {}
        if canary.get('binding', {}).get('nonce') != nonce:
            raise RuntimeError('Prepare the exact disposable session canary first')
        access_url = 'https://'+canary['hostname']+canary['desired']['domain'].removeprefix(canary['hostname'])
    browser_input = {key:proof[key] for key in ('username','password','email')}
    policy = json.loads((ROOT/'platform/identity/keycloak/contract.json').read_text())['sessions']
    limits = {key:policy[key] for key in ('access_token_seconds','private_revocation_convergence_seconds',
                                       'integrated_offboarding_deadline_seconds')}
    browser_input['offboarding_limits'] = limits
    browser_input.update(nonce=nonce,zone=runtime['zone'],gateway_address=runtime['private']['tailnet_gateway'],access_url=access_url)
    deadline = time.monotonic()+90
    while True:
        try:
            connection = socket.create_connection(('sessions',5055),timeout=10)
            break
        except OSError:
            if time.monotonic()>deadline: raise RuntimeError('Browser controller unavailable') from None
            time.sleep(2)
    with connection:
        connection.settimeout(limits['integrated_offboarding_deadline_seconds']+180)
        stream = connection.makefile('rw',encoding='utf-8')
        stream.write(json.dumps(browser_input)+'\n');stream.flush()
        ready = json.loads(stream.readline())
        if ready.get('ready') is not True:
            stages = ('input','account enrollment','account password','WebAuthn registration',
                      'account session','account reload','account API response','account token validation',
                      'native Argo SSO','Access SSO')
            if ready.get('failed_stage') in stages:
                print(json.dumps({'browser_failed_stage':ready['failed_stage'],
                                  'browser_error_type':ready.get('error_type') if ready.get('error_type') in
                                      ('Error','TimeoutError','TypeError') else None,
                                  'password_rejected':ready.get('password_rejected') is True,
                                  'profile_form_present':ready.get('profile_form_present') is True,
                                  'registration_error':ready.get('registration_error') is True,
                                  'headings':[text for text in ready.get('headings',[]) if isinstance(text,str)
                                      and re.fullmatch("[A-Za-z ,.!?'\\-]{1,120}",text)][:4],
                                  'webauthn_error':ready.get('webauthn_error') if ready.get('webauthn_error') in
                                      ('SecurityError','NotAllowedError','InvalidStateError','UnknownError','NotSupportedError') else None,
                                  'register_button_present':ready.get('register_button_present') is True,
                                  'authenticator_label_present':ready.get('authenticator_label_present') is True,
                                  'network':network_diagnostics(ready.get('network'))}),flush=True)
            raise RuntimeError('Browser baseline not accepted')
        print(json.dumps(ready),flush=True)
        stream.write('{"action":"observe-offboarding"}\n');stream.flush()
        started = time.monotonic()
        offboard_inputs(api,values,request)
        while remote_state(request)['enabled'] is not False:
            if time.monotonic()-started > limits['private_revocation_convergence_seconds']:
                raise RuntimeError('Private offboarding convergence deadline exceeded')
            time.sleep(5)
        source_disabled_seconds = round(time.monotonic()-started,1)
        outcome = local_offboard({key:before[key] for key in ('realm','username','user_id','email')})
        print(json.dumps(outcome),flush=True)
        measured = json.loads(stream.readline())
        print(json.dumps({'browser_observation_complete':measured.get('logout_is_not_instant_jwt_revocation') is True,
                          'browser_failed_stage':measured.get('failed_stage') if measured.get('failed_stage') in
                              ('offboarding observation','offboarded new Argo login','offboarded new Access login') else None,
                          'browser_error_type':measured.get('error_type') if measured.get('error_type') in
                              ('Error','TimeoutError','TypeError') else None}),flush=True)
        after = remote_state(request)
        if (after['enabled'] is not False or before['preservation'] != after['preservation'] or
                not measured.get('logout_is_not_instant_jwt_revocation')):
            raise RuntimeError('Disposable offboarding or unrelated user preservation failed')
        result = dict(measured,unrelated_platform_users_credentials_and_public_keys_preserved=True,
                      private_account_disabled_seconds=source_disabled_seconds,declared_limits=limits,
                      private_revocation_persisted=True,environment='existing lab; synthetic disposable passkey')
        with transaction() as receipts:
            state = receipts.load('external')
            state['identity_session_acceptance'] = {'nonce':nonce,'result':result,'verified_at':int(time.time())}
            receipts.save('external',state)
        return result


if __name__ == '__main__':
    try:
        print(json.dumps(run()))
    except Exception:
        raise SystemExit('Disposable integrated session acceptance incomplete; retain revocation and ownership. Private diagnostics withheld.') from None
