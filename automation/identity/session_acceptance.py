"""Measure real disposable-user sessions; never save credentials or browser tokens."""
import json
import os
from pathlib import Path
import shlex
import socket
import sys
import time

import yaml

from automation.identity.session_fixture import scope

ROOT = Path(__file__).resolve().parents[2]
REMOTE = '''import sys,json,hashlib
sys.path.insert(0,'/opt/cloudlab')
from automation.identity.session_fixture import scope
from automation.identity.emergency import vault_secret
from automation.identity.configuration import private_request
from automation.identity.maintenance import APP,NAMESPACE,BASE
from automation.mesh.kube import get,application_ready
from urllib.parse import urlencode
request=json.load(sys.stdin);nonce=scope(request)
owner=json.loads((BASE/'ownership.json').read_text())
app=get('application.argoproj.io',APP,'argocd');values=app['spec']['source']['helm']['valuesObject']
if owner['phase']!='scoped' or owner['uid']!=app['metadata']['uid'] or values.get('operation') or values.get('maintenance') or not application_ready(APP,owner['revision']):
 raise RuntimeError('Session observation requires normal scoped reconciliation')
checkpoint=json.loads((BASE/('proof-'+nonce+'.json')).read_text())
if checkpoint.get('phase')!='enrolled' or checkpoint.get('application_uid')!=owner['uid']: raise RuntimeError('Disposable enrollment is incomplete')
origin='https://'+values['adminHost'];root=origin+'/admin/realms/platform'
token=private_request(origin+'/realms/platform/protocol/openid-connect/token',form={'grant_type':'client_credentials','client_id':'realm-writer','client_secret':vault_secret('keycloak-realm-writers')['platform_client_secret']})['access_token']
rows=private_request(root+'/users?'+urlencode({'username':'proof-'+nonce,'exact':'true','max':2}),token=token)
if len(rows)!=1 or rows[0]['id']!=checkpoint['user_id'] or rows[0].get('attributes',{}).get('cloudlab-primary-owner')!=[nonce]: raise RuntimeError('Disposable identity changed')
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
keys=private_request('https://'+values['loginHost']+'/realms/platform/protocol/openid-connect/certs')
fingerprint=hashlib.sha256(json.dumps({'users':other,'keys':keys},sort_keys=True).encode()).hexdigest()
print(json.dumps({'realm':'platform','username':user['username'],'user_id':user['id'],'email':user['email'],'enabled':user['enabled'],'preservation':fingerprint,'groups':[r['path'] for r in private_request(root+'/users/'+user['id']+'/groups',token=token)]}))
'''


def remote_state(request):
    from automation.connectivity.preflight import ssh
    scope(request)
    return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c '+shlex.quote(REMOTE),
                          input=json.dumps(request), timeout=120))


def offboard_inputs(api, values, request):
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
    source, revoked = change(source, revoked, {'action':'offboard-user','realm':'platform','username':'proof-'+nonce})
    credentials = json.loads(fields('keycloak-client-secrets', ['client_secrets'])['client_secrets'])
    prepared = private_files(source, revoked, credentials, 'validation.invalid')
    expected = yaml.safe_load(prepared['identity/configmap.yaml'])
    if {k:v for k,v in before.items() if k!='data'} != {k:v for k,v in expected.items() if k!='data'}:
        raise RuntimeError('Private source metadata changed; overwrite refused')
    result = publish(api, values, prepared)
    if not result['private_source_changed']:
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
        connection.settimeout(660)
        stream = connection.makefile('rw',encoding='utf-8')
        stream.write(json.dumps(browser_input)+'\n');stream.flush()
        ready = json.loads(stream.readline())
        if ready.get('ready') is not True: raise RuntimeError('Browser baseline not accepted')
        print(json.dumps(ready),flush=True)
        stream.write('{"action":"observe-offboarding"}\n');stream.flush()
        started = time.monotonic()
        offboard_inputs(api,values,request)
        while remote_state(request)['enabled'] is not False:
            if time.monotonic()-started > 300: raise RuntimeError('Private offboarding did not converge within 300 seconds')
            time.sleep(5)
        outcome = local_offboard({key:before[key] for key in ('realm','username','user_id','email')})
        print(json.dumps(outcome),flush=True)
        measured = json.loads(stream.readline())
        after = remote_state(request)
        if (after['enabled'] is not False or before['preservation'] != after['preservation'] or
                not measured.get('logout_is_not_instant_jwt_revocation')):
            raise RuntimeError('Disposable offboarding or unrelated user preservation failed')
        result = dict(measured,unrelated_platform_users_credentials_and_public_keys_preserved=True,
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
