import base64
import copy
import json
import io
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import yaml

from automation.identity.operations import change, private_files
from automation.identity.session_acceptance import offboard_inputs, network_diagnostics, REMOTE


class SessionAcceptanceTests(unittest.TestCase):
    def test_observation_waits_for_convergence_and_rejects_owner_changes(self):
        nonce='a'*32
        owner={'phase':'scoped','uid':'owned','revision':'published'}
        with TemporaryDirectory() as directory:
            base=Path(directory)
            (base/'ownership.json').write_text(json.dumps(owner))
            (base/('proof-'+nonce+'.json')).write_text(json.dumps(
                {'phase':'enrolled','application_uid':'owned','user_id':'disposable'}))
            for realm,outcome in [('platform',case) for case in ('converged','failed','maintenance','owner')] + [
                    ('applications',case) for case in ('converged','wrong-realm','renamed')]:
                (base/'ownership.json').write_text(json.dumps(owner))
                (base/('proof-'+nonce+'.json')).write_text(json.dumps(
                    {'phase':'enrolled','application_uid':'owned','user_id':'disposable',
                     'realm':'platform' if outcome=='wrong-realm' else realm}))
                app={'metadata':{'uid':'owned'},'spec':{'source':{'helm':{'valuesObject':
                    {'adminHost':'admin.fixture.invalid','loginHost':'login.fixture.invalid'}}}}}
                calls=[]
                def ready(revision,uid):
                    self.assertEqual((revision,uid),('published','owned'))
                    calls.append(True)
                    if outcome=='failed':raise RuntimeError('Identity reconciliation failed')
                    if outcome=='maintenance':app['spec']['source']['helm']['valuesObject']['maintenance']=True
                    if outcome=='owner':(base/'ownership.json').write_text(json.dumps(dict(owner,uid='foreign')))
                    return len(calls)>1
                user={'id':'disposable','username':'foreign' if outcome=='renamed' else 'proof-'+nonce,'email':'viewer@fixture.invalid',
                      'enabled':False,'attributes':{'cloudlab-primary-owner':[nonce]}}
                def request(url,**kwargs):
                    self.assertIn('/realms/'+realm+'/',url)
                    if url.endswith('/token'):return {'access_token':'fixture'}
                    if '/users?' in url:return [user]
                    if url.endswith('/certs'):return {'keys':[]}
                    if url.endswith('/groups'):return [{'path':'/viewer'}]
                    raise AssertionError('Unexpected request')
                with patch('automation.identity.maintenance.BASE',base), \
                        patch('automation.mesh.kube.get',return_value=app), \
                        patch('automation.identity.bootstrap.reconciled',side_effect=ready), \
                        patch('automation.mesh.kube.time.sleep'), \
                        patch('automation.identity.emergency.vault_secret',return_value={realm+'_client_secret':'fixture'}), \
                        patch('automation.identity.configuration.private_request',side_effect=request) as api, \
                        patch('sys.stdin',io.StringIO(json.dumps(dict(nonce=nonce,realm=realm)))), redirect_stdout(io.StringIO()) as output:
                    if outcome=='converged':
                        exec(REMOTE,{})
                        self.assertFalse(json.loads(output.getvalue())['enabled'])
                        self.assertEqual(json.loads(output.getvalue())['realm'],realm)
                        self.assertEqual(len(calls),2)
                    else:
                        with self.assertRaises(RuntimeError):exec(REMOTE,{})
                        if outcome=='renamed':self.assertEqual(api.call_count,2)
                        else:api.assert_not_called()

    def test_deadline_includes_private_delivery_and_session_expiry(self):
        policy=json.loads((Path(__file__).resolve().parents[3]/'platform/identity/keycloak/contract.json').read_text())['sessions']
        self.assertEqual(policy['access_token_seconds'],300)
        self.assertGreaterEqual(policy['private_revocation_convergence_seconds'],
                                policy['reconcile_schedule_seconds']+180+210)
        self.assertGreaterEqual(policy['integrated_offboarding_deadline_seconds'],
                                policy['private_revocation_convergence_seconds']+policy['keycloak_session_max_seconds'])

    def test_network_diagnostics_drop_untrusted_details(self):
        self.assertEqual(network_diagnostics({'failed_resources':1001,'failed_account':True,
            'failed_protocol':-1,'failed_requests':'secret','iframe_timeout':True,
            'script_error':'secret','url':'secret','message':'secret'}),
            {'failed_resources':1000,'iframe_timeout':True,'script_error':False})
        self.assertEqual(network_diagnostics(None),{'iframe_timeout':False,'script_error':False})

    def test_review_rejects_unrelated_private_change_before_merge(self):
        nonce = 'a'*32
        source = {'format':1,'realms':{'platform':{'memberships':[
            {'username':'proof-'+nonce,'groups':['viewer']}, {'username':'personal-admin','groups':['platform-admin']}]}}}
        revoked = {'format':1,'realms':{}}
        original = yaml.safe_load(private_files(source,revoked,{},'validation.invalid')['identity/configmap.yaml'])
        intended_source,intended_revoked = change(source,revoked,
            {'action':'offboard-user','realm':'platform','username':'proof-'+nonce})
        intended = yaml.safe_load(private_files(intended_source,intended_revoked,{},'validation.invalid')['identity/configmap.yaml'])
        for drift in (False,True):
            head = copy.deepcopy(intended)
            if drift:
                altered=json.loads(head['data']['desired_state'])
                altered['realms']['platform']['memberships'][1]['groups']=['viewer']
                head['data']['desired_state']=json.dumps(altered)
            writes=[]
            class API:
                def request(self,method,path,body=None):
                    if method=='PUT':writes.append(body);return {'merged':True}
                    if path.endswith('/git/ref/heads/main'):return {'object':{'sha':'base'}}
                    if '/contents/' in path:
                        value=original if path.endswith('ref=base') else head
                        return {'content':base64.b64encode(yaml.safe_dump(value).encode()).decode()}
                    if path.endswith('/pulls/8'):return {'number':8,'base':{'sha':'base'},'head':{'sha':'head'}}
                    if path.endswith('/files'):return [{'filename':'identity/configmap.yaml','status':'modified'}]
                    raise AssertionError('Unexpected API operation')
            with patch('automation.identity.private_source.publish',return_value={'private_source_changed':True,'private_pull_request':8}), \
                    patch('playbooks.secrets.files.vault.fields',return_value={'client_secrets':'{}'}):
                if drift:
                    with self.assertRaises(RuntimeError):
                        offboard_inputs(API(),{'PRIVATE_CONFIG_REPOSITORY':'https://github.com/fixture/private.git'},{'nonce':nonce})
                    self.assertEqual(writes,[])
                else:
                    offboard_inputs(API(),{'PRIVATE_CONFIG_REPOSITORY':'https://github.com/fixture/private.git'},{'nonce':nonce})
                    self.assertEqual(len(writes),1)
                    self.assertEqual(writes[0]['sha'],'head')


if __name__ == '__main__':
    unittest.main()
