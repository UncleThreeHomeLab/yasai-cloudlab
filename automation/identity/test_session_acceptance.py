import base64
import copy
import json
import unittest
from unittest.mock import patch
import yaml

from automation.identity.operations import change, private_files
from automation.identity.session_acceptance import offboard_inputs


class SessionAcceptanceTests(unittest.TestCase):
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
                    patch('automation.credentials.vault.fields',return_value={'client_secrets':'{}'}):
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
