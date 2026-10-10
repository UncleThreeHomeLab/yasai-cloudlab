import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation.identity.configuration import proof_user
from automation.identity.chart import render
from automation.identity.session_fixture import scope, enroll, membership, retained_delivery_patches
from automation.identity.bootstrap import enrollment_handoff, branch_handoff_patches
from automation.identity import bootstrap


class ProofUserTests(unittest.TestCase):
    def test_source_handoff_writes_ownership_to_its_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);revision='b'*40
            path=root/'ownership.json'
            path.write_text(json.dumps({'phase':'scoped','uid':'owned','revision':revision}))
            current={'metadata':{'uid':'owned','resourceVersion':'1','labels':{'cloudlab.io/owner':bootstrap.OWNER}},
                     'spec':{'source':{'targetRevision':revision,'helm':{'valuesObject':{}}}}}
            desired=copy.deepcopy(current);desired['spec']['source']['targetRevision']='main'
            with patch.object(bootstrap,'BASE',root), patch.object(bootstrap,'application',return_value=desired), \
                    patch.object(bootstrap,'prerequisites'), patch.object(bootstrap,'private_resources',return_value=[]), \
                    patch.object(bootstrap,'private_inputs'), patch.object(bootstrap,'get',return_value=current), \
                    patch.object(bootstrap,'enrollment_handoff',return_value={'phase':'accepted','revision':revision,'application_uid':'owned'}), \
                    patch.object(bootstrap,'kube'), patch.object(bootstrap,'wait'):
                bootstrap.run({'revision':'c'*40},'scoped')
            self.assertEqual(json.loads(path.read_text())['revision'],'c'*40)

    def test_source_handoff_requires_completed_exact_nonce_user_and_application(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);nonce='a'*32;revision='b'*40
            state={'uid':'owned','revision':revision}
            current={'metadata':{'uid':'owned','resourceVersion':'1'},
                     'spec':{'source':{'targetRevision':revision,'helm':{'valuesObject':{}}}}}
            desired=copy.deepcopy(current);desired['spec']['source']['targetRevision']='main'
            path=root/('proof-'+nonce+'.json')
            self.assertIsNone(enrollment_handoff(current,state,root))
            record={'nonce':nonce,'revision':revision,'application_uid':'owned','phase':'enrolled','user_id':'immutable'}
            path.write_text(json.dumps(record))
            receipt=enrollment_handoff(current,state,root)
            self.assertEqual(branch_handoff_patches(current,desired,receipt)[-1]['value'],'main')
            for change in ({'application_uid':'foreign'}, {'user_id':None}, {'phase':'created'}, {'nonce':'malformed'}):
                path.write_text(json.dumps(dict(record,**change)))
                with self.assertRaises(RuntimeError):
                    enrollment_handoff(current,state,root)
    def test_resume_after_partial_creation_records_identity_and_removes_null_operation(self):
        self.resume_creation()

    def test_resume_after_operation_removal_still_requires_exact_created_identity(self):
        self.resume_creation(normal=True)

    def resume_creation(self, normal=False):
        nonce, uid = 'a' * 32, 'owned'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'ownership.json').write_text(json.dumps({'phase':'scoped','uid':uid,'revision':'a'*40}))
            checkpoint = root/('proof-'+nonce+'.json')
            checkpoint.write_text(json.dumps({'nonce':nonce,'application_uid':uid,'phase':'prepared'}))
            app = {'metadata':{'uid':uid,'resourceVersion':'1','labels':{'cloudlab.io/owner':'cloudlab-identity-bootstrap'}},
                   'spec':{'source':{'helm':{'valuesObject':{'bootstrapAdminEnabled':False,'operation':None,
                                                          'loginHost':'login.example.invalid','adminHost':'admin.example.invalid'}}}}}
            if normal:
                app['spec']['source']['targetRevision']='a'*40
                app['spec']['source']['helm']['valuesObject'].pop('operation')
                app['status']={'health':{'status':'Healthy'},'sync':{'comparedTo':{'source':copy.deepcopy(app['spec']['source'])}}}
                checkpoint.write_text(json.dumps({'nonce':nonce,'application_uid':uid,'phase':'created',
                                                  'revision':'a'*40,'user_id':'immutable'}))
            def resources(kind, name, namespace):
                if name=='cloudlab-identity':return app
                if name=='cloudlab-identity-private':return {'spec':{'source':{'repoURL':'private'}}}
                return {}
            state = {'users':[{'username':'proof-'+nonce,'email':'fixture@example.invalid'}]}
            user = {'id':'immutable','username':'proof-'+nonce,'enabled':False,
                    'attributes':{'cloudlab-primary-owner':[nonce]}}
            writes=[]
            def write(*args):
                patches=json.loads(args[-1]);writes.extend(patches)
                if any(p.get('op')=='remove' and p['path'].endswith('/operation') for p in patches):
                    app['spec']['source']['helm']['valuesObject'].pop('operation')
            with patch('automation.identity.maintenance.BASE',root), \
                    patch('automation.mesh.kube.get',side_effect=resources), \
                    patch('automation.mesh.kube.condition',return_value=True), \
                    patch('automation.mesh.kube.application_ready',side_effect=lambda *_:'operation' not in app['spec']['source']['helm']['valuesObject']), \
                    patch('automation.mesh.kube.contains',return_value=True), \
                    patch('automation.mesh.kube.wait',side_effect=lambda predicate,*a,**k:self.assertTrue(predicate())), \
                    patch('automation.mesh.kube.kube',side_effect=write), \
                    patch('automation.identity.bootstrap.writer_idle',return_value=True), \
                    patch('automation.identity.bootstrap.private_inputs',return_value=({}, {}, 'private-revision')), \
                    patch('automation.identity.configuration.compile_state',return_value=state), \
                    patch('automation.identity.emergency.vault_secret',side_effect=lambda name:{'client_secrets':'{}','platform_client_secret':'secret'}), \
                    patch('automation.identity.configuration.private_request',side_effect=lambda url,**k:[user] if '/users?' in url else {'access_token':'token'}), \
                    patch('automation.identity.emergency.phase_sync_patches',return_value=[{}, {'op':'add','path':'/operation','value':{}}]):
                result=enroll({'nonce':nonce})
            self.assertTrue(result['existing_credentials_preserved'])
            self.assertFalse(user['enabled'])
            self.assertEqual(json.loads(checkpoint.read_text())['user_id'],'immutable')
            self.assertEqual(any(p['op']=='remove' and p['path'].endswith('/operation') for p in writes), not normal)
            self.assertEqual(next(p['value'] for p in writes if p['path']=='/spec/source/targetRevision'),'a'*40)
            self.assertFalse(any('credentials' in p['path'] or 'enabled' in p['path'] for p in writes))
    def test_retained_delivery_refuses_foreign_scope_and_preserves_secret(self):
        nonce='a'*32
        external={'metadata':{'uid':'owned','resourceVersion':'7','annotations':{
            'argocd.argoproj.io/tracking-id':'cloudlab-identity:external-secrets.io/ExternalSecret:cloudlab-identity/keycloak-proof'}},
            'spec':{'dataFrom':[{'extract':{'key':'keycloak-proof-'+nonce}}],
                    'target':{'name':'keycloak-proof','creationPolicy':'Owner','deletionPolicy':'Retain'}}}
        patches=retained_delivery_patches(external,nonce,'cloudlab-identity')
        self.assertEqual(patches[:2],[{'op':'test','path':'/metadata/uid','value':'owned'},
                                     {'op':'test','path':'/metadata/resourceVersion','value':'7'}])
        self.assertEqual({p['value']for p in patches[2:]},{'IgnoreExtraneous','Prune=false'})
        self.assertTrue(all(p['path'].startswith('/metadata/')for p in patches))
        for patch_value in patches[2:]:
            external['metadata']['annotations'][patch_value['path'].split('/')[-1].replace('~1','/')]=patch_value['value']
        self.assertEqual(retained_delivery_patches(external,nonce,'cloudlab-identity'),[])
        for change in ('foreign','item','target','deleting'):
            altered=copy.deepcopy(external)
            if change=='foreign':altered['metadata']['annotations']['argocd.argoproj.io/tracking-id']='foreign'
            elif change=='item':altered['spec']['dataFrom'][0]['extract']['key']='other-secret'
            elif change=='target':altered['spec']['target']['deletionPolicy']='Delete'
            else:altered['metadata']['deletionTimestamp']='now'
            with self.assertRaises(RuntimeError):retained_delivery_patches(altered,nonce,'cloudlab-identity')
    def test_private_fixture_membership_repeat_preserves_other_users_and_refuses_revocation(self):
        nonce = 'a' * 32
        source = {'realms': {'platform': {'memberships': [{'username': 'unmanaged-input', 'groups': ['developer']}]}}}
        revoked = {'realms': {'platform': {'users': []}}}
        values = {'username': 'proof-' + nonce, 'ownership_id': nonce, 'email': 'fixture@example.invalid'}
        result = membership(source, revoked, values, {'nonce': nonce})
        self.assertEqual(result['realms']['platform']['memberships'][0], source['realms']['platform']['memberships'][0])
        self.assertEqual(len(source['realms']['platform']['memberships']), 1)
        self.assertEqual(membership(result, revoked, values, {'nonce': nonce}), result)
        self.assertNotIn('enabled', result['realms']['platform']['memberships'][1])
        self.assertNotIn('credentials', result['realms']['platform']['memberships'][1])
        revoked['realms']['platform']['users'].append(values['username'])
        with self.assertRaises(ValueError):
            membership(result, revoked, values, {'nonce': nonce})
    def test_foreign_identity_owner_is_rejected_before_any_resource_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owned', 'revision': 'a' * 40}))
            foreign = {'metadata': {'uid': 'foreign'}, 'spec': {'source': {'helm': {'valuesObject': {}}}}}
            with patch('automation.identity.maintenance.BASE', root), \
                    patch('automation.mesh.kube.get', return_value=foreign), \
                    patch('automation.mesh.kube.kube') as write:
                with self.assertRaises(RuntimeError):
                    enroll({'nonce': 'a' * 32})
                write.assert_not_called()
            self.assertFalse((root / ('proof-' + 'a' * 32 + '.json')).exists())
    def test_fixture_scope_cannot_select_people_realms_or_credentials(self):
        self.assertEqual(scope({'nonce': 'a' * 32}), 'a' * 32)
        for request in ({}, {'nonce': 123}, {'nonce': 'unsafe'}, {'nonce': 'a' * 32, 'realm': 'master'},
                        {'nonce': 'a' * 32, 'username': 'personal-admin'}):
            with self.assertRaises(ValueError):
                scope(request)
    def setUp(self):
        self.nonce = 'a' * 32
        self.values = {'username': 'proof-' + self.nonce, 'ownership_id': self.nonce,
                       'password': 'x' * 48, 'email': 'disposable@example.invalid'}
        self.state = {'realm': 'platform', 'users': [
            {'username': self.values['username'], 'groups': ['/viewer'],
             'email': self.values['email'], 'emailVerified': True}]}

    def test_creation_is_scoped_and_repeat_preserves_disabled_credentials(self):
        original = copy.deepcopy(self.state)
        result = proof_user(self.state, [], self.values, self.nonce)
        self.assertEqual(self.state, original)
        self.assertEqual(set(result), {'realm', 'users'})
        user = result['users'][0]
        self.assertEqual(user['requiredActions'], ['webauthn-register'])
        self.assertEqual(user['credentials'][0]['value'], self.values['password'])
        current = dict(user, enabled=False, id='immutable')
        self.assertEqual(proof_user(self.state, [current], self.values, self.nonce),
                         {'realm': 'platform', 'users': []})
        self.assertFalse(current['enabled'])

    def test_rejects_unowned_account_revocation_privilege_and_incomplete_private_inputs(self):
        with self.assertRaises(ValueError):
            proof_user(self.state, [{'username': self.values['username']}], self.values, self.nonce)
        for changes in ({'enabled': False}, {'groups': ['/platform-admin']}, {'groups': ['/viewer', '/developer']},
                        {'emailVerified': False}, {'email': 'other@example.invalid'}):
            state = copy.deepcopy(self.state); state['users'][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                proof_user(state, [], self.values, self.nonce)
        for values in (dict(self.values, ownership_id='b' * 32), dict(self.values, password='short'),
                       dict(self.values, username='personal-admin')):
            with self.assertRaises(ValueError):
                proof_user(self.state, [], values, self.nonce)

    def test_chart_uses_eso_and_the_same_lease_without_normal_state_tracking(self):
        values = {'enabled': True, 'reconciliationEnabled': True, 'privateStateEnabled': True,
                  'bootstrapAdminEnabled': False, 'trustedProxyAddresses': ['10.0.0.1'],
                  'databaseCA': 'fixture-ca',
                  'operation': {'action': 'initialize-proof', 'realm': 'platform', 'nonce': self.nonce}}
        objects = render(values)
        secret = next(o for o in objects if o['kind'] == 'ExternalSecret' and o['metadata']['name'] == 'keycloak-proof')
        self.assertEqual(secret['spec']['dataFrom'][0]['extract']['key'], 'keycloak-proof-' + self.nonce)
        self.assertEqual(secret['metadata']['annotations'],{'argocd.argoproj.io/compare-options':'IgnoreExtraneous',
                                                          'argocd.argoproj.io/sync-options':'Prune=false'})
        job = next(o for o in objects if o['kind'] == 'Job')['spec']['template']['spec']
        init = job['initContainers'][0]['args'][0]
        self.assertLess(init.index('acquire_sync();'), init.index("prepare_proof_user('/imports'"))
        self.assertIn('--import.remote-state.enabled=false', job['containers'][0]['args'][0])
        self.assertIn('/imports/proof.json', job['containers'][0]['args'][0])
        self.assertNotIn('prepare_removal(', init)
        self.assertTrue(next(o for o in objects if o['kind'] == 'CronJob' and o['metadata']['name'] == 'identity-reconcile')['spec']['suspend'])
        staged = render(dict(values, operation=dict(values['operation'], action='prepare-proof')))
        self.assertFalse(any(o['kind'] == 'Job' for o in staged))
        self.assertEqual(next(o for o in staged if o['kind'] == 'Keycloak')['spec']['instances'], 1)
        self.assertTrue(next(o for o in staged if o['kind'] == 'CronJob' and o['metadata']['name'] == 'identity-reconcile')['spec']['suspend'])
        for operation in (dict(values['operation'], realm='master'), dict(values['operation'], nonce='unsafe'),
                          dict(values['operation'], username='personal-admin')):
            with self.assertRaises(ValueError):
                render(dict(values, operation=operation))


if __name__ == '__main__':
    unittest.main()
