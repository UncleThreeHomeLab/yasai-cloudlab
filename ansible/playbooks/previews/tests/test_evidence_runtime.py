import copy
import json
import unittest
from unittest.mock import Mock, patch

from playbooks.previews.tests import evidence_runtime as evidence, fixtures, viewer_runtime


class EvidenceTests(unittest.TestCase):
    def test_requested_revision_rejects_old_ready_identity_before_observation_or_credentials(self):
        from playbooks.keycloak.files import maintenance, configuration, emergency
        from playbooks.istio.files import kube
        old, requested = 'b'*40, 'c'*40
        receipts = {'ownership.json': {'phase': 'scoped', 'uid': 'identity-owner', 'revision': old},
            'retirement.json': {'phase': 'accepted', 'application_uid': 'identity-owner', 'keycloak_uid': 'server'}}
        app = {'metadata': {'uid': 'identity-owner', 'labels': {'cloudlab.io/owner': maintenance.OWNER}},
            'spec': {'project': maintenance.APP, 'source': {'path': 'platform/identity/keycloak',
                'helm': {'valuesObject': {'enabled': True, 'reconciliationEnabled': True, 'bootstrapAdminEnabled': False}}}},
            'status': {'sync': {'status': 'Synced', 'revision': old, 'comparedTo': {'source': {}}},
                'health': {'status': 'Healthy'}}}
        server = {'metadata': {'uid': 'server', 'generation': 1}}
        request = {'action': 'lifecycle', 'nonce': 'e'*32, 'realm': 'applications',
            'approvals': [], 'expected': {}, 'revision': requested}
        with patch.object(maintenance, 'BASE') as base, \
                patch.object(maintenance, 'get', side_effect=lambda kind,*args: app if kind == 'application.argoproj.io' else server), \
                patch.object(maintenance, 'application_ready', side_effect=lambda name,revision: revision == old), \
                patch.object(maintenance, 'contains', return_value=True), patch.object(maintenance, 'condition', return_value=True), \
                patch.object(kube, 'get') as observe, patch.object(configuration, 'private_request') as private_request, \
                patch.object(emergency, 'vault_secret') as secret:
            base.__truediv__.side_effect = lambda name: Mock(exists=Mock(return_value=name in receipts),
                read_text=Mock(return_value=json.dumps(receipts.get(name))))
            maintenance.accepted_scoped_identity(revision=old)
            with patch.object(maintenance, 'accepted_scoped_identity', wraps=maintenance.accepted_scoped_identity) as accepted:
                with self.assertRaisesRegex(RuntimeError, 'Current retired scoped identity is not ready'):
                    evidence.run(request)
                accepted.assert_called_once_with(revision=requested)
            observe.assert_not_called(); secret.assert_not_called(); private_request.assert_not_called()

    def test_secret_presence_uses_only_metadata_projection(self):
        from playbooks.istio.files import kube
        with patch.object(kube,'kube',return_value='uid\n') as command:
            self.assertTrue(evidence.secret_presence('cloudlab-preview-'+'a'*32))
        self.assertIn('.metadata.uid',command.call_args.args[-1])
        self.assertNotIn('.data',command.call_args.args[-1])

    def test_active_resource_and_client_bindings_then_real_disable_and_absence(self):
        row, settings, lifecycle, identity, objects, client, platform = fixtures.lifecycle_observation()
        def get(kind, name=None, namespace=None): return copy.deepcopy(objects.get((kind, name, namespace)))
        first = evidence.inspect_row(row, settings, lifecycle, identity, {}, get, lambda identifier:[client], lambda uuid:client, 1200, platform, secrets_present=lambda ns:False)
        self.assertTrue(first['active']); self.assertIn('v1/Pod/cloudlab-preview-'+'a'*32+'/preview-pod', first['uids'])
        stored = {'active': first}
        state = json.loads(identity['data']['state.json']); state['entries'][row['instance']].update(phase='disabled', disabledAt=1250)
        identity['data']['state.json'] = json.dumps(state)
        client['enabled'] = False
        disabled = evidence.inspect_row(row, settings, lifecycle, identity, stored, get, lambda identifier:[client], lambda uuid:client, 1260, platform)
        self.assertTrue(disabled['disabled']); self.assertEqual(disabled['disabledAt'],1250)
        for obj in (lifecycle, identity): obj['data']['state.json']=json.dumps({'entries':{row['instance']:{'phase':'retired','approvalDigest':first['approvalDigest']}}})
        objects.clear()
        absent=evidence.inspect_row(row,settings,lifecycle,identity,stored,get,lambda identifier:[],lambda uuid:None,1850,platform)
        self.assertTrue(absent['absent'])
        with self.assertRaises(ValueError): evidence.inspect_row(row,settings,lifecycle,identity,stored,get,lambda identifier:[],lambda uuid:client,1850,platform)
        with self.assertRaises(RuntimeError): evidence.inspect_row(row,settings,lifecycle,identity,stored,get,lambda identifier:[],Mock(side_effect=RuntimeError('403')),1850,platform)

    def test_foreign_changed_resources_and_client_representations_refuse(self):
        for change in ('uid','image','source','callback','enabled','data'):
            row,settings,lifecycle,identity,objects,client,platform=fixtures.lifecycle_observation()
            if change=='uid': objects['namespace','cloudlab-preview-'+'a'*32,None]['metadata']['uid']='foreign'
            if change=='image': objects['deployment.apps','preview','cloudlab-preview-'+'a'*32]['spec']['template']['spec']['containers'][0]['image']='foreign'
            if change=='source': objects['application.argoproj.io','preview-'+'a'*32,'argocd']['spec']['source']['targetRevision']='foreign'
            if change=='callback': client['redirectUris']=['https://foreign.invalid/']
            if change=='enabled': client['enabled']=False
            if change=='data': objects['secrets',None,'cloudlab-preview-'+'a'*32]={'items':[{'metadata':{'name':'private'}}]}
            def get(kind,name=None,namespace=None): return objects.get((kind,name,namespace))
            with self.subTest(change=change), self.assertRaises(ValueError):
                evidence.inspect_row(row,settings,lifecycle,identity,{},get,lambda identifier:[client],lambda uuid:client,1200,platform,secrets_present=lambda ns:bool(objects.get(('secrets',None,ns))))

    def test_dispatch_has_fixed_bounded_schema_and_no_remote_mutation(self):
        row=fixtures.approval()
        request={'action':'lifecycle','nonce':'e'*32,'realm':'applications','approvals':[row],'expected':{},'revision':'c'*40}
        evidence.validate(request)
        with patch.object(evidence,'run',return_value={'entries':{}}) as run:
            self.assertEqual(viewer_runtime.run(request),{'entries':{}});run.assert_called_once_with(request)
        for value in (dict(request,realm='platform'),dict(request,approvals=[row]*5),dict(request,command='delete'),dict(request,expected={'f'*32:{}})):
            with self.assertRaises(ValueError): evidence.validate(value)
