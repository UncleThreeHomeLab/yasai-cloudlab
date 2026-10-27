import copy
import json
import unittest
from unittest.mock import Mock, patch

from playbooks.previews.tests import evidence_runtime as evidence, fixtures, viewer_runtime


class EvidenceTests(unittest.TestCase):
    def test_active_native_client_collection_order_preserves_exact_owned_bindings(self):
        values = fixtures.lifecycle_observation()
        row, settings, lifecycle, identity, objects, client, platform = values
        get = lambda kind,name=None,namespace=None: copy.deepcopy(objects.get((kind,name,namespace)))
        original = evidence.inspect_row(row, settings, lifecycle, identity, {}, get,
            lambda identifier:[client], lambda uuid:client, 1200, platform, secrets_present=lambda namespace:False)
        client['defaultClientScopes'].reverse(); client['protocolMappers'].reverse()
        for index, mapper in enumerate(client['protocolMappers']): mapper['id'] = 'server-mapper-' + str(index)
        before = copy.deepcopy(values)
        result = evidence.inspect_row(row, settings, lifecycle, identity, {},
            get,
            lambda identifier:[client], lambda uuid:client, 1200, platform, secrets_present=lambda namespace:False)
        self.assertTrue(result['active']); self.assertEqual(result['client']['id'], client['id'])
        self.assertEqual(result['knownUUID'], client['id']); self.assertTrue(result['uids'])
        self.assertEqual(result['uids'], original['uids']); self.assertEqual(result['client'], original['client'])
        self.assertEqual(values, before)

    def test_native_client_order_comparison_keeps_uuid_approval_and_mapper_policy_guards(self):
        for change in ('uuid', 'approval', 'callback', 'audience', 'mapper-config', 'extra-mapper', 'duplicate-mapper', 'pkce', 'typed-policy'):
            with self.subTest(change=change):
                row, settings, lifecycle, identity, objects, client, platform = fixtures.lifecycle_observation()
                client['defaultClientScopes'].reverse(); client['protocolMappers'].reverse()
                if change == 'uuid': client['id'] = 'foreign-uuid'
                elif change == 'approval': client['attributes']['cloudlab.preview.approval'] = 'f' * 64
                elif change == 'callback': client['redirectUris'] = ['https://foreign.invalid/callback']
                elif change == 'pkce': client['attributes']['pkce.code.challenge.method'] = 'plain'
                elif change == 'typed-policy': client['fullScopeAllowed'] = 0
                elif change == 'extra-mapper': client['protocolMappers'].append(copy.deepcopy(client['protocolMappers'][0]))
                elif change == 'duplicate-mapper': client['protocolMappers'][1] = copy.deepcopy(client['protocolMappers'][0])
                else:
                    mapper = next(value for value in client['protocolMappers'] if value['name'] == 'api-audience')
                    mapper['config']['included.custom.audience' if change == 'audience' else 'access.token.claim'] = 'foreign'
                with self.assertRaises(ValueError):
                    evidence.inspect_row(row, settings, lifecycle, identity, {},
                        lambda kind,name=None,namespace=None: copy.deepcopy(objects.get((kind,name,namespace))),
                        lambda identifier:[client], lambda uuid:client, 1200, platform, secrets_present=lambda namespace:False)

    def test_shared_kubernetes_contains_keeps_command_lists_ordered(self):
        from playbooks.istio.files.kube import contains
        desired = {'spec': {'command': ['python', 'serve']}}
        self.assertTrue(contains(copy.deepcopy(desired), desired))
        self.assertFalse(contains({'spec': {'command': ['serve', 'python']}}, desired))

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
        stored['disabled'] = disabled
        for obj in (lifecycle, identity): obj['data']['state.json']=json.dumps({'entries':{row['instance']:{'phase':'retired','approvalDigest':first['approvalDigest']}}})
        objects.clear()
        absent=evidence.inspect_row(row,settings,lifecycle,identity,stored,get,lambda identifier:[],lambda uuid:None,1850,platform)
        self.assertTrue(absent['absent'])
        self.assertTrue(absent['cleanupOnlyAbsent'])
        with self.assertRaises(ValueError): evidence.inspect_row(row,settings,lifecycle,identity,stored,get,lambda identifier:[],lambda uuid:client,1850,platform)
        with self.assertRaises(RuntimeError): evidence.inspect_row(row,settings,lifecycle,identity,stored,get,lambda identifier:[],Mock(side_effect=RuntimeError('403')),1850,platform)

    def test_retired_absence_without_history_is_cleanup_only_not_grace_proof(self):
        row, settings, lifecycle, identity, objects, client, platform = fixtures.lifecycle_observation()
        for obj in (lifecycle, identity):
            obj['data']['state.json'] = json.dumps({'entries': {row['instance']: {
                'phase': 'retired', 'approvalDigest': fixtures.digest(fixtures.canonical(row))}}})
        objects.clear(); by_uuid = Mock(return_value=None)
        current = evidence.inspect_row(row, settings, lifecycle, identity, {}, lambda *args:None,
            lambda identifier:[], by_uuid, 3000, platform)
        self.assertTrue(current['cleanupOnlyAbsent']); self.assertFalse(current['absent'])
        self.assertFalse(current['active']); self.assertFalse(current['disabled'])
        self.assertNotIn('client', current); self.assertNotIn('disabledAt', current); by_uuid.assert_not_called()
        expected = {'active': {'active': True, 'client': {'id': client['id']}}}
        known = evidence.inspect_row(row, settings, lifecycle, identity, expected, lambda *args:None,
            lambda identifier:[], by_uuid, 3000, platform)
        self.assertTrue(known['cleanupOnlyAbsent']); self.assertFalse(known['absent'])
        by_uuid.assert_called_once_with(client['id'])
        with self.assertRaises(ValueError):
            evidence.inspect_row(row, settings, lifecycle, identity, {'latest': {'client': {'id': client['id']}}},
                lambda *args:None, lambda identifier:[], lambda uuid:client, 3000, platform)
        with self.assertRaises(ValueError):
            evidence.inspect_row(row, settings, lifecycle, identity, dict(expected, disabled={'client': {'id': 'another-uuid'}}),
                lambda *args:None, lambda identifier:[], lambda uuid:None, 3000, platform)
        for find, lookup in ((lambda identifier:[client,client], lambda uuid:None),
                             (lambda identifier:[], lambda uuid:client),
                             (lambda identifier:[], Mock(side_effect=RuntimeError('unavailable')))):
            with self.assertRaises((ValueError, RuntimeError)):
                evidence.inspect_row(row, settings, lifecycle, identity, expected, lambda *args:None, find, lookup, 3000, platform)
        for phase in ('retiring', 'active'):
            lifecycle['data']['state.json'] = json.dumps({'entries': {row['instance']: {
                'phase': phase, 'approvalDigest': current['approvalDigest']}}})
            result = evidence.inspect_row(row, settings, lifecycle, identity, {}, lambda *args:None,
                lambda identifier:[], lambda uuid:None, 3000, platform)
            self.assertFalse(result['cleanupOnlyAbsent'])

    def test_surviving_owned_resource_prevents_cleanup_only_absence(self):
        row, settings, lifecycle, identity, objects, client, platform = fixtures.lifecycle_observation()
        for obj in (lifecycle, identity):
            state = json.loads(obj['data']['state.json']); state['entries'][row['instance']]['phase'] = 'retired'
            obj['data']['state.json'] = json.dumps(state)
        get = lambda kind,name=None,namespace=None: copy.deepcopy(objects.get((kind,name,namespace))) if kind == 'namespace' else None
        current = evidence.inspect_row(row, settings, lifecycle, identity, {}, get,
            lambda identifier:[], lambda uuid:None, 3000, platform)
        self.assertTrue(current['uids']); self.assertFalse(current['cleanupOnlyAbsent']); self.assertFalse(current['absent'])

    def test_pending_uuid_remains_durable_through_repeated_cleanup_observations(self):
        from playbooks.previews.tests import approval_fixture as approval
        row, settings, lifecycle, identity, objects, client, platform = fixtures.lifecycle_observation()
        runtime = json.loads(lifecycle['data']['state.json']); runtime['entries'][row['instance']]['phase'] = 'pending'
        lifecycle['data']['state.json'] = json.dumps(runtime)
        state = {'approvals': {'a': {'row': row}}}
        pending = evidence.inspect_row(row, settings, lifecycle, identity, {}, lambda *args:None,
            lambda identifier:[client], lambda uuid:client, 1200, platform)
        self.assertFalse(pending['active']); self.assertEqual(pending['knownUUID'], client['id'])
        approval.remember(state, {'entries': {row['instance']: pending}}, Mock())
        for obj in (lifecycle, identity):
            obj['data']['state.json'] = json.dumps({'entries': {row['instance']: {
                'phase': 'retired', 'approvalDigest': pending['approvalDigest']}}})
        for now in (3000, 3001):
            lookup = Mock(return_value=None)
            current = evidence.inspect_row(row, settings, lifecycle, identity, state['evidence'][row['instance']],
                lambda *args:None, lambda identifier:[], lookup, now, platform)
            lookup.assert_called_once_with(client['id']); self.assertTrue(current['cleanupOnlyAbsent'])
            approval.remember(state, {'entries': {row['instance']: current}}, Mock())
            saved = state['evidence'][row['instance']]
            self.assertEqual(saved['knownUUID'], client['id']); self.assertNotIn('client', saved['latest'])
            for proof in ('active', 'disabled', 'absent'): self.assertNotIn(proof, saved)
        renamed = dict(client, clientId='renamed-client')
        for lookup in (Mock(return_value=renamed), Mock(side_effect=RuntimeError('unavailable'))):
            with self.assertRaises((ValueError, RuntimeError)):
                evidence.inspect_row(row, settings, lifecycle, identity, saved, lambda *args:None,
                    lambda identifier:[], lookup, 3002, platform)
            lookup.assert_called_once_with(client['id'])

    def test_historical_uuid_metadata_refuses_malformed_or_conflicting_identifiers(self):
        from playbooks.previews.tests import approval_fixture as approval
        row, settings, lifecycle, identity, objects, client, platform = fixtures.lifecycle_observation()
        fingerprint = fixtures.digest(fixtures.canonical(row))
        for obj in (lifecycle, identity):
            obj['data']['state.json'] = json.dumps({'entries': {row['instance']: {'phase': 'retired', 'approvalDigest': fingerprint}}})
        for history in ({'knownUUID': ''}, {'knownUUID': None}, {'knownUUID': '../invalid'}, {'knownUUID': ['uuid']},
                        {'knownUUID': client['id'], 'latest': {'client': {'id': 'different-uuid'}}}):
            with self.subTest(history=history):
                lookup = Mock()
                with self.assertRaises(ValueError):
                    evidence.inspect_row(row, settings, lifecycle, identity, history, lambda *args:None,
                        lambda identifier:[], lookup, 3000, platform)
                lookup.assert_not_called()
                state = {'approvals': {'a': {'row': row}}, 'evidence': {row['instance']: copy.deepcopy(history)}}
                save = Mock()
                with self.assertRaises(ValueError):
                    approval.remember(state, {'entries': {row['instance']: {'approvalDigest': fingerprint}}}, save)
                save.assert_not_called()

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
