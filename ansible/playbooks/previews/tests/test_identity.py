import copy
import os
from pathlib import Path
import subprocess
import tempfile
import sys
from types import SimpleNamespace
import json
import unittest
from unittest.mock import patch
from fixtures import approval, catalog, Keycloak
from playbooks.previews.files.contract import canonical, digest, names
from playbooks.keycloak.files import preview_clients as identity


class IdentityTests(unittest.TestCase):
    def test_preview_representation_matches_native_collection_order_and_server_ids(self):
        row, settings = approval(), catalog()
        observed = identity.representation(row, settings)
        observed['defaultClientScopes'].reverse(); observed['protocolMappers'].reverse()
        for index, mapper in enumerate(observed['protocolMappers']): mapper['id'] = 'server-mapper-' + str(index)
        observed['attributes']['server-extra'] = 'preserved'
        before = copy.deepcopy((observed, row, settings))
        self.assertTrue(identity.representation_matches(observed, row, settings))
        self.assertEqual((observed, row, settings), before)
        for value in (None, [], 'client', 1): self.assertFalse(identity.representation_matches(value, row, settings))

    def test_preview_representation_requires_exact_unique_literal_collections(self):
        row, settings = approval(), catalog(); desired = identity.representation(row, settings)
        for field in ('redirectUris', 'webOrigins', 'defaultClientScopes', 'optionalClientScopes'):
            values = [None, {}, 'scope', 1, desired[field] + ['foreign'], [1] * max(1, len(desired[field]))]
            if desired[field]:
                values += [desired[field][:-1], desired[field] + [desired[field][0]], ['*', *desired[field][1:]]]
            else: values.append(['foreign', 'foreign'])
            for value in values:
                with self.subTest(field=field, value_type=type(value).__name__):
                    observed = copy.deepcopy(desired); observed[field] = value
                    before = copy.deepcopy(observed)
                    self.assertFalse(identity.representation_matches(observed, row, settings)); self.assertEqual(observed, before)

    def test_preview_representation_matches_each_mapper_name_and_all_required_config(self):
        row, settings = approval(), catalog(); desired = identity.representation(row, settings)
        for value in (None, {}, 'mapper', [None] * 3, desired['protocolMappers'][:-1],
                      desired['protocolMappers'] + [desired['protocolMappers'][0]], [desired['protocolMappers'][0]] * 3):
            observed = copy.deepcopy(desired); observed['protocolMappers'] = value
            self.assertFalse(identity.representation_matches(observed, row, settings))
        for index, mapper in enumerate(desired['protocolMappers']):
            for field in mapper:
                for change in ('missing', 'changed'):
                    with self.subTest(mapper=mapper['name'], field=field, change=change):
                        observed = copy.deepcopy(desired); target = observed['protocolMappers'][index]
                        if change == 'missing': del target[field]
                        else: target[field] = '' if field == 'name' else 'foreign'
                        self.assertFalse(identity.representation_matches(observed, row, settings))
            for key in mapper['config']:
                for change in ('missing', 'value', 'type'):
                    with self.subTest(mapper=mapper['name'], config=key, change=change):
                        observed = copy.deepcopy(desired); target = observed['protocolMappers'][index]['config']
                        if change == 'missing': del target[key]
                        else: target[key] = True if change == 'type' else 'foreign'
                        self.assertFalse(identity.representation_matches(observed, row, settings))

    def test_preview_representation_compares_all_security_fields_with_exact_json_types(self):
        row, settings = approval(), catalog(); desired = identity.representation(row, settings)
        for field, value in desired.items():
            with self.subTest(omitted=field):
                observed = copy.deepcopy(desired); del observed[field]
                self.assertFalse(identity.representation_matches(observed, row, settings))
            if type(value) in (str, bool):
                for changed in ('foreign', int(value) if type(value) is bool else None):
                    observed = copy.deepcopy(desired); observed[field] = changed
                    self.assertFalse(identity.representation_matches(observed, row, settings))
        for key in desired['attributes']:
            for change in ('missing', 'value', 'type'):
                with self.subTest(attribute=key, change=change):
                    observed = copy.deepcopy(desired)
                    if change == 'missing': del observed['attributes'][key]
                    else: observed['attributes'][key] = 300 if change == 'type' else 'foreign'
                    self.assertFalse(identity.representation_matches(observed, row, settings))

    def test_packaged_preview_comparer_imports_without_checkout_modules(self):
        root = Path(__file__).resolve().parents[4] / 'platform/identity/keycloak/runtime'
        script = '''import json,sys
sys.path.insert(0,sys.argv[1])
import preview_clients
row,settings=json.load(sys.stdin)
observed=preview_clients.representation(row,settings)
observed['defaultClientScopes'].reverse();observed['protocolMappers'].reverse()
for mapper in observed['protocolMappers']:mapper['id']='server-id'
assert preview_clients.representation_matches(observed,row,settings)
client=dict(observed,id='server-id',enabled=False)
state={'format':1,'entries':{row['instance']:{'approval':row,'approvalDigest':preview_clients.digest(preview_clients.canonical(row)),
    'clientId':client['clientId'],'uuid':'server-id','phase':'retiring','disabledAt':1200,'originVersion':preview_clients.ORIGIN_VERSION}}}
def api(action,value):
    assert action=='find'
    return [client]
saved=[]
preview_clients.reconcile(None,None,state,api,lambda value:saved.append(value['entries'][row['instance']]['phase']),1300,set())
assert state['entries'][row['instance']]['phase']=='disabled' and state['entries'][row['instance']]['disabledAt']==1200
assert saved==['disabled']
assert 'preview_contract' in sys.modules
assert preview_clients.__file__.startswith(sys.argv[1]+'/')
'''
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-I', '-c', script, str(root)], cwd=directory,
                input=json.dumps([approval(), catalog()]), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_legacy_origin_retires_before_repair_even_without_input(self):
        for available in (True, False):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'originVersion': 2, 'approvalDigest': digest(canonical(row))}}}
            state = {'format': 1, 'entries': {}}
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            del state['entries'][row['instance']]['originVersion']
            old_callback = ['https://preview.internal.example.invalid/previews/' + row['instance'] + '/callback']
            api.rows['owned-client-uuid']['redirectUris'] = old_callback
            identity.reconcile(settings if available else None, intent if available else None, state, api, lambda value: None, 1501, set(), input_available=available)
            self.assertFalse(api.rows['owned-client-uuid']['enabled'])
            self.assertEqual(api.rows['owned-client-uuid']['redirectUris'], old_callback)
            self.assertEqual(state['entries'][row['instance']]['approvalDigest'], digest(canonical(row)))
            identity.reconcile(None, None, state, api, lambda value: None, 2100, set(), input_available=False)
            self.assertEqual(api.deleted, [])
            identity.reconcile(None, None, state, api, lambda value: None, 2101, set(), input_available=False)
            self.assertEqual(api.deleted, ['owned-client-uuid'])
            identity.reconcile(settings, intent, state, api, lambda value: None, 1502, set())
            self.assertEqual(api.rows, {})


    def test_obsolete_client_is_disabled_then_uuid_deleted_with_or_without_catalog(self):
        from playbooks.previews.files import contract
        for available in (True, False):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'originVersion': 2, 'approvalDigest': digest(canonical(row))}}}
            state = {'format': 1, 'entries': {}}
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64):
                identity.reconcile(settings if available else None, intent if available else None,
                                   state, api, lambda value: None, 1501, set(), input_available=available)
                self.assertFalse(api.rows['owned-client-uuid']['enabled'])
                self.assertEqual(state['entries'][row['instance']]['approvalDigest'], digest(canonical(row)))
                identity.reconcile(settings if available else None, intent, state, api, lambda value: None,
                                   2101, set(), input_available=available)
            self.assertEqual(api.deleted, ['owned-client-uuid'])
            self.assertEqual(state['entries'][row['instance']]['phase'], 'retired')

    def test_expired_or_retiring_client_cleanup_ignores_new_callback_hostname(self):
        for phase, now in (('active', 2000), ('retiring', 1501)):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'originVersion': 2, 'approvalDigest': digest(canonical(row))}}}
            state = {'format': 1, 'entries': {}}
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            settings['hostname'] = 'changed.internal.example.invalid'
            with self.assertRaises(ValueError):
                identity.reconcile(settings, intent, state, api, lambda value: None, 1501, set())
            state['entries'][row['instance']]['phase'] = phase
            identity.reconcile(settings, intent, state, api, lambda value: None, now, set())
            self.assertFalse(api.rows['owned-client-uuid']['enabled'])
            identity.reconcile(settings, intent, state, api, lambda value: None, now + 600, set())
            self.assertEqual(api.deleted, ['owned-client-uuid'])

    def test_obsolete_new_or_creating_row_never_creates_or_reactivates_client(self):
        from playbooks.previews.files import contract
        row, settings, api = approval(), catalog(), Keycloak()
        intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'originVersion': 2, 'approvalDigest': digest(canonical(row))}}}
        state = {'format': 1, 'entries': {}}
        with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64):
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            self.assertEqual(state['entries'], {})
            self.assertEqual(api.rows, {})
        identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
        state['entries'][row['instance']]['phase'] = 'creating'
        api.rows.clear()
        with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64):
            identity.reconcile(None, None, state, api, lambda value: None, 1501, set(), input_available=False)
        self.assertEqual(api.rows, {})
        self.assertEqual(state['entries'][row['instance']]['phase'], 'retired')

    def test_image_change_keeps_client_uuid_and_persistent_collision_vetoes(self):
        from playbooks.previews.files import contract
        for change in ('uuid', 'persistent'):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'originVersion': 2, 'approvalDigest': digest(canonical(row))}}}
            state = {'format': 1, 'entries': {}}
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            if change == 'uuid':
                api.rows['owned-client-uuid']['id'] = 'replacement-client'
            persistent = {names(row)['client']} if change == 'persistent' else set()
            with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64), self.assertRaises(ValueError):
                identity.reconcile(None, None, state, api, lambda value: None, 1501, persistent, input_available=False)
            self.assertTrue(api.rows['owned-client-uuid']['enabled'])
            self.assertEqual(api.deleted, [])

    def test_runtime_adapter_retains_then_expires_clients_when_approval_input_disappears(self):
        from playbooks.previews.files import contract
        for corrupt, image_changed in ((False, False), (True, False), (False, True), (True, True)):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'originVersion': 2, 'approvalDigest': digest(canonical(row))}}}
            state = {'format': 1, 'entries': {}}
            identity.reconcile(settings, intent, state, api, lambda value: None, 1500, set())
            api.rows['unrelated'] = {'id': 'unrelated', 'clientId': 'persistent-client'}
            documents = {
                'cloudlab-preview-state': {'metadata': {'labels': {'cloudlab.io/owner': 'cloudlab-previews'}}, 'data': {'state.json': json.dumps(intent)}},
                'cloudlab-preview-identity-state': {'metadata': {'labels': {'cloudlab.io/owner': 'cloudlab-preview-identity'}}, 'data': {'state.json': json.dumps(state)}}}
            if corrupt:
                documents['cloudlab-preview-approvals'] = {'metadata': {'labels': {'cloudlab.io/owner': 'cloudlab-previews'}}, 'data': {'catalog.json': '{'}}
            def kube(method, path, value=None):
                name = path.rsplit('/', 1)[-1]
                if method == 'GET':
                    if name not in documents:
                        from urllib.error import HTTPError
                        raise HTTPError(path, 404, '', None, None)
                    return copy.deepcopy(documents[name])
                documents['cloudlab-preview-identity-state'] = copy.deepcopy(value)
                return copy.deepcopy(value)
            original = identity.reconcile
            def reconcile(settings, intent, state, adapter, save, now, persistent, **kwargs):
                return original(settings, intent, state, api, save, now, persistent, **kwargs)
            def read(path, *args, **kwargs):
                return json.dumps({'realms': {}}) if str(path) == '/private/desired_state' else 'synthetic-writer-secret'
            with patch.dict(sys.modules, {'lease': SimpleNamespace(api_request=kube),
                    'configuration': SimpleNamespace(private_request=lambda *args, **kwargs: {'access_token': 'synthetic'})}), \
                    patch.object(identity, 'reconcile', side_effect=reconcile), patch.object(Path, 'read_text', read), \
                    patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64 if image_changed else contract.IMAGE):
                for now in (1501, 2000, 2600):
                    with patch.object(identity.time, 'time', return_value=now), self.assertRaises(RuntimeError):
                        identity.run('identity-admin.internal.example.invalid')
                    if now == 1501: self.assertEqual(api.rows['owned-client-uuid']['enabled'], not image_changed)
            self.assertEqual(api.deleted, ['owned-client-uuid'])
            self.assertEqual(set(api.rows), {'unrelated'})

    def test_disable_confirm_grace_and_exact_removal_without_git(self):
        row = approval()
        settings = catalog()
        intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'originVersion': 2, 'approvalDigest': digest(canonical(row))}}}
        state = {'format': 1, 'entries': {}}
        api = Keycloak()
        saves = []
        save = lambda value: saves.append(copy.deepcopy(value))
        identity.reconcile(settings, intent, state, api, save, 1500, set())
        self.assertEqual(state['entries'][row['instance']]['phase'], 'active')
        self.assertEqual(next(iter(api.rows.values()))['redirectUris'], ['https://preview-' + row['instance'] + '.internal.example.invalid/previews/' + row['instance'] + '/callback'])
        identity.reconcile(None, None, state, api, save, 2000, set())
        self.assertFalse(next(iter(api.rows.values()))['enabled'])
        self.assertEqual(state['entries'][row['instance']]['disabledAt'], 2000)
        identity.reconcile(None, None, state, api, save, 2599, set())
        self.assertEqual(state['entries'][row['instance']]['phase'], 'disabled')
        self.assertEqual(api.deleted, [])
        identity.reconcile(None, None, state, api, save, 2600, set())
        self.assertEqual(api.deleted, ['owned-client-uuid'])
        identity.reconcile(settings, intent, state, api, save, 1501, set())
        self.assertEqual(api.rows, {})
        self.assertEqual(state['entries'][row['instance']]['phase'], 'retired')

    def test_uuid_change_and_persistent_collision_never_adopted(self):
        row = approval()
        settings = catalog()
        intent = {'format': 1, 'entries': {row['instance']: {'phase': 'pending', 'originVersion': 2, 'approvalDigest': digest(canonical(row))}}}
        state = {'format': 1, 'entries': {}}
        api = Keycloak()
        with self.assertRaises(ValueError): identity.reconcile(settings, intent, state, api, lambda x: None, 1500, {names(row)['client']})
        self.assertEqual(api.rows, {})
        identity.reconcile(settings, intent, state, api, lambda x: None, 1500, set())
        api.rows['owned-client-uuid']['id'] = 'replacement'
        with self.assertRaises(ValueError): identity.reconcile(None, None, state, api, lambda x: None, 2600, set())
        self.assertEqual(api.deleted, [])

    def test_confirmed_disable_repeats_and_legacy_restart_keep_same_grace(self):
        for legacy in (False, True):
            row, settings, api = approval(), catalog(), Keycloak()
            intent = {'format':1,'entries':{row['instance']:{'phase':'pending','originVersion':2,'approvalDigest':digest(canonical(row))}}}
            state = {'format':1,'entries':{}}
            identity.reconcile(settings,intent,state,api,lambda value:None,1500,set())
            identity.reconcile(None,None,state,api,lambda value:None,2000,set())
            if legacy: state['entries'][row['instance']]['phase']='retiring'
            state=copy.deepcopy(state);saved=[];actions=[]
            api.rows['persistent']={'id':'persistent','clientId':'persistent-client','enabled':True}
            unrelated=copy.deepcopy(api.rows['persistent'])
            def observed(action,value):
                actions.append(action);return api(action,value)
            for now in (2001,2599):
                identity.reconcile(None,None,state,observed,lambda value:saved.append(copy.deepcopy(value)),now,{'persistent-client'})
                record=state['entries'][row['instance']]
                self.assertEqual((record['phase'],record['uuid'],record['disabledAt']),('disabled','owned-client-uuid',2000))
                self.assertEqual(record['approval'],row);self.assertEqual(api.deleted,[])
            self.assertTrue(all(value['entries'][row['instance']]['phase']=='disabled' for value in saved))
            self.assertNotIn('update',actions)
            identity.reconcile(None,None,state,api,lambda value:None,2600,{'persistent-client'})
            self.assertEqual(api.deleted,['owned-client-uuid'])
            self.assertEqual(state['entries'][row['instance']],{'phase':'retired','approvalDigest':digest(canonical(row))})
            self.assertEqual(api.rows,{'persistent':unrelated})

    def test_reusable_disable_requires_saved_valid_time_and_uuid_before_any_write(self):
        cases=[('disabledAt',value) for value in (None,False,True,0,-1,2000.0,'2000',2501)]
        cases += [('uuid',None),('uuid',''),('uuid','changed'),('ownership','changed')]
        for field,value in cases:
            with self.subTest(field=field,value=value):
                row, settings, api = approval(), catalog(), Keycloak()
                intent={'format':1,'entries':{row['instance']:{'phase':'pending','originVersion':2,'approvalDigest':digest(canonical(row))}}}
                state={'format':1,'entries':{}}
                identity.reconcile(settings,intent,state,api,lambda value:None,1500,set())
                identity.reconcile(None,None,state,api,lambda value:None,2000,set())
                if field=='ownership':api.rows['owned-client-uuid']['attributes']['cloudlab.preview.approval']='foreign'
                else:state['entries'][row['instance']][field]=value
                before=copy.deepcopy((state,api.rows));saved=[]
                with self.assertRaises(ValueError):identity.reconcile(None,None,state,api,lambda value:saved.append(copy.deepcopy(value)),2500,set())
                self.assertEqual((state,api.rows),before);self.assertEqual(saved,[]);self.assertEqual(api.deleted,[])

    def test_reenabled_client_lost_write_or_confirmation_cannot_reuse_old_grace(self):
        for failure in ('write-before','write-after','missing','duplicate','uuid','ownership','enabled'):
            with self.subTest(failure=failure):
                row, settings, api = approval(), catalog(), Keycloak()
                intent={'format':1,'entries':{row['instance']:{'phase':'pending','originVersion':2,'approvalDigest':digest(canonical(row))}}}
                state={'format':1,'entries':{}}
                identity.reconcile(settings,intent,state,api,lambda value:None,1500,set())
                identity.reconcile(None,None,state,api,lambda value:None,2000,set())
                api.rows['owned-client-uuid']['enabled']=True;saved=[];updated=False
                def interrupted(action,value):
                    nonlocal updated
                    if action=='update':
                        durable=saved[-1]['entries'][row['instance']]
                        self.assertEqual(durable['phase'],'retiring');self.assertNotIn('disabledAt',durable)
                        if failure=='write-before':raise RuntimeError('write unavailable')
                        api(action,value);updated=True
                        if failure=='write-after':raise RuntimeError('lost write response')
                        return None
                    result=api(action,value)
                    if action=='find' and updated:
                        if failure=='missing':return []
                        if failure=='duplicate':return result*2
                        if failure=='uuid':result[0]['id']='changed'
                        if failure=='ownership':result[0]['attributes']['cloudlab.preview.approval']='foreign'
                        if failure=='enabled':result[0]['enabled']=True
                    return result
                with self.assertRaises((ValueError,RuntimeError)):
                    identity.reconcile(None,None,state,interrupted,lambda value:saved.append(copy.deepcopy(value)),2500,set())
                self.assertEqual(state['entries'][row['instance']]['phase'],'retiring')
                self.assertNotIn('disabledAt',state['entries'][row['instance']]);self.assertEqual(api.deleted,[])
                state=copy.deepcopy(saved[-1])
                identity.reconcile(None,None,state,api,lambda value:None,2600,set())
                record=state['entries'][row['instance']]
                self.assertEqual((record['phase'],record['uuid'],record['disabledAt']),('disabled','owned-client-uuid',2600))
                self.assertEqual(record['approval'],row);self.assertEqual(api.deleted,[])
                identity.reconcile(None,None,state,api,lambda value:None,3199,set());self.assertEqual(api.deleted,[])
                identity.reconcile(None,None,state,api,lambda value:None,3200,set());self.assertEqual(api.deleted,['owned-client-uuid'])

    def test_only_explicit_backend_false_keeps_confirmed_disable_time(self):
        for enabled in (False,True,None,0,'false','missing'):
            with self.subTest(enabled=enabled):
                row, settings, api = approval(), catalog(), Keycloak()
                intent={'format':1,'entries':{row['instance']:{'phase':'pending','originVersion':2,'approvalDigest':digest(canonical(row))}}}
                state={'format':1,'entries':{}}
                identity.reconcile(settings,intent,state,api,lambda value:None,1500,set())
                identity.reconcile(None,None,state,api,lambda value:None,2000,set())
                if enabled=='missing':api.rows['owned-client-uuid'].pop('enabled')
                else:api.rows['owned-client-uuid']['enabled']=enabled
                identity.reconcile(None,None,state,api,lambda value:None,2500,set())
                self.assertEqual(state['entries'][row['instance']]['disabledAt'],2000 if enabled is False else 2500)
                self.assertEqual(state['entries'][row['instance']]['phase'],'disabled');self.assertEqual(api.deleted,[])

    def test_preview_failure_returns_for_ordinary_realm_repair_then_marks_failure(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(identity, 'run', side_effect=RuntimeError('private failure')):
            self.assertFalse(identity.attempt('identity-admin.internal.example.invalid', directory))
            self.assertEqual(Path(directory, 'preview-error').read_text(), 'Preview identity reconciliation failed; diagnostics withheld\n')

    def test_rendered_writer_repairs_both_realms_before_reporting_preview_failure(self):
        from playbooks.keycloak.files.chart import render
        objects = render({'enabled': True, 'operatorEnabled': False, 'reconciliationEnabled': True,
            'privateStateEnabled': True, 'trustedProxyAddresses': ['10.43.0.10/32'], 'databaseCA': 'fixture-ca'})
        job = next(obj for obj in objects if obj['kind'] == 'Job' and obj['metadata']['name'] == 'identity-reconcile-sync')
        script = job['spec']['template']['spec']['containers'][0]['args'][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            imports, credentials, binary = (root / part for part in ('imports', 'credentials', 'bin'))
            for path in (imports, credentials, binary): path.mkdir()
            for realm in ('platform', 'applications'):
                credentials.joinpath(realm + '_client_secret').write_text('synthetic-' + 'x' * 48)
            with patch.object(identity, 'run', side_effect=RuntimeError('unavailable')):
                self.assertFalse(identity.attempt('identity-admin.internal.example.invalid', str(imports)))
            java = binary / 'java'
            java.write_text('#!/bin/sh\nprintf "%s\\n" "$KEYCLOAK_LOGINREALM" >> "$REALM_LOG"\n')
            java.chmod(0o700)
            script = script.replace('/imports', str(imports)).replace('/credentials', str(credentials)).replace('/tmp/result', str(root / 'result'))
            result = subprocess.run(['sh', '-ec', script], env=dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'],
                REALM_LOG=str(root / 'realms')), capture_output=True, text=True, timeout=10)
            self.assertEqual((root / 'realms').read_text().splitlines(), ['platform', 'applications'])
            self.assertEqual(result.returncode, 1)
            self.assertIn('ordinary realm repair completed', result.stdout)
