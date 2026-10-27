import copy
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

from playbooks.previews.files.kube import APIError, identity
from playbooks.previews.tests import fixtures, resource_runtime as runtime


class ResourceTests(unittest.TestCase):
    def test_native_batch_float_overflow_refuses_named_and_collection_objects(self):
        api=runtime.HostKubernetes();key=('v1','Pod','owned','probe')
        for mode in ('named','collections'):
            for number in ('1e309','-1e309','1.25'):
                raw=('{"apiVersion":"v1","kind":"List","metadata":{},"items":['
                     '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"probe","namespace":"owned"},'
                     '"status":{"value":'+number+'}}]}').encode()
                with self.subTest(mode=mode,number=number),patch.object(api,'_read_batch',return_value=raw):
                    def read():return api.named([key])[key] if mode=='named' else api.collections('owned')['v1','Pod'][0]
                    if number=='1.25':self.assertEqual(read()['status']['value'],1.25)
                    else:
                        with self.assertRaises(ValueError):read()

    def test_native_batch_maps_complete_missing_reordered_and_rejects_unsafe_observations(self):
        api=runtime.HostKubernetes();keys=[('v1','Service','owned','first'),('v1','Service','owned','second')]
        values=[{'apiVersion':'v1','kind':'Service','metadata':{'name':key[3],'namespace':'owned','uid':key[3]}} for key in keys]
        def encode(items):return json.dumps({'apiVersion':'v1','kind':'List','metadata':{},'items':items}).encode()+b'\n'
        for raw,expected in ((encode(values[::-1]),values),(encode(values[:1]),[values[0],None]),(encode([]),[None,None]),(b'',[None,None])):
            with patch.object(api,'_read_batch',return_value=raw):
                result=api.named(keys);self.assertEqual([result[key] for key in keys],expected)
        malformed=[b' ',b'null',b'{',encode(values)[:-3],encode(values)+b'x',encode(values)+b' '*(2*1024*1024),
                   b'{"apiVersion":"v1","apiVersion":"v1","kind":"List","metadata":{},"items":[]}',encode(values+values)]
        for field,wrong in (('kind','ServiceList'),('apiVersion','v2'),('items',None),('metadata',{'continue':'next'}),
                            ('metadata',{'remainingItemCount':1}),('metadata',{'continue':None}),('metadata',None),('extra',True)):
            value=json.loads(encode(values));value[field]=wrong;malformed.append(json.dumps(value).encode())
        for field,wrong in (('name','foreign'),('namespace','foreign'),('name',''),('namespace',None)):
            changed=copy.deepcopy(values);changed[0]['metadata'][field]=wrong;malformed.append(encode(changed))
        for field,wrong in (('apiVersion','v2'),('kind','Pod'),('metadata',[])):
            changed=copy.deepcopy(values);changed[0][field]=wrong;malformed.append(encode(changed))
        malformed.extend((encode(values[:1]*501),encode([dict(values[0],spec={'invalid':float('nan')})])))
        for raw in malformed:
            with self.subTest(size=len(raw)),patch.object(api,'_read_batch',return_value=raw),self.assertRaises(ValueError):api.named(keys)
        for invalid in ([],keys*33,keys+keys,[('v1','Secret','owned','secret')],[('v1','Pod','','pod')],
                        [('v1','Namespace','owned','namespace')],[('v1','Pod','owned','-bad')],[('v1','Pod','owned','')]):
            with patch.object(api,'_read_batch') as read,self.assertRaises(ValueError):api.named(invalid)
            read.assert_not_called()
        pods=[{'apiVersion':'v1','kind':'Pod','metadata':{'namespace':'owned','name':name}} for name in ('preview','waypoint')]
        with patch.object(api,'_read_batch',return_value=encode(pods)) as read:
            self.assertEqual(api.collections('owned')['v1','Pod'],pods)
            read.assert_called_once_with(['pods,replicasets.apps,endpointslices.discovery.k8s.io','-n','owned'],None,None)
        with patch.object(api,'_read_batch',return_value=encode([])):
            self.assertTrue(all(not values for values in api.collections('owned').values()))
        for raw in (b'',b' ',b'null',encode(values),encode(pods+pods),encode([dict(pods[0],apiVersion='v2')]),
                    encode([dict(pods[0],metadata={'name':'foreign','namespace':'other'})])):
            with patch.object(api,'_read_batch',return_value=raw),self.assertRaises(ValueError):api.collections('owned')

    def test_native_batch_process_get_only_identity_stdin_and_bounded_failure_never_becomes_missing(self):
        api=runtime.HostKubernetes();key=('v1','Service','owned','first')
        expected=runtime.contract.canonical({'apiVersion':'v1','kind':'List','items':[
            {'apiVersion':'v1','kind':'Service','metadata':{'name':'first','namespace':'owned'}}]})+b'\n'
        native_popen=subprocess.Popen
        for response,error,status,delay in ((b'',b'',0,0),(b'',b'private-diagnostic',0,0),(b'',b'',7,0),
                (b'x'*(2*1024*1024+1),b'',0,0),(b'',b'',0,2)):
            processes=[]
            def spawn(arguments,**options):
                self.assertEqual(arguments,['/usr/local/bin/k3s','kubectl','--kubeconfig=/etc/rancher/k3s/k3s.yaml',
                    '--request-timeout=10s','get','-f','-','--ignore-not-found=true','--show-managed-fields=true','-o','json'])
                self.assertEqual(options['env'],{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
                self.assertTrue(options['start_new_session']);self.assertNotIn('shell',options)
                output=repr(response) if len(response)<1024 else "b'x'*"+str(len(response))
                script='import sys,time;assert sys.stdin.buffer.read()=='+repr(expected)+';sys.stdout.buffer.write('+output+');sys.stderr.buffer.write('+repr(error)+');time.sleep('+str(delay)+');sys.exit('+str(status)+')'
                process=native_popen([sys.executable,'-c',script],**options);processes.append(process);return process
            with self.subTest(status=status,stderr=bool(error),delay=delay),patch.object(runtime.subprocess,'Popen',side_effect=spawn):
                if error or status or delay or response:
                    with self.assertRaises(RuntimeError) as failure:api.named([key],deadline=time.monotonic()+(.2 if delay else 5))
                    self.assertNotIn('private-diagnostic',str(failure.exception))
                else:self.assertEqual(api.named([key]),{key:None})
            for process in processes:
                self.assertIsNotNone(process.returncode)
                self.assertTrue(all(stream.closed for stream in (process.stdin,process.stdout,process.stderr)))
        with patch.object(runtime.subprocess,'Popen') as spawn,self.assertRaises(ValueError):api.named([key],deadline=time.monotonic()-1)
        spawn.assert_not_called()

    def test_custody_preparation_has_no_preview_rows_resource_receipts_or_stale_success(self):
        from playbooks.previews.tests import live_acceptance as live, probe_transport
        from playbooks.previews.tests import approval_fixture
        state={'nonce':'e'*32,'executionPlatform':'c'*40,'baseline':{},'viewer':{'nonce':'e'*32,'realm':'applications'},
               'enrolled':True,'identity':{'enabled':True},'pulls':{'a':{'head':'a'*40},'b':{'head':'b'*40}},'intent':None}
        request=live.resource_request('custody-install',state)
        self.assertEqual(request['rows'],[])
        with patch.object(runtime.Path,'mkdir') as mkdir, self.assertRaises(ValueError): runtime.run(request)
        mkdir.assert_not_called()
        with patch.object(live,'resource_remote',return_value={'installed':True}) as install:
            live.execute('custody-install',{},state,Mock())
            install.assert_called_once_with({},request)
        self.assertNotIn('resources',state);self.assertNotIn('resourceEvidence',state)
        with patch('playbooks.previews.files.command.vm_environment'), \
                patch.object(probe_transport,'handoff',return_value={'host':True}) as handoff:
            live.execute('custody-observe',{},state,Mock())
            handoff.assert_called_once_with(state,[],[],host_only=True)
        events=[]
        with patch.object(live,'remote',return_value=state['identity']), \
                patch.object(live,'host_readiness',side_effect=lambda *args: events.append('fresh-host')), \
                patch.object(approval_fixture,'prepare',side_effect=lambda *args: events.append('approval')):
            live.execute('approval-prepare',{},state,Mock())
        self.assertEqual(events,['fresh-host','approval'])
        with patch.object(live,'remote',return_value=state['identity']), \
                patch.object(live,'host_readiness',side_effect=ValueError('unavailable')), \
                patch.object(approval_fixture,'prepare') as prepare:
            with self.assertRaises(ValueError):live.execute('approval-prepare',{},state,Mock())
            prepare.assert_not_called()

    def test_invalid_runtime_cli_inputs_never_save_intent_or_block_normal_continuation(self):
        from playbooks.previews.tests import live_acceptance as live, catalog_fixture
        cases=[('probe-prepare','missing',None),('probe-cleanup','missing',None),('retained-delete','missing',None),
               ('probe-prepare','image',None),('probe-prepare','revision',None),('probe-prepare','source',None),
               ('probe-prepare','duplicate',None),('probe-prepare','valid','a'),('retained-create','valid','a'),
               ('outage-prepare','valid','a'),('outage-cleanup','valid','a')]
        for action,invalid,slot in cases:
            with self.subTest(action=action,invalid=invalid,slot=slot),tempfile.TemporaryDirectory() as directory, \
                    patch.object(catalog_fixture,'JOURNALS',Path(directory)), \
                    patch('playbooks.argocd.files.render.committed_payload',return_value={'revision':'c'*40}), \
                    patch.object(live,'dotenv_values',return_value={}):
                nonce='e'*32;rows={key:{'row':fixtures.approval(letter*32)} for key,letter in (('a','a'),('b','b'),('d','d'))}
                if invalid=='missing':rows={}
                elif invalid=='image':rows['a']['row']['image']='unapproved'
                elif invalid=='revision':rows['a']['row']['platformRevision']='f'*40
                elif invalid=='source':rows['a']['row']['sourceSha']='unapproved'
                elif invalid=='duplicate':rows['b']['row']=copy.deepcopy(rows['a']['row'])
                state={'format':1,'nonce':nonce,'platform':'c'*40,'intent':None,'viewer':{'nonce':nonce,'realm':'applications'},
                       'baseline':{'cluster':{'persistent':{},'clients':{}}},'approvals':rows}
                path=Path(directory)/nonce/'journal.json';catalog_fixture.journal(path,state);original=path.read_bytes()
                arguments=[action,'--nonce',nonce,'--live']+(['--slot',slot] if slot else [])
                with patch.object(catalog_fixture,'journal',wraps=catalog_fixture.journal) as save, \
                        patch.object(live,'resource_remote') as dispatch:
                    with self.assertRaises(ValueError):live.main(arguments)
                    save.assert_not_called();dispatch.assert_not_called()
                self.assertEqual(path.read_bytes(),original)
                with patch('playbooks.keycloak.files.session_fixture.provision',return_value={}):
                    live.main(['viewer-provision','--nonce',nonce,'--live'])
                continued=json.loads(path.read_text());self.assertIsNone(continued['intent']);self.assertTrue(continued['provisioned'])

    def test_pending_retained_post_absent_after_namespace_retirement_can_reduce_without_proof(self):
        for kind in ('pending','rejected','unknown','changed','knownUID'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                row=fixtures.approval('d'*32);nonce='e'*32;ns=fixtures.names(row)['namespace']
                desired=runtime.obj(nonce,'v1','ConfigMap','retained-proof',ns,data={'synthetic':'retained-'+nonce})
                desired['metadata']['annotations']={'cloudlab.io/retention':'retain'}
                record={'desired':desired,'intent':True}
                if kind=='rejected':record['rejected']=409
                if kind=='unknown':record['intent']=False
                if kind=='changed':record['desired']=dict(desired,data={'foreign':'retain'})
                if kind=='knownUID':record['uid']='known-uid'
                state={'resources':{'/'.join(identity(desired)):record}}
                api=fixtures.ResourceAPI();receipts=runtime.Receipts(Path(directory),state,api)
                api.objects[('v1','ConfigMap','argocd',runtime.contract.STATE)]={'metadata':{'uid':'runtime'},
                    'data':{'state.json':json.dumps({'entries':{row['instance']:{'phase':'retired','resources':[],
                        'approvalDigest':runtime.contract.digest(runtime.contract.canonical(row))}}})}}
                request={'action':'retained-delete','nonce':nonce,'revision':'c'*40,'rows':[row]}
                if kind=='pending':
                    self.assertEqual(runtime.retained(request,receipts),{'retained':False,'fixtureCMAbsent':True})
                    self.assertTrue(record['deleteIntent']);self.assertTrue(record['deleted'])
                    self.assertNotIn('uid',record);self.assertNotIn('retainedNamespaceUID',state)
                    self.assertNotIn('evidence',state)
                else:
                    with self.assertRaises(ValueError):runtime.retained(request,receipts)
                self.assertEqual(api.writes,[])

    def test_unknown_appset_spec_is_never_observed_overwritten_or_deleted(self):
        for action in ('outage-observe','outage-fault','outage-restore','outage-cleanup'):
            for change in ('retention','extraTemplate','extraTopLevel'):
                with self.subTest(action=action,change=change),tempfile.TemporaryDirectory() as directory:
                    request,api,receipts,appset=self.outage_fixture(directory)
                    runtime.outage_observe(request,receipts,appset)
                    if action=='outage-restore':
                        request['action']='outage-fault';runtime.outage(request,receipts,'https://github.com/example/platform.git')
                    actual=api.objects[identity(appset)]
                    if change=='retention':actual['spec']['template']['metadata']['annotations']={'helm.sh/resource-policy':'keep'}
                    elif change=='extraTemplate':actual['spec']['template']['spec']['info']=[{'name':'owner','value':'user'}]
                    else:actual['spec']['strategy']={'type':'RollingSync'}
                    original=copy.deepcopy(api.objects);writes=copy.deepcopy(api.writes);request['action']=action
                    with self.assertRaises(ValueError):runtime.outage(request,receipts,'https://github.com/example/platform.git')
                    self.assertEqual(api.objects,original);self.assertEqual(api.writes,writes)

    def test_lost_appset_revision_replace_cannot_strip_extra_live_spec_on_retry(self):
        for action in ('outage-fault','outage-restore'):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                request,api,receipts,appset=self.outage_fixture(directory);runtime.outage_observe(request,receipts,appset)
                if action=='outage-restore':
                    request['action']='outage-fault';runtime.outage(request,receipts,'https://github.com/example/platform.git')
                request['action']=action;api.fail='replace'
                with self.assertRaises(RuntimeError):runtime.outage(request,receipts,'https://github.com/example/platform.git')
                api.objects[identity(appset)]['spec']['template']['metadata']['annotations']={'helm.sh/resource-policy':'keep'}
                original=copy.deepcopy(api.objects);writes=copy.deepcopy(api.writes)
                with self.assertRaises(ValueError):runtime.outage(request,receipts,'https://github.com/example/platform.git')
                self.assertEqual(api.objects,original);self.assertEqual(api.writes,writes)

    def test_persisted_retained_early_failure_allows_only_confirmed_absent_noop(self):
        from playbooks.previews.tests import live_acceptance as live, catalog_fixture
        for outcome in ('absent','existing','uncertain'):
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as directory, \
                    patch.object(catalog_fixture,'JOURNALS',Path(directory)), \
                    patch('playbooks.argocd.files.render.committed_payload',return_value={'revision':'c'*40}), \
                    patch.object(live,'dotenv_values',return_value={}), \
                    patch.object(live,'remote',return_value={'persistent':{},'clients':{}}):
                nonce='e'*32;row=fixtures.approval('d'*32)
                state={'format':1,'nonce':nonce,'platform':'c'*40,'intent':None,'viewer':{'nonce':nonce,'realm':'applications'},
                    'baseline':{'cluster':{'persistent':{},'clients':{}}},'approvals':{'d':{'row':row}}}
                path=Path(directory)/nonce/'journal.json';catalog_fixture.journal(path,state)
                with patch.object(live,'resource_remote',side_effect=RuntimeError('failure before first host save')):
                    with self.assertRaises(RuntimeError):live.main(['retained-create','--nonce',nonce,'--live'])
                self.assertEqual(json.loads(path.read_text())['intent']['action'],'retained-create')
                api=fixtures.ResourceAPI();key=('v1','ConfigMap',fixtures.names(row)['namespace'],'retained-proof')
                if outcome=='existing':api.create(runtime.obj(nonce,'v1','ConfigMap','retained-proof',key[2],data={'synthetic':'owned'}))
                writes=copy.deepcopy(api.writes)
                receipts=runtime.Receipts(Path(directory),{},api)
                def dispatch(values,request):return runtime.retained(request,receipts)
                with patch.object(live,'resource_remote',side_effect=dispatch):
                    if outcome=='uncertain':
                        with patch.object(api,'get',side_effect=RuntimeError('API unavailable')),self.assertRaises(RuntimeError):
                            live.main(['retained-delete','--nonce',nonce,'--live'])
                    elif outcome=='existing':
                        with self.assertRaises(ValueError):live.main(['retained-delete','--nonce',nonce,'--live'])
                    else:
                        live.main(['retained-delete','--nonce',nonce,'--live'])
                        saved=json.loads(path.read_text());self.assertIsNone(saved['intent'])
                        self.assertEqual(saved['resourceEvidence']['retained-delete'],{'retained':False,'fixtureCMAbsent':True})
                        self.assertNotIn('evidence',saved);self.assertNotIn('retainedNamespaceUID',receipts.state)
                self.assertEqual(api.writes,writes);self.assertEqual(receipts.state,{})
    def test_persisted_interrupted_cli_permits_only_same_family_reducing_recovery(self):
        from playbooks.previews.tests import live_acceptance as live, catalog_fixture
        for failed,recovery in (('probe-prepare','probe-cleanup'),('retained-create','retained-delete'),
                                ('outage-prepare','outage-cleanup'),('outage-fault','outage-restore')):
            with self.subTest(failed=failed),tempfile.TemporaryDirectory() as directory, \
                    patch.object(catalog_fixture,'JOURNALS',Path(directory)), \
                    patch('playbooks.argocd.files.render.committed_payload',return_value={'revision':'c'*40}), \
                    patch.object(live,'dotenv_values',return_value={}), \
                    patch.object(live,'remote',return_value={'persistent':{},'clients':{}}):
                nonce='e'*32;state={'format':1,'nonce':nonce,'platform':'c'*40,'intent':None,
                    'viewer':{'nonce':nonce,'realm':'applications'},'baseline':{'cluster':{'persistent':{},'clients':{}}},
                    'approvals':{slot:{'row':fixtures.approval(letter*32)} for slot,letter in (('a','a'),('b','b'),('d','d'))}}
                path=Path(directory)/nonce/'journal.json';catalog_fixture.journal(path,state)
                with patch.object(live,'resource_remote',side_effect=RuntimeError('lost fixture reply')):
                    with self.assertRaises(RuntimeError):live.main([failed,'--nonce',nonce,'--live'])
                self.assertEqual(json.loads(path.read_text())['intent'],{'action':failed,'slot':None})
                with patch.object(live,'resource_remote',return_value={'recovered':True}) as dispatch:
                    live.main([recovery,'--nonce',nonce,'--live'])
                    self.assertEqual(dispatch.call_args.args[1]['action'],recovery)
                self.assertIsNone(json.loads(path.read_text())['intent'])
                blocked=json.loads(path.read_text());blocked['intent']={'action':failed,'slot':None}
                with self.assertRaises(ValueError):live.execute('outage-prepare' if failed.startswith('probe-') else 'probe-prepare',{},blocked,Mock())

    def test_partial_probe_and_outage_preparations_cleanup_only_recorded_intents(self):
        for group,count in (('probe',6),('outage',5)):
            for boundary in range(count):
                with self.subTest(group=group,boundary=boundary),tempfile.TemporaryDirectory() as directory:
                    api=fixtures.ResourceAPI();request=self.request(group+'-prepare')
                    receipts=runtime.Receipts(Path(directory),{},api)
                    objects=runtime.probe_objects(request) if group=='probe' else runtime.outage_objects(request,'https://github.com/example/platform.git')
                    for desired in objects[:boundary]:receipts.create(desired)
                    api.fail='create'
                    with self.assertRaises(RuntimeError):receipts.create(objects[boundary])
                    request['action']=group+'-cleanup'
                    if group=='probe':result=runtime.probe(request,receipts)
                    else:result=runtime.outage(request,receipts,'https://github.com/example/platform.git')
                    self.assertTrue(result['probeAbsent' if group=='probe' else 'outageFixtureAbsent'])
                    self.assertEqual(api.objects,{})

    def test_live_cli_uses_only_journal_slots_and_nonsecret_ansible_resource_dispatch(self):
        from playbooks.previews.tests import live_acceptance as live
        rows={slot:{'row':fixtures.approval(letter*32)} for slot,letter in (('a','a'),('b','d'),('d','f'))}
        state={'nonce':'e'*32,'viewer':{'nonce':'e'*32,'realm':'applications'},'executionPlatform':'c'*40,
               'baseline':{'cluster':{'persistent':{},'clients':{}}},'approvals':rows,'intent':None}
        with patch.object(live,'resource_remote',return_value={'probePrepared':True}) as dispatch, \
                patch.object(live,'remote',return_value={'persistent':{},'clients':{}}):
            live.execute('probe-prepare',{},state,Mock())
            self.assertEqual(dispatch.call_args.args[1]['rows'],[rows['a']['row'],rows['b']['row']])
            self.assertEqual(set(dispatch.call_args.args[1]),{'action','nonce','revision','rows'})
            self.assertIsNone(state['intent'])
        bad=dict(dispatch.call_args.args[1],tokens=['secret'])
        with self.assertRaises(ValueError):runtime.validate(bad)

    def test_fixture_chart_has_nonwritable_dependency_coverage(self):
        from playbooks.dependencies.files import inventory
        path='ansible/playbooks/previews/tests/git-outage/Chart.yaml'
        document=inventory.coverage()
        owners=[(name,owner) for name,owner in document['owners'].items() if path in inventory.paths(owner)]
        self.assertEqual(len(owners),1)
        name,owner=owners[0];self.assertEqual(owner['disposition'],'qualification-fixture')
        self.assertEqual(owner['writePaths'],[])
        with self.assertRaises(ValueError):inventory.selected([name])

    def request(self, action='probe-prepare'):
        rows = [fixtures.approval(letter*32) for letter in ('a', 'd')] if action.startswith('probe-') else []
        return {'action': action, 'nonce': 'e'*32, 'revision': 'c'*40, 'rows': rows}

    def test_fixed_schemas_reject_generic_dispatch_and_coordinates(self):
        original = self.request(); runtime.validate(original)
        for request in (dict(original, action='delete'), dict(original, command='apply'), dict(original, namespace='foreign'),
                        dict(original, nonce='../other'), dict(original, rows=[]), dict(original, rows=[original['rows'][0]]*2)):
            with self.subTest(request=request), self.assertRaises(ValueError): runtime.validate(request)

    def test_create_receipt_precedes_write_and_recovers_only_ambiguous_owned_reply(self):
        with tempfile.TemporaryDirectory() as directory:
            api = fixtures.ResourceAPI(); state = {}; receipts = runtime.Receipts(Path(directory), state, api)
            desired = runtime.obj('e'*32, 'v1', 'ConfigMap', 'fixture', 'synthetic', data={'synthetic': 'owned'})
            api.fail = 'create'
            with self.assertRaises(RuntimeError): receipts.create(desired)
            saved = json.loads((Path(directory)/'state.json').read_text())
            self.assertTrue(saved['resources']['/'.join(identity(desired))]['intent'])
            self.assertNotIn('uid', saved['resources']['/'.join(identity(desired))])
            receipts.create(desired); self.assertEqual(len(api.writes), 1)
            self.assertEqual((Path(directory)/'state.json').stat().st_mode & 0o777, 0o600)
            api.objects[identity(desired)]['data']['extra'] = 'user-data'
            with self.assertRaises(ValueError): receipts.delete(identity(desired))
            self.assertEqual(len(api.writes), 1)

    def test_explicit_rejected_create_cannot_adopt_exact_foreign_race(self):
        with tempfile.TemporaryDirectory() as directory:
            api = fixtures.ResourceAPI(); receipts = runtime.Receipts(Path(directory), {}, api)
            desired = runtime.obj('e'*32, 'v1', 'ConfigMap', 'fixture', 'synthetic', data={'synthetic': 'owned'})
            def race(value):
                fixtures.ResourceAPI.create(api, value)
                raise APIError(409)
            with patch.object(api, 'create', side_effect=race), self.assertRaises(APIError): receipts.create(desired)
            writes = copy.deepcopy(api.writes)
            with self.assertRaises(ValueError): receipts.create(desired)
            with self.assertRaises(ValueError): receipts.delete(identity(desired))
            self.assertEqual(api.writes, writes); self.assertIsNotNone(api.get(identity(desired)))

    def test_host_transport_preserves_definitive_status_without_private_diagnostic(self):
        api = runtime.HostKubernetes()
        for stdout, stderr in (('{"kind":"Status","code":409}', ''), ('', 'Error from server (AlreadyExists): private-metadata')):
            with patch.object(runtime, 'kube', return_value=Mock(returncode=1, stdout=stdout, stderr=stderr)):
                with self.assertRaises(APIError) as error: api.create(runtime.obj('e'*32,'v1','ConfigMap','fixture','synthetic'))
                self.assertNotIn('private-metadata', str(error.exception))

    def test_configmap_extra_binary_data_uid_and_finalizers_block_deletion(self):
        for change in ('data', 'binaryData', 'uid', 'finalizers'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                api = fixtures.ResourceAPI(); receipts = runtime.Receipts(Path(directory), {}, api)
                desired = runtime.obj('e'*32, 'v1', 'ConfigMap', 'fixture', 'synthetic', data={'synthetic': 'owned'})
                receipts.create(desired); current = api.objects[identity(desired)]
                if change == 'data': current['data']['foreign'] = 'retain'
                elif change == 'binaryData': current['binaryData'] = {'foreign': 'dmFsdWU='}
                else: current['metadata'][change] = ['retain'] if change == 'finalizers' else 'foreign'
                with self.assertRaises(ValueError): receipts.delete(identity(desired))
                self.assertEqual(len(api.writes), 1)

    def test_delete_lost_reply_reconciles_only_saved_delete_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            api = fixtures.ResourceAPI(); receipts = runtime.Receipts(Path(directory), {}, api)
            desired = runtime.obj('e'*32, 'v1', 'ConfigMap', 'fixture', 'synthetic', data={'synthetic': 'owned'})
            receipts.create(desired); api.fail = 'delete'
            with self.assertRaises(RuntimeError): receipts.delete(identity(desired))
            receipts.delete(identity(desired)); self.assertTrue(receipts.recorded(identity(desired))['deleted'])
            self.assertEqual(len(api.writes), 2)

    def test_probe_manifests_restrict_runtime_and_do_not_modify_preview_policies(self):
        request = self.request(); objects = runtime.probe_objects(request)
        namespace = objects[0]; self.assertFalse(namespace['metadata']['name'].startswith('cloudlab-preview-'))
        self.assertEqual(namespace['metadata']['labels']['pod-security.kubernetes.io/enforce'], 'restricted')
        self.assertNotIn('istio.io/use-waypoint', namespace['metadata']['labels'])
        pod = next(obj for obj in objects if obj['kind'] == 'Pod')
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        self.assertEqual(pod['spec']['containers'][0]['image'], fixtures.IMAGE)
        self.assertTrue(pod['spec']['containers'][0]['securityContext']['readOnlyRootFilesystem'])
        self.assertNotIn('env', pod['spec']['containers'][0])
        self.assertEqual({obj['kind'] for obj in objects}, {'Namespace','ResourceQuota','NetworkPolicy','ConfigMap','Service','Pod'})
        self.assertTrue(all(obj['metadata'].get('namespace') in (None, namespace['metadata']['name']) for obj in objects))

    def outage_fixture(self, directory):
        request = self.request('outage-prepare'); api = fixtures.ResourceAPI()
        receipts = runtime.Receipts(Path(directory), {'nonce': request['nonce'], 'revision': request['revision']}, api)
        objects = runtime.outage_objects(request, 'https://github.com/example/platform.git')
        for desired in objects: receipts.create(desired)
        appset = objects[-1]; actual = api.get(identity(appset)); name = appset['metadata']['name']
        app = {'apiVersion':'argoproj.io/v1alpha1','kind':'Application',**copy.deepcopy(appset['spec']['template']),
            'status': {'sync': {'status':'Synced','revision':request['revision']},'health':{'status':'Healthy'}}}
        app['metadata'].update(namespace='argocd', ownerReferences=[{'apiVersion':'argoproj.io/v1alpha1','kind':'ApplicationSet',
            'name':name,'uid':actual['metadata']['uid'],'controller':True,'blockOwnerDeletion':True}])
        api.create(app)
        data = runtime.obj(request['nonce'],'v1','ConfigMap','persistent-proof',name,data={'synthetic':'persistent-'+request['nonce']})
        data['metadata']['annotations']={'cloudlab.io/retention':'retain'};api.create(data)
        return request, api, receipts, appset

    def test_native_outage_manifest_preserves_apps_and_pins_all_template_coordinates(self):
        objects = runtime.outage_objects(self.request('outage-prepare'),'https://github.com/example/platform.git')
        appset = objects[-1]; spec = appset['spec']
        self.assertEqual(spec['syncPolicy'],{'applicationsSync':'create-update','preserveResourcesOnDeletion':True})
        template=spec['template']['spec'];self.assertFalse(template['syncPolicy']['automated']['prune'])
        self.assertNotIn('finalizers',spec['template']['metadata'])
        self.assertEqual(template['source']['targetRevision'],'c'*40)
        self.assertEqual(template['destination']['namespace'],objects[0]['metadata']['name'])
        self.assertEqual(objects[-2]['spec']['namespaceResourceWhitelist'],[{'group':'','kind':'ConfigMap'}])

    def test_git_fault_lost_replace_reply_reconciles_then_restores_exact_source(self):
        with tempfile.TemporaryDirectory() as directory:
            request, api, receipts, appset=self.outage_fixture(directory)
            runtime.outage_observe(request,receipts,appset)
            with patch.object(runtime,'platform',return_value='https://github.com/example/platform.git'):
                request['action']='outage-fault';api.fail='replace'
                with self.assertRaises(RuntimeError):runtime.outage(request,receipts)
                runtime.outage(request,receipts);self.assertTrue(receipts.state['outageFault'])
                api.objects[identity(appset)]['status']={'conditions':[{'type':'ErrorOccurred','status':'True'}]}
                request['action']='outage-observe';self.assertTrue(runtime.outage(request,receipts)['generatorFailed'])
                request['action']='outage-restore';runtime.outage(request,receipts)
                self.assertFalse(receipts.state['outageFault'])
                self.assertEqual(api.get(identity(appset))['spec'],appset['spec'])

    def test_outage_cleanup_lost_deletes_resume_without_requiring_deleted_sources(self):
        for lost in ('appset','application','data'):
            with self.subTest(lost=lost),tempfile.TemporaryDirectory() as directory:
                request,api,receipts,appset=self.outage_fixture(directory)
                native=api.delete; count=[0]
                def remove(*args,**kwargs):
                    count[0]+=1
                    result=native(*args,**kwargs)
                    if count[0]=={'appset':1,'application':2,'data':3}[lost]:raise RuntimeError('lost delete reply')
                    return result
                request['action']='outage-cleanup'
                with patch.object(runtime,'platform',return_value='https://github.com/example/platform.git'):
                    with patch.object(api,'delete',side_effect=remove),self.assertRaises(RuntimeError):runtime.outage(request,receipts)
                    self.assertEqual(runtime.outage(request,receipts),{'outageFixtureAbsent':True})
                self.assertEqual(api.objects,{})

    def test_native_generated_data_metadata_changes_quarantine_initial_and_interrupted_cleanup(self):
        for boundary in (0,1,2):
            for change in ('keep','customRetention','ownerLabel','ownerReference','finalizer','annotation'):
                with self.subTest(boundary=boundary,change=change),tempfile.TemporaryDirectory() as directory:
                    request,api,receipts,appset=self.outage_fixture(directory)
                    runtime.outage_observe(request,receipts,appset)
                    name=runtime.coordinates(request['nonce'],'git');key=('v1','ConfigMap',name,'persistent-proof')
                    original=api.get(key);request['action']='outage-cleanup'
                    if boundary:
                        native=api.delete;calls=[0]
                        def remove(*args,**kwargs):
                            calls[0]+=1
                            result=native(*args,**kwargs)
                            if calls[0]==boundary:raise RuntimeError('lost delete reply')
                            return result
                        with patch.object(api,'delete',side_effect=remove),self.assertRaises(RuntimeError):
                            runtime.outage(request,receipts,'https://github.com/example/platform.git')
                        self.assertTrue(receipts.state['outageCleanupStarted'])
                    metadata=api.objects[key]['metadata']
                    if change=='keep':metadata['annotations']['helm.sh/resource-policy']='keep'
                    elif change=='customRetention':metadata['annotations']['example.invalid/retention']='retain'
                    elif change=='ownerLabel':metadata['labels']['cloudlab.io/owner']='foreign'
                    elif change=='ownerReference':metadata['ownerReferences']=[{'kind':'Application','uid':'foreign'}]
                    elif change=='finalizer':metadata['finalizers']=['example.invalid/retain']
                    else:metadata['annotations']['example.invalid/owner']='user'
                    changed=api.get(key);writes=copy.deepcopy(api.writes)
                    with self.assertRaises(ValueError):runtime.outage(request,receipts,'https://github.com/example/platform.git')
                    self.assertEqual(api.get(key),changed)
                    self.assertEqual(api.get(key)['metadata']['uid'],original['metadata']['uid'])
                    self.assertEqual(api.get(key)['data'],original['data'])
                    self.assertEqual(api.writes,writes)

    def test_native_generated_data_with_initial_keep_is_not_adopted_into_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            request,api,receipts,appset=self.outage_fixture(directory)
            name=runtime.coordinates(request['nonce'],'git');key=('v1','ConfigMap',name,'persistent-proof')
            api.objects[key]['metadata']['annotations']['helm.sh/resource-policy']='keep'
            with self.assertRaises(ValueError):runtime.outage_observe(request,receipts,appset)
            self.assertNotIn('outageBaseline',receipts.state)
            self.assertIsNotNone(api.get(key))

    def test_changed_native_application_quarantines_initial_and_interrupted_cleanup(self):
        for interrupted in (False,True):
            for change in ('source','project','destination','owner','keep','customRetention','finalizer','reference','extraSpec'):
                with self.subTest(interrupted=interrupted,change=change),tempfile.TemporaryDirectory() as directory:
                    request,api,receipts,appset=self.outage_fixture(directory)
                    runtime.outage_observe(request,receipts,appset)
                    name=runtime.coordinates(request['nonce'],'git');appkey=('argoproj.io/v1alpha1','Application','argocd',name)
                    datakey=('v1','ConfigMap',name,'persistent-proof');original_data=api.get(datakey)
                    request['action']='outage-cleanup'
                    if interrupted:
                        api.fail='delete'
                        with self.assertRaises(RuntimeError):runtime.outage(request,receipts,'https://github.com/example/platform.git')
                        self.assertTrue(receipts.state['outageCleanupStarted'])
                        self.assertIsNone(api.get(identity(appset)))
                    application=api.objects[appkey]
                    if change=='source':application['spec']['source']['path']='charts/changed'
                    elif change=='project':application['spec']['project']='changed-project'
                    elif change=='destination':application['spec']['destination']['namespace']='changed-namespace'
                    elif change=='owner':application['metadata']['labels']['cloudlab.io/owner']='foreign'
                    elif change=='keep':application['metadata']['annotations']={'helm.sh/resource-policy':'keep'}
                    elif change=='customRetention':application['metadata']['annotations']={'example.invalid/retention':'retain'}
                    elif change=='finalizer':application['metadata']['finalizers']=['example.invalid/retain']
                    elif change=='reference':application['metadata']['ownerReferences'].append({'kind':'ApplicationSet','uid':'foreign'})
                    else:application['spec']['info']=[{'name':'owner','value':'user'}]
                    changed=api.get(appkey);writes=copy.deepcopy(api.writes)
                    with self.assertRaises(ValueError):runtime.outage(request,receipts,'https://github.com/example/platform.git')
                    self.assertEqual(api.get(appkey),changed);self.assertEqual(api.get(datakey),original_data)
                    self.assertEqual(api.writes,writes)

    def test_native_orphan_removes_only_journaled_own_application_parent(self):
        for journaled in (False,True):
            with self.subTest(journaled=journaled),tempfile.TemporaryDirectory() as directory:
                request,api,receipts,appset=self.outage_fixture(directory)
                runtime.outage_observe(request,receipts,appset)
                name=runtime.coordinates(request['nonce'],'git');appkey=('argoproj.io/v1alpha1','Application','argocd',name)
                request['action']='outage-cleanup'
                if journaled:
                    api.fail='delete'
                    with self.assertRaises(RuntimeError):runtime.outage(request,receipts,'https://github.com/example/platform.git')
                    self.assertTrue(receipts.recorded(identity(appset))['deleteIntent'])
                api.objects[appkey]['metadata'].pop('ownerReferences')
                if journaled:
                    self.assertEqual(runtime.outage(request,receipts,'https://github.com/example/platform.git'),{'outageFixtureAbsent':True})
                    self.assertEqual(api.objects,{})
                else:
                    writes=copy.deepcopy(api.writes)
                    with self.assertRaises(ValueError):runtime.outage(request,receipts,'https://github.com/example/platform.git')
                    self.assertEqual(api.writes,writes)

    def test_unknown_namespace_data_blocks_teardown(self):
        with tempfile.TemporaryDirectory() as directory:
            api=fixtures.ResourceAPI();receipts=runtime.Receipts(Path(directory),{},api)
            namespace=runtime.restricted_namespace('e'*32,'probe');receipts.create(namespace)
            api.create(runtime.obj('e'*32,'v1','ConfigMap','foreign',namespace['metadata']['name'],data={'user':'retain'}))
            with self.assertRaises(ValueError):runtime.cleanup_namespace(receipts,namespace['metadata']['name'])
            self.assertIsNotNone(api.get(identity(namespace)))

    def retained_fixture(self, directory):
        row,_,state,_,objects,_,_=fixtures.lifecycle_observation()
        row['definition']['message']='synthetic fixture d revision 0'
        row['sourceDigest']=fixtures.digest(fixtures.canonical(row['definition']))
        entry=json.loads(state['data']['state.json'])['entries'][row['instance']]
        entry['approvalDigest']=fixtures.digest(fixtures.canonical(row))
        entry['approval']=row
        ns=fixtures.names(row)['namespace'];namespace=objects['namespace',ns,None]
        namespace['metadata']['annotations']['cloudlab.io/approval-digest']=entry['approvalDigest']
        state['data']['state.json']=json.dumps({'entries':{row['instance']:entry}})
        api=fixtures.ResourceAPI();api.objects[('v1','ConfigMap','argocd',runtime.contract.STATE)]=state
        api.objects[('v1','Namespace','',ns)]=namespace
        request={'action':'retained-create','nonce':'e'*32,'revision':'c'*40,'rows':[row]}
        return request,api,runtime.Receipts(Path(directory),{},api)

    def test_retained_data_is_exact_and_foreign_namespace_uid_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            request,api,receipts=self.retained_fixture(directory)
            result=runtime.retained(request,receipts);self.assertTrue(result['retained'])
            ns=fixtures.names(request['rows'][0])['namespace'];key=('v1','ConfigMap',ns,'retained-proof')
            api.objects[key]['data']['user']='retain'
            request['action']='retained-delete'
            with self.assertRaises(ValueError):runtime.retained(request,receipts)
            del api.objects[key]['data']['user']
            api.objects['v1','Namespace','',ns]['metadata']['uid']='foreign'
            with self.assertRaises(ValueError):runtime.retained(request,receipts)
            self.assertIsNotNone(api.get(key))

    def test_retained_delete_lost_reply_and_later_namespace_retirement_can_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            request,api,receipts=self.retained_fixture(directory);runtime.retained(request,receipts)
            request['action']='retained-delete';api.fail='delete'
            with self.assertRaises(RuntimeError):runtime.retained(request,receipts)
            ns=fixtures.names(request['rows'][0])['namespace'];del api.objects['v1','Namespace','',ns]
            self.assertFalse(runtime.retained(request,receipts)['retained'])

    def test_published_revision_advance_allows_only_original_receipt_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);nonce='e'*32;owned=root/nonce;owned.mkdir(mode=0o700)
            (owned/'state.json').write_text(json.dumps({'nonce':nonce,'revision':'c'*40}))
            (owned/'state.json').chmod(0o600)
            request=self.request('probe-cleanup');request['revision']='f'*40
            with patch.object(runtime,'ROOT',root),patch.object(runtime,'HostKubernetes'), \
                    patch.object(runtime,'platform',return_value='https://github.com/example/platform.git') as platform, \
                    patch.object(runtime,'probe',return_value={'probeAbsent':True}) as probe:
                self.assertTrue(runtime.run(request)['probeAbsent'])
                self.assertEqual(platform.call_args.args[0]['revision'],'f'*40)
                self.assertEqual(probe.call_args.args[0]['revision'],'c'*40)
                request['action']='probe-prepare'
                with self.assertRaises(ValueError):runtime.run(request)

    def test_one_published_revision_supports_ab_probe_cleanup_then_cd_retained_data(self):
        from playbooks.previews.tests import probe_state
        from playbooks.previews.files.resources import metadata
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); api = fixtures.ResourceAPI(); request = self.request()
            request['rows'][1] = fixtures.approval('b'*32)
            ready = {'Namespace': {'metadata': {'uid': 'probe-namespace'}}, 'Pod': {'metadata': {'uid': 'probe-pod'}}}
            with patch.object(runtime, 'ROOT', root), patch.object(runtime, 'HostKubernetes', return_value=api), \
                    patch.object(runtime, 'platform', return_value='https://github.com/example/platform.git'), \
                    patch.object(probe_state, 'bound_probe', return_value=ready):
                self.assertTrue(runtime.run(request)['probePrepared'])
                request['action'] = 'probe-cleanup'; self.assertTrue(runtime.run(request)['probeAbsent'])
                target = root/request['nonce']/'state.json'; prior = json.loads(target.read_text())
                self.assertTrue(all(record['deleted'] for record in prior['resources'].values()))
                row = fixtures.orphan_pair(fixtures.CatalogGit())['approvals']['d']['row']; ns = fixtures.names(row)['namespace']
                namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': metadata(row, 'runtime-state', ns)}
                namespace['metadata'].update(uid='preview-d-namespace', resourceVersion='1')
                api.objects[identity(namespace)] = namespace
                entry = {'phase': 'active', 'approvalDigest': fixtures.digest(fixtures.canonical(row)),
                    'resources': [{'key': ['v1', 'Namespace', '', ns], 'uid': 'preview-d-namespace'}]}
                api.objects['v1','ConfigMap','argocd',runtime.contract.STATE] = {'metadata': {'uid': 'runtime-state'},
                    'data': {'state.json': json.dumps({'entries': {row['instance']: entry}})}}
                retained = dict(request, action='retained-create', rows=[row])
                self.assertTrue(runtime.run(retained)['retained'])
                retained['action'] = 'retained-delete'; self.assertFalse(runtime.run(retained)['retained'])
                current = json.loads(target.read_text())
                self.assertEqual(current['revision'], prior['revision']); self.assertEqual(current['probeRows'], prior['probeRows'])
                self.assertEqual({key: current['resources'][key] for key in prior['resources']}, prior['resources'])

    def test_oversized_or_public_host_receipts_refuse_before_cluster_access(self):
        for mode,raw in ((0o644,'{}'),(0o600,'x'*262145)):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);owned=root/('e'*32);owned.mkdir(mode=0o700)
                target=owned/'state.json';target.write_text(raw);target.chmod(mode)
                with patch.object(runtime,'ROOT',root),patch.object(runtime,'HostKubernetes') as api:
                    with self.assertRaises(ValueError):runtime.run(self.request('outage-cleanup'))
                    api.assert_not_called()
