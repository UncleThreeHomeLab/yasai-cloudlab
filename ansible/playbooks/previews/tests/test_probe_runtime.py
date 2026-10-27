import base64
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

from playbooks.previews.tests import fixtures, probe_program as program, probe_inspection as inspection, probe_state, probe_transport as transport
from playbooks.previews.files import contract


class ProbeTests(unittest.TestCase):
    def test_host_only_owner_observation_requires_current_healthy_source_without_resources(self):
        from playbooks.previews.tests import resource_runtime
        api=fixtures.ResourceAPI();key=('argoproj.io/v1alpha1','Application','argocd','cloudlab-previews')
        api.objects[key]={'spec':{'sources':[{'repoURL':'https://github.com/example/platform.git','targetRevision':'c'*40}]},
                          'status':{'sync':{'revisions':['c'*40]},'health':{'status':'Healthy'}}}
        with patch.object(resource_runtime,'HostKubernetes',return_value=api):
            probe_state.host_owner('c'*40)
            with self.assertRaises(ValueError):probe_state.host_owner('f'*40)
            api.objects[key]['status']['health']['status']='Progressing'
            with self.assertRaises(ValueError):probe_state.host_owner('c'*40)
        self.assertEqual(api.writes,[])

    def assurance(self,observation):
        def command(arguments):return observation['commands'][tuple(arguments)]
        with patch.dict(os.environ,{'SSH_CONNECTION':'100.64.0.1 4000 100.64.0.2 22'},clear=True), \
                patch.object(probe_state.os,'geteuid',return_value=0),patch.object(probe_state.os,'isatty',return_value=False), \
                patch.object(probe_state.os,'getppid',return_value=observation['parent']), \
                patch.object(probe_state,'command',side_effect=command), \
                patch.object(probe_state,'file',side_effect=lambda name:observation['files'][name]), \
                patch.object(Path,'exists',autospec=True,side_effect=lambda path:str(path)=='/root/.bashrc'), \
                patch.object(Path,'glob',autospec=True,side_effect=lambda *args:iter(())), \
                patch.object(Path,'resolve',autospec=True,side_effect=lambda path:Path(observation['executables'][str(path)])), \
                patch.object(Path,'read_bytes',autospec=True,side_effect=lambda path:observation['cmdlines'][str(path)]), \
                patch.object(probe_state.subprocess,'run',return_value=Mock(returncode=3,stdout='inactive\n',stderr='')):
            result=probe_state.assurance(Mock(observe=Mock(return_value={"native":"synthetic"})))
            return result

    def test_actual_assurance_accepts_packaged_debian13_session_and_legacy_native_chain(self):
        for native,pam,shell in (('/usr/lib/openssh/sshd-session','sshd',False),
                                 ('/usr/lib/openssh/sshd-session','sshd',True),('/usr/sbin/sshd',None,False)):
            with self.subTest(native=native,pam=pam,shell=shell):
                self.assertRegex(self.assurance(fixtures.probe_assurance_observation(native,pam,shell=shell)),'^[a-f0-9]{64}$')

    def test_actual_assurance_refuses_unknown_wrapper_unowned_native_or_custom_pam_stack(self):
        unknown=fixtures.probe_assurance_observation('/usr/local/bin/recording-wrapper')
        unowned=fixtures.probe_assurance_observation()
        unowned['commands'][('dpkg-query','--search','/usr/lib/openssh/sshd-session')]='custom-package: /usr/lib/openssh/sshd-session\n'
        changed=fixtures.probe_assurance_observation()
        changed['commands'][('dpkg','--verify','openssh-server','libpam-modules','libpam-runtime','bash')]='modified package file\n'
        for observation in (unknown,unowned,changed,fixtures.probe_assurance_observation(pam='recorded-ssh'),
                            fixtures.probe_assurance_observation(pam=None)):
            with self.subTest(observation=observation),self.assertRaises(ValueError):self.assurance(observation)

    def test_stock_color_environment_names_do_not_allow_unsafe_extra_patterns(self):
        for pattern in ('UNKNOWN','BASH_ENV','ENV','PYTHONPATH','LD_PRELOAD','HTTP_PROXY','HTTPS_PROXY',
                        'OP_SERVICE_ACCOUNT_TOKEN','*','COLORTERM*','NO_COLOR*'):
            observation=fixtures.probe_assurance_observation()
            key=('/usr/sbin/sshd','-T','-C','user=root,addr=100.64.0.1,laddr=100.64.0.2,lport=22')
            observation['commands'][key]=observation['commands'][key].replace('COLORTERM NO_COLOR\n','COLORTERM NO_COLOR '+pattern+'\n')
            with self.subTest(pattern=pattern),self.assertRaises(ValueError):self.assurance(observation)

    def test_only_tcp_connect_timeout_can_count_as_l4_denial(self):
        target={'host':'preview.internal.example.invalid','address':'10.42.0.1','path':'/preview/','tls':False,'expected':{'synthetic':'data'}}
        for failed,expected in (('connect','timeout'),('request','unproved'),('getresponse','unproved')):
            connection=Mock();getattr(connection,failed).side_effect=socket.timeout()
            with patch.object(program.http.client,'HTTPConnection',return_value=connection):
                self.assertEqual(program.request(target),expected)
        connection=Mock();connection.getresponse.return_value.read.side_effect=socket.timeout()
        with patch.object(program.http.client,'HTTPConnection',return_value=connection):
            self.assertEqual(program.request(target),'unproved')

    def test_gateway_positive_must_survive_each_targets_negative_paths(self):
        base={'host':'preview.internal.example.invalid','path':'/preview/','expected':{'synthetic':'data'}}
        groups=[{kind:dict(base,address='10.42.0.'+str(index*3+offset),tls=kind=='gateway')
                 for offset,kind in enumerate(('gateway','service','pod'),1)} for index in range(2)]
        frame={'phase':'probe','deadline':1250,'tokens':['synthetic-a','synthetic-b'],
               'control':dict(base,address='10.43.0.1',tls=False),'targets':groups}
        for outage in (False,True):
            calls=[]
            def request(target,bearer=None):
                calls.append((target['address'],bearer))
                if target==frame['control']:return 'allowed'
                if target['tls']:
                    count=sum(address==target['address'] for address,_ in calls)
                    return 'unproved' if outage and count==2 else 'allowed'
                return 'timeout'
            with self.subTest(outage=outage),patch.object(program,'request',side_effect=request),patch.object(program.time,'time',return_value=1200):
                if outage:
                    with self.assertRaises(ValueError):program.run(frame)
                else:
                    self.assertTrue(program.run(frame)['targets'][0]['podProtected'])
                    self.assertEqual(sum(address in [group['gateway']['address'] for group in groups] for address,_ in calls),4)
    def test_stock_noninteractive_bash_guards_are_accepted_but_wrappers_refuse(self):
        for raw in ('# comment\n', '[ -z "$PS1" ] && return\necho interactive',
                    'case $- in\n *i*) ;;\n *) return;;\nesac\necho interactive'):
            self.assertTrue(probe_state.bash_startup_safe(raw))
        for raw in ('record-stdin\n[ -z "$PS1" ] && return\n', 'source custom-wrapper', 'case $- in\n*) record;;\nesac'):
            self.assertFalse(probe_state.bash_startup_safe(raw))

    def test_effective_server_environment_cannot_redirect_config_or_audit(self):
        from playbooks.k3s.files.native_custody import environment_policy
        for key in ('K3S_KUBE_APISERVER_ARG','K3S_CONFIG_FILE','K3S_DATA_DIR','HTTPS_PROXY','LD_PRELOAD'):
            with self.assertRaises(ValueError) as error:environment_policy((key+'=private\0').encode())
            self.assertNotIn('private',str(error.exception))
        environment_policy(b'PATH=/usr/bin\0K3S_TOKEN=never-export\0')

    def test_targets_bind_exact_ready_pod_service_endpoints_and_policies(self):
        row,objects=fixtures.probe_observation()
        def get(kind,name=None,namespace=None):return copy.deepcopy(objects.get((kind,name,namespace)))
        with patch.object(probe_state,'get',side_effect=get):
            declarations,snapshot=probe_state.targets([row],row['platformRevision'])
            self.assertEqual(declarations[0]['pod']['address'],'10.42.0.5')
            self.assertEqual(snapshot['targets'][0]['podUID'],'pod')
        for change in ('podUID','endpointOwner','notReady','policy','selector','source','extraContainer'):
            row,objects=fixtures.probe_observation();ns=contract.names(row)['namespace']
            if change=='podUID':objects['pods',None,ns]['items'][0]['metadata']['uid']='foreign'
            if change=='endpointOwner':objects['endpointslices.discovery.k8s.io',None,ns]['items'][0]['metadata']['ownerReferences'][0]['uid']='foreign'
            if change=='notReady':objects['pods',None,ns]['items'][0]['status']['conditions']=[]
            if change=='policy':objects['networkpolicy.networking.k8s.io','application',ns]['spec']['ingress']=[]
            if change=='selector':objects['service','preview',ns]['spec']['selector']={'foreign':'pod'}
            if change=='source':objects['deployment.apps','preview',ns]['spec']['template']['spec']['containers'][0]['env'][0]['value']='foreign'
            if change=='extraContainer':objects['pods',None,ns]['items'][0]['spec']['containers'].append({'image':'foreign'})
            with self.subTest(change=change),patch.object(probe_state,'get',side_effect=get),self.assertRaises(ValueError):
                probe_state.targets([row],row['platformRevision'])

    def test_denial_status_cannot_hide_protected_application_data(self):
        from playbooks.access.files import traffic
        target={'host':'preview.internal.example.invalid','address':'10.43.0.1','path':'/preview/','tls':True,
                'expected':{'message':'synthetic','source':'b'*40}}
        response={'status':401,'body':json.dumps(target['expected']).encode()}
        with patch.dict('sys.modules',{'traffic':traffic}),patch.object(traffic,'https',return_value=response):
            self.assertEqual(program.request(target),'unexpected')
        response['body']=b'Unauthorized'
        with patch.dict('sys.modules',{'traffic':traffic}),patch.object(traffic,'https',return_value=response):
            self.assertEqual(program.request(target),'denied')

    def test_direct_classification_never_treats_startup_tls_or_application_data_as_denial(self):
        for service in (['allowed','denied','denied'], ['denied']*3, ['timeout']*3):
            self.assertTrue(program.classify('allowed','allowed',service,['timeout']*3)['podProtected'])
        for control,gateway,service,pod in (
                ('unproved','allowed',['timeout']*3,['timeout']*3),('allowed','unproved',['denied']*3,['denied']*3),
                ('allowed','allowed',['allowed']*3,['denied']*3),('allowed','allowed',['allowed','denied','denied'],['allowed','denied','denied']),
                ('allowed','allowed',['unproved']*3,['denied']*3),('allowed','allowed',['timeout']*3,['unexpected']*3)):
            with self.assertRaises(ValueError):program.classify(control,gateway,service,pod)

    def test_inspector_checks_logging_before_readiness_or_access_frame(self):
        request={'challenge':'f'*64,'nonce':'e'*32,'revision':'c'*40,
                 'digests':['a'*64,'b'*64],'deadline':1250,'source':inspection.source_binding(),'mode':'probe'}
        channel=Mock(deadline=1260);channel.read_frame.return_value=contract.canonical(request)
        channel.remaining.return_value=50
        with patch.object(inspection.signal,'setitimer'),patch.object(probe_state,'native_session',return_value=MagicMock()),patch.object(inspection,'source_binding',return_value=inspection.source_binding()),patch.object(inspection.time,'time',return_value=1200), \
                patch.object(inspection.time,'monotonic',return_value=1200), \
                patch.object(probe_state,'assurance',side_effect=ValueError('unknown logging')):
            with self.assertRaises(ValueError):inspection.run(channel)
        channel.read_frame.assert_called_once();channel.write_frame.assert_not_called()

    def test_fixed_inspection_schema_rejects_mutations_and_caller_transport(self):
        value={'challenge':'f'*64,'nonce':'e'*32,'revision':'c'*40,
               'digests':['a'*64,'b'*64],'deadline':1250,'source':inspection.source_binding(),'mode':'probe'}
        with patch.object(inspection.time,'time',return_value=1200):
            inspection.validate(value)
            for name in ('create','apply','patch','replace','delete','fault','restore','install','exec'):
                with self.assertRaises(ValueError):inspection.validate(dict(value,action=name))
            for name in ('host','command','namespace','path','diagnostics','options','rows','tokens','repository'):
                with self.assertRaises(ValueError):inspection.validate(dict(value,**{name:'foreign'}))

    def test_exec_carries_only_preview_access_credentials_on_stdin(self):
        frame={'phase':'probe','tokens':['synthetic-access-a','synthetic-access-b']}
        response={'targets':[dict(control=True,gateway=True,podProtected=True,serviceProtected=True,serviceMode='blocked')]*2}
        channel=MagicMock();channel.__enter__.return_value=channel;channel.read_frame.return_value=contract.canonical(response)
        with patch.object(inspection.subprocess,'Popen') as run,patch.object(inspection,'PipeChannel',return_value=channel):
            self.assertEqual(inspection.execute(frame,'cloudlab-fixture-probe-'+'e'*32,1250),response)
        call=run.call_args
        self.assertNotIn('synthetic-access',str(call.args))
        self.assertNotIn('synthetic-access',str(call.kwargs['env']))
        self.assertNotIn('input',call.kwargs)
        self.assertEqual(json.loads(channel.write_frame.call_args.args[0]),frame)
        self.assertIn('-i',call.args[0]);self.assertNotIn('-t',call.args[0]);self.assertTrue(call.kwargs['start_new_session'])

    def test_ssh_client_custom_recording_proxy_or_pty_refuses(self):
        valid={'requesttty':'false','permitlocalcommand':'no','controlmaster':'false','loglevel':'INFO','hostname':'example.invalid','user':'root'}
        with patch.dict(os.environ,{'VM_HOST':'example.invalid','VM_USER':'root'},clear=True):
            for key,value in [('requesttty','true'),('permitlocalcommand','yes'),('proxycommand','record'),('proxyjump','hop'),
                              ('controlmaster','true'),('localcommand','record'),('loglevel','DEBUG3')]:
                output='\n'.join(k+' '+v for k,v in dict(valid,**{key:value}).items())
                with patch.object(transport.subprocess,'run',return_value=Mock(returncode=0,stdout=output)):
                    with self.assertRaises(ValueError):transport.client_assurance()

    def test_controller_core_protection_precedes_ssh_and_fails_closed(self):
        with patch.object(transport.resource,'setrlimit',side_effect=OSError('unsupported')), \
                patch.object(transport.subprocess,'run') as run:
            with self.assertRaises(OSError):transport.client_assurance()
            run.assert_not_called()

    def test_remote_unsupported_environment_refuses_before_subprocess_or_receipt_read(self):
        for key in ('KUBECONFIG','HTTP_PROXY','K3S_CONFIG_FILE','BASH_ENV','SSH_TTY','LD_PRELOAD'):
            with patch.dict(os.environ,{'SSH_CONNECTION':'100.64.0.1 4000 100.64.0.2 22',key:'private'},clear=True), \
                    patch.object(probe_state.os,'geteuid',return_value=0),patch.object(probe_state.os,'isatty',return_value=False), \
                    patch.object(probe_state,'command') as command:
                with self.assertRaises(ValueError):probe_state.assurance(Mock())
                command.assert_not_called()

    def test_changed_target_or_assurance_after_exec_refuses(self):
        rows=[fixtures.approval('a'*32),fixtures.approval('d'*32)]
        request={'challenge':'f'*64,'nonce':'e'*32,'revision':'c'*40,
                 'digests':[contract.digest(contract.canonical(row)) for row in rows],'deadline':1250,'source':inspection.source_binding(),'mode':'probe'}
        root=Path(inspection.__file__).parent
        probe={'Namespace':{'metadata':{'name':'cloudlab-fixture-probe-'+'e'*32,'uid':'namespace'}},
               'Pod':{'metadata':{'uid':'pod'}},'Service':{'metadata':{'uid':'service'},'spec':{'clusterIP':'10.43.0.1'}},
               'ConfigMap':{'metadata':{'uid':'code'},'data':{'probe_program.py':(root/'probe_program.py').read_text(),
                            'traffic.py':root.parents[1].joinpath('access/files/traffic.py').read_text()}}}
        channel=Mock(deadline=1260);channel.read_frame.return_value=contract.canonical(request);channel.remaining.return_value=50
        with patch.object(inspection.time,'time',return_value=1200),patch.object(inspection.time,'monotonic',return_value=1200), \
                patch.object(inspection.signal,'setitimer'),patch.object(probe_state,'native_session',return_value=MagicMock()),patch.object(inspection,'source_binding',return_value=inspection.source_binding()),patch.object(probe_state,'assurance',return_value='a'*64), \
                patch.object(probe_state,'receipt',return_value={'revision':'c'*40,'probeRows':rows}), \
                patch.object(probe_state,'bound_probe',return_value=probe), \
                patch.object(probe_state,'targets',side_effect=[([],{'uid':'first'}),([],{'uid':'changed'})]), \
                patch.object(inspection,'execute',return_value={'preflight':True}):
            with self.assertRaises(ValueError):inspection.run(channel)
        channel.write_frame.assert_not_called()

    def test_chart_renders_retained_synthetic_data_with_pinned_helm(self):
        chart=Path(__file__).with_name('git-outage')
        result=subprocess.run(['helm','template','fixture',str(chart),'--set','nonce='+'e'*32],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        import yaml
        documents=list(yaml.safe_load_all(result.stdout))
        self.assertEqual(len(documents),1);self.assertEqual(documents[0]['kind'],'ConfigMap')
        self.assertEqual(documents[0]['data'],{'synthetic':'persistent-'+'e'*32})
        rejected=subprocess.run(['helm','template','fixture',str(chart),'--set','nonce=foreign'],capture_output=True,timeout=30)
        self.assertNotEqual(rejected.returncode,0)

    def test_actual_installer_closes_imports_without_checkout_and_requests_remain_nonsecret(self):
        import yaml
        tasks=yaml.safe_load(Path(__file__).with_name('resources.yml').read_text())[0]['tasks']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);installed=root/'installed';selected=[]
            for task in tasks:
                task=copy.deepcopy(task)
                if 'ansible.builtin.file' in task or 'src' in task.get('ansible.builtin.copy',{}):
                    module=task.get('ansible.builtin.file',task.get('ansible.builtin.copy'))
                    field='path' if 'path' in module else 'dest'
                    module[field]=module[field].replace('/opt/cloudlab',str(installed),1)
                elif 'dest' in task.get('ansible.builtin.copy',{}):
                    task['ansible.builtin.copy']['dest']=str(root/'resource-result.json')
                selected.append(task)
            playbook=root/'install.yml';playbook.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'tasks':selected}]))
            config=root/'ansible.cfg';config.write_text('[defaults]\ninterpreter_python=auto_silent\nremote_tmp='+str(root/'ansible-tmp')+'\n')
            environment=dict(os.environ,ANSIBLE_CONFIG=str(config),CLOUDLAB_PREVIEW_RESOURCE_REQUEST=json.dumps(
                {'action':'custody-install','nonce':'e'*32,'revision':'c'*40,'rows':[]}));environment.pop('PYTHONPATH',None)
            result=subprocess.run(['ansible-playbook','-i','localhost,','-c','local',str(playbook)],cwd=root,env=environment,capture_output=True,text=True,timeout=90)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(json.loads((root/'resource-result.json').read_text()),{'installed':True})
            self.assertEqual((root/'resource-result.json').stat().st_mode & 0o777,0o600)
            script="import sys;sys.path.insert(0,sys.argv[1]);from playbooks.previews.tests import resource_runtime,probe_inspection,probe_state;from playbooks.k3s.files import native_custody;assert resource_runtime.__file__.startswith(sys.argv[1]);assert probe_inspection.__file__.startswith(sys.argv[1]);assert probe_inspection.source_binding(trusted=True)==sys.argv[2]"
            result=subprocess.run([os.sys.executable,'-I','-B','-c',script,str(installed),inspection.source_binding()],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,'Installed closure failed')
            (installed/'playbooks/previews/files/contract.py').unlink()
            result=subprocess.run([os.sys.executable,'-I','-B','-c',script,str(installed),inspection.source_binding()],capture_output=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
        self.assertTrue(all(task.get('no_log') for task in tasks))
        text=Path(__file__).with_name('resources.yml').read_text()
        self.assertNotIn('TOKEN',text);self.assertNotIn('tokens',text)
