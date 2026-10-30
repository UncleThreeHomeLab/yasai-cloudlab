"""Offline fixture ownership and ordinary maintenance publication, not native proof."""
import base64
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from playbooks.dependencies.files import control, receipt, tools, workspace
from playbooks.dependencies.files.gate import Gate, canonical
from playbooks.dependencies.tests import live_fixture as live
from playbooks.dependencies.tests.fixtures import DependencyFixtureAPI


class LiveFixtureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.control = self.root/'control'; self.control.mkdir(mode=0o700)
        self.candidate = self.root/'candidate'
        self.handoff = self.root/'handoff'; self.handoff.mkdir()
        self.artifacts = self.root/'artifact'
        self.nonce = 'a'*32
        self.branch = 'cloudlab-maintenance-fixture/'+self.nonce
        self.archives = {}
        for version in ('1.13.0','1.13.1'):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream,'w') as archive: archive.writestr('tofu', b'synthetic public binary '+version.encode())
            self.archives[version] = stream.getvalue()
        source = {path: (control.ROOT/path).read_bytes() for path in live.PATHS}
        lock = json.loads(source['ansible/runner/tools.lock.json'])
        lock['tofu']['sha256'] = hashlib.sha256(self.archives['1.13.1']).hexdigest()
        source['ansible/runner/tools.lock.json'] = (json.dumps(lock,indent=2)+'\n').encode()
        source['ansible/runner/Dockerfile'] = (control.ROOT/'ansible/runner/Dockerfile').read_bytes()
        source['public.txt'] = b'preserved public source\n'
        source['infra/github/.terraform.lock.hcl'] = b'# synthetic readonly provider checksums\n'
        source['ansible/playbooks/dependencies/tests/fixtures/native/infra/github/versions.tf'] = b'terraform { required_version = "= 1.13.1" }\n'
        self.api = DependencyFixtureAPI(source)
        self.source = source
        self.lease = {'token':'synthetic-token','repository':'example/platform','repositoryId':1,'requester':'release[bot]'}
        patches = (
            patch.object(control,'CONTROL',self.control),patch.object(control,'CANDIDATE',self.candidate),
            patch.object(control,'HANDOFF',self.handoff),patch.object(control,'WRITER',self.root/'lock'),
            patch.object(control,'helper_hash',return_value='c'*64),
            patch.object(control,'committed_payload',return_value={'branch':'main','revision':self.api.base,'repository':'https://github.com/example/platform.git'}),
            patch.object(control,'dotenv_values',return_value={'OP_SERVICE_ACCOUNT_TOKEN':'synthetic-reader'}),
            patch.object(control.repository_tokens,'issue',return_value=self.lease),
            patch.object(control.repository_tokens,'revoke'),patch.object(control,'GitHub',return_value=self.api),
            patch.object(live,'GitHub',return_value=self.api),patch.object(live,'ARTIFACTS',self.artifacts),
            patch.object(live,'download',side_effect=self.download),
            patch('playbooks.dependencies.files.toolchain.embedded'),
            patch.object(workspace,'snapshot',side_effect=self.api.snapshot),
            patch.object(control,'snapshot',side_effect=self.api.snapshot),
            patch.object(receipt,'CANDIDATE',self.candidate),patch.object(receipt,'CONTROL',self.control),
            patch.object(receipt,'PublicGitHub',return_value=self.api),patch.object(receipt,'helper_hash',return_value='c'*64),
            patch.object(receipt,'Path',side_effect=lambda value: self.root/'checks.json' if str(value)=='/results/checks.json' else Path(value)),
        )
        for context in patches:
            context.start(); self.addCleanup(context.stop)

    def download(self,url,*,prefix):
        expected = tools.TOOLS['tofu'][0]
        self.assertEqual(prefix,expected)
        version = next(value for value in self.archives if url == expected+tools.TOOLS['tofu'][1].format(version=value))
        return self.archives[version]

    def stage(self,action,**extra):
        return live.run(action,dict(nonce=self.nonce,**extra))

    def state(self):
        return live.journal(self.nonce)[0]

    def prepare(self):
        self.stage('prepare')
        value = json.loads((self.control/'fixtures'/(self.nonce+'.public.json')).read_bytes())
        live.artifact(value,self.artifacts)

    def create(self):
        self.prepare(); self.stage('create')

    def native(self, *, complete=False):
        self.create()
        source = self.api.snapshot('example/platform',self.api.refs[self.branch])
        source['ansible/runner/tools.lock.json'] = self.source['ansible/runner/tools.lock.json']
        if complete: source = self.source
        tree = self.api.commits[self.api.commit(source)]['tree']['sha']
        head = self.api.request('POST','repos/example/platform/git/commits',{
            'message':'Native Renovate OpenTofu update','tree':tree,'parents':[self.api.refs[self.branch]]})['sha']
        self.api.native_pr(self.branch,head)
        self.stage('record-native',number=7)
        control.run('export',{'base':self.branch,'number':7,'owners':['tool:tofu']})
        if not complete:
            with patch.object(tools,'baseline',side_effect=lambda root,path: base64.b64decode(control.load('check-plan.json')['baseFiles'][path])):
                tools.update(self.candidate,'tofu','1.13.1',fetch=self.download)

    def verify_from_synthetic_checks(self):
        operation = control.load('operation.json')
        current = workspace.tree(self.candidate)
        plan = control.load('check-plan.json')
        control.save('toolchain.json',{'operation':operation['operation'],'candidateTree':current,
            'role':'candidate-runner','imageId':'sha256:'+'d'*64})
        (self.root/'checks.json').write_bytes(canonical({'operation':operation['operation'],'candidateTree':current,
            'checks':dict.fromkeys(operation['checks'],'PASS'),
            'plan':hashlib.sha256(json.dumps(plan,sort_keys=True).encode()).hexdigest()}))
        return receipt.write()

    def test_actual_repair_publication_final_verification_ready_and_owned_cleanup(self):
        self.native(); self.assertFalse(self.verify_from_synthetic_checks()['publishedHeadVerified'])
        initial = self.api.row['head']['sha']
        self.stage('expect-publication')
        control.run('publish',{'base':self.branch,'number':7})
        self.assertNotEqual(self.api.row['head']['sha'],initial)
        control.run('export',{'base':self.branch,'number':7,'owners':['tool:tofu']})
        self.assertTrue(self.verify_from_synthetic_checks()['publishedHeadVerified'])
        self.stage('bind-verified')
        self.assertEqual(self.state()['bound'],self.api.row['head']['sha'])
        self.assertTrue(control.run('ready',{'base':self.branch,'number':7})['ready'])
        self.stage('cleanup'); self.stage('cleanup')
        self.assertEqual(self.api.refs,{'main':self.api.base})
        self.assertEqual(self.api.row['state'],'closed')
        self.assertEqual(self.source,self.api.snapshot('example/platform',self.api.base))
        self.assertFalse(any('/merge' in route for _,route,_ in self.api.calls))

    def test_already_complete_native_head_binds_without_empty_publication(self):
        self.native(complete=True);self.verify_from_synthetic_checks()
        self.stage('bind-verified')
        self.assertIsNone(self.state()['expectation'])
        self.assertEqual(self.state()['bound'],self.state()['native']['head'])
        with self.assertRaises(ValueError):self.stage('expect-publication')
        state,previous=live.journal(self.nonce)
        state['native']['user']['login']='foreign[bot]';self.api.row['user']['login']='foreign[bot]'
        live.journal(self.nonce,state,previous);self.api.calls.clear()
        with self.assertRaises(ValueError):self.stage('cleanup')
        self.assertFalse(any(method!='GET' for method,_,_ in self.api.calls))

    def test_artifact_coherence_and_upstream_tampering_causes_zero_git_writes(self):
        self.prepare()
        path=self.artifacts/(self.nonce+'.json');original=path.read_bytes()
        cases=(lambda v:v['files'].pop('infra/harbor/versions.tf'),
               lambda v:v['files']['infra/github/versions.tf'].update(mode='100755'),
               lambda v:v.update(private='private-sentinel-never-log'),
               lambda v:v['files']['ansible/runner/tools.lock.json'].update(sha='f'*40))
        for mutate in cases:
            value=json.loads(original);mutate(value);path.write_bytes(canonical(value));self.api.calls.clear()
            with self.assertRaises(ValueError):self.stage('create')
            self.assertFalse(any(method!='GET' for method,_,_ in self.api.calls))
        path.write_bytes(original)
        with patch.object(live,'download',return_value=b'wrong public upstream'):
            with self.assertRaises(ValueError):self.stage('create')
        self.assertFalse(any(method!='GET' for method,_,_ in self.api.calls))
        request=self.api.request
        for value in (None,{},[],{'object':{'sha':'truncated'}}):
            def malformed(method,route,body=None,**kwargs):
                if route.endswith('/git/ref/heads/'+self.branch):return value
                return request(method,route,body,**kwargs)
            with patch.object(self.api,'request',side_effect=malformed):
                with self.assertRaises(ValueError):self.stage('create')
            self.assertFalse(any(method!='GET' for method,_,_ in self.api.calls))

    def test_owned_create_response_loss_resumes_but_collision_and_rejection_never_adopt(self):
        self.prepare();self.api.lose='create-ref'
        with self.assertRaises(RuntimeError):self.stage('create')
        self.assertEqual(self.state()['intent']['kind'],'create-ref')
        self.stage('create');self.assertTrue(self.state()['base']['created'])
        self.stage('create')
        owned=self.api.refs[self.branch]
        self.assertEqual(self.api.refs[self.branch],self.state()['base']['head'])
        other='b'*32
        self.api.refs['cloudlab-maintenance-fixture/'+other]=self.api.base
        self.assertNotEqual(other,self.nonce)
        state=self.state();state['base']=None;state['intent']=None
        _,previous=live.journal(self.nonce);live.journal(self.nonce,state,previous)
        with self.assertRaises(ValueError):self.stage('create')
        self.assertEqual(self.api.refs[self.branch],owned)

    def test_definitive_ref_rejection_is_quarantined(self):
        self.prepare();self.api.reject_ref=True
        with self.assertRaises(Exception):self.stage('create')
        self.assertTrue(self.state()['rejected'])
        count=len(self.api.calls)
        with self.assertRaises(ValueError):self.stage('create')
        self.assertEqual(len(self.api.calls),count)

    def test_private_journal_cas_permissions_symlinks_and_malformed_state(self):
        self.prepare();state,previous=live.journal(self.nonce)
        with self.assertRaises(ValueError):live.journal(self.nonce,state,'f'*64)
        path=self.control/'fixtures'/(self.nonce+'.json')
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        path.chmod(0o644)
        with self.assertRaises(ValueError):live.journal(self.nonce)
        path.chmod(0o600);path.unlink();path.symlink_to(self.control/'receipt-key')
        with self.assertRaises(OSError):live.journal(self.nonce)
        path.unlink();state['unexpected']='private-sentinel-never-log';live.journal(self.nonce,state)
        with self.assertRaises(ValueError):self.stage('create')

    def test_changed_requester_head_or_publication_parent_refuses(self):
        self.native();self.verify_from_synthetic_checks();self.stage('expect-publication')
        initial=self.api.row['head']['sha']
        # Same desired content cannot authorize an unplanned parent or message.
        head=self.api.commit(self.source);self.api.row['head']['sha']=head;self.api.refs[self.api.row['head']['ref']]=head
        self.api.commits[head].update(parents=[{'sha':'f'*40}],message='Maintain reviewed dependency companions')
        control.run('export',{'base':self.branch,'number':7,'owners':['tool:tofu']});self.verify_from_synthetic_checks()
        with self.assertRaises(ValueError):self.stage('bind-verified')
        self.assertIsNone(self.state()['bound'])
        with self.assertRaises(ValueError):self.stage('cleanup')
        self.assertEqual(self.api.row['state'],'open')
        self.api.row['user']['login']='collaborator'
        with self.assertRaises(ValueError):self.stage('record-native',number=7)
        self.assertNotEqual(initial,head)

    def test_close_and_delete_response_loss_and_expected_head_race(self):
        self.native(complete=True);self.verify_from_synthetic_checks();self.stage('bind-verified')
        self.api.lose='close'
        with self.assertRaises(RuntimeError):self.stage('cleanup')
        self.assertEqual(self.state()['intent']['kind'],'close')
        self.api.lose='delete'
        with self.assertRaises(RuntimeError):self.stage('cleanup')
        self.assertEqual(self.state()['intent']['kind'],'delete:bot')
        self.api.race_delete=True
        with self.assertRaises(Exception):self.stage('cleanup')
        self.assertIn(self.branch,self.api.refs)
        self.assertEqual(self.api.refs['main'],self.api.base)

    def test_lease_revocation_source_and_artifact_container_boundaries(self):
        self.prepare()
        self.assertNotIn('OP_SERVICE_ACCOUNT_TOKEN',os.environ)
        control.repository_tokens.revoke.assert_called_with(self.lease)
        self.assertTrue(control.repository_tokens.issue.call_args.kwargs['include_requester'])
        with patch.object(control,'committed_payload',side_effect=ValueError('private-sentinel')):
            count=control.repository_tokens.issue.call_count
            with self.assertRaises(ValueError):self.stage('create')
            self.assertEqual(control.repository_tokens.issue.call_count,count)
        import yaml
        recipe=yaml.safe_load((control.ROOT/'ansible/playbooks/dependencies/compose.yaml').read_text())
        artifact=recipe['services']['fixture-artifact']
        mounts=artifact['volumes']
        self.assertEqual(len(mounts),10)
        self.assertFalse(any(value.rsplit(':',2)[1] in ('/control','/handoff','/candidate','/workspace/.env','/workspace/.git') for value in mounts))
        self.assertTrue(artifact['read_only']);self.assertEqual(artifact['cap_drop'],['ALL'])
        self.assertEqual(artifact['entrypoint'][-1],'artifact')
        closure=self.root/'artifact-code';closure.mkdir()
        recipe=control.ROOT/'ansible/playbooks/dependencies/compose.yaml'
        for mount in mounts:
            source,destination,mode=mount.rsplit(':',2)
            if destination.startswith('/workspace/'):
                self.assertEqual(mode,'ro')
                target=closure/destination.removeprefix('/workspace/')
                target.parent.mkdir(parents=True,exist_ok=True)
                source=(recipe.parent/source).resolve()
                if source.is_dir():shutil.copytree(source,target,ignore=shutil.ignore_patterns('__pycache__'))
                else:shutil.copyfile(source,target)
        result=subprocess.run([sys.executable,'-B','-c','from playbooks.dependencies.tests import live_fixture; print("Artifact import closure verified")'],
            cwd=self.root,env={'PATH':os.environ['PATH'],'PYTHONPATH':str(closure/'ansible'),
                'PYTHONDONTWRITEBYTECODE':'1','HOME':str(self.root)},capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'Artifact import closure verified\n')
        result=subprocess.run([sys.executable,'-B','-m','playbooks.dependencies.tests.live_fixture','unsupported'],
            cwd=self.root,env={'PATH':os.environ['PATH'],'PYTHONPATH':str(closure/'ansible'),
                'PYTHONDONTWRITEBYTECODE':'1','HOME':str(self.root)},
            input='{"private":"private-sentinel-never-log"}',capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,'')
        self.assertEqual(result.stderr,'Dependency fixture refused; credentials and diagnostics withheld\n')
