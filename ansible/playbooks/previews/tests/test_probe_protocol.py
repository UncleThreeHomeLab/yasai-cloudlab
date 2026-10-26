"""Exercise actual child stdin/stdout and production protocol with synthetic observations."""
import base64
import json
import os
import resource
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from playbooks.access.files import preflight
from playbooks.previews.files import contract
from playbooks.previews.tests import fixtures, probe_transport as transport
from playbooks.tailscale.files import ssh_channel as pipes


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.rows=[fixtures.approval('a'*32),fixtures.approval('d'*32)]
        self.state={'nonce':'e'*32,'executionPlatform':'c'*40}
        self.digests=[contract.digest(contract.canonical(row)) for row in self.rows]
        self.prior={'clientAssurance':'a'*64,'remoteAssurance':'b'*64,'bindings':'c'*64,'namespaceUID':'namespace-uid',
                    'podUID':'pod-uid','revision':'c'*40,'digests':self.digests}
        payload=base64.urlsafe_b64encode(contract.canonical({'exp':int(time.time())+300})).decode().rstrip('=')
        self.tokens=['header.'+payload+'.signatureA','header.'+payload+'.signatureB']

    def invoke(self,mode='valid',*,preflight_only=False,budget=None,recheck_failure=False):
        owner=sys.modules[preflight.ssh_channel.__module__]
        native_popen=subprocess.Popen;native_write=os.write
        processes=[];sent=bytearray();calls=[];stderr=bytearray()
        native_read=os.read
        environment={'PATH':os.environ['PATH'],'PYTHONPATH':os.environ['PYTHONPATH'],'PYTHONDONTWRITEBYTECODE':'1'}
        def spawn(*args,**kwargs):
            self.assertEqual(resource.getrlimit(resource.RLIMIT_CORE),(0,0))
            self.assertNotIn('input',kwargs)
            for token in self.tokens:self.assertNotIn(token,str((args,kwargs)))
            process=native_popen(*args,**kwargs);processes.append(process);calls.append((args,kwargs));return process
        def write(descriptor,data):
            written=native_write(descriptor,data)
            if any(not process.stdin.closed and descriptor==process.stdin.fileno() for process in processes):
                sent.extend(bytes(data[:written]))
            return written
        def read(descriptor,count):
            data=native_read(descriptor,count)
            if any(not process.stderr.closed and descriptor==process.stderr.fileno() for process in processes):stderr.extend(data)
            return data
        error=None;result=None
        with patch.object(owner,'_ssh_transport',return_value=([sys.executable,'-u','-c',fixtures.probe_channel_child(mode)],environment)) as coordinates, \
                patch.object(owner.subprocess,'Popen',side_effect=spawn),patch.object(pipes.os,'write',side_effect=write),patch.object(pipes.os,'read',side_effect=read), \
                patch.object(transport,'client_assurance',return_value='a'*64),patch.dict(os.environ,{'VM_HOST':'example.invalid'}), \
                patch.object(preflight,'ssh',side_effect=AssertionError('legacy SSH fallback')):
            def call():
                return transport.handoff(self.state,self.rows,[] if preflight_only else self.tokens,
                    None if preflight_only else self.prior,browser_deadline=time.monotonic()+budget if budget else None)
            try:
                if recheck_failure:
                    with patch.object(transport,'lifetime',side_effect=[None,ValueError('expired')]):result=call()
                else:result=call()
            except Exception as caught:error=caught
        if processes:
            self.assertEqual(len(processes),1)
            self.assertEqual(coordinates.call_args.args[:3],('VM','example.invalid',transport.REMOTE))
            self.assertEqual(coordinates.call_args.args[3:],('/state/known_hosts','yes'))
        for process in processes:
            self.assertIsNotNone(process.returncode)
            self.assertTrue(all(stream.closed for stream in (process.stdin,process.stdout,process.stderr)))
            with self.assertRaises(ChildProcessError):os.waitpid(process.pid,os.WNOHANG)
        if error:
            for value in self.tokens+['private-diagnostic-sentinel']:
                self.assertNotIn(value,str(error));self.assertNotIn(value,repr(error))
        self.assertNotIn(b'SECRET_PROBE_EXECUTED',stderr)
        return result,error,bytes(sent),processes

    def test_valid_same_session_sends_exactly_one_bound_access_frame(self):
        result,error,sent,_=self.invoke()
        self.assertIsNone(error)
        frames=[json.loads(value) for value in sent.splitlines()]
        self.assertEqual(len(frames),2)
        init,access=frames
        self.assertEqual(set(init),{'challenge','nonce','revision','digests','deadline'})
        self.assertEqual(init['digests'],self.digests)
        self.assertNotIn(self.rows[0]['repository'],json.dumps(init));self.assertNotIn('https:',json.dumps(init))
        self.assertEqual(access['tokens'],self.tokens);self.assertEqual(access['challenge'],init['challenge'])
        self.assertRegex(access['serverNonce'],'^[a-f0-9]{64}$')
        self.assertRegex(access['readinessDigest'],'^[a-f0-9]{64}$')
        self.assertTrue(result['result']['targets'][0]['podProtected'])

    def test_prior_preflight_has_only_opaque_init_and_no_credential_bytes(self):
        result,error,sent,_=self.invoke(preflight_only=True)
        self.assertIsNone(error);self.assertEqual(len(sent.splitlines()),1)
        self.assertEqual(result['result'],{'preflight':True})
        for token in self.tokens:self.assertNotIn(token.encode(),sent)

    def test_refusal_missing_partial_malformed_drift_and_overflow_send_zero_jwt_bytes(self):
        for mode in ('startup-refuse','assurance-refuse','preflight-refuse','missing','partial','malformed',
                     'config-change','target-change','stderr','queued'):
            with self.subTest(mode=mode):
                result,error,sent,_=self.invoke(mode,budget=0.4 if mode in ('missing','partial','stderr') else None)
                self.assertIsNotNone(error);self.assertIsNone(result)
                for token in self.tokens:self.assertNotIn(token.encode(),sent)
                self.assertTrue(all(set(json.loads(raw))=={'challenge','nonce','revision','digests','deadline'} for raw in sent.splitlines()))

    def test_lifetime_and_browser_budget_are_rechecked_after_ready_before_access(self):
        for options in ({'budget':34},{'recheck_failure':True}):
            with self.subTest(options=options):
                _,error,sent,_=self.invoke(**options)
                self.assertIsNotNone(error);self.assertEqual(len(sent.splitlines()),1)
                for token in self.tokens:self.assertNotIn(token.encode(),sent)

    def test_ready_to_access_drift_refuses_before_secret_pod_execution(self):
        for mode in ('ready-target-change','ready-assurance-change'):
            with self.subTest(mode=mode):
                result,error,sent,_=self.invoke(mode)
                self.assertIsNone(result);self.assertIsNotNone(error)
                frames=[json.loads(raw) for raw in sent.splitlines()]
                self.assertEqual(len(frames),2)
                self.assertEqual(frames[1]['action'],'access')

    def test_post_probe_binding_drift_still_refuses_completed_proof(self):
        result,error,sent,_=self.invoke('post-target-change')
        self.assertIsNone(result);self.assertIsNotNone(error)
        self.assertEqual(len(sent.splitlines()),2)

    def manual_helper(self,mode):
        owner=sys.modules[preflight.ssh_channel.__module__]
        init={'challenge':'f'*64,'nonce':'e'*32,'revision':'c'*40,'digests':self.digests,'deadline':int(time.time())+55}
        environment={'PATH':os.environ['PATH'],'PYTHONPATH':os.environ['PYTHONPATH'],'PYTHONDONTWRITEBYTECODE':'1'}
        with patch.object(owner,'_ssh_transport',return_value=([sys.executable,'-u','-c',fixtures.probe_channel_child()],environment)):
            with preflight.ssh_channel('VM','example.invalid',transport.REMOTE,deadline=time.monotonic()+3) as channel:
                if mode!='reordered':channel.write_frame(contract.canonical(init))
                if mode=='eof':
                    channel.close_input()
                elif mode in ('early','reordered'):
                    channel.write_frame(contract.canonical({'action':'access','challenge':'f'*64,'serverNonce':'0'*64,
                        'readinessDigest':'0'*64,'tokens':self.tokens}))
                else:
                    ready=json.loads(channel.read_frame())
                    access={'action':'access','challenge':'f'*64,'serverNonce':ready['serverNonce'],
                            'readinessDigest':contract.digest(contract.canonical(ready)),'tokens':self.tokens}
                    if mode=='nonce':access['serverNonce']='0'*64
                    if mode=='digest':access['readinessDigest']='0'*64
                    channel.write_frame(contract.canonical(access))
                    if mode=='duplicate':channel.write_frame(contract.canonical(access))
                channel.close_input()
                with self.assertRaises(RuntimeError):
                    while True:
                        value=json.loads(channel.read_frame())
                        self.assertNotEqual(value.get('action'),'result')
                with self.assertRaises(RuntimeError):channel.finish()

    def test_helper_rejects_early_replayed_mismatched_or_extra_access_frames(self):
        for mode in ('early','reordered','nonce','digest','duplicate','eof'):
            with self.subTest(mode=mode):self.manual_helper(mode)
