"""Real local children prove bounded transport, empty startup and owned cleanup."""
import inspect
import json
import os
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

import verify_access
from ssh_channel import PipeChannel


class ChannelTests(unittest.TestCase):
    def child(self,code,*,timeout=2,frame_limit=32768,output_limit=65536):
        process=subprocess.Popen([sys.executable,'-u','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,bufsize=0,start_new_session=True)
        return PipeChannel(process,time.monotonic()+timeout,frame_limit=frame_limit,output_limit=output_limit)

    def test_factory_has_no_initial_input_and_reuses_ordinary_ssh_coordinates(self):
        self.assertNotIn('input',inspect.signature(verify_access.ssh_channel).parameters)
        with patch.dict(os.environ,{'VM_USER':'fixture','VM_PASSWORD':'synthetic'},clear=True), \
                patch.object(verify_access.subprocess,'Popen') as spawn,patch.object(verify_access,'PipeChannel'):
            verify_access.ssh_channel('VM','example.invalid','fixed-command',deadline=time.monotonic()+2)
            expected,environment=verify_access._ssh_transport('VM','example.invalid','fixed-command','/state/known_hosts','yes')
            self.assertEqual(spawn.call_args.args[0],expected);self.assertEqual(spawn.call_args.kwargs['env'],environment)
            self.assertIn('-T',expected);self.assertIn('StrictHostKeyChecking=yes',expected)
            self.assertTrue(spawn.call_args.kwargs['start_new_session']);self.assertNotIn('input',spawn.call_args.kwargs)
            spawn.reset_mock()
            with self.assertRaises(TypeError):verify_access.ssh_channel('VM','example.invalid','fixed-command',deadline=1,input='forbidden')
            spawn.assert_not_called()

    def test_constructor_starts_empty_then_frames_and_eof_are_explicit(self):
        code="import select,sys,json;print(json.dumps({'initial':bool(select.select([sys.stdin],[],[],.1)[0])}),flush=True);raw=sys.stdin.buffer.readline(32769);assert sys.stdin.buffer.read(32769)==b'';print(json.dumps({'bytes':len(raw)}),flush=True)"
        with self.child(code) as channel:
            self.assertEqual(json.loads(channel.read_frame()),{'initial':False})
            channel.write_frame(b'{"synthetic":true}');channel.close_input()
            self.assertEqual(json.loads(channel.read_frame()),{'bytes':19})
            channel.finish()
        self.assertEqual(channel.process.returncode,0)
        with self.assertRaises(ChildProcessError):os.waitpid(channel.process.pid,os.WNOHANG)

    def test_partial_frame_stdout_stderr_and_combined_overflow_are_bounded_and_redacted(self):
        for code in ("import sys,time;sys.stdout.write('partial');sys.stdout.flush();time.sleep(30)",
                     "import os;os.write(1,b'x'*5000)","import os;os.write(2,b'private-diagnostic-sentinel'*500)",
                     "import os;os.write(1,b'ok\\n');os.write(2,b'x'*63)"):
            with self.subTest(code=code):
                channel=self.child(code,timeout=.3,frame_limit=32,output_limit=64)
                with self.assertRaises(RuntimeError) as error:
                    with channel:
                        channel.read_frame();channel.finish()
                self.assertNotIn('private-diagnostic-sentinel',str(error.exception))
                self.assertLessEqual(channel.output_bytes,65)
                self.assertIsNotNone(channel.process.returncode)
                with self.assertRaises(ChildProcessError):os.waitpid(channel.process.pid,os.WNOHANG)

    def test_extra_frame_after_result_is_not_accepted_as_success(self):
        with self.child("import sys;sys.stdin.buffer.read(32769);print('result');print('extra')") as channel:
            channel.close_input();self.assertEqual(channel.read_frame(),b'result')
            with self.assertRaises(RuntimeError):channel.finish()

    def test_timeout_terminates_owned_descendant_group_and_reaps_root_only(self):
        code="import subprocess,sys,time;child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);print(child.pid,flush=True);time.sleep(30)"
        with self.child(code,timeout=.3) as channel:
            descendant=int(channel.read_frame())
            with self.assertRaises(RuntimeError):channel.read_frame()
        self.assertIsNotNone(channel.process.returncode)
        status='/proc/'+str(descendant)+'/stat'
        for _ in range(20):
            if not os.path.exists(status):break
            with open(status) as stream:state=stream.read().split()[2]
            if state=='Z':break
            time.sleep(.01)
        else:self.fail('Owned descendant remained running')
