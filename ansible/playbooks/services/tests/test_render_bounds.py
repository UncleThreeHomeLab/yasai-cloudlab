"""Real native child streams cannot bypass render limits or leave owned processes."""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from playbooks.services.files import gitops
from playbooks.services.tests.fixtures import approval, definition


class RenderBoundTests(unittest.TestCase):
    def child(self, code, *, timeout=2, payload='{}'):
        spawn = subprocess.Popen
        children = []
        def tracked(*args, **kwargs):
            process = spawn(*args, **kwargs)
            children.append(process)
            return process
        try:
            with patch.object(gitops.subprocess, 'Popen', side_effect=tracked):
                return gitops._render([sys.executable, '-c', code], payload, timeout=timeout)
        finally:
            self.assertEqual(len(children), 1)
            process = children[0]
            self.assertIsNotNone(process.returncode)
            self.assertTrue(all(stream.closed for stream in (process.stdin, process.stdout, process.stderr)))
            with self.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)

    def test_stdout_and_stderr_overflow_terminate_reap_and_withhold_diagnostics(self):
        for stream in (1, 2):
            code = ('import os,time;os.write(' + str(stream) + ',b"private-diagnostic"*1000);time.sleep(30)')
            started = time.monotonic()
            with self.subTest(stream=stream), patch.object(gitops, 'MAX_RENDER_OUTPUT', 4096), \
                    patch.object(gitops, 'MAX_RENDER_ERROR', 4096):
                with self.assertRaisesRegex(ValueError, '^Administrator service catalog render exceeded its output bound$'):
                    self.child(code)
            self.assertLess(time.monotonic() - started, 2)

    def test_timeout_with_closed_output_or_blocked_input_reaps_child(self):
        for code in ('import os,time;os.close(1);os.close(2);time.sleep(30)', 'import time;time.sleep(30)'):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, 'deadline'):
                self.child(code, timeout=.15, payload='x' * 1024 * 1024)

    def test_timeout_terminates_owned_descendant_group(self):
        with tempfile.TemporaryDirectory() as directory:
            path = directory + '/child-pid'
            code = ('import subprocess,sys,time;child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);'
                    'open(' + repr(path) + ',"w").write(str(child.pid));time.sleep(30)')
            with self.assertRaisesRegex(ValueError, 'deadline'):
                self.child(code, timeout=.3)
            with open(path) as stream:
                pid = int(stream.read())
            for _ in range(50):
                try:
                    with open('/proc/' + str(pid) + '/stat') as stream:
                        if stream.read().split()[2] == 'Z':
                            break
                except FileNotFoundError:
                    break
                time.sleep(.01)
            else:
                self.fail('Owned descendant remained running')

    def test_success_with_both_streams_and_nonzero_error_remain_sanitized(self):
        self.assertEqual(self.child('import sys;sys.stdin.read();print("valid");sys.stderr.write("diagnostic")'), 'valid\n')
        with self.assertRaisesRegex(ValueError, '^Administrator service catalog failed validation$'):
            self.child('import sys;sys.stdin.read();sys.stderr.write("private-diagnostic");sys.exit(2)')

    def test_overflow_fails_before_yaml_parsing(self):
        value = definition()
        with patch.object(gitops, 'validate', return_value=value), \
                patch.object(gitops, '_render', side_effect=ValueError('output bound')), \
                patch('yaml.safe_load_all') as parse:
            with self.assertRaisesRegex(ValueError, 'output bound'):
                gitops.resources(value, approval(), 'https://github.com/example/platform.git', 'a' * 40)
        parse.assert_not_called()

    def test_valid_native_chart_still_renders(self):
        objects = gitops.resources(definition(), approval(), 'https://github.com/example/platform.git', 'a' * 40)
        self.assertTrue(any(obj['kind'] == 'Namespace' for obj in objects))
