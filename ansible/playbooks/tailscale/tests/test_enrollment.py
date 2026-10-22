"""Exercise native enrollment against disposable HTTP and CLI fixtures, without credentials."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import parse_qs

import yaml


TASKS = Path(__file__).resolve().parents[1] / 'tasks'
CLIENT_SECRET = 'synthetic-client-secret'
TOKEN = 'synthetic-access-token'
KEY = 'synthetic-one-use-key'


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.requests = []
        self.token_response = {'access_token': TOKEN}
        self.key_response = {'key': KEY}
        self.status = 200
        self.redirect = False
        self.key_status = 200
        self.key_redirect = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length'])).decode()
                owner.requests.append((self.path, dict(self.headers), body))
                token = self.path.endswith('/token')
                redirect = owner.redirect if token else owner.key_redirect
                status = owner.status if token else owner.key_status
                self.send_response(302 if redirect else status)
                self.send_header('Content-Type', 'application/json')
                if redirect:
                    self.send_header('Location', '/redirected')
                self.end_headers()
                value = owner.token_response if self.path.endswith('/token') else owner.key_response
                self.wfile.write(json.dumps(value).encode())

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def run_enrollment(self, *, fields=None, state=None, up_exit=0, explicit=False):
        if fields is None:
            fields = [{'label': 'CLIENT_ID', 'value': 'synthetic-id'},
                      {'label': 'CLIENT_SECRET', 'value': CLIENT_SECRET}]
        status = {'BackendState': 'NeedsLogin', 'Self': {}} if state is None else state
        fixture = self.directory / 'fixture.json'
        fixture.write_text(json.dumps({'fields': fields}))
        op = self.directory / 'op'
        op.write_text('#!' + sys.executable + '\nfrom pathlib import Path\n'
                      'print(Path(' + repr(str(fixture)) + ').read_text())\n')
        op.chmod(0o700)
        key_path = self.directory / 'enrollment-key'
        recorded = self.directory / 'enrolled.json'
        tailscale = self.directory / 'tailscale'
        tailscale.write_text('#!' + sys.executable + '\nimport json,sys\nfrom pathlib import Path\n'
            'if sys.argv[1] == "status": print(' + repr(json.dumps(status)) + ')\n'
            'else:\n'
            '    key = Path(' + repr(str(key_path)) + ')\n'
            '    Path(' + repr(str(recorded)) + ').write_text(json.dumps({"args": sys.argv[1:], '
            '"key": key.read_text(), "mode": key.stat().st_mode & 0o777}))\n'
            '    raise SystemExit(' + str(up_exit) + ')\n')
        tailscale.chmod(0o700)
        request = copy.deepcopy(yaml.safe_load((TASKS / 'enrollment-key.yml').read_text()))
        for task in request[0]['block']:
            if 'ansible.builtin.command' in task:
                task['ansible.builtin.command']['argv'][0] = str(op)
            if 'ansible.builtin.uri' in task:
                options = task['ansible.builtin.uri']
                options['url'] = options['url'].replace('https://api.tailscale.com',
                    'http://127.0.0.1:' + str(self.server.server_port))
        (self.directory / 'enrollment-key.yml').write_text(yaml.safe_dump(request, sort_keys=False))
        source = (TASKS / 'enroll.yml').read_text().replace('/run/cloudlab-tailscale-key', str(key_path))
        source = source.replace('/usr/local/bin/tailscale', str(tailscale)).replace("['tailscale', 'up'", "['" + str(tailscale) + "', 'up'")
        (self.directory / 'enroll.yml').write_text(source)
        play = [{'hosts': 'localhost', 'gather_facts': False,
                 'vars': {'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable,
                          'tailscale_explicit_reauth': explicit},
                 'tasks': [{'ansible.builtin.import_tasks': 'enroll.yml'}]}]
        path = self.directory / 'play.yml'
        path.write_text(yaml.safe_dump(play, sort_keys=False))
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
            env=dict(os.environ, ANSIBLE_NOCOLOR='1'), capture_output=True, text=True, timeout=90)
        for secret in (CLIENT_SECRET, TOKEN, KEY):
            self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertFalse(key_path.exists(), 'Volatile enrollment key survives success or failure')
        return result, json.loads(recorded.read_text()) if recorded.exists() else None

    def test_native_requests_preserve_key_scope_and_secret_custody(self):
        result, enrolled = self.run_enrollment()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(parse_qs(self.requests[0][2]), {'client_id': ['synthetic-id'],
            'client_secret': [CLIENT_SECRET], 'grant_type': ['client_credentials']})
        self.assertEqual(self.requests[1][1]['Authorization'], 'Bearer ' + TOKEN)
        self.assertEqual(json.loads(self.requests[1][2]), {
            'capabilities': {'devices': {'create': {'reusable': False, 'ephemeral': False,
                'preauthorized': True, 'tags': ['tag:cloudlab-host']}}},
            'expirySeconds': 300, 'description': 'cloudlab host enrollment'})
        self.assertEqual(enrolled['key'], KEY)
        self.assertEqual(enrolled['mode'], 0o600)
        self.assertIn('--accept-dns=false', enrolled['args'])
        self.assertNotIn('--force-reauth', enrolled['args'])
        self.assertNotIn(KEY, ' '.join(enrolled['args']))

    def test_running_identity_makes_no_enrollment_requests(self):
        result, enrolled = self.run_enrollment(state={'BackendState': 'Running', 'Self': {'ID': 'retained'}})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.requests, [])
        self.assertIsNone(enrolled)

    def test_lost_or_expired_identity_requires_explicit_recovery(self):
        for state in ({'BackendState': 'NeedsLogin', 'Self': {'ID': 'retained'}},
                      {'BackendState': 'Running', 'Self': {'ID': 'retained', 'Expired': True}}):
            with self.subTest(state=state):
                result, enrolled = self.run_enrollment(state=state)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.requests, [])
                self.assertIsNone(enrolled)

    def test_duplicate_vault_field_fails_before_oauth(self):
        result, enrolled = self.run_enrollment(fields=[{'label': 'CLIENT_ID', 'value': 'first'},
            {'label': 'CLIENT_ID', 'value': 'duplicate'}, {'label': 'CLIENT_SECRET', 'value': CLIENT_SECRET}])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.requests, [])
        self.assertIsNone(enrolled)

    def test_missing_token_prevents_key_mutation(self):
        self.token_response = {}
        result, enrolled = self.run_enrollment()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.requests), 1)
        self.assertIsNone(enrolled)

    def test_api_failure_or_redirect_is_not_retried(self):
        for status, redirect in ((500, False), (200, True)):
            with self.subTest(status=status, redirect=redirect):
                self.requests.clear()
                self.status, self.redirect = status, redirect
                result, enrolled = self.run_enrollment()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(self.requests), 1)
                self.assertIsNone(enrolled)

    def test_failed_explicit_enrollment_removes_volatile_key(self):
        result, enrolled = self.run_enrollment(up_exit=2, explicit=True,
            state={'BackendState': 'Running', 'Self': {'ID': 'retained'}})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.requests), 2)
        self.assertIn('--force-reauth', enrolled['args'])

    def test_key_mutation_failure_or_redirect_does_not_retry_or_forward_authorization(self):
        for status, redirect in ((500, False), (200, True)):
            with self.subTest(status=status, redirect=redirect):
                self.requests.clear()
                self.key_status, self.key_redirect = status, redirect
                result, enrolled = self.run_enrollment()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(self.requests), 2)
                self.assertEqual(self.requests[-1][0], '/api/v2/tailnet/-/keys')
                self.assertIsNone(enrolled)

    def test_missing_key_prevents_host_enrollment_without_retry(self):
        self.key_response = {}
        result, enrolled = self.run_enrollment()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.requests), 2)
        self.assertIsNone(enrolled)


if __name__ == '__main__':
    unittest.main()
