"""Exercise the command contract with real OpenTofu and a loopback HTTP backend."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from playbooks.infrastructure.files import command
from playbooks.infrastructure.files.backend import environment
from playbooks.infrastructure.files.native import native, require


@unittest.skipUnless(shutil.which('tofu'), 'Requires the pinned Compose runner')
class NativeCommandTests(unittest.TestCase):
    def test_reviewed_update_encrypts_state_and_preserves_identity(self):
        stored = {'state': None, 'lock': None, 'reject_upload': False}

        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def response(self, status, body=b''):
                self.send_response(status)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.response(404 if stored['state'] is None else 200, stored['state'] or b'')

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                if self.path.endswith('/lock'):
                    if stored['lock'] is not None:
                        self.response(423, stored['lock'])
                        return
                    stored['lock'] = body
                elif stored['reject_upload']:
                    self.response(503)
                    return
                else:
                    stored['state'] = body
                self.response(200)

            def do_DELETE(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                if stored['lock'] is None or json.loads(body)['ID'] != json.loads(stored['lock'])['ID']:
                    self.response(409)
                    return
                stored['lock'] = None
                self.response(200)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary) / 'checkout'
                source = workspace / 'infra/github'
                source.mkdir(parents=True)
                (source / 'tests').mkdir()
                (workspace / 'ansible/playbooks/infrastructure/files').mkdir(parents=True)
                (source / 'main.tf').write_text('''terraform {
  required_version = "= 1.13.1"
  backend "http" {}
}
variable "owner" { type = string }
variable "repositories" { type = any }
variable "rulesets" { type = any }
resource "terraform_data" "fixture" { input = var.owner }
''')
                # No downloaded provider is needed for this builtin backend/command fixture.
                (source / '.terraform.lock.hcl').write_text('')
                private = Path(temporary) / 'private/github'
                private.mkdir(parents=True)
                desired = json.loads((command.WORKSPACE / 'infra/github/fixtures.json').read_text())
                documents = {'desired.tfvars.json': desired, 'backend.json': {'project_id': 1},
                             'encryption.json': {'passphrase': 'synthetic-protected-key-for-native-test'},
                             'acceptance.json': {'root': 'github', 'status': 'accepted'},
                             'inventory.json': {'terraform_data.fixture': {'id': 'pending'}}}
                for name, value in documents.items():
                    (private / name).write_text(json.dumps(value))
                (private / 'credentials.env').write_text('TF_HTTP_USERNAME=synthetic\nTF_HTTP_PASSWORD=synthetic\nGITHUB_TOKEN=synthetic\n')
                url = 'http://127.0.0.1:' + str(server.server_port) + '/state'

                def loopback(values, unused_url, passphrase):
                    return environment(values, url, passphrase)

                with patch.object(command, 'WORKSPACE', workspace), \
                        patch.object(command, 'PRIVATE', private.parent), \
                        patch.object(command, 'WORK', Path(temporary) / 'work'), \
                        patch.object(command, 'ciphertext'), patch.object(command, 'maintain'), \
                        patch.object(command, 'validate_inventory'), \
                        patch('playbooks.infrastructure.files.github_adoption.observe') as observe, \
                        patch.object(command, 'environment', side_effect=loopback), \
                        patch.object(command, 'source_binding', return_value={'revision': 'synthetic', 'source_hash': 'synthetic'}):
                    client = command.Client('github')
                    client.initialize()
                    # Bootstrap only a builtin disposable fixture, outside ordinary apply.
                    created = client.native('apply', '-input=false', '-auto-approve', '-var-file=desired.tfvars.json')
                    self.assertEqual(created.returncode, 0)
                    pulled = client.native('state', 'pull')
                    self.assertEqual(pulled.returncode, 0)
                    identity = json.loads(pulled.stdout)['resources'][0]['instances'][0]['attributes']['id']
                    self.assertNotIn(b'"resources"', (client.path / 'diagnostics.txt').read_bytes())
                    (private / 'inventory.json').write_text(json.dumps({'terraform_data.fixture': {'id': identity}}))
                    client = command.Client('github')
                    self.assertEqual(client.plan('verify'), 0)
                    self.assertIn('encrypted_data', json.loads(stored['state']))
                    self.assertNotIn(desired['owner'].encode(), stored['state'])
                    desired['owner'] = 'synthetic-updated'
                    (private / 'desired.tfvars.json').write_text(json.dumps(desired))
                    client = command.Client('github')
                    self.assertEqual(client.plan('drift'), 2)
                    binding = json.loads((client.path / 'plan-binding.json').read_text())
                    self.assertEqual(client.apply(binding['plan_hash']), 0)
                    self.assertEqual(client.plan('verify'), 0)
                    self.assertIsNone(stored['lock'])
                    self.assertIn('encrypted_data', json.loads(stored['state']))
                    self.assertNotIn(b'synthetic-updated', stored['state'])
                    original_state = stored['state']
                    desired['owner'] = 'synthetic-interrupted-update'
                    (private / 'desired.tfvars.json').write_text(json.dumps(desired))
                    client = command.Client('github')
                    self.assertEqual(client.plan('drift'), 2)
                    binding = json.loads((client.path / 'plan-binding.json').read_text())
                    stored['reject_upload'] = True
                    self.assertNotEqual(client.apply(binding['plan_hash']), 0)
                    recovery = client.path / 'errored.tfstate'
                    self.assertTrue(recovery.is_file())
                    recovery_bytes = recovery.read_bytes()
                    self.assertIn('encrypted_data', json.loads(recovery_bytes))
                    self.assertNotIn(b'synthetic-interrupted-update', recovery_bytes)
                    self.assertEqual(stored['state'], original_state)
                    self.assertIsNone(stored['lock'])
                    stored['reject_upload'] = False
                    # Decode locally into memory; native push encrypts for this loopback fixture.
                    decoder = Path(temporary) / 'decoder'
                    decoder.mkdir()
                    (decoder / 'main.tf.json').write_text(json.dumps({'terraform': {
                        'required_version': '= 1.13.1', 'backend': {'local': {'path': str(recovery)}}}}))
                    local_env = {key: value for key, value in client.env.items() if not key.startswith('TF_HTTP_')}
                    require(native(decoder, local_env, 'init', '-input=false'))
                    decrypted = require(native(decoder, local_env, 'state', 'pull')).stdout
                    recovered = json.loads(decrypted)
                    self.assertEqual(recovered['resources'][0]['instances'][0]['attributes']['id'], identity)
                    require(native(client.path, client.env, 'state', 'push', '-', input_data=decrypted))
                    self.assertEqual(recovery.read_bytes(), recovery_bytes)
                    self.assertEqual(client.plan('verify'), 0)
                    self.assertEqual(observe.call_count, 7)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
