import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from automation.services.check import run

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'apps/notes/lib.zip'))
spec = importlib.util.spec_from_file_location('notes_api', ROOT / 'apps/notes/api.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


def encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


class NotesTests(unittest.TestCase):
    def test_chart_and_shared_code_match_authoritative_sources(self):
        self.assertEqual(run()['notes_services'], 2)

    def test_real_http_api_rejects_invalid_grants_and_unauthorized_roles(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = key.public_key().public_numbers()
        jwks = {'keys': [{'kid': 'fixture', 'alg': 'RS256', 'use': 'sig', 'kty': 'RSA',
                           'n': encode(numbers.n.to_bytes(256, 'big')), 'e': encode(numbers.e.to_bytes(3, 'big'))}]}
        now = time.time()
        claims = {'iss': 'https://login.example.invalid/realms/applications', 'aud': 'notes-api',
                  'typ': 'Bearer', 'sub': 'synthetic', 'roles': ['reader'], 'iat': now-1, 'exp': now+60}
        def token(value):
            message = encode(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'fixture'}).encode()) + '.' + encode(json.dumps(value).encode())
            return message + '.' + encode(key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256()))
        class FakeDatabase:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def execute(self, *args): return self
            def fetchall(self): return [('synthetic', 'Hello', 'Persistent fixture', 'notes/fixture.txt')]
        with patch.dict(os.environ, OIDC_ISSUER=claims['iss'], OIDC_AUDIENCE='notes-api', OPERATIONS_HOST='notes.internal.example.invalid'), \
                patch.object(api, 'signing_keys', return_value=jwks), patch.object(api, 'database', return_value=FakeDatabase()):
            server = api.ThreadingHTTPServer(('127.0.0.1', 0), api.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def status(value, path='/api/notes', host=None):
                    headers = {'Authorization': 'Bearer '+token(value)} if value else {}
                    if host: headers['Host'] = host
                    request = urllib.request.Request('http://127.0.0.1:'+str(server.server_port)+path, headers=headers)
                    try:
                        with urllib.request.urlopen(request, timeout=5) as response: return response.status
                    except urllib.error.HTTPError as error: return error.code
                self.assertEqual(status(claims), 200)
                self.assertEqual(status(None), 401)
                for changed in ({'aud':'other-api'}, {'exp':now-1}, {'iss':'https://wrong.example.invalid'}, {'typ':'ID'}):
                    with self.subTest(changed=changed): self.assertEqual(status(dict(claims, **changed)), 401)
                self.assertEqual(status(dict(claims, roles=['writer'])), 403)
                self.assertEqual(status(dict(claims, roles=['operator']), '/api/operations'), 404)
                self.assertEqual(status(claims, '/api/operations', 'notes.internal.example.invalid'), 403)
                self.assertEqual(status(dict(claims, roles=['operator']), '/api/operations', 'notes.internal.example.invalid'), 200)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
