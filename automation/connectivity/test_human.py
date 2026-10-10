"""A saved human proof must authenticate the selected identity and exact Access audience."""
import base64
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from automation.connectivity import human


def encoded(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


class HumanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = cls.key.public_key().public_numbers()
        cls.jwk = {'kid': 'fixture', 'kty': 'RSA', 'e': encoded(public.e.to_bytes(3, 'big')),
                   'n': encoded(public.n.to_bytes(256, 'big'))}

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.receipt = Path(temp.name) / 'proof.json'
        receipt_store = patch.object(human, 'transaction')
        store = receipt_store.start().return_value.__enter__.return_value
        self.addCleanup(receipt_store.stop)
        store.load.side_effect = lambda name: json.loads(self.receipt.read_text()) if self.receipt.exists() else None
        for item in (patch.object(human, 'RECEIPT', self.receipt),
                     patch.dict(os.environ, {'CLOUDFLARE_HUMAN_EMAIL': 'admin@example.invalid'}),
                     patch.object(human, 'selected', return_value=([{'hostname': 'human.example.invalid', 'aud': 'audience'}],
                         [{'hostname': 'machine.example.invalid', 'access': 'machine'}], 'fixture.cloudflareaccess.com', 'binding')),
                     patch.object(human, 'open_request', side_effect=lambda request: io.BytesIO(json.dumps({'keys': [self.jwk]}).encode()))):
            item.start()
            self.addCleanup(item.stop)

    def token(self, **changes):
        claims = {'aud': ['audience'], 'email': 'admin@example.invalid', 'iss': 'https://fixture.cloudflareaccess.com', 'exp': time.time() + 60}
        claims.update(changes)
        head = encoded(json.dumps({'alg': 'RS256', 'kid': 'fixture'}).encode())
        body = encoded(json.dumps(claims).encode())
        signed = (head + '.' + body).encode()
        return head + '.' + body + '.' + encoded(self.key.sign(signed, padding.PKCS1v15(), hashes.SHA256()))

    def test_signed_human_proof_never_retains_session_token(self):
        token = self.token()
        with patch.object(human, 'https', side_effect=[{'status': 200, 'body': b'mesh-ok'}, {'status': 403, 'body': b'Forbidden'}]):
            self.assertTrue(human.record(token)['human_authenticated'])
        self.assertNotIn(token, self.receipt.read_text())
        self.assertTrue(human.retained()['human_policy_matches_signed_proof'])

    def test_central_acceptance_requires_signed_browser_proof_and_unchanged_provider_inputs(self):
        for drift in (False, True):
            with self.subTest(drift=drift):
                state = {'identity_cutover': {'phase': 'configured'}, 'identity_provider': {'phase': 'configured', 'credential_hash': 'original'}}
                saved = {}
                def response(*args, **kwargs):
                    if kwargs['headers'].get('Cookie') and args[0].startswith('machine'):
                        if drift: state['identity_provider']['credential_hash'] = 'changed'
                        return {'status': 403, 'body': b'Forbidden'}
                    return {'status': 200, 'body': b'mesh-ok'}
                with patch.object(human, 'transaction') as transaction, patch.object(human, 'https', side_effect=response):
                    store = transaction.return_value.__enter__.return_value
                    store.load.side_effect = lambda name: copy.deepcopy(state) if name == 'external' else saved.get(name)
                    store.save.side_effect = lambda name, value: saved.update({name: copy.deepcopy(value)})
                    if drift:
                        with self.assertRaises(RuntimeError): human.record(self.token())
                        self.assertNotIn('external', saved)
                        self.assertNotIn('human-proof', saved)
                    else:
                        self.assertTrue(human.record(self.token())['human_authenticated'])
                        self.assertEqual(saved['external']['identity_cutover']['phase'], 'accepted')
                        self.assertEqual(saved['external']['identity_provider']['phase'], 'accepted')

    def test_wrong_identity_audience_issuer_and_expiry_fail_before_backend_request(self):
        for changes in ({'email': 'other@example.invalid'}, {'aud': ['other']}, {'iss': 'https://other.invalid'}, {'exp': 1}):
            with self.subTest(changes=changes), patch.object(human, 'https') as request:
                with self.assertRaises(RuntimeError): human.record(self.token(**changes))
                request.assert_not_called()
                self.assertFalse(self.receipt.exists())

    def test_login_page_or_cross_machine_access_cannot_create_acceptance_receipt(self):
        for responses in ([{'status': 200, 'body': b'login'}],
                          [{'status': 200, 'body': b'mesh-ok'}, {'status': 200, 'body': b'mesh-ok'}]):
            with patch.object(human, 'https', side_effect=responses):
                with self.assertRaises(RuntimeError): human.record(self.token())
                self.assertFalse(self.receipt.exists())
