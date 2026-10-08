"""A saved human proof must authenticate the selected identity and exact Access audience."""
import base64
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
