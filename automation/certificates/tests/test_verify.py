"""Certificate proof rejects bad trust and cleans up failed delivery fixtures."""
import base64
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import verify


class VerificationTests(unittest.TestCase):
    def fingerprint(self, responses, trusted=False):
        certificate = {'metadata': {'uid': 'certificate'},
                       'spec': {'secretName': 'tls', 'dnsNames': ['*.example.invalid']},
                       'status': {'revision': 1, 'renewalTime': 'scheduled'}}
        secret = {'metadata': {'uid': 'secret'}, 'data': {
            'tls.crt': base64.b64encode(b'public certificate').decode(), 'tls.key': 'private fixture'}}
        with patch.object(verify, 'get', side_effect=[certificate, secret]), \
                patch.object(verify.subprocess, 'run', side_effect=responses):
            return verify.fingerprint('certificate', 'namespace', trusted)

    def test_hostname_mismatch_fails_even_when_openssl_returns_zero(self):
        with self.assertRaisesRegex(RuntimeError, 'DNS names'):
            self.fingerprint([SimpleNamespace(returncode=0),
                              SimpleNamespace(returncode=0, stdout=b'Hostname verification.example.invalid does NOT match certificate')])

    def test_untrusted_production_chain_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'publicly trusted'):
            self.fingerprint([SimpleNamespace(returncode=0),
                              SimpleNamespace(returncode=0, stdout=b'Hostname verification.example.invalid does match certificate'),
                              SimpleNamespace(returncode=2)], trusted=True)

    def test_failed_mount_comparison_removes_only_created_fixture(self):
        calls = []
        def kube(*args, **kwargs):
            calls.append((args, kwargs))
            return 'wrong /tls/tls.crt' if args[0] == 'exec' else ''
        with patch.object(verify, 'kube', side_effect=kube):
            with self.assertRaisesRegex(RuntimeError, 'Mounted certificate'):
                verify.delivery('cloudlab-gateway-public', 'pinned-image', 'expected')
        created = calls[0][1]['document']
        self.assertEqual(calls[-1][0][0:3], ('delete', 'pod', created['metadata']['name']))
        self.assertEqual(created['spec']['volumes'][0]['secret']['items'], [{'key': 'tls.crt', 'path': 'tls.crt'}])

    def test_failed_creation_does_not_delete_unknown_resource(self):
        with patch.object(verify, 'kube', side_effect=RuntimeError('creation failed')) as kube:
            with self.assertRaisesRegex(RuntimeError, 'creation failed'):
                verify.delivery('cloudlab-gateway-public', 'pinned-image', 'expected')
        self.assertEqual(kube.call_count, 1)


if __name__ == '__main__':
    unittest.main()
