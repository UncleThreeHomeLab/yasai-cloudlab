"""Retention cannot prune current state or release another client's lock."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from automation.infra import retention


class RetentionTests(unittest.TestCase):
    def test_scoped_prune_retains_latest_versions_ciphertext_and_owned_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = Mock(path=Path(temporary), env={})
            client.native.return_value = Mock(returncode=0, stdout=json.dumps({'serial': 34, 'lineage': 'fixture'}).encode())
            raw = b'{"encrypted_data":"synthetic"}'
            removed, calls, locks = [], [], []
            def request(env, suffix='', method='GET', document=None):
                calls.append((suffix, method))
                if suffix == '/lock':
                    locks.append(document['ID'])
                    return 200, b''
                if not suffix:
                    return 200, raw
                if method == 'DELETE':
                    removed.append(suffix)
                    return 204, b''
                return (404, b'') if suffix in removed else (200, raw)
            with patch.object(retention, 'request', side_effect=request):
                retention.maintain(client)
                retention.maintain(client)
            self.assertEqual(removed, ['/versions/1', '/versions/2'])
            self.assertEqual(locks[0], locks[1])
            self.assertEqual(locks[2], locks[3])
            self.assertNotEqual(locks[0], locks[2])
            self.assertEqual((client.path / 'retained-state.encrypted').read_bytes(), raw)
            self.assertNotIn(('', 'DELETE'), calls)

    def test_concurrent_lock_rejection_never_unlocks(self):
        with patch.object(retention, 'request', return_value=(423, b'')) as request:
            with self.assertRaisesRegex(RuntimeError, 'lock rejected'):
                retention.maintain(Mock(env={}))
        self.assertEqual(request.call_count, 1)

    def test_plaintext_and_oversized_state_rejected(self):
        for raw in (b'{"resources":[]}', b'x' * (retention.MAX_BYTES + 1)):
            with patch.object(retention, 'request', return_value=(200, raw)):
                with self.assertRaises(RuntimeError):
                    retention.ciphertext({})

    def test_production_state_delete_and_untrusted_backend_rejected_before_network(self):
        env = {'TF_HTTP_ADDRESS': 'https://gitlab.com/api/v4/projects/1/terraform/state/managed'}
        with self.assertRaises(ValueError):
            retention.request(env, method='DELETE')
        with self.assertRaises(ValueError):
            retention.request({'TF_HTTP_ADDRESS': 'https://foreign.invalid/state'})
        with self.assertRaises(ValueError):
            retention.request(env, '/../unrelated', 'DELETE')

    def test_pending_prune_keeps_ciphertext_and_releases_only_owned_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = Mock(path=Path(temporary), env={})
            client.native.return_value = Mock(returncode=0, stdout=b'{"serial":33,"lineage":"fixture"}')
            raw = b'{"encrypted_data":"synthetic"}'
            calls = []
            def request(env, suffix='', method='GET', document=None):
                calls.append((suffix, method))
                return 200, raw
            with patch.object(retention, 'request', side_effect=request):
                with self.assertRaisesRegex(RuntimeError, 'pending'):
                    retention.maintain(client)
            self.assertEqual(calls[-1], ('/lock', 'DELETE'))
            self.assertEqual((client.path / 'retained-state.encrypted').read_bytes(), raw)
            self.assertFalse((client.path / 'retention.json').exists())
