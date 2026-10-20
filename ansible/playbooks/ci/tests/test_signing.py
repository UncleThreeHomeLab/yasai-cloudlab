"""Signing custody precedes creation and preserves originals across interruption and repeat."""
import unittest
from unittest.mock import patch

from playbooks.ci.files import signing


class SigningCustodyTests(unittest.TestCase):
    def test_interrupted_verifier_delivery_preserves_durable_private_key_and_repeats_without_rotation(self):
        items = {}
        interrupted = False
        def ensure(token, definitions):
            nonlocal interrupted
            self.assertEqual(token, 'synthetic-local-writer')
            result = {'created': [], 'preserved': []}
            for title, fields in definitions.items():
                if title == signing.VERIFIER and not interrupted:
                    interrupted = True
                    raise RuntimeError('interrupted')
                if title in items:
                    result['preserved'].append(title)
                else:
                    items[title] = {field: factory() for field, (_, factory) in fields.items()}
                    result['created'].append(title)
            return result
        with patch.object(signing, 'ensure_items', side_effect=ensure), \
                patch.object(signing, 'durable', side_effect=lambda token, title, field, kind: items[title][field]):
            with self.assertRaises(RuntimeError):
                signing.provision('synthetic-local-writer')
            original = dict(items[signing.SIGNER])
            resumed = signing.provision('synthetic-local-writer')
            self.assertEqual(resumed, {'created_items': 1, 'preserved_items': 1, 'private_key_delivered': False})
            self.assertEqual(items[signing.SIGNER], original)
            self.assertEqual(items[signing.VERIFIER]['public_key'], signing.public_key(original['private_key']))
            with patch.object(signing, 'private_key', side_effect=AssertionError('Never rotate an existing signer')):
                self.assertEqual(signing.provision('synthetic-local-writer')['created_items'], 0)
            items[signing.VERIFIER]['public_key'] = signing.public_key(signing.private_key())
            verifier = dict(items[signing.VERIFIER])
            with self.assertRaises(ValueError):
                signing.provision('synthetic-local-writer')
            self.assertEqual(items[signing.SIGNER], original)
            self.assertEqual(items[signing.VERIFIER], verifier)
        self.assertNotEqual(signing.SIGNER, 'harbor-recovery-signer')
