import unittest
from unittest.mock import patch

from playbooks.previews.files import verify


class VerifyTests(unittest.TestCase):
    def test_empty_native_collections_are_normalized_without_hiding_api_failures(self):
        for value in (None, {'items': []}):
            with patch.object(verify, 'get', return_value=value):
                self.assertEqual(verify.collection('secrets', 'preview-fixture'), [])
        with patch.object(verify, 'get', side_effect=RuntimeError('API unavailable')), self.assertRaises(RuntimeError):
            verify.collection('secrets', 'preview-fixture')
        with patch.object(verify, 'get', return_value={}), self.assertRaises(ValueError):
            verify.collection('secrets', 'preview-fixture')
