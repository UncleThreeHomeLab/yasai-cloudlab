import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.services.files import inputs


class InputTests(unittest.TestCase):
    def test_missing_enabled_private_input_fails_before_mutation(self):
        with patch.object(inputs, 'dotenv_values', return_value={}):
            self.assertIsNone(inputs.catalog())
            with self.assertRaises(ValueError): inputs.catalog(required=True)

    def test_traversal_and_incomplete_catalog_are_rejected(self):
        for name in ('../secret.json', '/tmp/secret.json', 'docs/local/missing.json'):
            with patch.object(inputs, 'dotenv_values', return_value={'SERVICE_CATALOG_FILE': name}):
                with self.assertRaises(ValueError): inputs.catalog()
