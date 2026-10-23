import unittest
from unittest.mock import Mock, patch
import base64
import copy
import json
from pathlib import Path
import tempfile
import yaml

from playbooks.services.files import examples
from playbooks.services.files.examples import definitions
from playbooks.services.files.inputs import validate_catalog


class ExampleTests(unittest.TestCase):
    def test_notes_preparation_preserves_identity_data_and_chart_without_test_sources(self):
        public = yaml.safe_load((examples.ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
        value = definitions('example.invalid', public, 'a'*40, 'notes', 'notes')
        validate_catalog(value)
        self.assertEqual(len(value['catalog']), 1)
        notes = value['catalog'][0]
        self.assertEqual(notes['approval']['chartPath'], 'apps/notes')
        self.assertEqual(notes['definition']['exposure']['class'], 'public')
        self.assertTrue(notes['definition']['oidc']['enabled'])
        self.assertEqual(notes['definition']['additionalExposures'][0]['class'], 'private')
        self.assertEqual(set(value['dataApprovals']), {'notes-database', 'notes-objects'})
        self.assertEqual(notes['definition']['data']['database']['retention'], 'retain')
        value['catalog'][0]['approval']['repository'] = 'https://github.com/example/unapproved.git'
        with self.assertRaises(ValueError):
            validate_catalog(value)

    def test_bundles_preserve_private_approvals_without_publishing_or_repinning(self):
        value = {'catalog': [], 'dataApprovals': {}}
        from playbooks.services.tests.fixtures import definition, approval
        value['catalog'].append({'definition': definition(), 'approval': dict(approval(), visibility='private'), 'publication': 'ready'})
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            with patch.object(examples.subprocess, 'check_output', return_value='c'*40), \
                    patch.object(examples, 'Path', side_effect=lambda value: target if value == '/recovery/services' else Path(value)):
                examples.bundles(value)
                for entry in value['catalog']:
                    bundle = json.loads((target / (entry['definition']['name'] + '-bundle.json')).read_text())
                    self.assertEqual(bundle['approval'], entry['approval'])
