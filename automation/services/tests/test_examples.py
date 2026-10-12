import unittest
from unittest.mock import Mock, patch
import base64
import copy
import json
from pathlib import Path
import tempfile
import yaml

from automation.services import examples
from automation.services.examples import definitions
from automation.services.inputs import validate_catalog


class ExampleTests(unittest.TestCase):
    def test_bundle_rerun_preserves_approved_private_revision(self):
        accepted = definitions('example.invalid','https://github.com/example/public.git','a'*40,
                               'https://github.com/example/private.git','abcdef123456','notes','notes')
        proposed = copy.deepcopy(accepted)
        proposed['catalog'][1]['approval']['revision'] = 'b'*40
        document = lambda value: {'encoding': 'base64', 'content': base64.b64encode(value.encode()).decode()}
        api = Mock()
        api.request.side_effect = [document(json.dumps(accepted)), document(yaml.safe_dump(accepted['catalog'][1]['definition']))]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            with patch('automation.gitops.github_setup.inputs', return_value=({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/config.git'}, api)), \
                    patch('automation.gitops.private_fixture.prepare_service') as publish, \
                    patch.object(examples.subprocess, 'check_output', return_value='c'*40), \
                    patch.object(examples, 'Path', side_effect=lambda value: target if value == '/recovery/services' else Path(value)):
                examples.bundles(proposed)
                publish.assert_not_called()
                bundle = json.loads((target / 'fixture-abcdef123456-bundle.json').read_text())
                self.assertEqual(bundle['approval']['revision'], 'a'*40)

    def test_approved_examples_use_distinct_sources_scopes_and_retained_data(self):
        value = definitions('example.invalid','https://github.com/example/public.git','a'*40,
                            'https://github.com/example/private.git','abcdef123456','notes','notes')
        validate_catalog(value)
        notes, fixture = value['catalog']
        self.assertEqual(notes['approval']['visibility'],'public')
        self.assertEqual(fixture['approval']['visibility'],'private')
        self.assertEqual(notes['definition']['exposure']['class'],'public')
        self.assertEqual(fixture['definition']['exposure']['class'],'private')
        self.assertEqual(fixture['definition']['data']['database']['name'],'fixture_abcdef123456')
        self.assertEqual(fixture['definition']['persistence']['retention'],'retain')
        self.assertNotEqual(value['dataApprovals']['notes-database']['item'], value['dataApprovals']['fixture-database']['item'])
