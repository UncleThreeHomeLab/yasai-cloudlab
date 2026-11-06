import unittest
from contextlib import nullcontext
from unittest.mock import Mock, patch
import base64
import copy
import json
from pathlib import Path
import tempfile
import yaml

from playbooks.services.files import examples
from playbooks.services.files.examples import definitions, prices_definitions
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

    def test_prices_definition_is_ready_with_exact_approved_scope(self):
        public = yaml.safe_load((examples.ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
        value = prices_definitions(public, 'a' * 40)
        validate_catalog(value)
        self.assertEqual(len(value['catalog']), 1)
        entry = value['catalog'][0]
        self.assertEqual(entry['publication'], 'ready')
        self.assertEqual(entry['approval'], {
            'name': 'prices', 'namespace': 'cloudlab-app-prices', 'repository': public, 'revision': 'a' * 40,
            'valuesPath': 'apps/prices.yaml', 'secretReferences': ['prices-database', 'prices-storage'],
            'configMaps': [], 'visibility': 'public', 'egress': []})
        definition = entry['definition']
        self.assertEqual((definition['name'], definition['owner']), ('prices', 'platform'))
        self.assertEqual(definition['exposure'], {'class': 'none'})
        self.assertEqual(definition['oidc'], {'enabled': False})
        self.assertEqual(definition['data'], {
            'database': {'name': 'prices', 'credentialReference': 'prices-database', 'retention': 'retain'},
            'bucket': {'name': 'prices-history', 'credentialReference': 'prices-storage', 'retention': 'retain'}})
        self.assertEqual(len({row['credentialReference'] for row in definition['data'].values()}), 2)
        self.assertEqual(value['dataApprovals'], {
            'prices-database': {'kind': 'database', 'service': 'prices', 'name': 'prices',
                                'item': 'cnpg-prices-production', 'migrationItem': 'cnpg-prices-migration'},
            'prices-storage': {'kind': 'bucket', 'service': 'prices', 'name': 'prices-history',
                               'item': 's3-prices-production'}})

    def test_prices_definition_rejects_unapproved_source_or_retention(self):
        public = yaml.safe_load((examples.ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
        value = prices_definitions(public, 'a' * 40)
        for mutate in (
                lambda row: row['catalog'][0]['approval'].update(repository='https://example.com/unapproved.git'),
                lambda row: row['catalog'][0]['approval'].update(revision='not-a-revision'),
                lambda row: row['catalog'][0]['definition']['data']['database'].update(retention='delete'),
                lambda row: row['catalog'][0]['definition']['data']['bucket'].update(retention='delete')):
            mutated = copy.deepcopy(value)
            mutate(mutated)
            with self.assertRaises(ValueError):
                validate_catalog(mutated)

    def test_bundles_preserve_private_approvals_without_publishing_or_repinning(self):
        value = {'catalog': [], 'dataApprovals': {}}
        from playbooks.services.tests.fixtures import definition, approval
        value['catalog'].append({'definition': definition(), 'approval': dict(approval(), visibility='private'), 'publication': 'ready'})
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            with patch.object(examples.subprocess, 'check_output', return_value='c'*40), \
                    patch('playbooks.services.files.owner.chart', return_value=nullcontext(examples.ROOT / 'platform/delivery/services')), \
                    patch.object(examples, 'Path', side_effect=lambda value: target if value == '/recovery/services' else Path(value)):
                examples.bundles(value)
                for entry in value['catalog']:
                    bundle = json.loads((target / (entry['definition']['name'] + '-bundle.json')).read_text())
                    self.assertEqual(bundle['approval'], entry['approval'])
                    public = yaml.safe_load((examples.ROOT / 'gitops/roots/public/values.yaml').read_text())
                    self.assertEqual(bundle['platformRevision'], public['services']['revision'])
                    self.assertNotEqual(bundle['platformRevision'], 'c' * 40)
