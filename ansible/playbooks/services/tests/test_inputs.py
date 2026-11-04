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

    def test_catalog_accepts_paired_role_metadata_and_rejects_invalid_approvals(self):
        import copy
        from fixtures import definition, approval
        value = definition(); accepted = approval()
        value['data'] = {'database': {'name': 'fixture', 'credentialReference': 'fixture-db', 'retention': 'retain'}}
        accepted['secretReferences'] = ['fixture-db']
        scope = {'kind': 'database', 'service': accepted['name'], 'name': 'fixture', 'item': 'cnpg-fixture-production',
                 'migrationItem': 'cnpg-fixture-migration', 'applicationRole': 'fixture_app', 'migrationRole': 'fixture_migration'}
        catalog = {'catalog': [{'definition': value, 'approval': accepted, 'publication': 'retired'}], 'dataApprovals': {'fixture-db': scope}}
        self.assertEqual(inputs.validate_catalog(catalog), catalog)
        for change in ('partial', 'reserved', 'same'):
            bad = copy.deepcopy(catalog); selected = bad['dataApprovals']['fixture-db']
            if change == 'partial': selected.pop('migrationRole')
            if change == 'reserved': selected['applicationRole'] = 'template0'
            if change == 'same': selected['migrationRole'] = selected['applicationRole']
            with self.subTest(change=change), self.assertRaises(ValueError): inputs.validate_catalog(bad)
