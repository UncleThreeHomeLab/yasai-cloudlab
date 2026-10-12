"""Requests remain data-owned even when onboarding callers supply their inputs."""
import unittest
import copy

from automation.data.requests import resolve, protect, additions


class RequestResolutionTests(unittest.TestCase):
    def test_platform_database_roles_and_bucket_cannot_be_claimed_by_another_service(self):
        settings = {'database': 'notes', 'bucket': 'notes', 'applicationRole': 'notes_app',
                    'migrationRole': 'notes_migration', 'backupRole': 'backup',
                    'identity': {'enabled': True, 'database': 'identity', 'role': 'identity_app'}}
        row = {'service': 'fixture', 'database': {'name': 'fixture', 'applicationRole': 'fixture_app',
               'migrationRole': 'fixture_migration', 'applicationItem': 'cnpg-fixture-production',
               'migrationItem': 'cnpg-fixture-migration'}, 'bucket': {'name': 'fixture', 'item': 's3-fixture-production'}}
        protect([row], settings)
        for field, value in (('name', 'identity'), ('name', 'notes'),
                             ('applicationRole', 'backup'), ('migrationRole', 'identity_app')):
            changed = copy.deepcopy(row)
            changed['database'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): protect([changed], settings)
        changed = copy.deepcopy(row)
        changed['bucket']['name'] = 'notes'
        with self.assertRaises(ValueError): protect([changed], settings)

    def test_existing_data_scope_cannot_move_or_disappear(self):
        row = {'service': 'fixture', 'namespace': 'cloudlab-app-fixture', 'bucket': {'name': 'fixture'}}
        self.assertEqual(additions([row], [row]), [])
        for changed in ([], [dict(row, bucket={'name': 'other'})], [row, row]):
            with self.assertRaises(ValueError): additions([row], changed)

    def test_wrong_vault_database_and_overlapping_roles_are_rejected(self):
        request = {'service': 'fixture', 'namespace': 'cloudlab-app-fixture', 'database': {
            'name': 'fixture', 'item': 'cnpg-fixture-production', 'migrationItem': 'cnpg-fixture-migration'}}
        with self.assertRaises(ValueError):
            resolve([request], lambda *args: {'database': 'different', 'username': 'fixture_app'})
        with self.assertRaises(ValueError):
            resolve([request], lambda *args: {'database': 'fixture', 'username': 'fixture_app'})
