"""Requests remain data-owned even when onboarding callers supply their inputs."""
import unittest
import copy

from playbooks.data.files.requests import request, resolve, protect, additions


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

    def test_fixed_resource_and_credential_identity_collisions_are_rejected(self):
        settings = {'database': 'notes', 'bucket': 'notes', 'applicationRole': 'notes_app',
                    'migrationRole': 'notes_migration', 'backupRole': 'backup',
                    'identity': {'enabled': True, 'database': 'identity', 'role': 'identity_app'}}
        database = {'name': 'fixture', 'applicationRole': 'fixture_app', 'migrationRole': 'fixture_migration',
                    'applicationItem': 'cnpg-fixture-production', 'migrationItem': 'cnpg-fixture-migration'}
        for name, kind in (('notes', 'database'), ('notes', 'bucket'), ('keycloak', 'database'),
                           ('data-admin', 'bucket'), ('admin', 'bucket'), ('app', 'bucket')):
            value = database if kind == 'database' else {'name': 'fixture', 'item': 's3-fixture-production'}
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                protect([{'service': name, kind: value}], settings)
        original = {'service': 'notes', 'database': dict(database, name='notes', applicationRole='notes_app',
                    migrationRole='notes_migration', applicationItem='cnpg-notes-production', migrationItem='cnpg-notes-migration'),
                    'bucket': {'name': 'notes', 'item': 's3-notes-production'}}
        protect([original], settings)
        protect([{'service': 'keycloak', 'database': database}], settings | {'identity': {'enabled': False}})

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

    def test_optional_role_metadata_is_paired_scoped_and_matches_vault_usernames(self):
        data = {'database': {'name': 'fixture', 'credentialReference': 'fixture-db', 'retention': 'retain'}}
        scope = {'kind': 'database', 'service': 'fixture', 'name': 'fixture', 'item': 'cnpg-fixture-production', 'migrationItem': 'cnpg-fixture-migration'}
        lookup = lambda item, fields: {'database': 'fixture', 'username': 'fixture_migration' if item.endswith('migration') else 'fixture_app'}
        legacy = resolve([request('fixture', data, {'fixture-db': scope})], lookup)
        enriched = scope | {'applicationRole': 'fixture_app', 'migrationRole': 'fixture_migration'}
        self.assertEqual(resolve([request('fixture', data, {'fixture-db': enriched})], lookup), legacy)
        for bad in (scope | {'applicationRole': 'fixture_app'}, enriched | {'applicationRole': 'other'},
                    enriched | {'migrationRole': 'fixture_app'}, enriched | {'applicationRole': 'pg_reserved'},
                    enriched | {'applicationRole': 'postgres'}, enriched | {'applicationRole': 'template1'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError): resolve([request('fixture', data, {'fixture-db': bad})], lookup)
