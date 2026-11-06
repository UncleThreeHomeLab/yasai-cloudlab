"""Requests remain data-owned even when onboarding callers supply their inputs."""
import unittest
import copy

from playbooks.data.files.requests import request, resolve, protect, additions


class RequestResolutionTests(unittest.TestCase):
    def prices(self, roles=False):
        data = {'database': {'name': 'prices', 'credentialReference': 'prices-database', 'retention': 'retain'},
                'bucket': {'name': 'prices-history', 'credentialReference': 'prices-storage', 'retention': 'retain'}}
        approved = {'prices-database': {'kind': 'database', 'service': 'prices', 'name': 'prices',
                                        'item': 'cnpg-prices-production', 'migrationItem': 'cnpg-prices-migration'},
                    'prices-storage': {'kind': 'bucket', 'service': 'prices', 'name': 'prices-history',
                                       'item': 's3-prices-production'}}
        if roles:
            approved['prices-database'].update(applicationRole='prices_app', migrationRole='prices_migration')
        return data, approved

    def prices_lookup(self, item, fields):
        if fields == ('BUCKET',):
            return {'BUCKET': 'prices-history'}
        return {'database': 'prices', 'username': 'prices_migration' if item.endswith('migration') else 'prices_app'}

    def prices_row(self):
        data, approved = self.prices()
        return resolve([request('prices', data, approved)], self.prices_lookup)[0]

    def test_prices_request_resolves_exact_roles_items_and_scope(self):
        data, approved = self.prices()
        requested = request('prices', data, approved)
        self.assertEqual(requested, {'service': 'prices', 'namespace': 'cloudlab-app-prices',
            'database': dict(data['database'], item='cnpg-prices-production', migrationItem='cnpg-prices-migration'),
            'bucket': dict(data['bucket'], item='s3-prices-production')})
        rows = [self.prices_row()]
        self.assertEqual(rows, [{'service': 'prices', 'namespace': 'cloudlab-app-prices',
            'database': {'name': 'prices', 'applicationRole': 'prices_app', 'migrationRole': 'prices_migration',
                         'applicationItem': 'cnpg-prices-production', 'migrationItem': 'cnpg-prices-migration'},
            'bucket': {'name': 'prices-history', 'item': 's3-prices-production'}}])
        data, approved = self.prices(roles=True)
        enriched = request('prices', data, approved)
        self.assertEqual(enriched['database']['applicationRole'], 'prices_app')
        self.assertEqual(resolve([enriched], self.prices_lookup), rows)
        settings = {'database': 'notes', 'bucket': 'notes', 'applicationRole': 'notes_app',
                    'migrationRole': 'notes_migration', 'backupRole': 'backup',
                    'identity': {'enabled': True, 'database': 'identity', 'role': 'identity_app'}}
        protect(rows, settings)
        self.assertEqual(additions([], rows), rows)
        self.assertEqual(additions(rows, rows), [])

    def test_prices_request_rejects_retention_unpaired_roles_refs_and_items(self):
        for kind in ('database', 'bucket'):
            data, approved = self.prices()
            data[kind]['retention'] = 'delete'
            with self.subTest(retention=kind), self.assertRaises(ValueError): request('prices', data, approved)
        for roles in ({'applicationRole': 'prices_app'}, {'migrationRole': 'prices_migration'},
                      {'applicationRole': 'prices_app', 'migrationRole': 'prices_app'}):
            data, approved = self.prices()
            approved['prices-database'].update(roles)
            with self.subTest(roles=roles), self.assertRaises(ValueError): request('prices', data, approved)
        for kind, field, value in (
                ('database', 'item', 's3-prices-production'),
                ('database', 'item', 'cnpg-prices-migration'), ('database', 'migrationItem', 'cnpg-prices-production'),
                ('database', 'migrationItem', 's3-prices-migration'),
                ('bucket', 'item', 'cnpg-prices-production')):
            data, approved = self.prices()
            approved['prices-database' if kind == 'database' else 'prices-storage'][field] = value
            with self.subTest(kind=kind, field=field, value=value), self.assertRaises(ValueError):
                request('prices', data, approved)
        for kind, ref in (('bucket', 'prices-database'), ('database', 'prices-storage'), ('database', 'unknown')):
            data, approved = self.prices()
            data[kind]['credentialReference'] = ref
            with self.subTest(collision=kind, ref=ref), self.assertRaises(ValueError): request('prices', data, approved)

    def test_prices_resolve_rejects_wrong_lookup_and_role_overlap(self):
        data, approved = self.prices(roles=True)
        requested = request('prices', data, approved)
        def lookup(**changes):
            def fake(item, fields):
                result = self.prices_lookup(item, fields)
                return result | changes.get('bucket' if fields == ('BUCKET',) else
                                            'migration' if item.endswith('migration') else 'app', {})
            return fake
        for changes in ({'app': {'database': 'other'}}, {'migration': {'database': 'other'}},
                        {'bucket': {'BUCKET': 'prices'}}, {'bucket': {'BUCKET': 'other'}},
                        {'app': {'username': 'other_app'}}, {'migration': {'username': 'prices_app'}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError): resolve([requested], lookup(**changes))
        data, approved = self.prices()
        approved['prices-database']['item'] = 'cnpg-other-production'
        swapped = request('prices', data, approved)
        def other_item(item, fields):
            if item == 'cnpg-other-production':
                return {'database': 'other', 'username': 'other_app'}
            return self.prices_lookup(item, fields)
        with self.assertRaises(ValueError): resolve([swapped], other_item)
        data, approved = self.prices()
        other_data = {'database': {'name': 'other', 'credentialReference': 'other-database', 'retention': 'retain'}}
        approved['other-database'] = {'kind': 'database', 'service': 'other', 'name': 'other',
                                      'item': 'cnpg-other-production', 'migrationItem': 'cnpg-other-migration'}
        other = request('other', other_data, approved)
        def overlapping(item, fields):
            if item.startswith('cnpg-other'):
                return {'database': 'other', 'username': 'other_migration' if item.endswith('migration') else 'prices_app'}
            return self.prices_lookup(item, fields)
        with self.assertRaises(ValueError): resolve([request('prices', data, approved), other], overlapping)

    def test_prices_protect_and_additions_reject_scope_claim_removal_or_move(self):
        row = self.prices_row()
        settings = {'database': 'notes', 'bucket': 'notes', 'applicationRole': 'notes_app',
                    'migrationRole': 'notes_migration', 'backupRole': 'backup',
                    'identity': {'enabled': True, 'database': 'identity', 'role': 'identity_app'}}
        for field, value in (('name', 'notes'), ('applicationRole', 'notes_app'), ('migrationRole', 'backup')):
            changed = copy.deepcopy(row); changed['database'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): protect([changed], settings)
        changed = copy.deepcopy(row); changed['bucket']['name'] = 'notes'
        with self.assertRaises(ValueError): protect([changed], settings)
        for changed in ([], [row, row]):
            with self.assertRaises(ValueError): additions([row], changed)
        for mutate in (lambda r: r['database'].update(name='other'), lambda r: r['bucket'].update(name='other'),
                       lambda r: r['database'].update(applicationRole='other_app'),
                       lambda r: r['database'].update(applicationItem='cnpg-other-production'),
                       lambda r: r.update(namespace='cloudlab-app-other')):
            changed = copy.deepcopy(row); mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError): additions([row], [changed])

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
