import unittest
from unittest.mock import Mock, patch

from playbooks.data.files.requests import request, resolve, reconcile, retained_requests, additions
from playbooks.data.files.chart import render


class DataRequestTests(unittest.TestCase):
    def test_data_payload_keeps_retained_consumers_and_resolves_original_credentials(self):
        from playbooks.data.files import inputs
        data, approved = self.inputs()
        catalog = {'catalog': [], 'dataApprovals': approved,
                   'retainedDataRequests': [{'service': 'fixture', 'data': data}]}
        credentials = {
            'cnpg-notes-production': {'username': 'notes_app', 'database': 'notes'},
            'cnpg-notes-migration': {'username': 'notes_migration', 'database': 'notes'},
            'cnpg-backup': {'username': 'backup'},
            'cnpg-keycloak': {'username': 'identity_app', 'database': 'identity'},
            's3-notes-production': {'BUCKET': 'notes', 'ENDPOINT': 'https://s3.internal.example.invalid', 'REGION': 'us-east-1'},
            'cnpg-fixture-production': {'username': 'fixture_app', 'database': 'fixture'},
            'cnpg-fixture-migration': {'username': 'fixture_migration', 'database': 'fixture'},
            's3-fixture-production': {'BUCKET': 'fixture'}}
        with patch.object(inputs, 'check'), patch.object(inputs, 'render'), \
                patch.object(inputs, 'committed_payload', return_value={'repository': 'public', 'branch': 'main', 'revision': 'a' * 40}), \
                patch.object(inputs, 'fields', side_effect=lambda item, fields: {key: credentials[item][key] for key in fields}), \
                patch('playbooks.services.files.inputs.catalog', return_value=catalog):
            values = inputs.payload()['values']
        self.assertEqual(values['serviceConsumers'], ['cloudlab-app-fixture'])
        self.assertEqual(values['serviceRequests'][0]['database']['applicationItem'], 'cnpg-fixture-production')
        self.assertEqual(values['serviceRequests'][0]['bucket']['item'], 's3-fixture-production')

    def test_retired_source_can_be_removed_without_changing_declared_data_scope(self):
        data, approved = self.inputs()
        catalog = {'catalog': [], 'dataApprovals': approved,
                   'retainedDataRequests': [{'service': 'fixture', 'data': data}]}
        expected = request('fixture', data, approved)
        self.assertEqual(retained_requests(catalog), [expected])
        self.assertEqual(additions([expected], retained_requests(catalog)), [])
        with self.assertRaises(ValueError):
            additions([expected], [])
        from playbooks.services.files.inputs import validate_catalog
        validate_catalog(catalog)
        for entries in ([{'service': 'other', 'data': data}],
                        catalog['retainedDataRequests'] * 2, [{'service': 'fixture', 'data': {}}],
                        [{'service': [], 'data': data}], [{'service': 'fixture', 'data': ['invalid']}]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                validate_catalog(dict(catalog, retainedDataRequests=entries))

    def inputs(self):
        data = {'database': {'name': 'fixture', 'credentialReference': 'fixture-database', 'retention': 'retain'},
                'bucket': {'name': 'fixture', 'credentialReference': 'fixture-objects', 'retention': 'retain'}}
        approved = {'fixture-database': {'kind': 'database', 'service': 'fixture', 'name': 'fixture',
                                        'item': 'cnpg-fixture-production', 'migrationItem': 'cnpg-fixture-migration'},
                    'fixture-objects': {'kind': 'bucket', 'service': 'fixture', 'name': 'fixture', 'item': 's3-fixture-production'}}
        return data, approved

    def test_data_owner_renders_scoped_roles_database_and_bucket_without_new_operator(self):
        data, approved = self.inputs()
        request_value = request('fixture', data, approved)
        lookup = lambda item, fields: {'username': 'fixture_migration' if item.endswith('migration') else 'fixture_app',
                                       'database': 'fixture', 'BUCKET': 'fixture'}
        rows = resolve([request_value], lookup)
        objects = render('configuration', {'serviceRequests': rows})
        database = next(o for o in objects if o['kind'] == 'Database')
        self.assertEqual(database['spec']['databaseReclaimPolicy'], 'retain')
        cluster = next(o for o in objects if o['kind'] == 'Cluster')
        roles = [r for r in cluster['spec']['managed']['roles'] if r['name'].startswith('fixture')]
        self.assertEqual(len(roles), 2)
        self.assertTrue(all(r['superuser'] is False and r['createdb'] is False for r in roles))
        self.assertIn('hostssl fixture fixture_app all scram-sha-256', cluster['spec']['postgresql']['pg_hba'])
        scoped = next(o for o in objects if o['kind'] == 'ExternalSecret' and o['metadata']['name'] == 'fixture-application')
        self.assertEqual(scoped['spec']['dataFrom'], [{'extract': {'key': 'cnpg-fixture-production'}}])
        self.assertEqual(scoped['spec']['target']['template']['mergePolicy'], 'Replace')
        self.assertEqual(set(scoped['spec']['target']['template']['data']), {'username', 'password'})
        s3 = next(o for o in objects if o['kind'] == 'ExternalSecret' and o['metadata']['name'] == 'cloudlab-s3-config')
        self.assertIn('Read:fixture', s3['spec']['target']['template']['data']['seaweedfs_s3_config'])
        admin, grant = Mock(), Mock(return_value=False)
        admin.ensure_bucket.return_value = False
        self.assertFalse(reconcile({'serviceRequests': rows, 'backupRole': 'backup'}, Mock(), grant, admin))
        admin.ensure_bucket.assert_called_once_with('fixture')
        self.assertEqual(grant.call_args.args[0]['database'], 'fixture')

    def test_cross_service_scope_privileged_reference_and_disposal_are_rejected(self):
        data, approved = self.inputs()
        with self.assertRaises(ValueError): request('other', data, approved)
        data['database']['credentialReference'] = 'seaweedfs-admin'
        with self.assertRaises(ValueError): request('fixture', data, approved)
        data, approved = self.inputs()
        data['bucket']['retention'] = 'delete'
        with self.assertRaises(ValueError): request('fixture', data, approved)
