import unittest
from unittest.mock import Mock

from playbooks.data.files.requests import request, resolve, reconcile
from playbooks.data.files.chart import render


class DataRequestTests(unittest.TestCase):
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
