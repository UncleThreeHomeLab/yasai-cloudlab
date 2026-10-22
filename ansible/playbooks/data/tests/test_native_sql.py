"""Native SQL scope, validation, change detection and pod-local command boundaries."""
import copy
import unittest

import yaml

from playbooks.data.tests.fixtures import COMPONENT, retained, run_native


class NativeSQLTests(unittest.TestCase):
    def test_original_and_approved_service_databases_share_the_same_declarations(self):
        values = retained()
        settings = values['fixture_application']['spec']['source']['helm']['valuesObject']
        settings['serviceRequests'] = [{'service': 'fixture', 'database': {
            'name': 'fixture', 'applicationRole': 'fixture_app', 'migrationRole': 'fixture_migration'}}]
        result, output = run_native(values, 'native-sql.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(set(output), {'sql-notes', 'sql-fixture'})
        self.assertRegex(result.stdout, r'changed=0\s')
        for name in ('notes', 'fixture'):
            sql = output['sql-' + name]
            self.assertIn('REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;', sql)
            self.assertIn('REVOKE ALL ON DATABASE "' + name + '" FROM PUBLIC;', sql)
            self.assertIn('ALTER DEFAULT PRIVILEGES FOR ROLE "' + name + '_migration"', sql)
            self.assertIn('GRANT SELECT ON SEQUENCES TO "backup";', sql)

    def test_catalog_comparison_reports_actual_privilege_changes(self):
        values = retained()
        values['fixture_sql_after'] = 'repaired-catalog'
        result, output = run_native(values, 'native-sql.yml')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(set(output), {'sql-notes'})
        self.assertRegex(result.stdout, r'changed=1\s')

    def test_all_scopes_and_primary_readiness_are_checked_before_any_sql(self):
        changes = [
            lambda v: v['fixture_cluster']['spec'].update(instances=2),
            lambda v: v['fixture_cluster']['status'].update(conditions=[]),
            lambda v: v['fixture_cluster']['status'].update(currentPrimary='unrelated-pod'),
            lambda v: v['fixture_application']['spec']['source']['helm']['valuesObject'].update(maintenance=True),
        ]
        for identifier in ('postgres', 'pg_monitor', 'template1', 'notes;DROP DATABASE notes', 'UPPER', 'a'*64, 'notes\n'):
            changes.append(lambda v, identifier=identifier:
                v['fixture_application']['spec']['source']['helm']['valuesObject'].update(serviceRequests=[{
                    'database': {'name': 'fixture', 'applicationRole': identifier, 'migrationRole': 'fixture_migration'}}]))
        changes.append(lambda v: v['fixture_application']['spec']['source']['helm']['valuesObject'].update(migrationRole='backup'))
        for change in changes:
            values = copy.deepcopy(retained())
            change(values)
            with self.subTest(change=change):
                result, output = run_native(values, 'native-sql.yml')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, {}, result.stdout + result.stderr)

    def test_native_psql_is_atomic_bounded_and_uses_no_exported_credentials(self):
        tasks = yaml.safe_load((COMPONENT / 'tasks/sql-grants.yml').read_text())
        command = tasks[0]['ansible.builtin.set_fact']['data_sql_command']
        self.assertEqual(command[:4], ['/usr/local/bin/k3s', 'kubectl', 'exec', '-i'])
        self.assertIn('--single-transaction', command)
        self.assertIn('--file=-', command)
        self.assertIn('ON_ERROR_STOP=1', command)
        self.assertIn('PGOPTIONS=-c statement_timeout=40000 -c lock_timeout=30000 -c transaction_timeout=45000', command)
        self.assertNotIn('PGPASSWORD', str(tasks))
