"""Migration SQL runs under its approved identity without credential arguments."""
from contextlib import nullcontext
import hashlib
import unittest
from unittest.mock import patch
from playbooks.data.files import schema


class SchemaTests(unittest.TestCase):
    def request(self, sql='CREATE TABLE IF NOT EXISTS example (id integer PRIMARY KEY);'):
        return {'service': 'example', 'sql': sql, 'sha256': hashlib.sha256(sql.encode()).hexdigest()}

    def test_scope_credentials_and_sql_transaction(self):
        approved = {'serviceRequests': [{'service': 'example', 'database': {
            'name': 'example', 'applicationRole': 'example_app', 'migrationRole': 'example_migration'}}]}
        with patch.object(schema.control, 'locked', return_value=nullcontext()), \
                patch.object(schema.control, 'settings', return_value=approved), \
                patch.object(schema.control, 'secret', return_value={'username': 'example_migration', 'password': 'synthetic'}) as secret, \
                patch.object(schema.control, 'postgres') as postgres:
            self.assertTrue(schema.apply(self.request())['applied'])
            secret.assert_called_once_with('example-migration')
            arguments = postgres.call_args.args[0]
            self.assertNotIn('synthetic', str(arguments))
            self.assertIn('--single-transaction', arguments[2])
            self.assertIn('PGSSLMODE=verify-full', arguments[2])
            self.assertEqual(arguments[-2:], ['example_migration', 'example'])
            self.assertEqual(postgres.call_args.kwargs['input'], ('synthetic\n' + self.request()['sql']).encode())
            secret.return_value = {'username': 'other_migration', 'password': 'synthetic'}
            with self.assertRaises(ValueError): schema.apply(self.request())
            self.assertEqual(postgres.call_count, 1)
            approved['serviceRequests'] = []
            with self.assertRaises(ValueError): schema.apply(self.request())
            self.assertEqual(postgres.call_count, 1)

    def test_invalid_hash_scope_or_psql_metacommand_stops_before_data_access(self):
        for change in ({'sha256': '0' * 64}, {'service': '../other'}, {'sql': '\\! id'}, {'sql': ''}):
            request = {**self.request(), **change}
            with self.subTest(change=change), patch.object(schema.control, 'locked') as locked:
                with self.assertRaises(ValueError): schema.apply(request)
                locked.assert_not_called()
