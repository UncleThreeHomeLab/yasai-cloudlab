"""Check synchronized B2 inputs and credential handling without contacting storage."""

import importlib.util
import io
from pathlib import Path
import unittest
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / 'longhorn'))
spec = importlib.util.spec_from_file_location('check_backup', Path(__file__).parents[2] / 'longhorn/check_backup.py')
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.values = dict(BUCKET='example', REGION='test-region', AWS_ENDPOINTS='https://s3.example.test',
                           AWS_ACCESS_KEY_ID='example-key', AWS_SECRET_ACCESS_KEY='literal${SECRET}')

    def test_synchronized_credentials_exercise_list_write_read_delete(self):
        operations = []
        content = None

        def respond(request, **kwargs):
            nonlocal content
            operations.append(request.method)
            self.assertIn('Credential=example-key/', request.headers['Authorization'])
            if request.method == 'PUT':
                content = request.data
            return io.BytesIO(content if request.method == 'GET' and content is not None else b'')

        with patch.object(backup.urllib.request, 'urlopen', side_effect=respond), patch.object(backup, 'require_window'), patch('builtins.print') as output:
            backup.check(self.values)
            self.assertEqual(operations, ['GET', 'PUT', 'GET', 'DELETE'])
            self.assertNotIn('example-key', str(output.call_args_list))
            self.assertNotIn('literal${SECRET}', str(output.call_args_list))

    def test_missing_fields_and_http_endpoint_fail_before_network(self):
        for change in ({'AWS_SECRET_ACCESS_KEY': ''}, {'AWS_ENDPOINTS': 'http://s3.example.test'}):
            with self.subTest(change=change), patch.object(backup.urllib.request, 'urlopen') as network:
                with self.assertRaises(ValueError):
                    backup.check(dict(self.values, **change))
                network.assert_not_called()
