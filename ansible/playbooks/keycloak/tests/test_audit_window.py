import json
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from playbooks.keycloak.files.health import audit_window


class AuditWindowTests(unittest.TestCase):
    def test_pagination_filters_the_closed_window_and_exports_only_redacted_fields(self):
        event = {'time': 1500, 'operationType': 'UPDATE', 'resourceType': 'CLIENT',
                 'representation': 'synthetic-sensitive-content', 'authDetails': {'token': 'synthetic-token'}}
        with patch('playbooks.keycloak.files.health.json_get', side_effect=[[event] * 100, [event]]) as request:
            rows, incomplete = audit_window('https://example.invalid/admin/realms/platform',
                                            'admin-events', 'fixture-token', 1000, 1999, admin=True)
        self.assertFalse(incomplete)
        self.assertEqual(len(rows), 101)
        self.assertEqual(rows[0], {'time': 1500, 'operationType': 'UPDATE', 'resourceType': 'CLIENT'})
        self.assertNotIn('sensitive', json.dumps(rows))
        for offset, call in zip((0, 100), request.call_args_list):
            query = parse_qs(urlsplit(call.args[0]).query)
            self.assertEqual(query, {'dateFrom': ['1000'], 'dateTo': ['1999'], 'direction': ['asc'],
                                     'first': [str(offset)], 'max': ['100']})

    def test_exhausting_the_event_cap_remains_explicitly_incomplete(self):
        page = [{'time': 1500, 'type': 'LOGIN_ERROR', 'details': {'password': 'synthetic-private'}}] * 100
        with patch('playbooks.keycloak.files.health.json_get', return_value=page) as request:
            rows, incomplete = audit_window('https://example.invalid', 'events', 'fixture', 1000, 1999)
        self.assertTrue(incomplete)
        self.assertEqual(len(rows), 1000)
        self.assertEqual(request.call_count, 10)
        self.assertNotIn('password', json.dumps(rows))

    def test_malformed_oversized_or_out_of_window_pages_fail_closed(self):
        for page in ({'events': []}, [{}], [{'time': 999}], [{'time': 2000}], [{'time': '1500'}],
                     [{'time': 1500}] * 101):
            with self.subTest(page_type=type(page).__name__), patch('playbooks.keycloak.files.health.json_get', return_value=page):
                with self.assertRaises(ValueError): audit_window('https://example.invalid', 'events', 'fixture', 1000, 1999)
