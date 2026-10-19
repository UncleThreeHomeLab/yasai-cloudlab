"""Exercise the runner's read-only health gate without credentials or services."""
import copy
import importlib.util
import io
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[4]
specification = importlib.util.spec_from_file_location('ci_health', ROOT / 'platform/delivery/ci/runner/health.py')
health = importlib.util.module_from_spec(specification)
specification.loader.exec_module(health)


def nodes():
    conditions = [{'type': name, 'status': 'True' if name == 'Ready' else 'False'}
                  for name in ('Ready', 'MemoryPressure', 'DiskPressure', 'PIDPressure')]
    return {'items': [{'metadata': {'name': 'node-' + str(index)},
                       'status': {'conditions': copy.deepcopy(conditions)}} for index in range(2)]}


class Response(io.BytesIO):
    status = 200


class HealthTests(unittest.TestCase):
    def test_redirect_cannot_forward_health_credentials_to_another_endpoint(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(302 if self.path == '/' else 200)
                self.send_header('Location', '/destination')
                self.end_headers()

            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            opener = health.urllib.request.build_opener(health.urllib.request.ProxyHandler({}), health.NoRedirect())
            request = health.urllib.request.Request('http://127.0.0.1:' + str(server.server_port) + '/',
                                                   headers={'Authorization': 'Bearer synthetic'})
            with self.assertRaises(urllib.error.HTTPError) as failure:
                opener.open(request, timeout=2)
            self.assertEqual(failure.exception.code, 302)
            self.assertEqual(requests, ['/'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_requires_two_ready_nodes_and_all_pressure_signals(self):
        self.assertTrue(health.nodes_ready(nodes()))
        for name in ('Ready', 'MemoryPressure', 'DiskPressure', 'PIDPressure'):
            for status in ('True', 'False', 'Unknown', None):
                if status == ('True' if name == 'Ready' else 'False'):
                    continue
                document = nodes()
                next(row for row in document['items'][1]['status']['conditions'] if row['type'] == name)['status'] = status
                self.assertFalse(health.nodes_ready(document))
        document = nodes()
        document['items'][1]['status']['conditions'].append({'type': 'NetworkUnavailable', 'status': 'True'})
        self.assertFalse(health.nodes_ready(document))

    def test_missing_duplicate_or_paginated_node_data_fails_closed(self):
        for document in (None, {}, {'metadata': None}, {'items': []}, {'items': [None, None]},
                         {'items': [{'status': None}, {'status': None}]},
                         {'items': nodes()['items'][:1]}, {'items': nodes()['items'] * 2},
                         dict(nodes(), metadata={'continue': 'next-page'})):
            self.assertFalse(health.nodes_ready(document))
        document = nodes()
        document['items'][0]['status']['conditions'].append({'type': 'Ready', 'status': 'True'})
        self.assertFalse(health.nodes_ready(document))
        document = nodes()
        document['items'][0]['status']['conditions'].pop()
        self.assertFalse(health.nodes_ready(document))
        document = nodes()
        document['items'][1]['metadata']['name'] = document['items'][0]['metadata']['name']
        self.assertFalse(health.nodes_ready(document))
        document = nodes()
        document['items'][0]['metadata']['deletionTimestamp'] = '2000-01-01T00:00:00Z'
        self.assertFalse(health.nodes_ready(document))

    def test_queries_only_fixed_read_only_endpoints_with_pinned_ca_and_no_proxy(self):
        opener = Mock()
        opener.open.side_effect = [Response(b'ok'), Response(json.dumps(nodes()).encode())]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'token').write_text('header.payload.signature')
            with patch.object(health.ssl, 'create_default_context') as context, \
                    patch.object(health.urllib.request, 'build_opener', return_value=opener) as factory:
                self.assertTrue(health.check(directory))
                context.assert_called_once_with(cafile=str(directory / 'ca.crt'))
                self.assertEqual(factory.call_args.args[0].proxies, {})
                self.assertIsInstance(factory.call_args.args[2], health.NoRedirect)
        self.assertEqual([call.args[0].full_url for call in opener.open.call_args_list],
                         [health.SERVER + '/readyz', health.SERVER + '/api/v1/nodes?limit=3'])
        for call in opener.open.call_args_list:
            self.assertEqual(call.args[0].get_method(), 'GET')
            self.assertEqual(call.args[0].get_header('Authorization'), 'Bearer header.payload.signature')
            self.assertEqual(call.kwargs, {'timeout': 2})

    def test_malformed_credential_and_failed_readiness_stop_before_node_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'token').write_text('header.payload.signature\r\nInjected: value')
            with patch.object(health.urllib.request, 'build_opener') as factory:
                with self.assertRaises(ValueError):
                    health.check(directory)
                factory.assert_not_called()
            (directory / 'token').write_text('header.payload.signature')
            opener = Mock()
            opener.open.return_value = Response(b'not ready')
            with patch.object(health.ssl, 'create_default_context'), \
                    patch.object(health.urllib.request, 'build_opener', return_value=opener):
                self.assertFalse(health.check(directory))
                self.assertEqual(opener.open.call_count, 1)

    def test_failures_never_print_credential_or_server_diagnostics(self):
        for error in (OSError('synthetic-sensitive-value'), ValueError('synthetic-sensitive-value'),
                      RuntimeError('synthetic-sensitive-value')):
            output = io.StringIO()
            with patch.object(health, 'check', side_effect=error), patch('sys.stderr', output):
                self.assertEqual(health.main(), 1)
            self.assertEqual(output.getvalue(), 'CI node health check failed.\n')
