import json
import os
import unittest
from unittest.mock import Mock, patch

from automation.harbor import transport


class TransportTests(unittest.TestCase):
    def test_forward_keeps_vault_and_registry_credentials_out_of_ssh(self):
        process = Mock()
        process.poll.return_value = None
        values = {'VM_USER': 'fixture', 'VM_HOST': '192.0.2.1', 'VM_PASSWORD': 'synthetic-ssh-password'}
        with patch.dict(os.environ, {'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'synthetic-writer',
                                    'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic-reader', 'HARBOR_PASSWORD': 'synthetic-admin'}), \
                patch.object(transport.Path, 'is_file', return_value=True), \
                patch.object(transport, '_ports', return_value=(10001, 10002)), \
                patch.object(transport.socket, 'create_connection'), \
                patch.object(transport.subprocess, 'Popen', return_value=process) as start:
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                with transport.forward(values, 'harbor.internal.example.invalid') as (port, environment):
                    self.assertEqual(port, 10002)
                    self.assertEqual(environment, {'HTTPS_PROXY': 'socks5://127.0.0.1:10001',
                                                 'NO_PROXY': 'gitlab.com,localhost,127.0.0.1'})
                    raise RuntimeError('interrupted')
            arguments, child = start.call_args.args[0], start.call_args.kwargs['env']
            self.assertEqual(set(child) - {'PATH', 'HOME'}, {'SSHPASS'})
            self.assertEqual(child['SSHPASS'], values['VM_PASSWORD'])
            self.assertEqual(start.call_args.kwargs['stdin'], transport.subprocess.DEVNULL)
            self.assertNotIn(values['VM_PASSWORD'], ' '.join(arguments))
            self.assertIn('StrictHostKeyChecking=yes', arguments)
            self.assertIn('127.0.0.1:10001', arguments)
            self.assertIn('127.0.0.1:10002:harbor.internal.example.invalid:443', arguments)
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)

    def test_unknown_host_identity_stops_before_starting_ssh(self):
        with patch.object(transport.Path, 'is_file', return_value=False), \
                patch.object(transport.subprocess, 'Popen') as start:
            with self.assertRaisesRegex(ValueError, 'verified SSH'):
                with transport.forward({'VM_USER': 'fixture', 'VM_HOST': '192.0.2.1', 'VM_PASSWORD': 'synthetic'},
                                       'harbor.internal.example.invalid'):
                    self.fail('Unexpected connection')
            start.assert_not_called()

    def test_reader_preserves_private_sni_and_basic_auth_through_loopback(self):
        connection, context, stream = Mock(), Mock(), Mock()
        response = connection.getresponse.return_value
        response.status, response.read.return_value = 200, json.dumps({'auth_mode': 'oidc_auth'}).encode()
        reader = transport.Reader('harbor.internal.example.invalid', 10002, 'admin', 'synthetic')
        with patch.object(transport.http.client, 'HTTPSConnection', return_value=connection), \
                patch.object(transport.ssl, 'create_default_context', return_value=context), \
                patch.object(transport.socket, 'create_connection', return_value=stream) as connect:
            self.assertEqual(reader.get('/api/v2.0/configurations'), {'auth_mode': 'oidc_auth'})
            context.wrap_socket.assert_called_once_with(stream, server_hostname=reader.host)
            connect.assert_called_once_with(('127.0.0.1', 10002), timeout=15)
            self.assertEqual(connection.request.call_args.args, ('GET', '/api/v2.0/configurations'))
            self.assertTrue(connection.request.call_args.kwargs['headers']['Authorization'].startswith('Basic '))
            connection.close.assert_called_once()

    def test_reader_never_follows_redirects_or_returns_oversized_inventory(self):
        reader = transport.Reader('harbor.internal.example.invalid', 10002, 'admin', 'synthetic')
        for status, body in ((302, b''), (403, b''), (200, b'x' * (8 * 1024**2 + 1))):
            connection = Mock()
            response = connection.getresponse.return_value
            response.status, response.read.return_value = status, body
            with patch.object(transport.http.client, 'HTTPSConnection', return_value=connection), \
                    patch.object(transport.ssl, 'create_default_context'), patch.object(transport.socket, 'create_connection'):
                with self.assertRaises(RuntimeError): reader.get('/api/v2.0/projects')
                self.assertEqual(connection.request.call_count, 1)
                connection.close.assert_called_once()

    def test_only_absent_gc_schedule_accepts_an_empty_success_response(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status, response.read.return_value = 200, b''
        reader = transport.Reader('harbor.internal.example.invalid', 10002, 'admin', 'synthetic')
        with patch.object(transport.http.client, 'HTTPSConnection', return_value=connection), \
                patch.object(transport.ssl, 'create_default_context'), patch.object(transport.socket, 'create_connection'):
            self.assertIsNone(reader.get('/api/v2.0/system/gc/schedule'))
            with self.assertRaises(json.JSONDecodeError):
                reader.get('/api/v2.0/projects/cloudlab-public', missing=True)

    def test_foreign_host_or_api_path_is_rejected_before_connection(self):
        for host in ('registry.example.invalid', 'harbor.internal.example.invalid/other', 'harbor.internal.-invalid'):
            with self.assertRaises(ValueError): transport.Reader(host, 10002, 'admin', 'synthetic')
        reader = transport.Reader('harbor.internal.example.invalid', 10002, 'admin', 'synthetic')
        with patch.object(transport.socket, 'create_connection') as connect:
            for path in ('https://example.invalid/api/v2.0/projects', '/api/v2.0/../secrets', '/api/v2.0/projects\r\nHost:other'):
                with self.assertRaises(ValueError): reader.get(path)
            connect.assert_not_called()
