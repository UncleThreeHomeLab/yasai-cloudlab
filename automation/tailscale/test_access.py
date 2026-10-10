"""Reject workstation fallback and distinguish transport faults from denial."""
import io
import unittest
from unittest.mock import MagicMock, patch

from verify_access import ssh, tailnet_connect


class AccessTests(unittest.TestCase):
    def test_inspection_ssh_uses_default_port_without_exposing_password(self):
        for configured, expected in ((None, '22'), ('', '22'), ('2222', '2222')):
            environment = {'VM_USER': 'fixture', 'VM_PASSWORD': 'fixture-secret'}
            if configured is not None:
                environment['VM_PORT'] = configured
            with self.subTest(port=configured), patch.dict('verify_access.os.environ', environment, clear=True), \
                    patch('verify_access.subprocess.run') as process:
                process.return_value.returncode = 0
                process.return_value.stdout = 'inspected'
                self.assertEqual(ssh('VM', 'example.invalid', 'hostname'), 'inspected')
                command = process.call_args.args[0]
                self.assertEqual(command[command.index('-p') + 1], expected)
                self.assertNotIn('fixture-secret', command)
                self.assertEqual(process.call_args.kwargs['env']['SSHPASS'], 'fixture-secret')

    def dial(self, response, peers=()):
        stream = MagicMock()
        stream.makefile.return_value = io.BytesIO(response)
        with patch('verify_access.socket.socket') as factory:
            factory.return_value.__enter__.return_value = stream
            return tailnet_connect('/private/test.sock', '100.64.0.1', 22, peers)

    def test_hidden_peer_refuses_system_fallback(self):
        self.assertFalse(self.dial(b'HTTP/1.1 200 OK\r\nDial-Self: true\r\nContent-Length: 0\r\n\r\n'))

    def test_connected_peer_is_not_denied(self):
        self.assertTrue(self.dial(b'HTTP/1.1 101 Switching Protocols\r\n\r\n'))

    def test_known_peer_fallback_is_not_policy_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'system routing'):
            self.dial(b'HTTP/1.1 200 OK\r\nDial-Self: true\r\n\r\n', {'100.64.0.1'})

    def test_daemon_error_is_not_denial(self):
        with self.assertRaisesRegex(RuntimeError, 'not proven'):
            self.dial(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')


if __name__ == '__main__':
    unittest.main()
