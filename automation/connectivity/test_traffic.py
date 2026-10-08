"""Authentication proof must not mistake login pages or redirects for backend success."""
import unittest
from unittest.mock import patch
from automation.connectivity.traffic import denied, https, success


class TrafficTests(unittest.TestCase):
    def test_access_login_html_is_not_backend_success(self):
        response = {'status': 200, 'body': b'<html>Sign in</html>'}
        self.assertFalse(success(response))
        self.assertFalse(denied(response))
        self.assertTrue(denied({'status': 403, 'body': b'Forbidden'}))
        self.assertTrue(denied({'status': 302, 'body': b''}))
        self.assertTrue(success({'status': 200, 'body': b'mesh-ok'}))

    def test_header_injection_fails_before_network_or_credentials_are_sent(self):
        with patch('socket.create_connection') as connect:
            with self.assertRaises(ValueError):
                https('example.invalid', headers={'CF-Access-Client-Secret': 'secret\r\nInjected: true'})
            connect.assert_not_called()
