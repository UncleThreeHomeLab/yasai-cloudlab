import base64
import json
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import github_app


class AppAccessTests(unittest.TestCase):
    def test_signed_jwt_has_bounded_lifetime(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
        with patch.object(github_app.time, 'time', return_value=1000):
            token = github_app.app_token({'APP_ID': '123', 'INSTALLATION_ID': '456', 'PRIVATE_KEY': pem})
        header, payload, signature = token.split('.')
        def decode(value):
            return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
        self.assertEqual(json.loads(decode(payload)), {'iat': 940, 'exp': 1540, 'iss': '123'})
        key.public_key().verify(decode(signature), (header + '.' + payload).encode(),
                                padding.PKCS1v15(), hashes.SHA256())

    def test_broad_permissions_and_installations_are_denied(self):
        base = {'app_id': 123, 'repository_selection': 'selected', 'suspended_at': None,
                'permissions': {'contents': 'read', 'metadata': 'read'}}
        github_app.verify_installation(base, '123')
        for change in ({'repository_selection': 'all'}, {'suspended_at': 'fixture'},
                       {'app_id': 999}, {'permissions': {'contents': 'write', 'metadata': 'read'}}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                github_app.verify_installation(dict(base, **change), '123')

    def test_missing_repository_error_excludes_private_names(self):
        with self.assertRaises(RuntimeError) as raised:
            github_app.verify_repositories({'total_count': 0, 'repositories': []},
                                           {'PRIVATE_CONFIG_REPOSITORY': 'private-owner/private-name'})
        self.assertIn('PRIVATE_CONFIG_REPOSITORY', str(raised.exception))
        self.assertNotIn('private-owner', str(raised.exception))

    def test_failed_scope_check_still_revokes_token(self):
        app = Mock()
        app.request.side_effect = [
            {'app_id': 123, 'repository_selection': 'selected', 'suspended_at': None,
             'permissions': {'contents': 'read', 'metadata': 'read'}}, {'token': 'fixture-token'}]
        installation = Mock()
        installation.request.return_value = {'total_count': 0, 'repositories': []}
        installation.opener.open.return_value.__enter__ = Mock(return_value=Mock(status=204))
        installation.opener.open.return_value.__exit__ = Mock(return_value=False)
        with patch.object(github_app, 'GitHub', side_effect=[app, installation]), \
                patch.object(github_app, 'app_token', return_value='fixture-jwt'):
            with self.assertRaisesRegex(RuntimeError, 'lacks access'):
                github_app.verify({'APP_ID': '123', 'INSTALLATION_ID': '456'},
                    {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/config.git',
                     'PRIVATE_TEST_REPOSITORY': 'https://github.com/example/fixture.git'})
        request = installation.opener.open.call_args.args[0]
        self.assertEqual(request.method, 'DELETE')
        self.assertEqual(request.full_url, 'https://api.github.com/installation/token')
