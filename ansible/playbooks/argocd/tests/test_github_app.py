import base64
import json
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import github_app


class AppAccessTests(unittest.TestCase):
    def public_fixture(self, *, scope=None, inventory=None, cleanup=None):
        credentials = {'APP_ID': '123', 'INSTALLATION_ID': '456', 'PRIVATE_KEY': 'synthetic'}
        issued = {'token': 'synthetic-public', 'expires_at': '2023-11-14T23:13:20Z',
            'permissions': {'contents': 'read', 'metadata': 'read'}, 'repository_selection': 'selected'}
        issued.update(scope or {})
        api, client = Mock(), Mock()
        api.request.side_effect = [{'app_id': 123, 'repository_selection': 'selected',
            'permissions': {'contents': 'read', 'metadata': 'read'}}, issued]
        entry = {'full_name': github_app.PUBLIC_READER, 'private': False, 'fork': False,
            'archived': False, 'disabled': False, 'default_branch': 'main'}
        def request(method, path):
            if method == 'DELETE':
                if cleanup: raise RuntimeError('secret-sentinel')
                return None
            if path.startswith('installation/repositories'):
                return inventory if inventory is not None else {'total_count': 1, 'repositories': [entry]}
            return {'protected': True}
        client.request.side_effect = request
        return credentials, api, client

    def test_public_session_scopes_token_bounds_paths_and_closes_before_writes(self):
        credentials, api, client = self.public_fixture()
        with patch.object(github_app, 'app_token', return_value='jwt'), \
                patch.object(github_app, 'GitHub', side_effect=lambda token, **kwargs: api if token == 'jwt' else client), \
                patch.object(github_app.time, 'time', return_value=1700000000), \
                patch.object(github_app.time, 'monotonic', return_value=100):
            with github_app.public_metadata(credentials, deadline=280) as fetch:
                self.assertTrue(fetch('repos/' + github_app.PUBLIC_READER + '/branches/main', 250)['protected'])
                for suffix in ('contents/file?ref=main', 'contents/../file?ref=' + 'a' * 40,
                        'contents/%2e%2e/file?ref=' + 'a' * 40, 'git/commits/main'):
                    with self.assertRaises(ValueError): fetch('repos/' + github_app.PUBLIC_READER + '/' + suffix, 250)
                for path in ('https://api.github.com/repos/' + github_app.PUBLIC_READER + '/branches/main',
                        '//raw.githubusercontent.com/secret', 'repos/other/repository/branches/main', 'rate_limit'):
                    with self.assertRaises(ValueError): fetch(path, 250)
            client.request.assert_called_with('DELETE', 'installation/token')
            self.assertEqual(client.token, '')
            with self.assertRaisesRegex(RuntimeError, 'closed'):
                fetch('repos/' + github_app.PUBLIC_READER + '/branches/main', 250)
        self.assertEqual(api.request.call_args.args[2], {'repositories': ['yasai-cloudlab'], 'permissions': {'contents': 'read'}})

    def test_public_session_validation_failure_always_revokes_known_token(self):
        entry = {'full_name': github_app.PUBLIC_READER, 'private': False, 'fork': False,
            'archived': False, 'disabled': False, 'default_branch': 'main'}
        invalid = [({'permissions': {'contents': 'write', 'metadata': 'read'}}, None),
            ({'expires_at': '2023-11-14T22:13:21Z'}, None), ({}, {'total_count': 2, 'repositories': []})]
        invalid += [({}, {'total_count': 1, 'repositories': [dict(entry, **changed)]}) for changed in (
            {'full_name': 'other/repository'}, {'private': True}, {'fork': True}, {'archived': True}, {'disabled': True})]
        for scope, inventory in invalid:
            credentials, api, client = self.public_fixture(scope=scope, inventory=inventory)
            with patch.object(github_app, 'app_token', return_value='jwt'), \
                    patch.object(github_app, 'GitHub', side_effect=lambda token, **kwargs: api if token == 'jwt' else client), \
                    patch.object(github_app.time, 'time', return_value=1700000000), \
                    patch.object(github_app.time, 'monotonic', return_value=100):
                with self.assertRaises(RuntimeError), github_app.public_metadata(credentials, deadline=280):
                    self.fail('Invalid public scope reached caller')
            client.request.assert_called_with('DELETE', 'installation/token')

    def test_public_timeout_preserves_reserved_revocation_budget(self):
        credentials, api, client = self.public_fixture()
        now, budgets = [100], []
        def transport(token, **kwargs):
            budgets.append(kwargs['deadline'])
            return api if token == 'jwt' else client
        with patch.object(github_app, 'app_token', return_value='jwt'), \
                patch.object(github_app, 'GitHub', side_effect=transport), \
                patch.object(github_app.time, 'time', return_value=1700000000), \
                patch.object(github_app.time, 'monotonic', side_effect=lambda: now[0]):
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                with github_app.public_metadata(credentials, deadline=280): now[0] = 251
        self.assertEqual(budgets, [250, 250, 280])
        client.request.assert_called_with('DELETE', 'installation/token')

    def test_public_revocation_failure_blocks_following_write_and_lost_issuance_is_uncertain(self):
        for lost in (False, True):
            credentials, api, client = self.public_fixture(cleanup=True)
            if lost:
                api.request.side_effect = [{'app_id': 123, 'repository_selection': 'selected',
                    'permissions': {'contents': 'read', 'metadata': 'read'}}, RuntimeError('secret-sentinel')]
            write = Mock()
            with patch.object(github_app, 'app_token', return_value='jwt'), \
                    patch.object(github_app, 'GitHub', side_effect=lambda token, **kwargs: api if token == 'jwt' else client), \
                    patch.object(github_app.time, 'time', return_value=1700000000), \
                    patch.object(github_app.time, 'monotonic', return_value=100):
                with self.assertRaisesRegex(RuntimeError, 'unconfirmed') as caught:
                    with github_app.public_metadata(credentials, deadline=280): pass
                    write()
                self.assertNotIn('sentinel', str(caught.exception))
            write.assert_not_called()
            self.assertEqual(sum(call.args[0] == 'POST' for call in api.request.call_args_list), 1)
            if lost: client.request.assert_not_called()

    def test_configuration_head_requires_private_visibility_and_immutable_commit(self):
        credentials = {'APP_ID': '123', 'INSTALLATION_ID': '456', 'PRIVATE_KEY': 'synthetic'}
        current = {'full_name': 'example/config', 'private': True, 'default_branch': 'main'}
        for metadata, revision in ((current, 'a' * 40), (dict(current, private=False), 'a' * 40),
                                   (current, 'main')):
            api, client = Mock(), Mock()
            api.request.side_effect = [
                {'app_id': 123, 'repository_selection': 'selected',
                 'permissions': {'contents': 'read', 'metadata': 'read'}}, {'token': 'synthetic'}]
            client.request.side_effect = [metadata, {'object': {'sha': revision}}, None]
            with patch('playbooks.secrets.files.vault.fields', return_value=credentials), \
                    patch.object(github_app, 'app_token', return_value='synthetic'), \
                    patch.object(github_app, 'GitHub', side_effect=[api, client]):
                if metadata['private'] and revision != 'main':
                    self.assertEqual(github_app.configuration_revision(
                        {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/config.git'}), revision)
                else:
                    with self.assertRaises(RuntimeError):
                        github_app.configuration_revision({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/config.git'})
            client.request.assert_called_with('DELETE', 'installation/token')

    def test_configuration_head_read_scopes_and_revokes_token_on_failure(self):
        credentials = {'APP_ID': '123', 'INSTALLATION_ID': '456', 'PRIVATE_KEY': 'synthetic'}
        api, client = Mock(), Mock()
        api.request.side_effect = [
            {'app_id': 123, 'repository_selection': 'selected',
             'permissions': {'contents': 'read', 'metadata': 'read'}}, {'token': 'synthetic'}]
        client.request.side_effect = [RuntimeError('unavailable'), None]
        with patch('playbooks.secrets.files.vault.fields', return_value=credentials), \
                patch.object(github_app, 'app_token', return_value='synthetic'), \
                patch.object(github_app, 'GitHub', side_effect=[api, client]), self.assertRaises(RuntimeError):
            github_app.configuration_revision({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/config.git'})
        self.assertEqual(api.request.call_args.args[2], {'repositories': ['config'], 'permissions': {'contents': 'read'}})
        client.request.assert_called_with('DELETE', 'installation/token')

    def test_configuration_reader_uses_same_authenticated_revision_and_always_revokes(self):
        credentials = {'APP_ID': '123', 'INSTALLATION_ID': '456', 'PRIVATE_KEY': 'synthetic'}
        for failed in (False, True):
            api, client = Mock(), Mock()
            api.request.side_effect = [{'app_id': 123, 'repository_selection': 'selected',
                'permissions': {'contents': 'read', 'metadata': 'read'}}, {'token': 'synthetic'}]
            client.request.side_effect = [{'full_name': 'example/config', 'private': True,
                'default_branch': 'main'}, {'object': {'sha': 'a' * 40}}, None]
            reader = Mock(side_effect=RuntimeError('invalid registry') if failed else None, return_value={'sources': []})
            with patch('playbooks.secrets.files.vault.fields', return_value=credentials), \
                    patch.object(github_app, 'app_token', return_value='synthetic'), \
                    patch.object(github_app, 'GitHub', side_effect=[api, client]):
                if failed:
                    with self.assertRaises(RuntimeError):
                        github_app.configuration_revision({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/config.git'}, read=reader)
                else:
                    self.assertEqual(github_app.configuration_revision(
                        {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/config.git'}, read=reader), {'sources': []})
            reader.assert_called_once_with(client, 'a' * 40)
            client.request.assert_called_with('DELETE', 'installation/token')

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

    def test_pem_storage_forms_sign_the_same_jwt_without_changing_credentials(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for kind in (serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL):
            pem = key.private_bytes(serialization.Encoding.PEM, kind, serialization.NoEncryption()).decode()
            credentials = {'APP_ID': '123', 'INSTALLATION_ID': '456', 'PRIVATE_KEY': pem}
            with patch.object(github_app.time, 'time', return_value=1000):
                expected = github_app.app_token(credentials)
                for stored in (pem.replace('\n', '\\n'), pem.replace('\n', ' '), pem.replace('\n', '\r\n')):
                    variant = dict(credentials, PRIVATE_KEY=stored)
                    self.assertEqual(github_app.app_token(variant), expected)
                    self.assertEqual(variant['PRIVATE_KEY'], stored)
        with self.assertRaises(RuntimeError):
            github_app.app_token(dict(credentials, PRIVATE_KEY=pem.replace('END RSA PRIVATE KEY', 'END PRIVATE KEY')))

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
                    {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/config.git'})
        request = installation.opener.open.call_args.args[0]
        self.assertEqual(request.method, 'DELETE')
        self.assertEqual(request.full_url, 'https://api.github.com/installation/token')
