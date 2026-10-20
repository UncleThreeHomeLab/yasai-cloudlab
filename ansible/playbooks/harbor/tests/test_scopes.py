import copy
import unittest
from unittest.mock import Mock, patch

from playbooks.harbor.files import scopes


class ScopeTests(unittest.TestCase):
    def test_release_apps_are_separate_scoped_gitops_writers_without_actions_or_administration_grants(self):
        for title in ('github-release-public', 'github-release-private'):
            _, permissions = scopes.APPS[title]
            self.assertEqual(permissions, {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read'})
        excessive = {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read', 'actions': 'write'}
        _, app, installation, _ = self.fixture()
        app['permissions'] = installation['permissions'] = excessive
        api = Mock()
        api.request.side_effect = [app, installation]
        with patch.object(scopes, 'app_token', return_value='synthetic-jwt'), \
                patch.object(scopes, 'GitHub', return_value=api), self.assertRaises(RuntimeError):
            scopes.verify_app({'APP_ID': '7', 'INSTALLATION_ID': '9'}, {'fixture/private': True},
                              {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read'})
        self.assertEqual(api.request.call_count, 2)

    def fixture(self):
        permissions = {'administration': 'write', 'metadata': 'read'}
        return permissions, {'id': 7, 'permissions': permissions}, {
            'app_id': 7, 'permissions': permissions, 'repository_selection': 'selected',
            'account': {'login': 'fixture'}, 'target_type': 'Organization'}, {
            'total_count': 1, 'repositories': [{'full_name': 'fixture/private', 'private': True}]}

    def execute(self, app, installation, document, permissions):
        api, client = Mock(), Mock()
        api.request.side_effect = [app, installation, {'token': 'synthetic-token'}]
        client.request.return_value = document
        with patch.object(scopes, 'app_token', return_value='synthetic-jwt'), \
                patch.object(scopes, 'GitHub', side_effect=[api, client]):
            result = scopes.verify_app({'APP_ID': '7', 'INSTALLATION_ID': '9'},
                                      {'fixture/private': True}, permissions)
        return result, api, client

    def test_exact_repository_scope_uses_metadata_token_and_revokes_it(self):
        permissions, app, installation, document = self.fixture()
        result, api, client = self.execute(app, installation, document, permissions)
        self.assertTrue(result['permissions_verified'])
        self.assertFalse(result['write_capable_token_created'])
        self.assertEqual(api.request.call_args_list[-1].args,
                         ('POST', 'app/installations/9/access_tokens', {'permissions': {'metadata': 'read'}}))
        client.request.assert_called_with('DELETE', 'installation/token')

    def test_extra_organization_grants_or_pending_old_installation_grants_fail_before_token(self):
        permissions, app, installation, document = self.fixture()
        for target in ('app', 'installation'):
            changed = copy.deepcopy(app if target == 'app' else installation)
            changed['permissions']['organization_administration'] = 'write'
            api = Mock()
            api.request.side_effect = [changed if target == 'app' else app,
                                       changed if target == 'installation' else installation]
            with patch.object(scopes, 'app_token', return_value='synthetic-jwt'), \
                    patch.object(scopes, 'GitHub', return_value=api):
                with self.assertRaises(RuntimeError):
                    scopes.verify_app({'APP_ID': '7', 'INSTALLATION_ID': '9'},
                                      {'fixture/private': True}, permissions)
            self.assertEqual(api.request.call_count, 2)

    def test_wrong_repository_visibility_or_extra_selection_always_revokes_token(self):
        for private, count in ((False, 1), (True, 2)):
            permissions, app, installation, document = self.fixture()
            document['repositories'][0]['private'] = private
            document['total_count'] = count
            api, client = Mock(), Mock()
            api.request.side_effect = [app, installation, {'token': 'synthetic-token'}]
            client.request.return_value = document
            with patch.object(scopes, 'app_token', return_value='synthetic-jwt'), \
                    patch.object(scopes, 'GitHub', side_effect=[api, client]):
                with self.assertRaises(RuntimeError):
                    scopes.verify_app({'APP_ID': '7', 'INSTALLATION_ID': '9'},
                                      {'fixture/private': True}, permissions)
            client.request.assert_called_with('DELETE', 'installation/token')
