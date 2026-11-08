import unittest
import urllib.error
from unittest.mock import Mock, patch

from github_setup import GitHub, GitHubHTTPError, MARKER, inspect, repository
import github_setup


class RepositorySetupTests(unittest.TestCase):
    def test_http_rejection_keeps_status_and_runtime_error_compatibility(self):
        api = GitHub('synthetic-token')
        for status in (403, 409, 422):
            with self.subTest(status=status), patch.object(api.opener, 'open', side_effect=urllib.error.HTTPError(
                    'https://api.github.com/fixture', status, 'synthetic', {}, None)):
                with self.assertRaises(GitHubHTTPError) as caught:
                    api.request('POST', 'repos/example/private/pulls', {})
                self.assertIsInstance(caught.exception, RuntimeError)
                self.assertEqual(caught.exception.status, status)
                self.assertEqual(str(caught.exception), 'GitHub repository operation failed: HTTP ' + str(status))
        with patch.object(api.opener, 'open', side_effect=urllib.error.HTTPError(
                'https://api.github.com/fixture', 404, 'synthetic', {}, None)):
            self.assertIsNone(api.request('GET', 'fixture', missing=True))

    def test_successful_delete_accepts_empty_response_without_json_read(self):
        api = GitHub('synthetic-token')
        response = Mock(status=204)
        with patch.object(api.opener, 'open') as request:
            request.return_value.__enter__.return_value = response
            self.assertIsNone(api.request('DELETE', 'installation/token'))
        response.read.assert_not_called()

    def test_retired_creator_never_recreates_missing_repositories(self):
        api = Mock()
        api.request.return_value = None
        self.assertFalse(hasattr(github_setup, 'provision'))
        self.assertIsNone(inspect(api, 'public-platform', 'example/platform', False))
        api.request.assert_called_once_with('GET', 'repos/example/platform', missing=True)

    def test_existing_visibility_is_never_changed(self):
        api = Mock()
        api.request.return_value = {'full_name': 'example/platform', 'private': True,
                                    'description': MARKER + 'public-platform'}
        with self.assertRaisesRegex(RuntimeError, 'adoption refused'):
            inspect(api, 'public-platform', 'example/platform', False)
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_retained_content_owner_rejects_unrelated_repository(self):
        api = Mock()
        api.request.return_value = {'full_name': 'example/config', 'private': True, 'description': 'unrelated'}
        with self.assertRaises(RuntimeError):
            inspect(api, 'private-config', 'example/config', True)
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_repeat_keeps_existing_repositories_unchanged(self):
        api = Mock()
        api.request.return_value = {'full_name': 'example/platform', 'private': False,
                                    'description': MARKER + 'public-platform'}
        self.assertEqual(inspect(api, 'public-platform', 'example/platform', False)['full_name'], 'example/platform')
        api.request.assert_called_once()

    def test_repository_inputs_reject_credentials_and_external_hosts(self):
        for value in ('https://token@github.com/example/repo.git', 'https://evil.example/repo.git', '../repo'):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                repository(value)

    def test_retired_snapshot_publisher_has_no_runtime_module(self):
        self.assertFalse(hasattr(github_setup, 'publish_snapshot'))
        with self.assertRaises(ImportError):
            __import__('publish_snapshot')
