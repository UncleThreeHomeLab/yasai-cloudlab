import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from github_setup import MARKER, provision, repository
from publish_snapshot import validate_file
import publish_snapshot


class RepositorySetupTests(unittest.TestCase):
    def test_existing_visibility_is_never_changed(self):
        api = Mock()
        api.request.return_value = {'full_name': 'example/platform', 'private': True,
                                    'description': MARKER + 'public-platform'}
        with self.assertRaisesRegex(RuntimeError, 'adoption refused'):
            provision(api, [('public-platform', 'example/platform', False)])
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_validation_of_all_targets_precedes_creation(self):
        api = Mock()
        api.request.side_effect = [None, {'full_name': 'example/config', 'private': True, 'description': 'unrelated'}]
        with self.assertRaises(RuntimeError):
            provision(api, [('public-platform', 'example/platform', False), ('private-config', 'example/config', True)])
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_repeat_keeps_existing_repositories_unchanged(self):
        api = Mock()
        api.request.return_value = {'full_name': 'example/platform', 'private': False,
                                    'description': MARKER + 'public-platform'}
        self.assertEqual(provision(api, [('public-platform', 'example/platform', False)])['repositories_created'], 0)
        api.request.assert_called_once()

    def test_repository_inputs_reject_credentials_and_external_hosts(self):
        for value in ('https://token@github.com/example/repo.git', 'https://evil.example/repo.git', '../repo'):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                repository(value)

    def test_snapshot_rejects_private_inputs_and_plans(self):
        for name in ('.env', 'docs/milestone-prompts.md', '../secret', 'key.pem', '.git/config'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                validate_file(name, b'example', {})
        with self.assertRaises(RuntimeError):
            validate_file('README.md', b'https://github.com/example/private.git',
                          {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'})
        validate_file('.env.example', b'PRIVATE_CONFIG_REPOSITORY=', {})

    def test_initial_publication_repeats_without_overwriting_canonical_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            remote = Path(directory) / 'remote.git'
            remote.mkdir()
            original = publish_snapshot.git
            original(remote, 'init', '--bare')
            def local_transport(folder, *args, **kwargs):
                args = tuple(str(remote) if x == 'https://github.com/example/platform.git' else x for x in args)
                return original(folder, *args, **kwargs)
            api = Mock(token='fixture')
            with patch.object(publish_snapshot, 'git', side_effect=local_transport), \
                    patch.object(publish_snapshot, 'configuration', return_value=[('public-platform', 'example/platform', False)]), \
                    patch.object(publish_snapshot, 'inspect', return_value={}), \
                    patch.object(publish_snapshot, 'snapshot', return_value={'fixture.txt': (b'first', 0o644)}) as snapshot:
                self.assertTrue(publish_snapshot.publish(api, {})['published'])
                first = original(remote, 'rev-parse', 'refs/heads/main').stdout
                self.assertFalse(publish_snapshot.publish(api, {})['published'])
                snapshot.return_value = {'fixture.txt': (b'different', 0o644)}
                with self.assertRaisesRegex(RuntimeError, 'canonical checkout'):
                    publish_snapshot.publish(api, {})
                self.assertEqual(first, original(remote, 'rev-parse', 'refs/heads/main').stdout)
                self.assertEqual(original(remote, 'rev-list', '--count', 'refs/heads/main').stdout.strip(), b'1')
