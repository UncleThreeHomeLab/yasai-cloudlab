import copy
import io
import unittest
from unittest.mock import patch

from fixtures import approval, catalog
from playbooks.previews.files import command
from playbooks.argocd.files import repository_tokens, private_publish


class CommandTests(unittest.TestCase):
    def request(self):
        return {'repository': 'example/platform', 'pullRequest': 7, 'image': approval()['image'],
                'platformRevision': 'c' * 40, 'private': True, 'lifetimeSeconds': 600}

    def test_private_prepare_revokes_temporary_token_after_source_failure(self):
        lease = {'token': 'ghs_synthetic', 'repository': 'example/platform', 'repositoryId': 123,
            'permissions': {'contents': 'read', 'pull_requests': 'read', 'metadata': 'read'}, 'expiresAt': 4500}
        with patch.object(command, 'dotenv_values', return_value={'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/platform.git'}), \
                patch.object(repository_tokens, 'issue', return_value=lease) as issue, patch.object(repository_tokens, 'revoke') as revoke, \
                patch.object(command, 'prepare_source', side_effect=RuntimeError('unavailable')), self.assertRaises(RuntimeError):
            command.prepare(self.request())
        issue.assert_called_once_with({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/platform.git'},
                                     'private-config', {'contents': 'read', 'pull_requests': 'read'})
        revoke.assert_called_once_with(lease)

    def test_private_scope_and_lifetime_fail_before_token_creation(self):
        for change in ({'repository': 'foreign/repo'}, {'lifetimeSeconds': 3001}, {'pullRequest': '../contents'}):
            with patch.object(command, 'dotenv_values', return_value={'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/platform.git'}), \
                    patch.object(repository_tokens, 'issue') as issue, self.assertRaises(ValueError):
                command.prepare(self.request() | change)
            issue.assert_not_called()

    def test_catalog_publication_uses_scoped_app_without_operator_token_and_always_revokes(self):
        for failure in (False, True):
            lease = {'token': 'ghs_synthetic_write'}
            with patch.object(command, 'read', return_value={'catalog': catalog()}), \
                    patch.object(command, 'dotenv_values', return_value={}), \
                    patch.object(repository_tokens, 'issue', return_value=lease) as issue, \
                    patch.object(repository_tokens, 'revoke') as revoke, \
                    patch.object(private_publish, 'publish', side_effect=RuntimeError('failed') if failure else None,
                                 return_value={'private_source_changed': True}) as publish, patch('sys.stdout', new_callable=io.StringIO) as output:
                if failure:
                    with self.assertRaises(RuntimeError): command.main(['catalog-propose', 'docs/local/catalog.json'])
                else:
                    command.main(['catalog-propose', 'docs/local/catalog.json'])
                    self.assertNotIn(lease['token'], output.getvalue())
            issue.assert_called_once_with({}, 'private-config', {'contents': 'write', 'pull_requests': 'write'})
            self.assertEqual(publish.call_args.kwargs['scope'], 'previews')
            revoke.assert_called_once_with(lease)
