import base64
import copy
import json
import unittest
from unittest.mock import Mock, patch

from fixtures import approval, catalog
from playbooks.argocd.files import repository_tokens
from playbooks.previews.files import credentials, credentials_remote
from playbooks.previews.files.contract import canonical, digest, PRIVATE_MAX_LIFETIME, catalog as validate_catalog
from playbooks.previews.files.github import GitHub


def lease(expires=4500):
    return {'token': 'ghs_synthetic_discovery_token', 'repository': 'example/platform', 'repositoryId': 123,
            'permissions': {'contents': 'read', 'pull_requests': 'read', 'metadata': 'read'}, 'expiresAt': expires}


def secret(value=None):
    value = value or lease()
    return {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
        'metadata': {'name': 'github-preview-discovery', 'namespace': 'argocd', 'uid': 'secret-uid', 'resourceVersion': '12',
            'labels': {'cloudlab.io/owner': 'cloudlab-preview-discovery', 'argocd.argoproj.io/secret-type': 'scm-creds'}},
        'data': {'TOKEN': base64.b64encode(value['token'].encode()).decode(),
            'lease.json': base64.b64encode(json.dumps({key: item for key, item in value.items() if key != 'token'}).encode()).decode()}}


class CredentialTests(unittest.TestCase):
    def test_token_request_is_exact_and_validation_failure_revokes(self):
        issuer, reader = Mock(), Mock()
        issued = {'token': lease()['token'], 'expires_at': '1970-01-01T01:15:00Z', 'permissions': lease()['permissions']}
        issuer.request.return_value = issued
        reader.request.return_value = {'total_count': 1, 'repositories': [{'full_name': 'example/platform', 'private': True, 'id': 123}]}
        with patch.object(repository_tokens, 'configuration', return_value=[('private-config', 'example/platform', True)]), \
                patch.object(repository_tokens, 'fields', return_value={'APP_ID': '1', 'INSTALLATION_ID': '2', 'PRIVATE_KEY': 'local-only'}), \
                patch.object(repository_tokens, 'verify_app') as verify, patch.object(repository_tokens, 'app_token', return_value='jwt'), \
                patch.object(repository_tokens, 'GitHub', side_effect=[issuer, reader]), patch.object(repository_tokens.time, 'time', return_value=1000):
            result = repository_tokens.issue({}, 'private-config', {'contents': 'read', 'pull_requests': 'read'})
        self.assertEqual(result, lease())
        self.assertEqual(issuer.request.call_args.args[2], {'repositories': ['platform'], 'permissions': {'contents': 'read', 'pull_requests': 'read'}})
        self.assertEqual(verify.call_args.args[1], {'example/platform': True})
        for changed in ({'contents': 'write', 'pull_requests': 'read', 'metadata': 'read'}, {'metadata': 'read'}):
            issuer.request.return_value = dict(issued, permissions=changed)
            revoked = Mock()
            with patch.object(repository_tokens, 'configuration', return_value=[('private-config', 'example/platform', True)]), \
                    patch.object(repository_tokens, 'fields', return_value={'APP_ID': '1', 'INSTALLATION_ID': '2', 'PRIVATE_KEY': 'local-only'}), \
                    patch.object(repository_tokens, 'verify_app'), patch.object(repository_tokens, 'app_token', return_value='jwt'), \
                    patch.object(repository_tokens, 'GitHub', side_effect=[issuer, reader]), \
                    patch.object(repository_tokens, 'revoke', revoked), patch.object(repository_tokens.time, 'time', return_value=1000), self.assertRaises(RuntimeError):
                repository_tokens.issue({}, 'private-config', {'contents': 'read', 'pull_requests': 'read'})
            revoked.assert_called_once_with({'token': lease()['token']})

    def test_repeat_apply_reuses_same_owned_secret_and_failure_revokes_new_token(self):
        settings = catalog()
        settings['privateDiscovery'] = True
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/platform.git'}
        existing = secret()
        with patch.object(credentials, 'remote', return_value=existing) as remote, patch.object(credentials, 'issue') as issue:
            self.assertEqual(credentials.ensure(settings, values, now=1500)['changed'], False)
            issue.assert_not_called()
            remote.assert_called_once_with({'action': 'inspect'})
        with patch.object(credentials, 'remote', side_effect=[None, RuntimeError('delivery interrupted')]), \
                patch.object(credentials, 'issue', return_value=lease()), patch.object(credentials, 'revoke') as revoke, self.assertRaises(RuntimeError):
            credentials.ensure(settings, values, now=1500)
        revoke.assert_called_once_with(lease())

    def test_foreign_owner_or_replacement_uid_is_never_overwritten(self):
        foreign = secret()
        foreign['metadata']['labels']['cloudlab.io/owner'] = 'persistent-owner'
        with patch.object(credentials_remote, 'get', return_value=foreign), self.assertRaises(ValueError):
            credentials_remote.dispatch({'action': 'inspect'})
        with patch.object(credentials_remote, 'get', return_value=secret()), patch.object(credentials_remote, 'kube') as kube, self.assertRaises(ValueError):
            credentials_remote.dispatch({'action': 'deliver', 'expected': {'uid': 'replaced', 'resourceVersion': '12'}, 'lease': lease()})
        kube.assert_not_called()

    def test_delivery_has_only_ephemeral_token_metadata_and_no_app_key(self):
        with patch.object(credentials_remote, 'get', return_value=None), patch.object(credentials_remote, 'kube') as kube:
            result = credentials_remote.dispatch({'action': 'deliver', 'expected': None, 'lease': lease()})
        delivered = kube.call_args.kwargs['document']
        self.assertEqual(set(delivered['data']), {'TOKEN', 'lease.json'})
        self.assertEqual(result, {'changed': True})
        self.assertNotIn(lease()['token'], json.dumps(result))
        self.assertNotIn('PRIVATE_KEY', json.dumps(delivered))

    def test_missing_expired_or_mismatched_leases_never_authorize_activation(self):
        row = approval()
        for value in (None, {}, dict(lease(), expiresAt=1999), dict(lease(), repository='example/other'),
                      dict(lease(), permissions={'contents': 'write'}), dict(lease(), repositoryId=456)):
            token = value.get('token', '') if value else ''
            client = GitHub(token, private=True, lease={key: item for key, item in value.items() if key != 'token'} if value else None)
            self.assertFalse(client.allows(row, 1500))
        self.assertTrue(GitHub(lease()['token'], private=True,
            lease={key: item for key, item in lease().items() if key != 'token'}).allows(row, 1500))

    def test_private_lifetime_is_bounded_but_public_one_day_remains_supported(self):
        row = approval()
        row['expiresAt'] = row['createdAt'] + 86400
        settings = catalog([row])
        validate_catalog(settings)
        settings['privateDiscovery'] = True
        with self.assertRaises(ValueError): validate_catalog(settings)
        row['expiresAt'] = row['createdAt'] + PRIVATE_MAX_LIFETIME
        settings = catalog([row])
        settings['privateDiscovery'] = True
        validate_catalog(settings)
