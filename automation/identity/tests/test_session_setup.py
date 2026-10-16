import json
import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from automation.identity.session_setup import prepare, wait_private_source


class SessionSetupTests(unittest.TestCase):
    def test_membership_merge_refuses_extra_files_changed_head_and_advanced_main(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory, 'fixture.json')
            request = {'nonce': 'a' * 32, 'realm': 'platform'}
            checkpoint.write_text(json.dumps(request))
            current = json.dumps({'data': {'desired_state': '{}', 'revocations': '{}'}}).encode()
            prepared = {'identity/configmap.yaml': 'expected declaration\n'}
            for mutation in (None, 'file', 'head', 'main'):
                calls, writes = [], []
                def provider(method, path, document=None):
                    calls.append(path)
                    if method == 'PUT':
                        writes.append(path)
                        return {'merged': True, 'sha': 'c' * 40}
                    if path.endswith('/git/ref/heads/main'):
                        count = sum(p.endswith('/git/ref/heads/main') for p in calls)
                        return {'object': {'sha': ('d' if mutation == 'main' and count > 1 else 'b') * 40}}
                    if '/contents/' in path:
                        body = current if path.endswith('b' * 40) else (
                            b'changed declaration' if mutation == 'head' else prepared['identity/configmap.yaml'].encode())
                        return {'content': base64.b64encode(body).decode()}
                    if path.endswith('/files'):
                        return [{'filename': 'foreign' if mutation == 'file' else 'identity/configmap.yaml', 'status': 'modified'}]
                    return {'number': 1, 'base': {'sha': 'b' * 40}, 'head': {'sha': 'c' * 40}}
                api = Mock()
                api.request.side_effect = provider
                with patch('automation.identity.session_setup.inputs', return_value=(
                        {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/fixture/private.git'}, api, {}, {})), \
                        patch('automation.identity.session_setup.environment'), \
                        patch('automation.identity.session_setup.provision'), \
                        patch('automation.identity.session_setup.local'), \
                        patch('automation.identity.session_setup.membership', return_value={}), \
                        patch('automation.identity.session_setup.fields', return_value={'client_secrets': '{}'}), \
                        patch('automation.identity.session_setup.private_files', return_value=prepared), \
                        patch('automation.identity.session_setup.publish', return_value={
                            'private_source_changed': True, 'private_pull_request': 1}), \
                        patch('automation.identity.session_setup.wait_private_source'):
                    if mutation:
                        with self.assertRaisesRegex(RuntimeError, 'review changed'): prepare(checkpoint, 'platform')
                        self.assertEqual(writes, [])
                    else:
                        self.assertTrue(prepare(checkpoint, 'platform')['disposable_viewer_ready'])
                        self.assertEqual(len(writes), 1)

    def test_unknown_realm_or_checkpoint_scope_cannot_provision_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory, 'fixture.json')
            checkpoint.write_text(json.dumps({'nonce': 'a' * 32, 'realm': 'applications'}))
            with patch('automation.identity.session_setup.inputs', return_value=({}, Mock(), {}, {})), \
                    patch('automation.identity.session_setup.environment'), \
                    patch('automation.identity.session_setup.provision') as provision:
                for realm in ('master', 'platform'):
                    with self.subTest(realm=realm), self.assertRaises(ValueError): prepare(checkpoint, realm)
                provision.assert_not_called()

    def test_prepare_resumes_native_enrollment_and_keeps_failed_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory, 'fixture.json')
            request = {'nonce': 'a' * 32, 'realm': 'applications'}
            checkpoint.write_text(json.dumps(request))
            api = Mock()
            api.request.return_value = {'object': {'sha': 'b' * 40}}
            with (patch('automation.identity.session_setup.inputs', return_value=(
                      {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/fixture/private.git'}, api, {}, {})),
                  patch('automation.identity.session_setup.environment'),
                  patch('automation.identity.session_setup.provision'),
                  patch('automation.identity.session_setup.wait_private_source') as wait_source,
                  patch('automation.identity.session_setup.publish') as publish,
                  patch('automation.identity.session_setup.local') as local):
                local.side_effect = [RuntimeError('stage refused'), RuntimeError('resume refused')]
                with self.assertRaises(RuntimeError): prepare(checkpoint, 'applications')
                self.assertTrue(checkpoint.exists())
                publish.assert_not_called()
                local.reset_mock()
                local.side_effect = [RuntimeError('stage refused'), {'existing_credentials_preserved': True}]
                self.assertTrue(prepare(checkpoint, 'applications')['disposable_viewer_ready'])
                self.assertEqual(local.call_args_list[0].kwargs, {'stage': True})
                self.assertEqual(local.call_args_list[1].args, (request,))
                wait_source.assert_called_with('b' * 40)
                publish.assert_not_called()
                local.reset_mock()
                local.side_effect = [RuntimeError('stage refused')]
                wait_source.side_effect = RuntimeError('private source unavailable')
                with self.assertRaises(RuntimeError): prepare(checkpoint, 'applications')
                self.assertEqual(local.call_count, 1)
                self.assertTrue(checkpoint.exists())

    def test_private_source_wait_rejects_mutable_or_malformed_revisions_before_ssh(self):
        with patch('automation.connectivity.preflight.ssh') as ssh:
            for revision in (None, 'main', 'x' * 40, 'a' * 40 + '\n'):
                with self.assertRaises(ValueError): wait_private_source(revision)
            ssh.assert_not_called()
