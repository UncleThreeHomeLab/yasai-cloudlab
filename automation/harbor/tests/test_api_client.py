import json
import subprocess
import sys
from contextlib import nullcontext, redirect_stderr
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

from automation.harbor import api, api_policy


class ClientTests(unittest.TestCase):
    def test_project_robot_adoption_uses_explicit_level_and_project_query(self):
        client = api.Client.__new__(api.Client)
        client.reader = Mock()
        projects = {'cloudlab-public': 11, 'cloudlab-private': 12}
        def read(path, **kwargs):
            for project, identifier in projects.items():
                if path == '/api/v2.0/projects/' + project:
                    return {'project_id': identifier, 'metadata': {}}
                if path.startswith('/api/v2.0/robots?q=Level%3Dproject%2CProjectID%3D' + str(identifier) + '&'):
                    return [{'id': identifier * 10 + offset, 'name': f'robot${project}+{role}'}
                            for offset, role in enumerate(('push', 'pull'))]
            if path.startswith('/api/v2.0/robots'):
                self.fail('Default robot list silently omits project robots')
            return []
        client.reader.get.side_effect = read
        result = client.live_ids()
        for project, identifier in projects.items():
            for offset, role in enumerate(('push', 'pull')):
                self.assertEqual(result['harbor_robot_account.robot[' + json.dumps(project + '-' + role) + ']'],
                                 '/robots/' + str(identifier * 10 + offset))

    def test_empty_backend_accepts_only_absent_or_empty_no_content_responses(self):
        client = api.Client.__new__(api.Client)
        client.env, client.native = {}, Mock()
        for status, raw in ((404, b''), (204, b''), (204, b'unexpected-body'), (200, b'{"resources":[]}')):
            with self.subTest(status=status, body=bool(raw)), \
                    patch.object(api, 'request', return_value=(status, raw)), \
                    patch.object(api, 'ciphertext', side_effect=RuntimeError('Encryption required')) as encrypted:
                if status == 404 or (status == 204 and not raw):
                    client.empty_state()
                    encrypted.assert_not_called()
                else:
                    with self.assertRaisesRegex(RuntimeError, 'Encryption required'): client.empty_state()
                client.native.assert_not_called()

    def test_wrong_operation_options_fail_before_credentials_or_connections(self):
        for arguments in (['apply'], ['recover-import', '--address', 'missing-id'],
                          ['inputs', '--bootstrap'], ['verify', '--review', 'unused']):
            with self.subTest(arguments=arguments), patch.object(sys, 'argv', ['harbor', *arguments]), \
                    patch.object(api, 'Client') as client, patch.object(api, 'inputs') as inputs, \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                api.main()
            client.assert_not_called()
            inputs.assert_not_called()

    def test_inventory_rejects_ambiguous_groups_and_keeps_absent_projects_absent(self):
        client = api.Client.__new__(api.Client)
        client.reader = Mock()
        rows = []
        client.reader.get.side_effect = lambda path, **kwargs: None if '/projects/' in path else rows
        self.assertEqual(client.live_ids(), dict.fromkeys(api_policy.resources()))
        rows.extend([{'id': 21, 'group_name': '/platform-admin', 'group_type': 3}] * 2)
        with self.assertRaisesRegex(ValueError, 'Duplicate Harbor'): client.live_ids()
        rows.pop()
        rows[0]['group_type'] = 1
        with self.assertRaisesRegex(ValueError, 'another identity type'): client.live_ids()
        rows[:] = [{}] * 100
        with self.assertRaisesRegex(ValueError, 'bounded scope'): client.live_ids()

    def test_recovery_preserves_original_plan_and_refuses_recreation_of_live_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = api.Client.__new__(api.Client)
            client.path = Path(temporary)
            original = b'synthetic-original-encrypted-plan'
            (client.path / 'reviewed.tfplan').write_bytes(original)
            pending = {'plan_hash': api.checksum(original), 'bootstrap': True}
            client.pending = Mock(return_value=pending)
            client.initialize = Mock()
            address = next(iter(api_policy.resources()))
            document = {'resource_changes': [{'mode': 'managed', 'address': address, 'change': {'actions': ['create']}}]}
            client.native = Mock(return_value=Mock(returncode=0, stdout=json.dumps(document).encode()))
            client.live_ids = Mock(return_value={address: '/projects/11'})
            with patch.object(api.api_policy, 'plan', return_value=1):
                with self.assertRaisesRegex(ValueError, 'inspect and import'): client.recover_plan()
            self.assertEqual((client.path / ('interrupted-' + pending['plan_hash'] + '.tfplan')).read_bytes(), original)
            self.assertFalse((client.path / 'plan-binding.json').exists())

    def test_provider_receives_only_scoped_credentials_and_oidc_gates_all_operations(self):
        values = {'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic-reader', 'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'synthetic-writer',
                  'VM_HOST': '192.0.2.1', 'VM_USER': 'fixture', 'VM_PASSWORD': 'synthetic-ssh-password'}
        vault = {'gitlab-state-harbor': {'PROJECT_ID': '7', 'USERNAME': 'synthetic', 'TOKEN': 'synthetic-backend'},
                 'opentofu-state-harbor': {'PASSPHRASE': 'x' * 64},
                 'harbor-emergency': {'username': 'admin', 'password': 'synthetic-admin'}}
        settings = {'auth_mode': 'oidc_auth', 'oidc_endpoint': 'https://login.example.invalid/realms/platform',
            'oidc_client_id': 'harbor', 'oidc_admin_group': '/platform-admin', 'oidc_verify_cert': True,
            'self_registration': False, 'project_creation_restriction': 'adminonly',
            'oidc_user_claim': 'sub', 'oidc_groups_claim': 'groups'}
        for mode in ('oidc_auth', 'db_auth'):
            settings['auth_mode'] = mode
            reader = Mock()
            reader.get.side_effect = lambda path: ({key: {'value': value} for key, value in settings.items()}
                                                  if path.endswith('/configurations') else {'schedule': {'type': 'None'}})
            with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, values), \
                    patch.object(api, 'binding', return_value='a' * 40), patch.object(api, 'WORK', Path(temporary)), \
                    patch.object(api, 'dotenv_values', return_value=values), \
                    patch.object(api, 'fields', side_effect=lambda title, required: vault[title]), \
                    patch.object(api.credentials, 'read_robot', side_effect=lambda token, title, username: {
                        'username': username, 'password': 'p' * 48, 'secret_version': '1'}), \
                    patch.object(api, 'metadata', return_value={'harborHost': 'harbor.internal.example.invalid',
                        'loginHost': 'login.example.invalid', 'images': ['synthetic-pin']}), \
                    patch.object(api.transport, 'forward', return_value=nullcontext((10002, {
                        'HTTPS_PROXY': 'socks5://127.0.0.1:10001', 'NO_PROXY': 'gitlab.com'}))), \
                    patch.object(api.transport, 'Reader', return_value=reader):
                client = api.Client()
                client.native = Mock()
                if mode == 'db_auth':
                    with self.assertRaisesRegex(ValueError, 'OIDC prerequisites'):
                        with client.connected(): self.fail('Unverified authentication mode')
                else:
                    with client.connected():
                        self.assertFalse(any(key.startswith('OP_') or key.startswith('VM_') for key in client.env))
                        self.assertNotIn('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', os.environ)
                        self.assertEqual(len(json.loads(client.env['TF_VAR_robot_secrets'])), 4)
                        self.assertEqual(client.env['TF_HTTP_PASSWORD'], 'synthetic-backend')
                        self.assertEqual(client.env['HARBOR_PASSWORD'], 'synthetic-admin')
                        self.assertNotIn('synthetic-writer', json.dumps(client.private))
                        self.assertNotIn('synthetic-ssh-password', json.dumps(client.private))
                client.native.assert_not_called()

    def test_recorded_main_ancestor_is_recoverable_but_an_unmerged_revision_is_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*arguments):
                return subprocess.check_output(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    '-c', 'commit.gpgsign=false', *arguments], cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
            git('init', '-q', '-b', 'main')
            path = root / 'gitops/roots/public/values.yaml'
            path.parent.mkdir(parents=True)
            path.write_text('repository: https://github.com/fixture/platform.git\nrevision: main\n')
            git('add', '.')
            git('commit', '-qm', 'First public source')
            first = git('rev-parse', 'HEAD')
            (root / 'marker').write_text('published')
            git('add', '.')
            git('commit', '-qm', 'Next public source')
            published = git('rev-parse', 'HEAD')
            git('checkout', '-q', first)
            original = subprocess.run
            def run(arguments, **kwargs):
                if 'ls-remote' in arguments:
                    return subprocess.CompletedProcess(arguments, 0, published + '\trefs/heads/main\n', '')
                return original(arguments, **kwargs)
            with patch.object(api, 'ROOT', root), patch.object(api.subprocess, 'run', side_effect=run):
                self.assertEqual(api.binding(), first)
                (root / 'marker').write_text('unmerged')
                git('add', '.')
                git('commit', '-qm', 'Unmerged source')
                with self.assertRaisesRegex(ValueError, 'public-main ancestor'): api.binding()

    def test_compose_client_has_isolated_work_and_read_only_bootstrap_inputs(self):
        services = yaml.safe_load((api.ROOT / 'compose.yaml').read_text())['services']
        mounts = services['infra-harbor']['volumes']
        work = next(row['source'] for row in mounts if row['target'] == '/infra-work')
        for name in ('lab', 'infra', 'infra-github'):
            self.assertFalse(any(row['source'] == work for row in services[name]['volumes']))
        self.assertTrue(all(row['read_only'] for row in mounts if row['target'] in ('/workspace', '/state')))
        self.assertFalse(any(row['target'].startswith('/inputs') or 'docker.sock' in row['target'] for row in mounts))

    def test_pending_operation_blocks_repeat_apply_before_any_native_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = api.Client.__new__(api.Client)
            client.path, client.native = Path(temporary), Mock()
            pending = client.path / 'operation-pending.json'
            pending.write_text('{"preserve":"synthetic-original-input"}')
            with self.assertRaisesRegex(ValueError, 'Interrupted native'): client.apply('0' * 64)
            client.native.assert_not_called()
            self.assertEqual(pending.read_text(), '{"preserve":"synthetic-original-input"}')

    def test_independent_state_recovery_never_uses_harbor_or_force_unlock(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(api, 'binding', return_value='a' * 40):
            client = api.Client.__new__(api.Client)
            client.path, client.provider, client.backend = Path(temporary), 'b' * 64, 'c' * 64
            client.initialize, client.native = Mock(), Mock(return_value=Mock(returncode=0))
            record = {'revision': 'a' * 40, 'provider': client.provider, 'backend': client.backend}
            (client.path / 'operation-pending.json').write_text(json.dumps(record))
            checkpoint = client.path / 'errored.tfstate'
            checkpoint.write_text('{"encrypted_data":"synthetic-ciphertext"}')
            with patch.object(api.transport, 'forward') as connection:
                self.assertTrue(client.recover_state()['native_state_checkpoint_restored'])
                connection.assert_not_called()
            client.native.assert_called_once_with('state', 'push', '-lock-timeout=0s', str(checkpoint))
            checkpoint.write_text('{"resources":[]}')
            client.native.reset_mock()
            with self.assertRaisesRegex(ValueError, 'encrypted failure'): client.recover_state()
            client.native.assert_not_called()

    def test_foreign_recovery_import_stops_before_native_state_or_registry_writes(self):
        client = api.Client.__new__(api.Client)
        client.pending, client.native, client.local_import = Mock(return_value={'bootstrap': True}), Mock(), Mock()
        address = next(address for address, value in api_policy.resources().items() if value == ('robot_account', 'cloudlab-public-push'))
        client.live_ids = Mock(return_value={address: '/robots/71'})
        with self.assertRaisesRegex(ValueError, 'exact live identity'): client.recover_import(address, '/robots/72')
        client.native.assert_not_called()
        client.local_import.assert_not_called()
        client.pending.return_value = {'bootstrap': False}
        with self.assertRaisesRegex(ValueError, 'cannot reset robot secrets'): client.recover_import(address, '/robots/71')
        client.native.assert_not_called()

    def test_native_import_fixture_cannot_reach_the_production_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = api.Client.__new__(api.Client)
            client.path = Path(temporary)
            client.env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/root', 'TF_HTTP_ADDRESS': 'https://example.invalid',
                          'TF_HTTP_PASSWORD': 'synthetic-backend', 'TF_ENCRYPTION': 'synthetic-enforced',
                          'HARBOR_PASSWORD': 'synthetic-registry'}
            def command(directory, environment, *arguments):
                self.assertFalse(any(key.startswith('TF_HTTP_') for key in environment))
                self.assertEqual(environment['TF_ENCRYPTION'], 'synthetic-enforced')
                self.assertNotIn('backend "http"', (directory / 'versions.tf').read_text())
                return Mock(returncode=0)
            with patch.object(api, 'native', side_effect=command):
                with client.local_import() as (directory, environment):
                    self.assertTrue((directory / '.terraform.lock.hcl').is_file())
                    self.assertNotIn('TF_HTTP_PASSWORD', environment)

    def test_backend_or_source_change_blocks_checkpoint_recovery(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(api, 'binding', return_value='d' * 40):
            client = api.Client.__new__(api.Client)
            client.path, client.provider, client.backend = Path(temporary), 'b' * 64, 'c' * 64
            client.native = Mock()
            (client.path / 'operation-pending.json').write_text(json.dumps({
                'revision': 'a' * 40, 'provider': client.provider, 'backend': client.backend}))
            with self.assertRaisesRegex(ValueError, 'recorded source'): client.recover_state()
            client.native.assert_not_called()
