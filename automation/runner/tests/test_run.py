"""Check input isolation and proof failures without contacting real VMs."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock


spec = importlib.util.spec_from_file_location('lab_run', Path(__file__).parents[1] / 'run.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.values = {
            'VM_HOST': 'server.example', 'VM_USER': 'root', 'VM_PASSWORD': 'literal${PASSWORD}',
            'VM2_HOST': 'worker.example', 'VM2_USER': 'root', 'VM2_PASSWORD': 'second-secret',
            'OP_SERVICE_ACCOUNT_TOKEN': 'literal${TOKEN}',
        }

    def invoke(self, action='inspect'):
        with patch.object(runner.sys, 'argv', ['run.py', action]), \
                patch.object(runner, 'dotenv_values', return_value=self.values), \
                patch.object(runner.socket, 'gethostbyname',
                             side_effect=lambda host: {'server.example': '192.0.2.1',
                                                       'worker.example': '192.0.2.2'}[host]), \
                patch.object(runner, 'gitops_preflight'), \
                patch.object(runner, 'playbook') as playbook:
            runner.main()
            return playbook

    def test_each_vm_keeps_its_own_credentials_and_passwords_remain_literal(self):
        with patch.dict(os.environ, {}, clear=True):
            playbook = self.invoke()
            self.assertEqual(os.environ['VM_PASSWORD'], 'literal${PASSWORD}')
            self.assertEqual(os.environ['VM2_BECOME_PASSWORD'], 'second-secret')
            self.assertEqual(os.environ['VM_PORT'], '22')
            self.assertEqual(os.environ['VM2_PUBLIC_IP'], '192.0.2.2')
            playbook.assert_called_once_with('inspect.yml')

    def test_missing_worker_password_fails_before_any_playbook(self):
        del self.values['VM2_PASSWORD']
        with self.assertRaisesRegex(SystemExit, 'Missing .env inputs: VM2_PASSWORD'):
            self.invoke()

    def test_legacy_backup_inputs_are_not_exported_or_required(self):
        self.values['LONGHORN_BACKUP_SECRET_ACCESS_KEY'] = 'unused-secret'
        with patch.dict(os.environ, {}, clear=True):
            self.invoke('prove')
            self.assertNotIn('LONGHORN_BACKUP_SECRET_ACCESS_KEY', os.environ)
            self.assertNotIn('LONGHORN_BACKUP_ENABLED', os.environ)

    def test_invalid_worker_port_is_rejected(self):
        for value in ('0', '65536', 'not-a-port'):
            with self.subTest(value=value):
                self.values['VM2_PORT'] = value
                with self.assertRaisesRegex(SystemExit, 'VM2_PORT must be between'):
                    self.invoke()

    def test_same_machine_cannot_be_configured_as_both_roles(self):
        self.values['VM2_HOST'] = self.values['VM_HOST']
        with self.assertRaisesRegex(SystemExit, 'must identify different VMs'):
            self.invoke()

    def test_prove_applies_twice_then_verifies(self):
        playbook = self.invoke('prove')
        self.assertEqual([call.args[0] for call in playbook.call_args_list],
                         ['apply.yml', 'apply.yml', 'verify.yml'])
        self.assertEqual(playbook.call_args_list[1].kwargs, {'unchanged': True})

    def test_initial_export_uses_host_playbook_and_does_not_enable_longhorn(self):
        window = Mock()
        with patch.dict(runner.sys.modules, {'write_window': window}), \
                patch.object(runner.subprocess, 'run') as command:
            playbook = self.invoke('recovery-initial')
        window.authorize_initial.assert_called_once_with()
        playbook.assert_called_once_with('recovery.yml')
        command.assert_not_called()
        self.assertEqual(os.environ['LAB_RECOVERY_ACTION'], 'initial')
        self.assertEqual(os.environ['LAB_MONTHLY_PROOF'], '0')
        self.invoke('prove')
        self.assertEqual(os.environ['LAB_RECOVERY_ACTION'], 'monthly')

    def test_replacement_proof_is_explicit_and_keeps_longhorn_disabled(self):
        window = Mock()
        with patch.dict(runner.sys.modules, {'write_window': window}), \
                patch.object(runner.subprocess, 'run') as command:
            playbook = self.invoke('recovery-replacement-test')
        window.authorize_replacement.assert_called_once_with()
        playbook.assert_called_once_with('recovery.yml')
        command.assert_not_called()
        self.assertEqual(os.environ['LAB_RECOVERY_ACTION'], 'replacement-test')
        self.assertEqual(os.environ['LAB_MONTHLY_PROOF'], '0')

    def test_external_secrets_token_is_required_before_apply_and_verify(self):
        del self.values['OP_SERVICE_ACCOUNT_TOKEN']
        for action in ('apply', 'prove', 'verify'):
            with self.subTest(action=action), self.assertRaisesRegex(SystemExit, 'OP_SERVICE_ACCOUNT_TOKEN'):
                self.invoke(action)

    def test_external_secrets_token_remains_literal_and_clears_inherited_value(self):
        with patch.dict(os.environ, {}, clear=True):
            self.invoke()
            self.assertEqual(os.environ['OP_SERVICE_ACCOUNT_TOKEN'], 'literal${TOKEN}')
            del self.values['OP_SERVICE_ACCOUNT_TOKEN']
            self.invoke()
            self.assertEqual(os.environ['OP_SERVICE_ACCOUNT_TOKEN'], '')

    def test_syntax_does_not_require_credentials_or_dns(self):
        self.values = {}
        playbook = self.invoke('syntax')
        self.assertEqual(playbook.call_count, 13)
        self.assertTrue(all(call.kwargs == {'syntax': True} for call in playbook.call_args_list))

    def test_independent_retrieval_does_not_require_vm_credentials_or_playbooks(self):
        self.values = {'OP_SERVICE_ACCOUNT_TOKEN': 'fixture-token'}
        with patch.object(runner.subprocess, 'run') as command:
            playbook = self.invoke('recovery-retrieve')
        playbook.assert_not_called()
        self.assertEqual(command.call_args.args[0][-2:], ['/workspace/automation/recovery/runner.py', 'retrieve'])

    def test_zero_change_proof_requires_both_hosts_and_rejects_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            stats_path = Path(directory) / 'stats.json'
            cases = [
                ({'cloudlab': {'changed': 0}}, 'both expected VMs'),
                ({'cloudlab': {'changed': 0}, 'cloudlab-worker': {'changed': 1}}, 'idempotency proof failed'),
            ]
            for stats, message in cases:
                with self.subTest(stats=stats), \
                        patch.object(runner, 'Path', return_value=stats_path), \
                        patch.object(runner.subprocess, 'run') as execute:
                    def finish(*args, **kwargs):
                        stats_path.write_text(json.dumps(stats))
                        return type('Completed', (), {'returncode': 0})()
                    execute.side_effect = finish
                    with self.assertRaisesRegex(SystemExit, message):
                        runner.playbook('apply.yml', unchanged=True)

    def test_migration_retrieves_backup_and_accepts_only_after_full_proof(self):
        self.values.update(TAILSCALE_HOSTS_ENABLED='1', K3S_BACKUP_ENABLED='1')
        with patch.object(runner.subprocess, 'run') as command:
            playbook = self.invoke('k3s-migrate')
        self.assertEqual(command.call_count, 2)
        self.assertEqual(command.call_args_list[0].args[0][-1], '/workspace/automation/tailscale/verify_access.py')
        self.assertEqual(command.call_args.args[0][-1], 'retrieve')
        self.assertEqual([call.args[0] for call in playbook.call_args_list],
                         ['k3s-migration.yml', 'apply.yml', 'apply.yml', 'verify.yml', 'k3s-migration.yml'])
        self.assertEqual(playbook.call_args_list[2].kwargs, {'unchanged': True})

    def test_migration_cannot_skip_host_access_or_recovery_gate(self):
        with patch.object(runner.subprocess, 'run') as command:
            with self.assertRaisesRegex(SystemExit, 'milestone 01'):
                self.invoke('k3s-migrate')
            command.assert_not_called()

    def test_migration_requires_vault_before_any_transition(self):
        del self.values['OP_SERVICE_ACCOUNT_TOKEN']
        with self.assertRaisesRegex(SystemExit, 'OP_SERVICE_ACCOUNT_TOKEN'):
            self.invoke('k3s-migrate')

    def test_gitops_bootstrap_has_an_explicit_bounded_entrypoint(self):
        playbook = self.invoke('gitops-bootstrap')
        self.assertEqual([call.args[0] for call in playbook.call_args_list], ['gitops.yml', 'gitops.yml'])
        self.assertEqual(os.environ['LAB_GITOPS_ACTION'], 'verify')

    def test_eso_recovery_uses_its_explicit_suspended_writer_gate(self):
        self.invoke('eso-recover').assert_called_once_with('eso-recovery.yml')
        self.invoke('eso-bootstrap').assert_called_once_with('eso.yml')
        del self.values['OP_SERVICE_ACCOUNT_TOKEN']
        with self.assertRaisesRegex(SystemExit, 'OP_SERVICE_ACCOUNT_TOKEN'):
            self.invoke('eso-recover')

    def test_gitops_interruption_proof_resumes_the_same_playbook(self):
        playbook = self.invoke('gitops-interruption-test')
        self.assertEqual([call.args[0] for call in playbook.call_args_list], ['gitops.yml', 'gitops.yml', 'gitops.yml'])
        self.assertEqual(os.environ['LAB_GITOPS_STOP_AFTER_SEED'], '0')

    def test_storage_interruption_resumes_and_recovery_uses_the_writer_gate(self):
        playbook = self.invoke('longhorn-interruption-test')
        self.assertEqual([call.args[0] for call in playbook.call_args_list], ['longhorn.yml', 'longhorn.yml'])
        self.assertEqual(os.environ['LAB_LONGHORN_STOP_AFTER_SEED'], '0')
        self.invoke('longhorn-recover').assert_called_once_with('longhorn-recovery.yml')
        del self.values['OP_SERVICE_ACCOUNT_TOKEN']
        with self.assertRaisesRegex(SystemExit, 'OP_SERVICE_ACCOUNT_TOKEN'):
            self.invoke('longhorn-bootstrap')

    def test_unreadable_public_source_fails_before_any_host_operation(self):
        for action in ('apply', 'prove', 'gitops-bootstrap', 'gitops-interruption-test'):
            with self.subTest(action=action), \
                    patch.object(runner.sys, 'argv', ['run.py', action]), \
                    patch.object(runner, 'dotenv_values', return_value=self.values), \
                    patch.object(runner.socket, 'gethostbyname', side_effect=['192.0.2.1', '192.0.2.2']), \
                    patch.object(runner.subprocess, 'run', return_value=Mock(returncode=1)), \
                    patch.object(runner, 'playbook') as playbook:
                with self.assertRaisesRegex(SystemExit, 'before host mutation'):
                    runner.main()
                playbook.assert_not_called()


    def test_repository_setup_is_independent_of_vm_and_vault_credentials(self):
        self.values = {}
        for action, module in (('repository-setup', 'github_setup.py'), ('publish-platform', 'publish_snapshot.py'), ('github-app-check', 'github_app.py'), ('private-fixture-prepare', 'private_fixture.py')):
            with self.subTest(action=action), patch.object(runner.subprocess, 'run', return_value=Mock(returncode=0)) as command:
                playbook = self.invoke(action)
                playbook.assert_not_called()
                self.assertEqual(command.call_args.args[0][-1], '/workspace/automation/gitops/' + module)


if __name__ == '__main__':
    unittest.main()
