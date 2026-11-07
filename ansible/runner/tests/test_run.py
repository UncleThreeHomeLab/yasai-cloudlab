"""Check input isolation and proof failures without contacting real VMs."""

import importlib.util
import os
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch, Mock

import test as test_runner

spec = importlib.util.spec_from_file_location('lab_run', Path(__file__).parents[1] / 'run.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def test_retired_private_remove_command_is_rejected_before_credentials_or_apply(self):
        with patch.object(sys, 'argv', ['run.py', 'gitops-private-remove']), \
                patch.object(runner, 'dotenv_values') as dotenv, patch.object(runner, 'playbook') as playbook:
            with self.assertRaises(SystemExit): runner.main()
        dotenv.assert_not_called()
        playbook.assert_not_called()

    def test_dotenv_preserves_literal_shell_and_secret_characters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            secret = ' space # ${TOKEN} $(command) `literal` "quoted" \\ tail '
            path.write_text("VM_PASSWORD='" + secret + "'\n")
            self.assertEqual(runner.dotenv_values(path, interpolate=False)['VM_PASSWORD'], secret)

    def test_real_ansible_workdir_imports_workspace_before_missing_input_gate(self):
        code = '''import importlib.util,sys
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('runner','/opt/runner/run.py')
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
sys.argv=['run.py','inspect']
with patch.object(runner,'dotenv_values',return_value={}), patch('dotenv.dotenv_values',return_value={}):
 try: runner.main()
 except (SystemExit,ValueError,RuntimeError): print('input gate reached')
 else: raise AssertionError('Missing inputs must stop before VM access')
'''
        result = subprocess.run([sys.executable, '-c', code], cwd='/workspace/ansible',
                                env=dict(os.environ, PYTHONPATH=''), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('input gate reached', result.stdout)

    def test_test_runner_isolates_owners_and_reports_failures_after_all_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('ansible/playbooks/services/tests', 'ansible/playbooks/data/tests', 'verification/integration'):
                folder = root / name
                folder.mkdir(parents=True)
                (folder / 'test_example.py').write_text('')
            with patch.object(test_runner.subprocess, 'run', side_effect=[Mock(returncode=1), Mock(returncode=0), Mock(returncode=0)]) as command, \
                    patch('builtins.print'), \
                    self.assertRaisesRegex(RuntimeError, 'Tests failed: ansible[/\\\\]playbooks[/\\\\]data[/\\\\]tests'):
                test_runner.run(root)
            self.assertEqual(command.call_count, 3)
            for call, directory in zip(command.call_args_list, ('ansible/playbooks/data', 'ansible/playbooks/services', 'verification')):
                self.assertEqual(call.kwargs['cwd'], root)
                paths = call.kwargs['env']['PYTHONPATH'].split(os.pathsep)
                self.assertEqual(paths[0], str(root / directory))
                self.assertIn(str(root), paths)

    def test_test_runner_rejects_empty_test_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'verification/integration').mkdir(parents=True)
            with patch.object(test_runner.subprocess, 'run') as command, \
                    self.assertRaisesRegex(RuntimeError, 'No tests found'):
                test_runner.run(root)
            command.assert_not_called()

    def test_component_tests_run_once_in_isolated_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            groups = ('ansible/playbooks/data/tests', 'ansible/playbooks/host/tests',
                      'ansible/runner/tests', 'verification/integration')
            for name in groups:
                folder = root / name
                folder.mkdir(parents=True)
                (folder / 'test_example.py').write_text('')
            with patch.object(test_runner.subprocess, 'run', return_value=Mock(returncode=0)) as command:
                test_runner.run(root)
            self.assertEqual([call.args[0][-1] for call in command.call_args_list],
                             [str(root / name) for name in groups])

    def setUp(self):
        self.values = {
            'VM_HOST': 'server.example', 'VM_USER': 'root', 'VM_PASSWORD': 'literal${PASSWORD}',
            'VM2_HOST': 'worker.example', 'VM2_USER': 'root', 'VM2_PASSWORD': 'second-secret',
            'OP_SERVICE_ACCOUNT_TOKEN': 'literal${TOKEN}',
        }

    def test_read_only_host_checks_need_no_extra_inputs(self):
        for action, expected in (
                ('inspect', 'playbooks/inspect.yml'),
                ('baseline', 'playbooks/baseline.yml'),
                ('storage-check', 'playbooks/longhorn/check-host.yml')):
            with self.subTest(action=action):
                self.invoke(action).assert_called_once_with(expected)

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
            playbook.assert_called_once_with('playbooks/inspect.yml')

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
                         ['playbooks/setup.yml', 'playbooks/setup.yml', 'playbooks/verify.yml'])
        self.assertEqual(playbook.call_args_list[1].kwargs, {'unchanged': True})

    def test_setup_converges_then_verifies(self):
        playbook = self.invoke('setup')
        self.assertEqual([call.args[0] for call in playbook.call_args_list],
                         ['playbooks/setup.yml', 'playbooks/verify.yml'])

    def test_retired_apply_alias_refuses_before_credentials_or_hosts(self):
        with patch.object(runner.sys, 'argv', ['run.py', 'apply']), \
                patch.object(runner, 'dotenv_values', side_effect=AssertionError('Read credentials')), \
                patch.object(runner, 'playbook') as playbook:
            with self.assertRaises(SystemExit):
                runner.main()
        playbook.assert_not_called()

    def test_unspecified_operations_are_rejected_before_inputs_or_hosts(self):
        for action in ('maintenance', 'upgrade', 'nuke', 'recovery', 'backup', 'test',
                       'service', 'preview', 'observe', 'infra', 'identity-operation',
                       'data-bootstrap', 'recovery-initial', 'k3s-migrate',
                       'gitops-bootstrap', 'eso-bootstrap', 'observability-prove',
                       'publish-platform', 'access-preflight', 'mesh-check'):
            with self.subTest(action=action), \
                    patch.object(runner.sys, 'argv', ['run.py', action]), \
                    patch.object(runner, 'dotenv_values', side_effect=AssertionError('Read credentials')), \
                    patch.object(runner.socket, 'gethostbyname', side_effect=AssertionError('VM access')), \
                    patch.object(runner, 'playbook') as playbook:
                with self.assertRaisesRegex(SystemExit, 'Unknown action'):
                    runner.main()
            playbook.assert_not_called()

    def test_external_secrets_token_is_required_before_setup_and_verify(self):
        del self.values['OP_SERVICE_ACCOUNT_TOKEN']
        for action in ('setup', 'prove', 'verify'):
            with self.subTest(action=action), self.assertRaisesRegex(SystemExit, 'OP_SERVICE_ACCOUNT_TOKEN'):
                self.invoke(action)

    def test_workload_sysctl_input_is_exact_and_clears_inherited_value(self):
        with patch.dict(os.environ, {'K3S_ALLOWED_UNSAFE_SYSCTLS': '["kernel.shmmax"]'}):
            self.invoke()
            self.assertEqual(json.loads(os.environ['K3S_ALLOWED_UNSAFE_SYSCTLS']), [])
            self.values['K3S_ALLOWED_UNSAFE_SYSCTLS'] = '["net.ipv6.conf.all.disable_ipv6"]'
            self.invoke()
            self.assertEqual(json.loads(os.environ['K3S_ALLOWED_UNSAFE_SYSCTLS']), ['net.ipv6.conf.all.disable_ipv6'])
            for value in ('invalid', 'null', '"net.ipv6.conf.all.disable_ipv6"', '["net.*"]',
                          '["net.ipv6.conf.all.disable_ipv6","net.ipv6.conf.all.disable_ipv6"]'):
                self.values['K3S_ALLOWED_UNSAFE_SYSCTLS'] = value
                with self.subTest(value=value), self.assertRaisesRegex(SystemExit, 'K3S_ALLOWED_UNSAFE_SYSCTLS'):
                    self.invoke()

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
        self.assertGreaterEqual(playbook.call_count, 20)
        self.assertTrue(all(call.kwargs == {'syntax': True} for call in playbook.call_args_list))

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
                        runner.playbook('playbooks/setup.yml', unchanged=True)

    def test_retired_tailnet_policy_has_no_runner_dispatch(self):
        with patch.object(runner.subprocess, 'run') as command:
            with self.assertRaisesRegex(SystemExit, 'Unknown action'):
                self.invoke('tailnet-policy')
        command.assert_not_called()

    def test_host_access_and_lifecycle_use_explicit_component_operations(self):
        self.invoke('host-access').assert_called_once_with('playbooks/tailscale/access.yml')
        for action, target, operation in [('host-reauth-worker', 'cloudlab-worker', 'reauth'), ('host-logout-server', 'cloudlab', 'logout')]:
            self.invoke(action).assert_called_once_with('playbooks/tailscale/lifecycle.yml')
            self.assertEqual(os.environ['LAB_TAILSCALE_TARGET'], target)
            self.assertEqual(os.environ['LAB_TAILSCALE_ACTION'], operation)

    def test_unreadable_public_source_fails_before_any_host_operation(self):
        for action in ('setup', 'prove'):
            with self.subTest(action=action), \
                    patch.object(runner.sys, 'argv', ['run.py', action]), \
                    patch.object(runner, 'dotenv_values', return_value=self.values), \
                    patch.object(runner.socket, 'gethostbyname', side_effect=['192.0.2.1', '192.0.2.2']), \
                    patch.object(runner.subprocess, 'run', return_value=Mock(returncode=1)), \
                    patch.object(runner, 'playbook') as playbook:
                with self.assertRaisesRegex(SystemExit, 'before host mutation'):
                    runner.main()
                playbook.assert_not_called()


    def test_retired_repository_creator_has_no_runner_dispatch(self):
        with patch.object(runner.subprocess, 'run') as command:
            with self.assertRaisesRegex(SystemExit, 'Unknown action'):
                self.invoke('repository-setup')
        command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
