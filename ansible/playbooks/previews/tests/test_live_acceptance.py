import copy
import json
import fcntl
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.previews.tests import live_acceptance as live, viewer_runtime as runtime
from playbooks.keycloak.files import session_fixture, lifecycle


class AcceptanceTests(unittest.TestCase):
    def request(self, action, **extra):
        return {'action': action, 'nonce': 'a' * 32, 'realm': 'applications', **extra}

    def test_remote_dispatch_uses_owner_primitives_and_never_local_ssh_wrappers(self):
        with patch.object(session_fixture, 'enroll', return_value={}) as enroll, \
                patch.object(session_fixture, 'local', side_effect=AssertionError('local SSH wrapper')), \
                patch.object(lifecycle, 'local_offboard', side_effect=AssertionError('local SSH wrapper')):
            for action, stage in (('stage', True), ('enroll', False)):
                runtime.run(self.request(action))
                enroll.assert_called_with({'nonce': 'a' * 32, 'realm': 'applications'}, stage=stage)
            identity = {'realm': 'applications', 'username': 'proof-' + 'a' * 32,
                        'user_id': '11111111-1111-1111-1111-111111111111', 'email': 'fixture@example.invalid'}
            with patch.object(runtime, 'observe', return_value=dict(identity, enabled=False)), patch.object(lifecycle, 'offboard', return_value={}) as offboard:
                runtime.run(self.request('offboard', identity=identity))
                offboard.assert_called_once_with(identity)
        with patch.object(session_fixture, 'enroll') as enroll:
            for request in (dict(self.request('stage'), realm='platform'), self.request('--stage'), self.request('local'),
                            self.request('stage', identity={})):
                with self.assertRaises(ValueError): runtime.run(request)
            enroll.assert_not_called()

    def test_intent_is_saved_before_runtime_mutation_and_conflicting_stage_refuses(self):
        state = {'viewer': {'nonce': 'a' * 32, 'realm': 'applications'}, 'baseline': {}, 'provisioned': True, 'intent': None}
        observations = []
        save = lambda: observations.append(copy.deepcopy(state))
        def remote(values, request):
            self.assertEqual(observations[-1]['intent']['action'], 'viewer-stage')
            raise RuntimeError('ambiguous remote response')
        with patch.object(live, 'remote', side_effect=remote):
            with self.assertRaises(RuntimeError): live.execute('viewer-stage', {}, state, save)
            with self.assertRaises(ValueError): live.execute('viewer-enroll', {}, state, save)
        self.assertEqual(state['intent'], {'action': 'viewer-stage', 'slot': None})

    def test_missing_local_prerequisite_does_not_trap_journal_before_provision(self):
        state = {'viewer': {'nonce': 'a' * 32, 'realm': 'applications'}, 'baseline': {}, 'intent': None}
        saved = []
        with self.assertRaises(ValueError): live.execute('viewer-stage', {}, state, lambda: saved.append(copy.deepcopy(state)))
        self.assertEqual(saved, [])
        self.assertIsNone(state['intent'])
        with patch.object(session_fixture, 'provision', return_value={}):
            live.execute('viewer-provision', {}, state, lambda: saved.append(copy.deepcopy(state)))
        self.assertTrue(state['provisioned'])
        self.assertIsNone(state['intent'])

    def test_descendant_published_execution_preserves_original_provenance_and_receipts(self):
        state = {'platform': 'b' * 40, 'baseline': {'retained': True}, 'pulls': {'a': {'retained': True}}}
        before = copy.deepcopy(state)
        with patch.object(live.subprocess, 'run', return_value=Mock(returncode=0)) as git:
            live.execution_source(state, 'c' * 40)
            self.assertEqual(git.call_args.args[0], ['git', 'merge-base', '--is-ancestor', 'b' * 40, 'c' * 40])
        self.assertEqual({key: state[key] for key in before}, before)
        self.assertEqual(state['executionPlatform'], 'c' * 40)
        with patch.object(live.subprocess, 'run', return_value=Mock(returncode=1)):
            with self.assertRaises(ValueError): live.execution_source(state, 'd' * 40)

    def test_operation_lock_refuses_second_invocation_before_credentials(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(live.fixture, 'JOURNALS', Path(directory)), \
                patch('playbooks.argocd.files.render.committed_payload', return_value={'revision': 'b' * 40}), \
                patch.object(live, 'dotenv_values') as values:
            path = Path(directory) / ('a' * 32) / 'journal.json'
            live.fixture.journal(path, {'format': 1, 'nonce': 'a' * 32, 'platform': 'b' * 40,
                'viewer': {'nonce': 'a' * 32, 'realm': 'applications'}, 'pulls': {}, 'intent': None})
            descriptor = os.open(path.parent / 'operation.lock', os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError): live.main(['inspect', '--nonce', 'a' * 32, '--live'])
                values.assert_not_called()
            finally:
                os.close(descriptor)

    def test_unopted_execution_and_private_arguments_cannot_read_credentials_or_echo_values(self):
        with patch.object(live, 'dotenv_values') as read, patch('playbooks.argocd.files.render.committed_payload') as published:
            for args in (['inspect', '--nonce', 'a' * 32], ['private-sentinel', '--nonce', 'a' * 32, '--live']):
                with self.assertRaises(ValueError) as error: live.main(args)
                self.assertNotIn('private-sentinel', str(error.exception))
            read.assert_not_called()
            published.assert_not_called()

    def test_ansible_dispatch_keeps_requests_results_private_and_runs_no_legacy_modes(self):
        import yaml
        path = Path(runtime.__file__).with_name('viewer.yml')
        tasks = yaml.safe_load(path.read_text())[0]['tasks']
        command = next(task for task in tasks if 'ansible.builtin.command' in task)
        self.assertTrue(command['no_log'])
        self.assertTrue(command['ansible.builtin.command'].endswith('/previews/tests/viewer_runtime.py'))
        self.assertTrue(tasks[-1]['no_log'])
        self.assertEqual(tasks[-1]['ansible.builtin.copy']['mode'], '0600')

    def test_actual_installer_closes_preactivation_baseline_imports_without_checkout_path(self):
        import yaml
        tasks = yaml.safe_load(Path(runtime.__file__).with_name('viewer.yml').read_text())[0]['tasks']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installed = root / 'installed'
            selected = []
            for task in tasks:
                if 'ansible.builtin.command' in task:
                    break
                if 'ansible.builtin.file' in task or 'src' in task.get('ansible.builtin.copy', {}):
                    task = copy.deepcopy(task)
                    module = task.get('ansible.builtin.file', task.get('ansible.builtin.copy'))
                    field = 'path' if 'path' in module else 'dest'
                    module[field] = module[field].replace('/opt/cloudlab', str(installed), 1)
                    selected.append(task)
            playbook = root / 'install.yml'
            playbook.write_text(yaml.safe_dump([{'hosts': 'all', 'gather_facts': False, 'tasks': selected}]))
            config = root / 'ansible.cfg'
            config.write_text('[defaults]\ninterpreter_python=auto_silent\n')
            environment = dict(os.environ, ANSIBLE_CONFIG=str(config))
            environment.pop('PYTHONPATH', None)
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                cwd=root, env=environment, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            probe = '''import json,sys,types
sys.path.insert(0,sys.argv[1])
from playbooks.previews.tests import viewer_runtime as viewer
for name in ('playbooks.istio','playbooks.istio.files','playbooks.istio.files.kube'):
 module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
kube=sys.modules['playbooks.istio.files.kube']
kube.get=lambda *args:None
kube.kube=lambda *args:'' if args[1]=='secrets' else json.dumps({'items':[]})
viewer.client_baseline=lambda request:{}
result=viewer.baseline({'instances':[]})
from playbooks.previews.files import contract
assert set(result['states'])=={contract.STATE,contract.IDENTITY_STATE}
assert contract.__file__.startswith(sys.argv[1]+'/')
assert viewer.__file__.startswith(sys.argv[1]+'/')
'''
            result = subprocess.run([sys.executable, '-I', '-c', probe, str(installed)], cwd=root,
                env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            installed.joinpath('playbooks/previews/files/contract.py').unlink()
            result = subprocess.run([sys.executable, '-I', '-c', probe, str(installed)], cwd=root,
                env=environment, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No module named 'playbooks.previews.files.contract'", result.stderr)

    def test_secret_baseline_captures_only_metadata_and_keeps_values_out(self):
        from playbooks.istio.files import kube
        objects = {'items': [{'metadata': {'name': 'persistent', 'namespace': 'system', 'uid': 'uid', 'labels': {}}}]}
        def command(*args):
            if args[1] == 'secrets':
                self.assertIn('-o=jsonpath=', args[3])
                self.assertNotIn('data', args[3].replace('metadata', ''))
                return 'system\tcredential\tsecret-uid\towner\n'
            return json.dumps(objects)
        with patch.object(kube, 'get', return_value=None), patch.object(kube, 'kube', side_effect=command), \
                patch.object(runtime, 'client_baseline', return_value={'platform': {'identityHash': 'hash'}}):
            result = runtime.baseline(self.request('baseline', instances=[]))
        self.assertEqual(result['persistent']['secrets']['count'], 1)
        self.assertEqual(result['persistent']['secrets']['identities'], {'system/credential': 'secret-uid'})
        self.assertNotIn('data', result['persistent']['secrets'])

    def test_client_baseline_projects_only_persistent_identity_pairs(self):
        from playbooks.keycloak.files import maintenance, configuration, emergency
        from playbooks.istio.files import kube
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath('ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owner', 'revision': 'b' * 40}))
            app = {'metadata': {'uid': 'owner', 'labels': {'cloudlab.io/owner': maintenance.OWNER}},
                   'spec': {'source': {'helm': {'valuesObject': {'adminHost': 'identity-admin.internal.example.invalid'}}}}}
            def request(url, **kwargs):
                if '/token' in url: return {'access_token': 'synthetic-writer-token'}
                return [{'clientId': 'persistent', 'id': 'persistent-uuid'}, {'clientId': 'preview-' + 'a' * 32, 'id': 'fixture-uuid'}]
            with patch.object(maintenance, 'BASE', root), patch.object(kube, 'get', return_value=app), \
                    patch.object(kube, 'application_ready', return_value=True), patch.object(configuration, 'private_request', side_effect=request), \
                    patch.object(emergency, 'vault_secret', return_value={'platform_client_secret': 'synthetic', 'applications_client_secret': 'synthetic'}):
                result = runtime.client_baseline(self.request('baseline', instances=['a' * 32]))
            self.assertEqual(result['applications']['count'], 1)
            self.assertEqual(result['platform']['count'], 2)
            self.assertEqual(result['applications']['identities'], {'persistent': 'persistent-uuid'})
            self.assertNotIn('synthetic', json.dumps(result))
