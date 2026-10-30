"""Check the qualification trust boundary and preserve the real pool profile."""
import json
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import yaml

from playbooks.ci.files import qualification
from playbooks.ci.files import direct_test_proof
from playbooks.ci.files.chart import POOL, ROOT
from playbooks.ci.files.qualification import bundle, images
from playbooks.ci.tests.fixtures import bootstrap_document, render_resources


class QualificationTests(unittest.TestCase):
    def test_direct_failure_retains_bounded_output_and_native_progress_without_forwarding_arguments(self):
        result = subprocess.CompletedProcess(['private-command'], 1, 'x' * 20000, 'offline test execution failed')
        ref = 'a' * 25
        history = '\n'.join(json.dumps({'record': {'Ref': value}}) for value in ('--unsafe', '../escape', ref))
        replies = [subprocess.CompletedProcess([], 0, history, ''),
                   subprocess.CompletedProcess([], 0, '', 'native source stage evidence')]
        with patch.object(direct_test_proof.subprocess, 'run', side_effect=replies) as run:
            failure = direct_test_proof.failed_execution(result)
        details = json.loads(str(failure).split(': ', 1)[1])
        self.assertEqual(details['execution']['rc'], 1)
        self.assertEqual(details['execution']['stdout'], 'x' * 16384)
        self.assertEqual(details['execution']['stderr'], result.stderr)
        self.assertEqual(details['progress'][0]['stderr'], 'native source stage evidence')
        self.assertNotIn('private-command', str(failure))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0][-4:], ['logs', '--progress', 'plain', ref])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs['timeout'], 10)
            self.assertNotIn('shell', call.kwargs)
            self.assertNotIn('env', call.kwargs)
        timeout = subprocess.TimeoutExpired(['private-command'], 260, output=b'partial stdout', stderr=b'partial stderr')
        for error in (OSError('private detail'), subprocess.TimeoutExpired(['diagnostic'], 10)):
            with self.subTest(error=type(error).__name__), patch.object(direct_test_proof.subprocess, 'run', side_effect=error):
                failure = direct_test_proof.failed_execution(timeout)
            details = json.loads(str(failure).split(': ', 1)[1])
            self.assertTrue(details['execution']['timeout'])
            self.assertEqual(details['execution']['stdout'], 'partial stdout')
            self.assertEqual(details['execution']['stderr'], 'partial stderr')
            self.assertNotIn('private detail', str(failure))

    def test_native_rescue_retains_diagnostics_privately_and_still_fails_and_cleans_up(self):
        rescue = yaml.safe_load((ROOT / 'ansible/playbooks/ci/verify-bootstrap.yml').read_text())[1]['tasks'][-1]['rescue']
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output, cleanup = directory / 'failure.json', directory / 'cleaned'
            fake = directory / 'kubectl.py'
            fake.write_text('import sys\nprint("SYNTHETIC_PRIVATE_DIAGNOSTIC")\nsys.exit(1)\n')
            tasks = json.loads(json.dumps(rescue))
            for task in tasks:
                if 'ansible.builtin.copy' in task:
                    task['ansible.builtin.copy']['dest'] = str(output)
            playbook = directory / 'rescue.json'
            playbook.write_text(json.dumps([{'hosts': 'localhost', 'gather_facts': False,
                'vars': {'ansible_python_interpreter': sys.executable,
                         'ci_kubectl': [sys.executable, str(fake)], 'ci_namespace': 'fixture',
                         'ci_pod': {'metadata': {'name': 'fixture'}},
                         'ci_direct_test_proof': {'rc': 1, 'stderr': 'SYNTHETIC_ORIGINAL_FAILURE'}},
                'tasks': [{'block': [{'ansible.builtin.fail': {'msg': 'synthetic qualification failure'}}],
                           'rescue': tasks, 'always': [{'ansible.builtin.copy': {
                               'content': 'cleanup', 'dest': str(cleanup), 'mode': '0600'}}]}]}]))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                                    capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(cleanup.exists(), result.stdout + result.stderr)
            retained = json.loads(output.read_text())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(retained['direct_test']['stderr'], 'SYNTHETIC_ORIGINAL_FAILURE')
            self.assertEqual(retained['builder_logs']['rc'], 1)
            self.assertEqual(len(retained['builder_usage']['results']), 3)
            self.assertNotIn('SYNTHETIC_PRIVATE_DIAGNOSTIC', result.stdout + result.stderr)
            self.assertNotIn('SYNTHETIC_ORIGINAL_FAILURE', result.stdout + result.stderr)

    def test_direct_cleanup_waits_for_native_in_use_records_and_fails_closed(self):
        with patch.object(direct_test_proof.subprocess, 'check_output', return_value='[{"inUse":true}]') as read, \
                patch.object(direct_test_proof.time, 'sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError, 'retained active'):
                direct_test_proof.require_released_sandbox()
            self.assertEqual(read.call_count, 10)
            self.assertEqual(sleep.call_count, 10)
        with patch.object(direct_test_proof.subprocess, 'check_output',
                          side_effect=['[{"inUse":true}]', '[{"inUse":false}]']) as read, \
                patch.object(direct_test_proof.time, 'sleep') as sleep:
            direct_test_proof.require_released_sandbox()
            self.assertEqual(read.call_count, 2)
            sleep.assert_called_once_with(1)
        for raw in ('[]', 'null', '[{"inUse":false}]'):
            with self.subTest(raw=raw), patch.object(direct_test_proof.subprocess, 'check_output', return_value=raw), \
                    patch.object(direct_test_proof.time, 'sleep') as sleep:
                direct_test_proof.require_released_sandbox()
                sleep.assert_not_called()
        for raw in ('{}', '[{}]', '[{"InUse":true}]', '[{"inUse":null}]',
                    '[{"inUse":0}]', '[{"inUse":"false"}]', '[null]'):
            with self.subTest(raw=raw), patch.object(direct_test_proof.subprocess, 'check_output', return_value=raw), \
                    patch.object(direct_test_proof.time, 'sleep') as sleep:
                with self.assertRaisesRegex(RuntimeError, 'invalid sandbox state'):
                    direct_test_proof.require_released_sandbox()
                sleep.assert_not_called()

    def test_qualification_binds_the_shared_builder_identity_map(self):
        with tempfile.TemporaryDirectory() as temporary:
            pool = Path(temporary) / 'pool'
            shutil.copytree(POOL, pool)
            with patch.object(qualification, 'POOL', pool):
                original = qualification.profile_fingerprint()
                path = pool / 'builder-ids.yaml'
                path.write_text(path.read_text().replace('user:1001:64535', 'user:1001:64534'))
                self.assertNotEqual(qualification.profile_fingerprint(), original)

    def test_real_ansible_reads_protected_invocation_file_and_preserves_eso_templates(self):
        original_run = subprocess.run
        fixture = bundle(images(bootstrap_document()), 'cloudlab-ci-proof-' + 'a' * 12)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'ci').mkdir()
            (directory / 'ci/images.json').write_text(json.dumps(bootstrap_document()))
            output = directory / 'rendered.json'
            playbook = directory / 'native.json'
            playbook.write_text(json.dumps([{'name': 'Read real extra-vars file', 'hosts': 'localhost',
                'gather_facts': False, 'vars': {'ansible_python_interpreter': sys.executable}, 'tasks': [
                    {'name': 'Preserve ESO expressions', 'ansible.builtin.copy': {
                        'content': '{{ ci_fixture.resources_b64 | b64decode }}',
                        'dest': str(output), 'mode': '0600'}}]}]))
            def execute(command, **kwargs):
                inputs = Path(command[-1][1:])
                self.assertEqual(stat.S_IMODE(inputs.stat().st_mode), 0o600)
                self.assertNotIn('input', kwargs)
                return original_run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook),
                                     '--extra-vars', command[-1]], capture_output=True, text=True, timeout=60)
            with patch.object(qualification.api, 'WORK', directory), \
                    patch.object(qualification.api, 'binding', return_value='c' * 40), \
                    patch.object(qualification.api, 'reviewed_ancestor', return_value=True), \
                    patch.object(qualification, 'bundle', return_value=fixture), \
                    patch.object(qualification.subprocess, 'run', side_effect=execute):
                with self.assertRaises(SystemExit) as result:
                    qualification.main()
                self.assertEqual(result.exception.code, 0)
            self.assertEqual(json.loads(output.read_text()), fixture['resources'])

    def test_failed_qualification_preserves_prior_receipt_and_success_records_exact_images(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'ci').mkdir()
            (directory / 'ci/images.json').write_text(json.dumps(bootstrap_document()))
            receipt = directory / 'ci/qualified.json'
            original = b'{"original":true}'
            receipt.write_bytes(original)
            for code in (1, 0):
                with self.subTest(code=code), patch.object(qualification.api, 'WORK', directory), \
                        patch.object(qualification.api, 'binding', return_value='c' * 40), \
                        patch.object(qualification.api, 'reviewed_ancestor', return_value=True), \
                        patch.object(qualification, 'bundle', return_value={'resources': {'items': []}}), \
                        patch.object(qualification.subprocess, 'run', return_value=Mock(returncode=code)) as command:
                    with self.assertRaises(SystemExit) as failure:
                        qualification.main()
                    self.assertEqual(failure.exception.code, code)
                    argument = command.call_args.args[0][-1]
                    self.assertTrue(argument.startswith('@/dev/shm/'))
                    self.assertFalse(Path(argument[1:]).exists())
                    self.assertNotIn('input', command.call_args.kwargs)
                if code:
                    self.assertEqual(receipt.read_bytes(), original)
                else:
                    verified = json.loads(receipt.read_text())
                    self.assertEqual(verified['images'], bootstrap_document()['images'])
                    self.assertEqual(verified['nodes_verified'], 2)
                    self.assertEqual(verified['direct_test_nodes_verified'], 2)
                    self.assertEqual(verified['direct_test_profile_sha256'], qualification.direct_test_profile())
                    self.assertEqual(verified['max_build_pods'], 1)
                    self.assertEqual(verified['health_access_loss_shutdown_bound_seconds'], 90)
                    self.assertFalse(verified['github_or_signing_credentials_provisioned'])

    def test_native_ansible_preserves_eso_templates_without_evaluating_vault_fields(self):
        fixture = bundle(images(bootstrap_document()), 'cloudlab-ci-proof-' + 'a' * 12)
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(render_resources(Path(temporary), fixture), fixture['resources'])

    def test_only_complete_scanned_public_tool_references_enter_the_fixture(self):
        self.assertEqual(images(bootstrap_document()), bootstrap_document()['images'])
        for change in ('revision', 'missing', 'foreign-project', 'mixed-host', 'mutable', 'wrong-repository', 'unknown'):
            document = bootstrap_document()
            if change == 'revision':
                document['revision'] = 'main'
            elif change == 'missing':
                document['images'].pop('builder')
            elif change == 'unknown':
                document['extra'] = True
            else:
                old = document['images']['runner']
                document['images']['runner'] = {
                    'foreign-project': old.replace('cloudlab-public', 'cloudlab-private'),
                    'mixed-host': old.replace('harbor.internal.example.invalid', 'harbor.internal.other.invalid'),
                    'mutable': old.split('@')[0] + ':latest',
                    'wrong-repository': old.replace('ci-runner', 'other')}[change]
            with self.subTest(change=change), self.assertRaises(ValueError):
                images(document)
        for document in (None, [], {'revision': None, 'images': {}},
                         {'revision': 'a' * 40, 'images': None}):
            with self.assertRaises(ValueError):
                images(document)

    def test_real_pool_security_resources_and_sidecar_survive_the_fixture_substitutions(self):
        references = images(bootstrap_document())
        fixture = bundle(references, 'cloudlab-ci-proof-' + 'a' * 12)
        self.assertEqual(fixture['namespace']['metadata']['labels']['cloudlab.io/service-secrets'], 'approved')
        actual = fixture['pod']
        original = json.loads((POOL / 'values.json').read_text())['arc']['template']['spec']
        self.assertEqual(actual['securityContext'], original['securityContext'])
        self.assertFalse(actual['automountServiceAccountToken'])
        self.assertFalse(actual['hostUsers'])
        for key in ('containers', 'initContainers'):
            expected, = original[key]
            container, = actual[key]
            for field in ('securityContext', 'resources', 'imagePullPolicy'):
                self.assertEqual(container[field], expected[field])
            self.assertEqual(container['image'], references[container['name']])
        builder, = actual['initContainers']
        self.assertEqual(builder['restartPolicy'], 'Always')
        self.assertEqual(builder['startupProbe'], original['initContainers'][0]['startupProbe'])
        self.assertFalse({'workspace', 'health', 'eligibility'} & {row['name'] for row in builder['volumeMounts']})
        objects = fixture['resources']['items']
        self.assertFalse(any(row['kind'] == 'Secret' for row in objects))
        external, = [row for row in objects if row['kind'] == 'ExternalSecret']
        self.assertEqual(external['spec']['dataFrom'], [{'extract': {'key': 'harbor-cloudlab-public-pull'}}])
        role, = [row for row in objects if row['kind'] == 'ClusterRole']
        self.assertEqual(role['rules'], [{'apiGroups': [''], 'resources': ['nodes'], 'verbs': ['list']},
                                       {'nonResourceURLs': ['/readyz'], 'verbs': ['get']}])
        policy, = [row for row in objects if row['kind'] == 'ConfigMap' and row['metadata']['name'] == 'cloudlab-ci-eligibility']
        self.assertEqual(json.loads(policy['data']['eligibility.json']), {'workflows': []})
        quota, = [row for row in objects if row['kind'] == 'ResourceQuota']
        self.assertEqual(quota['spec']['hard']['pods'], '1')
        self.assertEqual(quota['spec']['hard']['persistentvolumeclaims'], '0')
        self.assertNotIn('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', json.dumps(fixture))
        proof, = [row for row in objects if row['kind'] == 'ConfigMap' and row['metadata']['name'] == 'proof']
        compile(proof['data']['api-denial.py'], '/proof/api-denial.py', 'exec')
        compile(proof['data']['direct-test-proof.py'], '/proof/direct-test-proof.py', 'exec')
        self.assertEqual(json.loads(proof['data']['test-config.json']), {'image': references['runner']})
        self.assertEqual(len(json.loads(proof['data']['test-meta.json'])['gate_overlays']), 2)
        runner, = actual['containers']
        self.assertIn({'name': 'proof', 'mountPath': '/run/cloudlab-test/config/config.json',
                       'subPath': 'test-config.json', 'readOnly': True}, runner['volumeMounts'])
        self.assertNotIn('test-pull', {row['name'] for row in builder['volumeMounts']})

    def test_fixture_rejects_a_permanent_or_foreign_namespace_before_rendering(self):
        for namespace in ('cloudlab-ci-private', 'kube-system', 'cloudlab-ci-proof-invalid'):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                bundle(images(bootstrap_document()), namespace)

    def test_shared_build_proof_remains_valid_posix_shell_with_a_disposable_workspace(self):
        path = ROOT / 'ansible/playbooks/buildkit/files/build-proof.sh'
        subprocess.run(['/bin/sh', '-n', str(path)], check=True, timeout=10)
        self.assertIn('BUILD_PROOF_WORKSPACE:-/workspace', path.read_text())
