"""Exercise qualified GitOps inputs and native indexed Helm image overrides."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from playbooks.ci.files.chart import POOL, render
from playbooks.ci.files.configuration import configuration
from playbooks.ci.files import configuration as command
from playbooks.ci.tests.fixtures import fixture_repository, qualified_tools


class ConfigurationTests(unittest.TestCase):
    def test_command_preserves_existing_inputs_and_requires_reviewed_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'ci').mkdir()
            (work / 'ci/qualified.json').write_text(json.dumps(qualified_tools()))
            output = work / 'ci/configuration.json'
            api = Mock()
            with patch.object(command.harbor_api, 'WORK', work), \
                    patch.object(command.harbor_api, 'binding', return_value='e' * 40), \
                    patch.object(command.harbor_api, 'reviewed_ancestor', return_value=True) as ancestor, \
                    patch.object(command, 'inputs', return_value=({'PRIVATE_TEST_REPOSITORY':
                        fixture_repository()['html_url'] + '.git'}, api)), \
                    patch.object(command, 'inspect', return_value=fixture_repository()), \
                    patch('sys.argv', ['configuration', '--output', str(output)]):
                command.main()
                original = output.read_bytes()
                self.assertEqual(ancestor.call_count, 2)
                with patch.object(command, 'atomic') as write:
                    command.main()
                    write.assert_not_called()
                output.write_text('{"preserve":true}')
                with self.assertRaises(ValueError):
                    command.main()
                self.assertEqual(output.read_text(), '{"preserve":true}')
                output.write_bytes(original)
                ancestor.return_value = False
                with self.assertRaises(ValueError):
                    command.main()
                self.assertEqual(output.read_bytes(), original)
                api.request.assert_not_called()

    def test_command_requires_actual_main_workflow_before_eligibility(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'ci').mkdir()
            (work / 'ci/qualified.json').write_text(json.dumps(qualified_tools()))
            output = work / 'ci/configuration.json'
            api = Mock()
            with patch.object(command.harbor_api, 'WORK', work), \
                    patch.object(command.harbor_api, 'binding', return_value='e' * 40), \
                    patch.object(command.harbor_api, 'reviewed_ancestor', return_value=True), \
                    patch.object(command, 'inputs', return_value=({'PRIVATE_TEST_REPOSITORY':
                        fixture_repository()['html_url'] + '.git'}, api)), \
                    patch.object(command, 'inspect', return_value=fixture_repository()), \
                    patch('sys.argv', ['configuration', '--output', str(output), '--workflow-revision', 'd' * 40]):
                api.request.side_effect = [{'object': {'sha': 'c' * 40}}]
                with self.assertRaises(ValueError):
                    command.main()
                self.assertFalse(output.exists())
                api.request.side_effect = [{'object': {'sha': 'd' * 40}}, None]
                with self.assertRaises(ValueError):
                    command.main()
                self.assertFalse(output.exists())
                api.request.side_effect = [{'object': {'sha': 'd' * 40}}, {'type': 'file'}]
                command.main()
                self.assertEqual(len(json.loads(output.read_text())['eligibility']), 2)
                self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_registration_rejects_incomplete_or_stale_profile_and_foreign_repository(self):
        for field, value in (('nodes_verified', 1), ('max_build_pods', 2), ('workload_api_writes_denied', False),
                             ('health_access_loss_shutdown_bound_seconds', 120), ('revision', 'main'),
                             ('github_or_signing_credentials_provisioned', True), ('profile_sha256', 'a' * 64)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                configuration(dict(qualified_tools(), **{field: value}), fixture_repository())
        for field, value in (('private', False), ('fork', True), ('archived', True), ('default_branch', 'other'),
                             ('description', 'unrelated repository')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                configuration(qualified_tools(), dict(fixture_repository(), **{field: value}))

    def test_no_pool_registration_until_actual_workflow_revision_is_reviewed(self):
        values = configuration(qualified_tools(), fixture_repository())
        self.assertEqual(values['eligibility'], [])
        repository, digest = values['images']['controller'].split('@')
        objects = render(values, parameters={'arc.image.repository': repository, 'arc.image.tag': '0.15.0@' + digest})
        deployment, = [row for row in objects if row['kind'] == 'Deployment']
        self.assertEqual(deployment['spec']['template']['spec']['containers'][0]['image'],
                         repository + ':0.15.0@' + digest)
        with self.assertRaises(subprocess.CalledProcessError):
            render(values, chart=POOL)
        with self.assertRaises(ValueError):
            configuration(qualified_tools(), fixture_repository(), 'main')

    def test_indexed_image_parameters_preserve_full_security_profile_without_private_duplicates(self):
        values = configuration(qualified_tools(), fixture_repository(), 'd' * 40)
        parameters = {'arc.template.spec.containers[0].image': values['images']['runner'],
                      'arc.template.spec.initContainers[0].image': values['images']['builder']}
        objects = render(values, chart=POOL, parameters=parameters)
        scale_set, = [row for row in objects if row['kind'] == 'AutoscalingRunnerSet']
        pod = scale_set['spec']['template']['spec']
        original = json.loads((POOL / 'values.json').read_text())['arc']['template']['spec']
        self.assertNotIn('template', values['arc'])
        for key in ('containers', 'initContainers'):
            for field in ('securityContext', 'resources', 'volumeMounts'):
                self.assertEqual(pod[key][0][field], original[key][0][field])
        self.assertEqual(pod['initContainers'][0]['restartPolicy'], 'Always')
        self.assertEqual(pod['containers'][0]['image'], values['images']['runner'])
        self.assertEqual(pod['initContainers'][0]['image'], values['images']['builder'])
