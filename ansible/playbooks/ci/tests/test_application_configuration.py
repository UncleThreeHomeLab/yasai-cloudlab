"""Repository onboarding shares the qualified profile and preserves trust boundaries."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.ci.files.chart import POOL, render
from playbooks.ci.files.configuration import application_configuration
from playbooks.ci.files import configuration as command
from playbooks.ci.tests.fixtures import qualified_tools, pool_values


class ApplicationConfigurationTests(unittest.TestCase):
    def test_reviewed_template_uses_native_gate_and_rejects_foreign_or_mixed_policies(self):
        application, current = self.inputs()
        row = {'repository_id': '123', 'repository': current['full_name'], 'visibility': 'public',
               'workflow_path': '.github/workflows/ci.yaml', 'workflow_sha256': 'a' * 64, 'job': 'test',
               'job_workflow_ref': 'example/platform/.github/workflows/application-test.yaml@' + 'b' * 40}
        document = application_configuration(qualified_tools(), application, current, templates=[row])['runner.json']
        objects = render(document['values'], chart=POOL, namespace=document['namespace'])
        policy = next(x for x in objects if x['kind'] == 'ConfigMap' and x['metadata']['name'] == 'cloudlab-ci-eligibility')
        self.assertEqual(json.loads(policy['data']['eligibility.json']), {'templates': [row]})
        with self.assertRaises(ValueError):
            application_configuration(qualified_tools(), application, current, templates=[dict(row, repository_id='999')])
        with self.assertRaises(ValueError):
            application_configuration(qualified_tools(), application, current, [pool_values()['eligibility'][0]], [row])

    def test_local_command_reads_only_approved_metadata_and_preserves_repeated_output(self):
        application, current = self.inputs()
        api = Mock()
        api.request.return_value = current
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'ci').mkdir()
            (work / 'ci/qualified.json').write_text(json.dumps(qualified_tools()))
            source = work / 'application.json'
            source.write_text(json.dumps(application))
            output = work / 'output'
            with patch.object(command.harbor_api, 'WORK', work), \
                    patch.object(command.harbor_api, 'binding', return_value='e' * 40), \
                    patch.object(command.harbor_api, 'reviewed_ancestor', return_value=True), \
                    patch.object(command, 'inputs', return_value=({}, api)), \
                    patch.object(command.yaml, 'safe_load', return_value={'repository': 'https://github.com/example/platform.git'}), \
                    patch('sys.argv', ['configuration', '--application-file', str(source), '--output', str(output)]):
                command.main()
                original = (output / 'controller.json').read_bytes()
                with patch.object(command, 'atomic') as write:
                    command.main()
                    write.assert_not_called()
                self.assertEqual((output / 'controller.json').read_bytes(), original)
                self.assertFalse((output / 'runner.json').exists())
                self.assertTrue(all(call.args == ('GET', 'repos/example/example') for call in api.request.call_args_list))

    def inputs(self, name='example', scope='public'):
        application = {'name': name, 'repository': 'https://github.com/example/' + name + '.git', 'visibility': scope}
        current = {'id': 123, 'full_name': 'example/' + name, 'html_url': 'https://github.com/example/' + name,
                   'visibility': scope, 'private': scope == 'private', 'fork': False, 'archived': False, 'default_branch': 'main'}
        return application, current

    def test_different_apps_use_same_charts_and_never_enable_unapproved_jobs(self):
        for name, scope in (('first', 'public'), ('second', 'private')):
            application, current = self.inputs(name, scope)
            documents = application_configuration(qualified_tools(), application, current)
            self.assertEqual(set(documents), {'controller.json'})
            controller = documents['controller.json']
            self.assertEqual(controller['namespace'], 'cloudlab-ci-' + scope + '-' + name)
            self.assertFalse(controller['values']['manageSystemNamespace'])
            objects = render(controller['values'], include_crds=False)
            self.assertFalse(any(row['kind'] == 'ExternalSecret' and row['spec']['dataFrom'] !=
                [{'extract': {'key': 'harbor-cloudlab-public-pull'}}] for row in objects))

    def test_approved_pool_keeps_complete_native_security_profile_and_only_its_app(self):
        application, current = self.inputs()
        workflow = pool_values()['eligibility'][0]
        workflow.update(repository='example/example', repository_id='123',
                        workflow_ref='example/example/.github/workflows/publish.yaml@refs/heads/main')
        documents = application_configuration(qualified_tools(), application, current, [workflow])
        pool = documents['runner.json']
        values = pool['values']
        baseline = json.loads((POOL / 'values.json').read_text())['arc']['template']['spec']
        actual = values['arc']['template']['spec']
        self.assertEqual(actual['securityContext'], baseline['securityContext'])
        self.assertEqual(actual['initContainers'][0]['securityContext'], baseline['initContainers'][0]['securityContext'])
        objects = render(values, chart=POOL, namespace=pool['namespace'])
        secret, = [row for row in objects if row['kind'] == 'ExternalSecret']
        self.assertEqual(secret['spec']['dataFrom'], [{'extract': {'key': 'github-arc-public'}}])
        foreign = copy.deepcopy(workflow)
        foreign['repository_id'] = '999'
        with self.assertRaises(ValueError):
            application_configuration(qualified_tools(), application, current, [foreign])

    def test_fork_visibility_identity_archive_and_unqualified_tools_fail_closed(self):
        application, current = self.inputs()
        for field, value in (('fork', True), ('private', True), ('visibility', 'private'),
                             ('archived', True), ('full_name', 'example/other'), ('id', 0)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                application_configuration(qualified_tools(), application, dict(current, **{field: value}))
        tools = qualified_tools()
        tools['nodes_verified'] = 1
        with self.assertRaises(ValueError):
            application_configuration(tools, application, current)
