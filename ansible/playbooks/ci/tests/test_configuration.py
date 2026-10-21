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
    def setUp(self):
        patcher = patch('playbooks.ci.files.network.discover', return_value={
            'enforce': True, 'apiServiceCIDRs': ['10.43.0.1/32'],
            'apiEndpointCIDRs': ['100.64.0.2/32'], 'registryCIDRs': ['100.64.0.3/32']})
        self.network = patcher.start()
        self.addCleanup(patcher.stop)

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
                    patch.object(command, 'inputs', return_value=({'PRIVATE_CONFIG_REPOSITORY':
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
        values['network'] = {'enforce': False}
        objects = render(values, parameters={'arc.image.repository': repository, 'arc.image.tag': '0.15.0@' + digest})
        deployment, = [row for row in objects if row['kind'] == 'Deployment']
        self.assertEqual(deployment['spec']['template']['spec']['containers'][0]['image'],
                         repository + ':0.15.0@' + digest)
        with self.assertRaises(subprocess.CalledProcessError):
            render(values, chart=POOL)
        with self.assertRaises(ValueError):
            configuration(qualified_tools(), fixture_repository(), 'main')
