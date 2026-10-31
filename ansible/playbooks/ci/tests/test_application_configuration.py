"""Repository onboarding shares the qualified profile and preserves trust boundaries."""
import copy
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import Mock, patch

from playbooks.ci.files.chart import POOL, render
from playbooks.ci.files.configuration import application_configuration
from playbooks.ci.files import configuration as command
from playbooks.ci.tests.fixtures import qualified_tools, pool_values


class ApplicationConfigurationTests(unittest.TestCase):
    def test_direct_testing_requires_fresh_proof_and_keeps_credentials_out_of_builder(self):
        application, current = self.inputs('example', 'public')
        application['testing'] = {'image': 'harbor.internal.example.invalid/cloudlab-public/test-env@sha256:' + 'a' * 64}
        templates = [{'repository_id': str(current['id']), 'repository': current['full_name'],
                      'visibility': 'public', 'workflow_path': '.github/workflows/ci.yaml',
                      'workflow_sha256': 'a' * 64, 'job': job,
                      'job_workflow_ref': current['full_name'] + '/.github/workflows/ci.yaml@refs/heads/main'}
                     for job in ('test', 'build')]
        with self.assertRaises(ValueError):
            application_configuration(qualified_tools(), application, current, templates=templates)
        qualified = qualified_tools(direct=True)
        document = application_configuration(qualified, application, current, templates=templates)['runner.json']
        values = document['values']
        objects = render(values, chart=POOL, namespace=document['namespace'])
        config = next(row for row in objects if row['kind'] == 'ConfigMap' and row['metadata']['name'] == 'cloudlab-testing')
        self.assertEqual(json.loads(config['data']['config.json']), application['testing'])
        self.assertEqual([r['job'] for r in values['workflowTemplates']], ['test', 'build'])
        builder = values['arc']['template']['spec']['initContainers'][0]
        self.assertFalse(any(row['name'] in ('testing', 'test-pull') for row in builder['volumeMounts']))
        for mutate in ('mutable', 'foreign', 'stale', 'missing-node', 'builder-secret', 'writable'):
            bad_app, bad_proof, bad_values = copy.deepcopy(application), copy.deepcopy(qualified), copy.deepcopy(values)
            with self.subTest(mutate=mutate):
                if mutate in ('builder-secret', 'writable'):
                    if mutate == 'builder-secret':
                        bad_values['arc']['template']['spec']['initContainers'][0]['volumeMounts'].append(
                            {'name': 'test-pull', 'mountPath': '/secret', 'readOnly': True})
                    else:
                        bad_values['arc']['template']['spec']['containers'][0]['volumeMounts'][-1]['readOnly'] = False
                    with self.assertRaises(subprocess.CalledProcessError):
                        render(bad_values, chart=POOL, namespace=document['namespace'])
                    continue
                if mutate == 'mutable': bad_app['testing']['image'] = bad_app['testing']['image'].split('@')[0] + ':latest'
                if mutate == 'foreign': bad_app['testing']['image'] = bad_app['testing']['image'].replace('cloudlab-public', 'cloudlab-private')
                if mutate == 'stale': bad_proof['direct_test_profile_sha256'] = '0' * 64
                if mutate == 'missing-node': bad_proof['direct_test_nodes_verified'] = 1
                with self.assertRaises(ValueError):
                    application_configuration(bad_proof, bad_app, current, templates=templates)

    def setUp(self):
        patcher = patch('playbooks.ci.files.network.discover', return_value={
            'enforce': True, 'apiServiceCIDRs': ['10.43.0.1/32'],
            'apiEndpointCIDRs': ['100.64.0.2/32'], 'registryCIDRs': ['100.64.0.3/32']})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_repository_owned_workflow_binds_roles_and_rejects_shared_or_unbounded_jobs(self):
        import base64
        import yaml
        application, current = self.inputs('example', 'public')
        workflow = {'jobs': {role: {'runs-on': 'cloudlab-example' + ('-publish' if role == 'publish' else ''),
                                   'timeout-minutes': 20, 'steps': [{'run': 'python ci/' + role + '.py'}]}
                             for role in ('test', 'publish')}}
        def approve(value):
            raw = yaml.safe_dump(value).encode()
            file = {'type': 'file', 'path': '.github/workflows/ci.yaml', 'encoding': 'base64',
                    'size': len(raw), 'content': base64.b64encode(raw).decode()}
            api = Mock()
            api.request.side_effect = lambda method, path, **kwargs: (
                {'object': {'sha': 'a' * 40}} if '/git/ref/' in path else
                {'protected': True} if '/branches/' in path else file)
            return command.application_templates(api, current, 'a' * 40,
                platform_repository='https://github.com/example/platform.git',
                application_name=application['name'], repository_owned=True)
        rows = approve(workflow)
        self.assertEqual({r['job'] for r in rows}, {'test', 'publish'})
        self.assertTrue(all(r['job_workflow_ref'] == 'example/example/.github/workflows/ci.yaml@refs/heads/main'
                            for r in rows))
        document = application_configuration(qualified_tools(), application, current,
            templates=[row for row in rows if row['job'] == 'test'])['runner.json']
        objects = render(document['values'], chart=POOL, namespace=document['namespace'])
        policy = next(o for o in objects if o['kind'] == 'ConfigMap' and 'eligibility.json' in o.get('data', {}))
        self.assertEqual(json.loads(policy['data']['eligibility.json'])['templates'],
                         [row for row in rows if row['job'] == 'test'])
        for field, value in (('runs-on', 'cloudlab-foreign'), ('container', 'untrusted'),
                             ('timeout-minutes', 0), ('timeout-minutes', True),
                             ('steps', [{'uses': 'actions/checkout@main'}]),
                             ('uses', 'foreign/workflow@main')):
            changed = copy.deepcopy(workflow)
            changed['jobs']['test'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): approve(changed)

    def test_publication_binds_the_owning_gitops_role_and_checks_existing_app_scope_read_only(self):
        application, current = self.inputs('example', 'public')
        targets = [('public-platform', 'example/gitops', False), ('private-config', 'example/private', True),
                   ('public-fixture', 'example/public-fixture', False), ('private-fixture', 'example/private-fixture', True)]
        metadata = {'full_name': 'example/gitops', 'private': False, 'fork': False,
                    'archived': False, 'default_branch': 'main', 'id': 456}
        api = Mock()
        api.request.return_value = metadata
        row = {'job': 'publish', 'job_workflow_ref': 'example/platform/.github/workflows/application-publish.yaml@' + 'b' * 40}
        with patch('playbooks.argocd.files.github_setup.configuration', return_value=targets), \
                patch('playbooks.ci.files.workflow_permissions.require_release_guard') as guard, \
                patch('playbooks.secrets.files.vault.fields', return_value={'APP_ID': '7'}) as fields, \
                patch('playbooks.harbor.files.scopes.verify_app') as scope:
            result = command.publication(api, {'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic-read-only'}, application,
                                         current, qualified_tools(), [row])
            self.assertEqual(result['release_repository'], 'example/gitops')
            self.assertEqual(result['release_repository_id'], 456)
            self.assertEqual(result['project'], 'cloudlab-public')
            guard.assert_called_once_with(api, 'example/gitops')
            self.assertEqual(scope.call_args.args[1], {'example/gitops': False})
            fields.assert_called_once_with('github-release-public', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
            fields.reset_mock()
            scope.reset_mock()
            api.request.return_value = dict(metadata, private=True)
            with self.assertRaises(ValueError):
                command.publication(api, {}, application, current, qualified_tools(), [row])
            fields.assert_not_called()
            scope.assert_not_called()

    def test_missing_release_guard_cannot_load_or_deliver_app_credentials(self):
        application, current = self.inputs('example', 'private')
        targets = [('public-platform', 'example/gitops', False), ('private-config', 'example/private', True)]
        api = Mock()
        api.request.return_value = {'full_name': 'example/private', 'private': True, 'fork': False,
                                    'archived': False, 'default_branch': 'main', 'id': 456}
        with patch('playbooks.argocd.files.github_setup.configuration', return_value=targets), \
                patch('playbooks.ci.files.workflow_permissions.require_release_guard', side_effect=ValueError('Unavailable')), \
                patch('playbooks.secrets.files.vault.fields') as fields:
            with self.assertRaises(ValueError):
                command.publication(api, {}, application, current, qualified_tools(),
                                    [{'job': 'publish', 'job_workflow_ref': 'example/workflow@' + 'a' * 40}])
            fields.assert_not_called()

    def test_private_exact_reusable_policy_pins_source_and_caller_sha_without_automatic_templates(self):
        application, current = self.inputs('example', 'private')
        workflows = [{'repository': current['full_name'], 'repository_id': str(current['id']),
                      'workflow_ref': current['full_name'] + '/.github/workflows/ci.yaml@refs/heads/main',
                      'workflow_sha': 'a' * 40, 'sha': 'a' * 40, 'ref': 'refs/heads/main',
                      'event_name': event, 'job': role}
                     for event in ('push', 'workflow_dispatch') for role in ('test', 'publish')]
        before = copy.deepcopy(workflows)
        document = application_configuration(qualified_tools(), application, current, workflows=workflows,
                                               exact_reusable=True)['runner.json']
        self.assertNotIn('workflowTemplates', document['values'])
        policies = document['values']['eligibility']
        self.assertEqual(len(policies), 2)
        self.assertTrue(all(row['job'] == '__default' and row['sha'] == row['workflow_sha'] == 'a' * 40 and
                            row['ref'] == 'refs/heads/main' for row in policies))
        self.assertEqual(workflows, before)
        changed = copy.deepcopy(workflows)
        changed[0]['sha'] = 'b' * 40
        with self.assertRaises(ValueError):
            application_configuration(qualified_tools(), application, current, workflows=changed, exact_reusable=True)
        public, public_current = self.inputs('example', 'public')
        with self.assertRaises(ValueError):
            application_configuration(qualified_tools(), public, public_current, workflows=workflows, exact_reusable=True)

    def test_publisher_uses_one_shared_budget_with_role_scoped_credentials_and_no_builder_secret_mounts(self):
        for scope, release_scope, mode in (('public', 'public', 'automatic'), ('private', 'private', 'automatic'),
                                           ('public', 'private', 'automatic'), ('public', 'private', 'manual')):
            application, current = self.inputs('example', scope)
            application['testing'] = {'image': 'harbor.internal.example.invalid/cloudlab-public/test-env@sha256:' + 'a' * 64}
            templates = [{'repository_id': str(current['id']), 'repository': current['full_name'],
                          'visibility': scope, 'workflow_path': '.github/workflows/ci.yaml',
                          'workflow_sha256': 'a' * 64, 'job': job,
                          'job_workflow_ref': 'example/platform/.github/workflows/application-' + job + '.yaml@' + 'b' * 40}
                         for job in ('test', 'publish')]
            publishing = {'application': 'example', 'source_repository': current['full_name'],
                          'source_repository_id': str(current['id']), 'visibility': scope,
                          'registry': 'registry.example.invalid', 'project': 'cloudlab-' + scope,
                          'release_repository': 'example/gitops', 'release_repository_id': 456,
                          'workflow_identity': 'https://github.com/' + templates[1]['job_workflow_ref']}
            if release_scope != scope:
                application.update(releaseRepository='example/gitops', primaryComponent='agent',
                                   components={'agent': {'dockerfile': 'deploy/agent.Dockerfile'}})
                publishing.update(release_visibility=release_scope, components=application['components'], primary_component='agent')
            if mode == 'manual':
                application['releaseMode'] = 'manual'
                publishing['release_mode'] = 'manual'
            documents = application_configuration(qualified_tools(direct=True), application, current,
                                                   templates=templates, publishing=publishing)
            self.assertEqual(set(documents), {'controller.json', 'runner.json', 'publisher.json'})
            self.assertEqual(documents['controller.json']['values']['runnerPools'], 2)
            primary, publisher = (documents[key]['values'] for key in ('runner.json', 'publisher.json'))
            self.assertIn('testing', primary)
            self.assertNotIn('testing', publisher)
            self.assertFalse(any(v['name'] in ('testing', 'test-pull') for v in publisher['arc']['template']['spec']['volumes']))
            self.assertEqual([row['job'] for row in primary['workflowTemplates']], ['test'])
            self.assertEqual([row['job'] for row in publisher['workflowTemplates']], ['publish'])
            self.assertFalse(any(row['name'].startswith('publish-') for row in primary['arc']['template']['spec']['volumes']))
            self.assertEqual(primary['arc']['template']['spec']['initContainers'], publisher['arc']['template']['spec']['initContainers'])
            namespace = documents['publisher.json']['namespace']
            objects = render(publisher, chart=POOL, namespace=namespace, release='publisher')
            secrets = [row for row in objects if row['kind'] == 'ExternalSecret']
            items = {entry['extract']['key'] for row in secrets for entry in row['spec']['dataFrom']}
            expected = {'github-release-' + release_scope, 'harbor-cloudlab-' + scope + '-pull',
                        'harbor-cloudlab-' + scope + '-push'}
            if mode == 'manual':
                expected.remove('github-release-' + release_scope)
                self.assertFalse(any(v['name'] == 'publish-github' for v in publisher['arc']['template']['spec']['volumes']))
                bad = copy.deepcopy(publisher)
                bad['arc']['template']['spec']['volumes'].append({'name': 'publish-github', 'secret': {'secretName': 'cloudlab-release'}})
                with self.assertRaises(subprocess.CalledProcessError): render(bad, chart=POOL, namespace=namespace)
            if scope == 'private':
                expected |= {'ci-private-signer', 'ci-private-verifier'}
            self.assertEqual(items, expected)
            if release_scope != scope:
                bad = copy.deepcopy(publisher)
                bad['publishing']['primary_component'] = 'missing'
                with self.assertRaises(subprocess.CalledProcessError):
                    render(bad, chart=POOL, namespace=namespace)
            unsafe = copy.deepcopy(publisher)
            unsafe['arc']['template']['spec']['initContainers'][0]['volumeMounts'].append(
                {'name': 'publish-push', 'mountPath': '/tmp/credential'})
            with self.assertRaises(subprocess.CalledProcessError):
                render(unsafe, chart=POOL, namespace=namespace)
            with self.assertRaises(ValueError):
                application_configuration(qualified_tools(), application, current,
                    templates=templates[:1], publishing=publishing)

    def test_release_target_is_independent_but_confined_to_the_designated_repository_and_app(self):
        application, current = self.inputs('example', 'public')
        application.update(releaseRepository='example/private-config', primaryComponent='agent',
                           components={'agent': {'dockerfile': 'deploy/agent.Dockerfile'}})
        template = {'job': 'publish', 'job_workflow_ref': 'example/example/.github/workflows/ci.yaml@refs/heads/main'}
        designated = [('public-platform', 'example/platform', False), ('private-config', 'example/private-config', True)]
        api = Mock()
        api.request.return_value = {'id': 456, 'full_name': 'example/private-config', 'private': True,
                                    'fork': False, 'archived': False, 'default_branch': 'main'}
        with patch('playbooks.argocd.files.github_setup.configuration', return_value=designated), \
                patch('playbooks.ci.files.workflow_permissions.require_release_guard') as guard, \
                patch('playbooks.secrets.files.vault.fields', return_value={}) as fields, \
                patch('playbooks.harbor.files.scopes.verify_app') as verify:
            document = command.publication(api, {}, application, current, qualified_tools(), [template])
            self.assertEqual(document['visibility'], 'public')
            self.assertEqual(document['project'], 'cloudlab-public')
            self.assertEqual(document['release_visibility'], 'private')
            self.assertEqual(document['release_repository'], 'example/private-config')
            self.assertEqual(document['release_repository_id'], 456)
            self.assertEqual(document['components'], application['components'])
            self.assertEqual(document['primary_component'], 'agent')
            fields.assert_called_once_with('github-release-private', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
            guard.assert_called_once_with(api, 'example/private-config')
            self.assertEqual(verify.call_args.args[1], {'example/private-config': True})
            fields.reset_mock(); guard.reset_mock(); verify.reset_mock()
            manual = command.publication(api, {}, dict(application, releaseMode='manual'), current, qualified_tools(), [template])
            self.assertEqual(manual['release_mode'], 'manual')
            self.assertEqual(manual['release_visibility'], 'private')
            fields.assert_not_called(); guard.assert_not_called(); verify.assert_not_called()
            fields.reset_mock(); api.reset_mock()
            for target in ('example/unapproved', 'foreign/private-config'):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    command.publication(api, {}, dict(application, releaseRepository=target), current, qualified_tools(), [template])
            api.request.assert_not_called(); fields.assert_not_called()
            private, private_current = self.inputs('example', 'private')
            with self.assertRaises(ValueError):
                command.publication(api, {}, dict(private, releaseRepository='example/platform'), private_current,
                                    qualified_tools(), [template])

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
            controller['values']['network'] = {'enforce': False}
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
