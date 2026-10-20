"""Qualify native repository policy fields and reject broader state or resource changes."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.ci.files import workflow_permissions as permissions
from playbooks.ci.tests.fixtures import workflow_permissions
from playbooks.infrastructure.files.backend import environment


class WorkflowPermissionsTests(unittest.TestCase):
    def plan(self, *, importing=False, changed=True):
        desired, observed = workflow_permissions()
        policy = json.loads((permissions.BASE / 'policy.json').read_text())
        rows = []
        for key, repository in desired['repositories'].items():
            before = dict(observed[key], id=repository['name'], repository=repository['name'])
            after = dict((observed if importing else policy)[key], id=repository['name'], repository=repository['name'])
            change = {'actions': ['no-op'] if importing or not changed else ['update'],
                      'before': None if importing else before, 'after': after}
            if importing:
                change['importing'] = {'id': repository['name']}
            elif not changed:
                change['before'] = copy.deepcopy(after)
            rows.append({'address': 'github_workflow_repository_permissions.release[' + json.dumps(key) + ']',
                         'type': 'github_workflow_repository_permissions', 'change': change})
        return {'resource_changes': rows}, desired, observed, policy

    def test_import_is_creation_free_and_policy_convergence_changes_only_approved_fields(self):
        plan, desired, observed, _ = self.plan(importing=True)
        permissions.guard(plan, desired, observed, importing=True)
        plan, desired, _, policy = self.plan()
        permissions.guard(plan, desired, policy)
        plan['resource_changes'][0]['change']['before']['default_workflow_permissions'] = 'write'
        permissions.guard(plan, desired, policy)
        plan['resource_changes'][0]['change']['before']['etag'] = 'old-computed-etag'
        plan['resource_changes'][0]['change']['after']['etag'] = None
        plan['resource_changes'][0]['change']['after_unknown'] = {'etag': True}
        permissions.guard(plan, desired, policy)

    def test_import_cannot_modify_fields_or_adopt_another_repository(self):
        for field in ('actions', 'import_id', 'default_permission'):
            plan, desired, observed, _ = self.plan(importing=True)
            row = plan['resource_changes'][0]['change']
            if field == 'actions':
                row['actions'] = ['update']
            elif field == 'import_id':
                row['importing']['id'] = 'other'
            else:
                row['after']['default_workflow_permissions'] = 'write'
            with self.subTest(field=field), self.assertRaises(ValueError):
                permissions.guard(plan, desired, observed, importing=True)

    def test_unapproved_resource_scope_replacement_or_unowned_fields_fail_closed(self):
        for change in ('extra', 'create', 'delete', 'replace', 'identity', 'repository', 'permission', 'foreign_field'):
            plan, desired, _, policy = self.plan()
            row = plan['resource_changes'][0]['change']
            if change == 'extra':
                plan['resource_changes'].append(copy.deepcopy(plan['resource_changes'][0]))
            elif change in ('create', 'delete', 'replace'):
                row['actions'] = ['delete', 'create'] if change == 'replace' else [change]
            elif change in ('identity', 'repository'):
                row['after']['id' if change == 'identity' else 'repository'] = 'other'
            elif change == 'permission':
                row['after']['can_approve_pull_request_reviews'] = not policy['public_platform']['can_approve_pull_request_reviews']
            else:
                row['before']['foreign_field'] = 'retain'
                row['after']['foreign_field'] = 'changed'
            with self.subTest(change=change), self.assertRaises(ValueError):
                permissions.guard(plan, desired, policy)

    def test_foreign_or_incomplete_state_cannot_trigger_live_provider_refresh(self):
        plan, desired, _, _ = self.plan(changed=False)
        state = {'values': {'root_module': {'resources': [
            {'address': row['address'], 'type': row['type'], 'values': row['change']['after']}
            for row in plan['resource_changes']]}, 'outputs': {
                'repository_identities': {'value': permissions.identities(desired)}}}}
        self.assertTrue(permissions.occupied(state, desired))
        self.assertFalse(permissions.occupied({}, desired))
        for kind in ('module', 'missing', 'address', 'type', 'identity', 'original_id'):
            changed = copy.deepcopy(state)
            root = changed['values']['root_module']
            if kind == 'module': root['child_modules'] = [{'address': 'module.foreign'}]
            elif kind == 'missing': root['resources'] = []
            elif kind == 'address': root['resources'][0]['address'] = 'github_repository.foreign'
            elif kind == 'type': root['resources'][0]['type'] = 'github_repository'
            elif kind == 'identity': root['resources'][0]['values']['id'] = 'foreign'
            else: changed['values']['outputs']['repository_identities']['value']['public_platform']['id'] = 999
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                permissions.occupied(changed, desired)

    def test_only_designated_gitops_repositories_are_read_and_unknown_api_fields_are_retained(self):
        desired, observed = workflow_permissions()
        targets = [('public-platform', 'example/public-gitops', False),
                   ('private-config', 'example/private-gitops', True),
                   ('public-fixture', 'example/public-app', False), ('private-fixture', 'example/private-app', True)]
        replies = []
        for key, private in (('public_platform', False), ('private_config', True)):
            repository = desired['repositories'][key]
            replies += [dict(repository, full_name='example/' + repository['name'], private=private,
                             fork=False, archived=False), observed[key]]
        api = Mock()
        api.request.side_effect = replies
        with patch.object(permissions, 'configuration', return_value=targets):
            self.assertEqual(permissions.repositories(api, {}), (desired, observed))
            self.assertTrue(all(call.args[0] == 'GET' and '/orgs/' not in call.args[1]
                                and '-app/' not in call.args[1] for call in api.request.call_args_list))
            api.request.side_effect = [replies[0], dict(observed['public_platform'], future_policy='retain')]
            with self.assertRaises(ValueError):
                permissions.repositories(api, {})

    def test_work_directory_cannot_inject_implicit_inputs_or_redirect_source_files(self):
        for filename in ('foreign.tf', 'terraform.tfvars.json', 'versions.tf'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                target = directory / filename
                outside = directory / 'outside'
                outside.write_text('retained')
                if filename == 'versions.tf':
                    target.symlink_to(outside)
                else:
                    target.write_text('retained')
                with self.assertRaises(ValueError):
                    permissions.copy_source(directory)
                self.assertEqual(outside.read_text(), 'retained')

    def test_native_provider_schema_and_both_import_and_managed_policies_without_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            permissions.copy_source(directory)
            shutil.copytree(permissions.BASE / 'tests', directory / 'tests')
            env = environment({'USERNAME': 'fixture', 'TOKEN': 'not-a-real-credential'},
                'https://gitlab.com/api/v4/projects/123/terraform/state/ci-workflow-permissions',
                'synthetic-encryption-passphrase-with-at-least-32-characters')
            self.assertFalse(any(key.startswith('OP_') for key in env))
            for command in (['tofu', 'init', '-backend=false', '-lockfile=readonly', '-input=false'],
                            ['tofu', 'fmt', '-check'], ['tofu', 'test', '-no-color']):
                result = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
