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
        if not importing:
            tag = {'id': '125', 'repository': desired['repositories']['public_platform']['name'],
                   'name': permissions.TAG_NAME, 'target': 'tag', 'enforcement': 'active',
                   'conditions': [{'ref_name': [{'include': ['~ALL'], 'exclude': []}]}],
                   'bypass_actors': [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}],
                   'rules': [{'creation': True, 'update': True, 'deletion': True}]}
            rows.append({'address': permissions.TAG_GUARD, 'type': 'github_repository_ruleset',
                         'change': {'actions': ['no-op'], 'before': copy.deepcopy(tag), 'after': tag}})
            value = {'id': '123', 'repository': desired['repositories']['public_platform']['name'],
                     'name': permissions.MERGE_NAME, 'target': 'branch', 'enforcement': 'active',
                     'conditions': [{'ref_name': [{'include': ['~DEFAULT_BRANCH'], 'exclude': []}]}],
                     'bypass_actors': [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'pull_request'}],
                     'rules': [{'update': True}]}
            rows.append({'address': permissions.MERGE_GUARD, 'type': 'github_repository_ruleset',
                         'change': {'actions': ['no-op'], 'before': copy.deepcopy(value), 'after': value}})
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

    def test_merge_guard_refuses_app_bypass_direct_push_scope_changes_or_removal(self):
        for defect in ('app', 'direct', 'branch', 'repository', 'extra_rule', 'remove', 'replace'):
            plan, desired, _, policy = self.plan()
            change = plan['resource_changes'][-1]['change']
            after = change['after']
            if defect == 'app': after['bypass_actors'][0]['actor_type'] = 'Integration'
            elif defect == 'direct': after['bypass_actors'][0]['bypass_mode'] = 'always'
            elif defect == 'branch': after['conditions'][0]['ref_name'][0]['include'] = ['~ALL']
            elif defect == 'repository': after['repository'] = 'private-gitops'
            elif defect == 'extra_rule': after['rules'][0]['pull_request'] = [{'required_approving_review_count': 0}]
            else: change['actions'] = ['delete', 'create'] if defect == 'replace' else ['delete']
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                permissions.guard(plan, desired, policy)

    def test_publishing_requires_live_merge_gate_and_independent_pull_request_rule(self):
        merge = {'id': 123, 'name': permissions.MERGE_NAME, 'target': 'branch', 'enforcement': 'active',
                 'conditions': {'ref_name': {'include': ['~DEFAULT_BRANCH'], 'exclude': []}},
                 'bypass_actors': [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'pull_request'}],
                 'rules': [{'type': 'update'}]}
        pull = {'id': 124, 'name': 'main', 'target': 'branch', 'enforcement': 'active',
                'conditions': {'ref_name': {'include': ['refs/heads/main'], 'exclude': []}},
                'bypass_actors': [], 'rules': [{'type': 'pull_request'}]}
        tag = {'id': 125, 'name': permissions.TAG_NAME, 'target': 'tag', 'enforcement': 'active',
               'conditions': {'ref_name': {'include': ['~ALL'], 'exclude': []}},
               'bypass_actors': [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}],
               'rules': [{'type': key} for key in ('creation', 'update', 'deletion')]}
        for defect in (None, 'missing', 'app', 'direct', 'inactive', 'no_pr', 'pr_bypass', 'tag_missing', 'tag_app', 'tag_update'):
            rows = copy.deepcopy([merge, pull, tag])
            if defect == 'missing': rows.pop(0)
            elif defect == 'app': rows[0]['bypass_actors'][0]['actor_type'] = 'Integration'
            elif defect == 'direct': rows[0]['bypass_actors'][0]['bypass_mode'] = 'always'
            elif defect == 'inactive': rows[0]['enforcement'] = 'disabled'
            elif defect == 'no_pr': rows[1]['rules'] = []
            elif defect == 'pr_bypass': rows[1]['bypass_actors'] = [{'actor_type': 'Integration'}]
            elif defect == 'tag_missing': rows.pop()
            elif defect == 'tag_app': rows[2]['bypass_actors'][0]['actor_type'] = 'Integration'
            elif defect == 'tag_update': rows[2]['rules'].pop(1)
            api = Mock()
            api.request.side_effect = lambda method, path: (rows if '?includes_parents' in path else
                                                            next(row for row in rows if path.endswith('/' + str(row['id']))))
            if defect is None:
                permissions.require_release_guard(api, 'example/public-gitops')
            else:
                with self.subTest(defect=defect), self.assertRaises(ValueError):
                    permissions.require_release_guard(api, 'example/public-gitops')

    def test_tag_guard_cannot_exclude_refs_expand_bypass_or_drop_any_mutation_rule(self):
        for defect in ('exclude', 'app', 'scope', 'creation', 'update', 'deletion', 'remove'):
            plan, desired, _, policy = self.plan()
            change = next(row['change'] for row in plan['resource_changes'] if row['address'] == permissions.TAG_GUARD)
            value = change['after']
            if defect == 'exclude': value['conditions'][0]['ref_name'][0]['exclude'] = ['refs/tags/main']
            elif defect == 'app': value['bypass_actors'][0]['actor_type'] = 'Integration'
            elif defect == 'scope': value['conditions'][0]['ref_name'][0]['include'] = ['refs/tags/release-*']
            elif defect == 'remove': change['actions'] = ['delete']
            else: value['rules'][0][defect] = False
            with self.subTest(defect=defect), self.assertRaises(ValueError): permissions.guard(plan, desired, policy)

    def test_existing_merge_guard_cannot_be_duplicated_or_adopted_from_another_state(self):
        desired, _ = workflow_permissions()
        api = Mock()
        api.request.return_value = [{'name': permissions.MERGE_NAME, 'id': 123}]
        with self.assertRaises(ValueError):
            permissions.guard_existing_merge_rule(api, desired, {})
        state = {'values': {'root_module': {'resources': [{'address': permissions.MERGE_GUARD,
            'values': {'ruleset_id': 123}}]}}}
        permissions.guard_existing_merge_rule(api, desired, state)
        api.request.return_value.append({'name': permissions.MERGE_NAME, 'id': 456})
        with self.assertRaises(ValueError):
            permissions.guard_existing_merge_rule(api, desired, state)

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
