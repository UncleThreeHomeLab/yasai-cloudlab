import copy
import json
from pathlib import Path
import tempfile
import unittest

from automation.harbor import api, api_policy
from automation.harbor.tests.fixtures import completed_api_plan
from automation.infra.backend import environment
from automation.infra.native import native


class NativePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        api.copy_source(cls.directory)
        versions = cls.directory / 'versions.tf'
        text = versions.read_text()
        if text.count('  backend "http" {}') != 1:
            raise AssertionError('Synthetic native fixture must remove its production backend')
        versions.write_text(text.replace('  backend "http" {}', ''))
        secret = 'synthetic-ephemeral-password-' + 'x' * 48
        cls.secret = secret
        env = environment({'USERNAME': 'synthetic', 'TOKEN': 'synthetic'}, 'https://example.invalid',
                          'synthetic-only-passphrase-never-used-for-live-state')
        env = {key: value for key, value in env.items() if not key.startswith('TF_HTTP_')}
        env.update(HARBOR_URL='https://127.0.0.1:1', HARBOR_USERNAME='synthetic', HARBOR_PASSWORD='synthetic',
                   TF_VAR_robot_secrets=json.dumps({project + '-' + role: secret
                       for project in ('cloudlab-public', 'cloudlab-private') for role in ('push', 'pull')}))
        for arguments in (('init', '-backend=false', '-input=false', '-lockfile=readonly'),
                          ('plan', '-input=false', '-refresh=false', '-out=synthetic.tfplan')):
            result = native(cls.directory, env, *arguments)
            if result.returncode:
                raise AssertionError('Credential-free native Harbor fixture failed: ' + result.stderr.decode())
        cls.plan = json.loads(native(cls.directory, env, 'show', '-json', 'synthetic.tfplan').stdout)

    def test_real_provider_bootstrap_plan_preserves_scope_and_write_only_custody(self):
        self.assertEqual(api_policy.plan(self.plan, bootstrap=True), 18)
        self.assertNotIn(self.secret, json.dumps(self.plan))
        self.assertNotIn(self.secret.encode(), (self.directory / 'synthetic.tfplan').read_bytes())
        self.assertEqual(api_policy.plan(completed_api_plan(self.plan)), 0)

    def test_robot_import_can_only_restore_original_version_metadata_under_maintenance(self):
        value = completed_api_plan(self.plan)
        robot = next(row for row in value['resource_changes'] if row['type'] == 'harbor_robot_account')
        robot['change']['before']['secret_wo_version'] = 0
        robot['change']['actions'] = ['update']
        with self.assertRaisesRegex(ValueError, 'must not rotate'): api_policy.plan(value)
        self.assertEqual(api_policy.plan(value, imported=True), 1)
        robot['change']['before']['description'] = 'unrecognized robot'
        with self.assertRaisesRegex(ValueError, 'must not rotate'): api_policy.plan(value, imported=True)

    def test_registry_privilege_or_preservation_weakening_is_rejected(self):
        changes = (
            ('harbor_project', lambda row: row.update(public=True)),
            ('harbor_project', lambda row: row.update(storage_quota=21)),
            ('harbor_robot_account', lambda row: row['permissions'][0].update(namespace='other-project')),
            ('harbor_robot_account', lambda row: row['permissions'][0]['access'].append({'action': 'delete', 'resource': 'repository', 'effect': 'allow'})),
            ('harbor_retention_policy', lambda row: row['rule'][0].update(untagged_artifacts=False)),
            ('harbor_retention_policy', lambda row: row.update(schedule='Daily')),
            ('harbor_immutable_tag_rule', lambda row: row.update(disabled=True)),
            ('harbor_project_member_group', lambda row: row.update(type='internal')),
        )
        for kind, mutation in changes:
            value = copy.deepcopy(self.plan)
            row = next(row for row in value['resource_changes'] if row['type'] == kind)
            mutation(row['change']['after'])
            with self.subTest(kind=kind), self.assertRaises(ValueError): api_policy.plan(value, bootstrap=True)

    def test_replacement_unknown_resource_or_foreign_group_cannot_be_applied(self):
        value = completed_api_plan(self.plan)
        value['resource_changes'][0]['change']['actions'] = ['delete', 'create']
        with self.assertRaises(ValueError): api_policy.plan(value)
        value = completed_api_plan(self.plan)
        value['resource_changes'].append(copy.deepcopy(value['resource_changes'][0]))
        with self.assertRaises(ValueError): api_policy.plan(value)
        value = completed_api_plan(self.plan)
        row = next(row for row in value['resource_changes'] if row['type'] == 'harbor_project_member_group')
        row['change']['after']['group_id'] = 999
        with self.assertRaisesRegex(ValueError, 'another OIDC group'): api_policy.plan(value)
