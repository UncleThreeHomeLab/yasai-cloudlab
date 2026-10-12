import unittest
import copy
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from automation.infra import github_adoption as adoption
from automation.infra.tests.fixtures import github_owner


class GitHubAdoptionTests(unittest.TestCase):
    def test_reverse_preserves_current_history_after_legitimate_code_commits(self):
        snapshot = github_owner()
        snapshot['fixture']['branch']['commit'] = {'sha': 'original'}
        desired, imports = adoption.declarations(snapshot)
        checkpoint = {'desired': desired, 'imports': imports, 'snapshot': snapshot}
        current = copy.deepcopy(snapshot)
        current['fixture']['branch']['commit']['sha'] = 'newer'
        with patch.object(adoption, 'GitHub', return_value=Mock()), patch.object(adoption, 'capture', return_value=current):
            with self.assertRaisesRegex(ValueError, 'history changed'):
                adoption.preserved(checkpoint, 'synthetic-token')
            self.assertEqual(adoption.preserved(checkpoint, 'synthetic-token', history=False), {'fixture': 'newer'})

    def maintenance(self, directory):
        destination = Path(directory) / 'inputs'
        destination.mkdir()
        work = Path(directory) / 'work'
        path = work / 'github'
        path.mkdir(parents=True)
        desired, imports = adoption.declarations(github_owner())
        binding = {'revision': 'synthetic-revision', 'source_hash': 'synthetic-hash'}
        checkpoint = {'phase': 'prepared', 'binding': binding, 'desired': desired,
                      'snapshot': github_owner(), 'imports': imports, 'operation': 'synthetic-operation',
                      'private_inputs': dict.fromkeys(('desired.tfvars.json', 'backend.json', 'credentials.env',
                                                     'encryption.json', 'inventory.json'), 'synthetic-digest')}
        (destination / 'handoff.json').write_text(json.dumps(checkpoint))
        gates = ('native_import', 'native_update', 'repeat_plan_empty', 'identities_policy_history_preserved',
                 'disposable_drift_detected_repaired', 'provider_success_failed_upload_recovery',
                 'concurrent_apply_rejected', 'public_private_clone_access', 'free_pr_enforcement', 'fixtures_removed')
        (path / 'qualification-result.json').write_text(json.dumps(dict.fromkeys(gates, True) | {
            'source_hash': binding['source_hash'], 'declaration_hash': adoption.declaration_hash()}))
        client = Mock(path=path, desired=desired, inventory=adoption.inventory(imports), env={'GITHUB_TOKEN': 'synthetic'})
        client.binding = {'inputs': checkpoint['private_inputs'].copy()}
        return destination, work, checkpoint, client

    def test_failed_native_import_retains_importing_checkpoint_for_safe_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            destination, work, checkpoint, client = self.maintenance(directory)
            client.native.return_value = SimpleNamespace(returncode=1)
            with patch.object(adoption, 'WORK', work), patch.object(adoption, 'source_binding', return_value=checkpoint['binding']), \
                    patch.object(adoption, 'Client', return_value=client), patch.object(adoption, 'preserved'), \
                    patch.object(adoption, 'reviewed_import'):
                with self.assertRaisesRegex(RuntimeError, 'recovery retained'):
                    adoption.advance(destination)
            self.assertEqual(json.loads((destination / 'handoff.json').read_text())['phase'], 'importing')
            self.assertEqual(json.loads((destination / 'acceptance.json').read_text())['status'], 'importing')
            self.assertTrue((client.path / 'imports.tf.json').exists())

    def test_imported_checkpoint_resumes_acceptance_without_duplicate_import(self):
        with tempfile.TemporaryDirectory() as directory:
            destination, work, checkpoint, client = self.maintenance(directory)
            checkpoint['phase'] = 'imported'
            (destination / 'handoff.json').write_text(json.dumps(checkpoint))
            with patch.object(adoption, 'WORK', work), patch.object(adoption, 'source_binding', return_value=checkpoint['binding']), \
                    patch.object(adoption, 'Client', return_value=client), patch.object(adoption, 'preserved'), \
                    patch.object(adoption, 'reviewed_import') as imports, patch.object(adoption, 'plan', return_value=(0, {})):
                adoption.advance(destination)
            imports.assert_not_called()
            client.native.assert_not_called()
            self.assertEqual(json.loads((destination / 'acceptance.json').read_text())['status'], 'accepted')

    def test_reverse_withdraws_acceptance_before_state_only_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            destination, _, checkpoint, client = self.maintenance(directory)
            checkpoint['phase'] = 'accepted'
            (destination / 'handoff.json').write_text(json.dumps(checkpoint))
            address = 'github_repository.repository["fixture"]'
            state = {'resources': [{'type': 'github_repository', 'name': 'repository', 'instances': [
                {'index_key': 'fixture', 'attributes': client.inventory[address]}]}]}
            def native(*arguments):
                self.assertEqual(json.loads((destination / 'acceptance.json').read_text())['status'], 'reversing')
                if arguments[:2] == ('state', 'pull'):
                    result = state.copy()
                    state.clear()
                    return SimpleNamespace(returncode=0, stdout=json.dumps(result).encode())
                self.assertEqual(arguments[:2], ('state', 'rm'))
                self.assertEqual(arguments[-1], address)
                return SimpleNamespace(returncode=0)
            client.native.side_effect = native
            with patch.object(adoption, 'Client', return_value=client), patch.object(adoption, 'preserved'), \
                    patch('automation.infra.retention.ciphertext', return_value=b'protected-ciphertext'):
                adoption.reverse(destination)
            self.assertTrue(list(client.path.glob('reverse-*.encrypted')))
            self.assertEqual(json.loads((destination / 'handoff.json').read_text())['phase'], 'reversed')

    def test_existing_ids_history_visibility_reviews_and_bypass_scope_survive(self):
        snapshot = github_owner()
        snapshot['fixture']['rulesets'][0]['bypass_actors'] = [
            {'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'pull_request'}]
        desired, imports = adoption.declarations(snapshot)
        self.assertEqual(desired['repositories']['fixture']['visibility'], 'public')
        self.assertEqual(imports['github_repository.repository["fixture"]'], {
            'id': 'synthetic-repository', 'import_id': 'synthetic-repository', 'repo_id': 123, 'node_id': 'synthetic-node'})
        self.assertEqual(imports['github_branch_default.default["fixture"]']['id'], 'synthetic-repository')
        rule = desired['rulesets']['fixture_ruleset_1']
        self.assertEqual(rule['pull_request']['required_approving_review_count'], 0)
        self.assertEqual(rule['bypass_actors'], snapshot['fixture']['rulesets'][0]['bypass_actors'])

    def test_empty_repository_has_no_branch_creation_or_import(self):
        snapshot = github_owner()
        snapshot['fixture']['branch'] = None
        desired, imports = adoption.declarations(snapshot)
        self.assertIsNone(desired['repositories']['fixture']['default_branch'])
        self.assertNotIn('github_branch_default.default["fixture"]', imports)

    def test_non_default_or_unknown_review_fields_are_not_discarded(self):
        for field, value in (('require_extra_approval_for_unattributed_changes', False),
                             ('dismissal_restriction', {'enabled': True, 'allowed_actors': []}),
                             ('required_reviewers', [{'team': 1}]), ('new_future_requirement', True)):
            with self.subTest(field=field):
                snapshot = github_owner()
                snapshot['fixture']['rulesets'][0]['rules'][-1]['parameters'][field] = value
                with self.assertRaises(ValueError):
                    adoption.declarations(snapshot)

    def test_unsupported_rule_never_becomes_weaker_policy(self):
        snapshot = github_owner()
        snapshot['fixture']['rulesets'][0]['rules'].append({'type': 'required_signatures'})
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            adoption.declarations(snapshot)

    def test_read_only_observer_allows_supported_drift_but_rejects_identity_change(self):
        snapshot = github_owner()
        desired, imports = adoption.declarations(snapshot)
        snapshot['fixture']['repository']['description'] = 'disposable drift'
        with patch.object(adoption, 'GitHub', return_value=Mock()), patch.object(adoption, 'capture', return_value=snapshot):
            adoption.observe(desired, adoption.inventory(imports), 'synthetic-token')
            snapshot['fixture']['repository']['id'] = 999
            with self.assertRaisesRegex(ValueError, 'identities'):
                adoption.observe(desired, adoption.inventory(imports), 'synthetic-token')


if __name__ == '__main__':
    unittest.main()
