import copy
import unittest

from fixtures import PrivatePreviewGit
from playbooks.previews.tests import catalog_fixture as fixture


class PullFixtureTests(unittest.TestCase):
    def setUp(self):
        self.api, self.nonce, self.slot = PrivatePreviewGit(), 'a' * 32, 'a'
        self.receipt = fixture.pull_receipt(self.api, 'example/private', self.nonce, self.slot)
        self.saved = []

    def save(self):
        self.saved.append(copy.deepcopy(self.receipt))

    def create(self):
        fixture.commit_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        fixture.open_pull(self.api, self.receipt, self.nonce, self.slot, self.save)

    def test_lost_ref_pr_and_delete_responses_resume_without_duplicate_or_adoption(self):
        self.api.fail = 'ref'
        with self.assertRaises(RuntimeError): fixture.commit_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.assertEqual(self.saved[-1]['pending']['head'], self.api.head)
        fixture.commit_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.api.fail = 'pull'
        with self.assertRaises(RuntimeError): fixture.open_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.assertTrue(self.saved[-1]['pullIntent'])
        fixture.open_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.api.fail = 'delete'
        with self.assertRaises(RuntimeError): fixture.cleanup_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.assertTrue(self.saved[-1]['deleteIntent'])
        fixture.cleanup_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.assertTrue(self.receipt['deleted'])
        self.assertEqual(sum(method == 'POST' and path.endswith('/git/refs') for method, path, body in self.api.writes), 1)
        self.assertEqual(sum(method == 'POST' and path.endswith('/pulls') for method, path, body in self.api.writes), 1)
        self.assertEqual(sum(path == 'graphql' for method, path, body in self.api.writes), 1)
        self.assertFalse(any(method == 'DELETE' for method, path, body in self.api.writes))

    def test_concurrent_branch_and_stale_main_fail_before_any_git_write(self):
        for collision in ('branch', 'main'):
            api = PrivatePreviewGit()
            receipt = fixture.pull_receipt(api, 'example/private', self.nonce, self.slot)
            if collision == 'branch': api.head = 'f' * 40
            else: api.main = 'e' * 40
            with self.assertRaises(ValueError): fixture.commit_pull(api, receipt, self.nonce, self.slot, lambda: None)
            self.assertEqual(api.writes, [])

    def test_unapproved_commit_is_single_file_nonforced_and_cleanup_refuses_changed_head(self):
        self.create()
        original = self.receipt['head']
        self.api.fail = 'advance'
        with self.assertRaises(RuntimeError): fixture.commit_pull(self.api, self.receipt, self.nonce, self.slot, self.save, advance=True)
        fixture.commit_pull(self.api, self.receipt, self.nonce, self.slot, self.save, advance=True)
        self.assertNotEqual(self.receipt['head'], original)
        self.assertEqual(self.receipt['generation'], 1)
        self.assertEqual(sum(method == 'PATCH' and '/git/refs/' in path for method, path, body in self.api.writes), 1)
        self.api.head = 'e' * 40
        before = len(self.api.writes)
        with self.assertRaises(ValueError): fixture.cleanup_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.assertEqual(len(self.api.writes), before)

    def test_existing_unjournaled_pr_is_never_adopted(self):
        fixture.commit_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.api.number = 42
        with self.assertRaises(ValueError): fixture.open_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.assertIsNone(self.receipt['number'])

    def test_atomic_delete_preserves_a_commit_racing_the_last_ref_inspection(self):
        self.create()
        self.api.race_head = 'e' * 40
        with self.assertRaises(RuntimeError) as error:
            fixture.cleanup_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.assertEqual(self.api.head, 'e' * 40)
        self.assertFalse(self.receipt['deleted'])
        self.assertTrue(self.saved[-1]['deleteIntent'])
        self.assertNotIn('synthetic private provider mismatch', str(error.exception))
        mutation = next(body for method, path, body in self.api.writes if path == 'graphql')
        update = mutation['variables']['input']['refUpdates'][0]
        self.assertEqual(update, {'name': 'refs/heads/' + self.receipt['branch'], 'beforeOid': self.receipt['head'],
                                  'afterOid': '0' * 40, 'force': False})

    def test_graphql_errors_missing_or_malformed_data_never_mark_deletion(self):
        for response in (None, [], {'errors': [{'message': 'private-sentinel'}]}, {'data': None}, {'data': {'updateRefs': None}},
                         {'data': {'updateRefs': {'clientMutationId': 'wrong'}}},
                         {'errors': {}, 'data': {'updateRefs': {'clientMutationId': 'wrong'}}}):
            with self.subTest(response=response):
                self.setUp()
                self.create()
                self.api.graphql_result = response
                with self.assertRaises(RuntimeError) as error:
                    fixture.cleanup_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
                self.assertNotIn('private-sentinel', str(error.exception))
                self.assertFalse(self.receipt['deleted'])
                self.assertEqual(self.api.head, self.receipt['head'])

    def test_success_requires_absence_readback_and_repository_identity_cannot_change(self):
        self.create()
        self.api.retain_ref = True
        with self.assertRaises(RuntimeError): fixture.cleanup_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.assertFalse(self.receipt['deleted'])
        for field, value in (('repository_id', 999), ('repository_node', 'R_another')):
            with self.subTest(field=field):
                self.setUp()
                self.create()
                setattr(self.api, field, value)
                writes = len(self.api.writes)
                with self.assertRaises(ValueError): fixture.cleanup_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
                self.assertEqual(len(self.api.writes), writes)

    def test_malformed_expected_head_fails_before_any_cleanup_mutation(self):
        self.create()
        self.receipt['head'] = None
        writes = len(self.api.writes)
        with self.assertRaises(ValueError): fixture.cleanup_pull(self.api, self.receipt, self.nonce, self.slot, self.save)
        self.assertEqual(len(self.api.writes), writes)
