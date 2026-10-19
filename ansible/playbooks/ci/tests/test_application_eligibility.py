"""Exact reviewed revisions and same-repository PR origins precede runner registration."""
import copy
import base64
import hashlib
import unittest
from unittest.mock import Mock

from playbooks.ci.files.configuration import application_workflows, application_templates


class ApplicationEligibilityTests(unittest.TestCase):
    def test_template_approval_pins_reviewed_bytes_and_requires_protected_main(self):
        content = b'jobs:\n  test:\n    uses: example/platform/.github/workflows/application-test.yaml@' + b'b' * 40 + b'\n'
        file = {'type': 'file', 'path': '.github/workflows/ci.yaml', 'encoding': 'base64',
                'size': len(content), 'content': base64.b64encode(content).decode()}
        current = dict(self.current, private=False)
        called = b'''jobs:
  test:
    runs-on: "${{ format('cloudlab-{0}', inputs.application) }}"
    steps: [{run: 'true'}]
'''
        called_file = {'type': 'file', 'path': '.github/workflows/application-test.yaml', 'encoding': 'base64',
                       'size': len(called), 'content': base64.b64encode(called).decode()}
        self.api.request.side_effect = [self.request, {'type': 'file'}, {'protected': True}, file, called_file]
        rows = application_templates(self.api, current, self.revision, 42,
                                     platform_repository='https://github.com/example/platform.git')
        self.assertEqual({row['job'] for row in rows}, {'test'})
        self.assertEqual(rows[0]['job_workflow_ref'], 'example/platform/.github/workflows/application-test.yaml@' + 'b' * 40)
        self.assertTrue(all(row['workflow_sha256'] == hashlib.sha256(content).hexdigest() and
                            row['visibility'] == 'public' for row in rows))
        for branch, workflow in (({'protected': False}, file), ({'protected': True}, dict(file, size=65537)),
                                 ({'protected': True}, dict(file, size=1))):
            self.api.request.side_effect = [self.request, {'type': 'file'}, branch, workflow]
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                application_templates(self.api, current, self.revision, 42)

        for bad in (called.replace(b"cloudlab-{0}", b"ubuntu-latest"), called + b"  extra: {steps: [{run: 'true'}]}\n"):
            invalid = dict(called_file, size=len(bad), content=base64.b64encode(bad).decode())
            self.api.request.side_effect = [self.request, {'type': 'file'}, {'protected': True}, file, invalid]
            with self.assertRaises(ValueError):
                application_templates(self.api, current, self.revision, 42,
                                      platform_repository='https://github.com/example/platform.git')
        for bad in (content.replace(b'example/platform', b'foreign/platform'), content.replace(b'b' * 40, b'main')):
            invalid = dict(file, size=len(bad), content=base64.b64encode(bad).decode())
            self.api.request.side_effect = [self.request, {'type': 'file'}, {'protected': True}, invalid]
            with self.assertRaises(ValueError):
                application_templates(self.api, current, self.revision, 42,
                                      platform_repository='https://github.com/example/platform.git')

    def setUp(self):
        self.current = {'id': 123, 'full_name': 'example/application'}
        self.revision = 'a' * 40
        origin = dict(self.current, fork=False)
        self.request = {'state': 'open', 'mergeable': True, 'merge_commit_sha': self.revision,
                        'base': {'ref': 'main', 'repo': origin}, 'head': {'repo': copy.deepcopy(origin)}}
        self.api = Mock()

    def test_only_the_exact_reviewed_internal_merge_can_get_a_test_job(self):
        self.api.request.side_effect = [self.request, {'type': 'file'}]
        rows = application_workflows(self.api, self.current, self.revision, 42)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], {'repository_id': '123', 'repository': 'example/application',
            'workflow_ref': 'example/application/.github/workflows/ci.yaml@refs/pull/42/merge',
            'workflow_sha': self.revision, 'sha': self.revision, 'ref': 'refs/pull/42/merge',
            'event_name': 'pull_request', 'job': 'test'})
        self.assertTrue(all(call.args[0] == 'GET' for call in self.api.request.call_args_list))

    def test_fork_foreign_closed_stale_and_unknown_mergeability_fail_before_workflow_access(self):
        for change in ('fork', 'foreign_id', 'foreign_name', 'closed', 'stale', 'unknown', 'base'):
            request = copy.deepcopy(self.request)
            if change == 'fork': request['head']['repo']['fork'] = True
            elif change == 'foreign_id': request['head']['repo']['id'] = 999
            elif change == 'foreign_name': request['head']['repo']['full_name'] = 'foreign/application'
            elif change == 'closed': request['state'] = 'closed'
            elif change == 'stale': request['merge_commit_sha'] = 'b' * 40
            elif change == 'unknown': request['mergeable'] = None
            else: request['base']['ref'] = 'unreviewed'
            self.api.reset_mock()
            self.api.request.side_effect = [request]
            with self.subTest(change=change), self.assertRaises(ValueError):
                application_workflows(self.api, self.current, self.revision, 42)
            self.assertEqual(self.api.request.call_count, 1)

    def test_main_registration_requires_current_main_and_the_exact_workflow(self):
        self.api.request.side_effect = [{'object': {'sha': self.revision}}, {'type': 'file'}]
        rows = application_workflows(self.api, self.current, self.revision)
        self.assertEqual({(row['event_name'], row['job']) for row in rows}, {
            ('push', 'test'), ('push', 'publish'), ('workflow_dispatch', 'test'), ('workflow_dispatch', 'publish')})
        self.api.request.side_effect = [{'object': {'sha': 'b' * 40}}]
        with self.assertRaises(ValueError):
            application_workflows(self.api, self.current, self.revision)
        self.api.request.side_effect = [self.request, None]
        with self.assertRaises(ValueError):
            application_workflows(self.api, self.current, self.revision, 42)

    def test_invalid_revision_or_number_never_reaches_github(self):
        for revision, number in (('main', 42), (self.revision, 0), (self.revision, -1), (self.revision, True)):
            self.api.reset_mock()
            with self.subTest(revision=revision, number=number), self.assertRaises(ValueError):
                application_workflows(self.api, self.current, revision, number)
            self.api.request.assert_not_called()
