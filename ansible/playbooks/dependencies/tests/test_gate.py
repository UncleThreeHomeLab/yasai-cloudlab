"""Draft conversion and final head receipts fail closed across bot writes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from playbooks.dependencies.files.gate import Gate, branch_prefix

SCOPE = {'repository': 'example/platform', 'repositoryId': 1, 'requester': 'release[bot]',
         'base': 'main', 'branchPrefix': branch_prefix('main')}
HEAD, BASE = '1' * 40, '2' * 40
EVIDENCE = {'head': HEAD, 'base': BASE, 'candidateTree': 'a' * 64,
            'pinset': 'b' * 64, 'helpers': 'c' * 64,
            'toolchain': ['example/image:1@sha256:' + 'd' * 64],
            'checks': {'owner-check': 'PASS'}}


class API:
    def __init__(self):
        self.row = {'number': 7, 'node_id': 'PR_7', 'state': 'open', 'draft': True,
                    'user': {'login': 'release[bot]', 'type': 'Bot'},
                    'head': {'repo': {'id': 1}, 'ref': branch_prefix('main') + 'tool', 'sha': HEAD},
                    'base': {'repo': {'id': 1}, 'ref': 'main', 'sha': BASE}}
        self.calls, self.redraft_fails, self.change_on_ready = [], False, False
        self.base_ref = BASE

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path == 'repos/example/platform':
            return {'id': 1, 'full_name': 'example/platform', 'private': False}
        if path.endswith('/pulls?state=open&per_page=100'):
            return [copy.deepcopy(self.row)]
        if '/git/ref/heads/' in path:
            return {'object': {'sha': self.base_ref}}
        if path.endswith('/pulls/7'):
            return copy.deepcopy(self.row)
        if path == 'graphql':
            if 'convertPullRequestToDraft' in body['query']:
                if not self.redraft_fails:
                    self.row['draft'] = True
            else:
                self.row['draft'] = False
                if self.change_on_ready:
                    self.row['head']['sha'] = '3' * 40
            return {}
        if '/git/commits/' in path:
            return {'tree': {'sha': 'tree'}}
        if method == 'PATCH' and '/git/refs/heads/' in path:
            self.row['head']['sha'] = body['sha']
            return {}
        if method == 'POST':
            return {'sha': '4' * 40}
        raise AssertionError('Unexpected synthetic API request')


class GateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.api = API()
        self.gate = Gate(self.api, SCOPE, self.directory.name)

    def test_only_exact_owned_public_pr_can_be_touched(self):
        for section, key, value in (('user', 'login', 'collaborator'),
                                    ('head', 'ref', 'unowned/branch'),
                                    ('base', 'ref', 'other-base')):
            original = copy.deepcopy(self.api.row)
            self.api.row[section][key] = value
            with self.assertRaises(ValueError):
                self.gate.current(7)
            self.api.row = original

    def test_failed_redraft_blocks_every_git_object_write_and_invalidates_receipt(self):
        self.gate.stamp(7, EVIDENCE)
        self.api.row['draft'], self.api.redraft_fails = False, True
        with self.assertRaises(ValueError):
            self.gate.publish(7, HEAD, BASE, {'pins.json': b'{}'}, {'pins.json'})
        self.assertFalse((Path(self.directory.name) / '7.json').exists())
        self.assertFalse(any('/git/' in path and method != 'GET' for method, path, _ in self.api.calls))

    def test_publication_redrafts_before_commit_and_requires_final_head_verification(self):
        self.api.row['draft'] = False
        result = self.gate.publish(7, HEAD, BASE, {'pins.json': b'{}'}, {'pins.json'})
        draft = next(i for i, call in enumerate(self.api.calls) if call[1] == 'graphql')
        commit = next(i for i, call in enumerate(self.api.calls) if call[1].endswith('/git/commits'))
        self.assertLess(draft, commit)
        self.assertTrue(result['verificationRequired'])
        self.assertTrue(self.api.row['draft'])
        with self.assertRaises(FileNotFoundError):
            self.gate.ready(7, {})

    def test_workflow_publication_is_prohibited(self):
        path = '.github/workflows/application-test.yaml'
        with self.assertRaisesRegex(ValueError, 'workflow'):
            self.gate.publish(7, HEAD, BASE, {path: b'uses: example'}, {path})
        self.assertFalse(any('/git/blobs' in call[1] for call in self.api.calls))

    def test_stale_head_base_or_tampered_receipt_never_promotes(self):
        for field in ('head', 'base'):
            self.api.row['head']['sha'], self.api.row['base']['sha'] = HEAD, BASE
            self.gate.stamp(7, EVIDENCE)
            self.api.row[field]['sha'] = '5' * 40
            with self.assertRaises(ValueError):
                self.gate.ready(7, {})
            self.assertTrue(self.api.row['draft'])
        self.api.row['head']['sha'], self.api.row['base']['sha'] = HEAD, BASE
        self.gate.stamp(7, EVIDENCE)
        receipt = Path(self.directory.name) / '7.json'
        document = json.loads(receipt.read_bytes())
        document['body']['head'] = '6' * 40
        receipt.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            self.gate.ready(7, {})

    def test_exact_final_head_promotes_but_race_redrafts(self):
        expected = {key: EVIDENCE[key] for key in ('candidateTree', 'pinset', 'helpers', 'toolchain', 'checks')}
        self.gate.stamp(7, EVIDENCE)
        self.assertTrue(self.gate.ready(7, expected)['ready'])
        self.api.row['draft'] = True
        self.gate.stamp(7, EVIDENCE)
        self.api.change_on_ready = True
        with self.assertRaises(ValueError):
            self.gate.ready(7, expected)
        self.assertTrue(self.api.row['draft'])

    def test_base_advancing_during_promotion_still_allows_redraft(self):
        expected = {key: EVIDENCE[key] for key in ('candidateTree', 'pinset', 'helpers', 'toolchain', 'checks')}
        self.gate.stamp(7, EVIDENCE)
        original = self.api.request

        def advancing(method, path, body=None):
            result = original(method, path, body)
            if path == 'graphql' and 'markPullRequestReadyForReview' in body['query']:
                self.api.base_ref = '8' * 40
            return result

        self.api.request = advancing
        with self.assertRaises(ValueError):
            self.gate.ready(7, expected)
        self.assertTrue(self.api.row['draft'])


if __name__ == '__main__':
    unittest.main()
