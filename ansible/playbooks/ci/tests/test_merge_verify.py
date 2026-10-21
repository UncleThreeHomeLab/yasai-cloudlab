"""Authorization proofs must reject ambiguous failures and preserve foreign refs."""
import io
import json
import unittest
import urllib.error
from unittest.mock import Mock

from playbooks.ci.files import merge_verify


class MergeVerificationTests(unittest.TestCase):
    def test_tag_mutation_denials_require_policy_and_never_target_a_deployment_ref(self):
        for method in ('POST', 'PATCH', 'DELETE'):
            for code, message, accepted in ((422, 'Repository rule violations found', True),
                    (403, 'Protected tag update not allowed', True),
                    (422, 'Reference already exists', False), (403, 'Bad credentials', False)):
                api = Mock(token='synthetic')
                api.opener.open.side_effect = urllib.error.HTTPError('https://api.github.com/fixture', code,
                    'withheld', {}, io.BytesIO(json.dumps({'message': message}).encode()))
                if accepted:
                    self.assertEqual(merge_verify.tag_denied(api, 'example/gitops', 'ci/merge-guard-proof-0123456789abcdef', 'a' * 40, method), code)
                else:
                    with self.assertRaises(RuntimeError):
                        merge_verify.tag_denied(api, 'example/gitops', 'ci/merge-guard-proof-0123456789abcdef', 'a' * 40, method)
        with self.assertRaises(ValueError): merge_verify.tag_denied(Mock(), 'example/gitops', 'main', 'a' * 40, 'POST')

    def test_only_repository_policy_denials_prove_the_merge_boundary(self):
        for status, message, accepted in ((403, 'Merge blocked by repository rules', True),
                (405, 'Protected branch update not allowed', True),
                (403, 'Bad credentials', False), (409, 'Head SHA changed', False)):
            api = Mock(token='synthetic')
            api.opener.open.side_effect = urllib.error.HTTPError('https://api.github.com/fixture', status,
                'withheld', {}, io.BytesIO(json.dumps({'message': message}).encode()))
            if accepted:
                self.assertEqual(merge_verify.denied(api, 'example/gitops', 1, 'a' * 40), status)
            else:
                with self.assertRaises(RuntimeError):
                    merge_verify.denied(api, 'example/gitops', 1, 'a' * 40)
            request = api.opener.open.call_args.args[0]
            self.assertEqual(json.loads(request.data), {'sha': 'a' * 40, 'merge_method': 'squash'})

    def test_successful_merge_is_a_failed_proof_not_a_pass(self):
        api = Mock(token='synthetic')
        api.opener.open.return_value = io.BytesIO(b'{"merged":true}')
        with self.assertRaises(RuntimeError):
            merge_verify.denied(api, 'example/gitops', 1, 'a' * 40)

    def test_cleanup_cannot_delete_foreign_changed_or_merged_branches(self):
        receipt = {'repository': 'example/gitops', 'branch': 'ci/merge-guard-proof-0123456789abcdef', 'head': 'a' * 40}
        for defect in ('prefix', 'head', 'merged'):
            value = dict(receipt)
            api = Mock()
            if defect == 'prefix': value['branch'] = 'release/real'
            api.request.side_effect = [{'object': {'sha': 'b' * 40 if defect == 'head' else value['head']}},
                [{'head': {'sha': value['head']}, 'merged_at': 'now', 'number': 1, 'state': 'closed'}]]
            with self.assertRaises(ValueError): merge_verify.cleanup(api, value)
            self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_operator_tag_cleanup_refuses_foreign_refs_and_changed_heads(self):
        receipt = {'repository': 'example/gitops', 'branch': 'ci/merge-guard-proof-0123456789abcdef',
                   'head': 'a' * 40, 'tag': 'ci/merge-guard-proof-0123456789abcdef'}
        for defect in ('foreign', 'head'):
            value = dict(receipt)
            if defect == 'foreign': value['tag'] = 'main'
            api = Mock()
            api.request.return_value = {'object': {'sha': value['head']}}
            operator = Mock()
            operator.request.return_value = {'object': {'sha': 'b' * 40}}
            with self.assertRaises(ValueError): merge_verify.cleanup(api, value, tag_api=operator)
            self.assertTrue(all(call.args[0] == 'GET' for call in (*api.request.call_args_list, *operator.request.call_args_list)))
