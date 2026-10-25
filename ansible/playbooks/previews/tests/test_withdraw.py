import copy
import json
import unittest
from unittest.mock import patch

from fixtures import approval
from playbooks.previews.files.contract import OWNER, canonical, digest
from playbooks.previews.files.lifecycle import enroll
from playbooks.previews.files import withdraw


class WithdrawalTests(unittest.TestCase):
    def fixture(self):
        row = approval()
        state = enroll({'format': 1, 'entries': {}}, row, 1500)
        current = {'metadata': {'uid': 'fixture-state', 'resourceVersion': '12', 'labels': {'cloudlab.io/owner': OWNER}},
                   'data': {'state.json': json.dumps(state)}}
        request = {'stateUID': 'fixture-state', 'entries': {row['instance']: digest(canonical(row))}}
        return current, request

    def test_exact_withdrawal_is_irreversible_and_uses_native_cas_without_git(self):
        current, request = self.fixture()
        desired = withdraw.withdraw(current, request)
        self.assertEqual(json.loads(desired['data']['state.json'])['entries']['a' * 32]['phase'], 'retiring')
        self.assertEqual(desired['metadata']['resourceVersion'], '12')
        self.assertEqual(withdraw.withdraw(desired, request), desired)
        with patch.object(withdraw, 'get', return_value=current), patch.object(withdraw, 'kube') as kube:
            self.assertTrue(withdraw.run(request)['retirement_requested'])
            kube.assert_called_once_with('replace', '-f', '-', document=desired)

    def test_changed_uid_digest_ownership_or_missing_state_refuses_all_writes(self):
        current, request = self.fixture()
        foreign = copy.deepcopy(current)
        foreign['metadata']['labels']['cloudlab.io/owner'] = 'other'
        for observed, expected in ((None, request), (foreign, request),
                                   (current, dict(request, stateUID='replacement')),
                                   (current, dict(request, entries={'a' * 32: 'f' * 64}))):
            with patch.object(withdraw, 'get', return_value=observed), patch.object(withdraw, 'kube') as kube:
                with self.assertRaises(ValueError): withdraw.run(expected)
                kube.assert_not_called()
