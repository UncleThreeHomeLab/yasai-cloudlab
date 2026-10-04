"""Never adopt or delete unrelated resources while proving attached storage."""
import unittest
from unittest.mock import patch

import handoff_fixture as fixture


class HandoffScopeTests(unittest.TestCase):
    def test_existing_foreign_namespace_is_neither_used_nor_deleted(self):
        foreign = {'metadata': {'name': fixture.NAMESPACE, 'uid': 'foreign',
                                'labels': {'cloudlab.io/handoff': 'someone-else'}}}
        with patch.object(fixture, 'get', return_value={'items': [foreign]}), patch.object(fixture, 'kubectl') as mutate:
            with self.assertRaisesRegex(RuntimeError, 'another operation'):
                fixture.prepare({}, {'nonce': 'ours'})
            with self.assertRaisesRegex(RuntimeError, 'foreign handoff namespace'):
                fixture.cleanup({'namespace_uid': 'ours', 'nonce': 'ours'})
            mutate.assert_not_called()

    def test_replaced_workload_fails_even_when_running(self):
        namespace = {'metadata': {'uid': 'namespace', 'labels': {'cloudlab.io/handoff': 'ours'}}}
        pod = {'metadata': {'uid': 'replacement'}, 'status': {'phase': 'Running'}}
        with patch.object(fixture, 'get', side_effect=[namespace, pod]), patch.object(fixture, 'kubectl') as execute:
            with self.assertRaisesRegex(RuntimeError, 'interrupted or replaced'):
                fixture.verify({}, {'namespace_uid': 'namespace', 'nonce': 'ours', 'pod_uid': 'original'})
            execute.assert_not_called()
