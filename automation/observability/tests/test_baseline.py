import copy
import unittest

from automation.observability.baseline import result
from automation.observability.slo import definition


class ReleaseEvidenceTests(unittest.TestCase):
    def test_only_redacted_bounded_measurements_can_pass_release_gate(self):
        policy = definition()['release']
        good = {'scenario': 'notes-release-read', 'passed': True, 'samples': 240,
                'p95_ms': 100, 'maximum_ms': 200, 'failure_rate': 0, 'evaluation_seconds': 120}
        self.assertEqual(result(good, policy), good)
        for change in ({'samples': 229}, {'samples': 9999}, {'p95_ms': 250}, {'maximum_ms': 1000},
                       {'failure_rate': 0.01}, {'p95_ms': float('nan')}, {'maximum_ms': float('inf')},
                       {'evaluation_seconds': 60}, {'passed': False}, {'access_token': 'must-not-export'}):
            invalid = copy.deepcopy(good)
            invalid.update(change)
            with self.assertRaises(ValueError): result(invalid, policy)
