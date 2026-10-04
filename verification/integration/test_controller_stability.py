import copy
import unittest
from controller_stability import fingerprint


class StabilityTests(unittest.TestCase):
    def setUp(self):
        self.items = [
            {'kind': 'Deployment', 'metadata': {'namespace': 'fixture', 'uid': 'controller', 'generation': 2},
             'spec': {'replicas': 1}, 'status': {'observedGeneration': 2, 'readyReplicas': 1, 'updatedReplicas': 1}},
            {'kind': 'Pod', 'metadata': {'namespace': 'fixture', 'uid': 'pod'}, 'status': {
                'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}],
                'containerStatuses': [{'name': 'main', 'restartCount': 0, 'containerID': 'original'}]}}]

    def test_restart_and_replacement_change_fingerprint(self):
        before = fingerprint(self.items)
        for change in ('restart', 'replacement'):
            items = copy.deepcopy(self.items)
            if change == 'restart': items[1]['status']['containerStatuses'][0]['restartCount'] = 1
            else: items[1]['metadata']['uid'] = 'replacement'
            self.assertNotEqual(fingerprint(items), before)

    def test_unready_pod_and_incomplete_rollout_fail(self):
        for change in ('pod', 'generation', 'replicas'):
            items = copy.deepcopy(self.items)
            if change == 'pod': items[1]['status']['conditions'][0]['status'] = 'False'
            elif change == 'generation': items[0]['status']['observedGeneration'] = 1
            else: items[0]['status']['updatedReplicas'] = 0
            with self.assertRaises(RuntimeError): fingerprint(items)

    def test_empty_inventory_is_not_stability(self):
        with self.assertRaises(RuntimeError): fingerprint([])
