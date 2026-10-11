"""Storage health must prove replica placement and engine read/write state."""
import copy
import unittest
from unittest.mock import patch

import verify_health as proof


class LonghornTests(unittest.TestCase):
    def test_healthy_label_alone_cannot_pass_replication_proof(self):
        data = {
            'volumes.longhorn.io': {'status': {'robustness': 'healthy'}},
            'replicas.longhorn.io': {'items': [
                {'spec': {'volumeName': 'test', 'nodeID': node}, 'status': {'currentState': 'running'}}
                for node in ('one', 'two')]},
            'engines.longhorn.io': {'items': [{'spec': {'volumeName': 'test'},
                'status': {'currentState': 'running', 'replicaModeMap': {'r1': 'RW', 'r2': 'RW'}}}]},
        }
        def read(kind, *args):
            return data[kind]
        with patch.object(proof, 'get', side_effect=read):
            self.assertTrue(proof.healthy_volume('test', ['one', 'two']))
            original = copy.deepcopy(data)
            data['replicas.longhorn.io']['items'][1]['spec']['nodeID'] = 'one'
            self.assertFalse(proof.healthy_volume('test', ['one', 'two']))
            data = original
            data['engines.longhorn.io']['items'][0]['status']['replicaModeMap']['r2'] = 'WO'
            self.assertFalse(proof.healthy_volume('test', ['one', 'two']))
