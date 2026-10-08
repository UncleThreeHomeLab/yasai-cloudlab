"""Failure injection must target only redundant, healthy stateless access Pods."""
import copy
import json
import unittest
from unittest.mock import patch
from automation.connectivity import cluster_fixture


class FailureBoundaryTests(unittest.TestCase):
    def pods(self):
        return [{'metadata': {'name': 'fixture-' + str(n), 'uid': str(n)},
                 'spec': {'nodeName': 'node-' + str(n), 'containers': [{
                     'startupProbe': {'tcpSocket': {'port': 9002}},
                     'readinessProbe': {'tcpSocket': {'port': 9002}},
                     'livenessProbe': {'tcpSocket': {'port': 9002}}}]},
                 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}} for n in range(2)]

    def test_one_node_or_missing_probes_cannot_satisfy_redundancy_gate(self):
        for defect in ('one-node', 'missing-probe', 'one-replica'):
            pods = self.pods()
            if defect == 'one-node': pods[1]['spec']['nodeName'] = pods[0]['spec']['nodeName']
            if defect == 'missing-probe': pods[1]['spec']['containers'][0].pop('readinessProbe')
            if defect == 'one-replica': pods.pop()
            with self.subTest(defect=defect), patch.object(cluster_fixture, 'kube', return_value=json.dumps({'items': pods})):
                with self.assertRaises(RuntimeError): cluster_fixture.snapshot()

    def test_failure_target_cannot_select_control_plane_or_storage(self):
        with patch.object(cluster_fixture, 'snapshot', return_value={'cloudlab-connectors/app=cloudflared': self.pods()}), \
                patch.object(cluster_fixture, 'kube') as kube:
            for component in ('kube-system/k3s', 'longhorn-system/longhorn', 'arbitrary'):
                with self.assertRaises(RuntimeError): cluster_fixture.fail_one({'component': component})
            kube.assert_not_called()

    def test_namespace_collision_prevents_fixture_cleanup(self):
        with patch.object(cluster_fixture, 'get', return_value={'metadata': {'labels': {}}}), \
                patch.object(cluster_fixture, 'kube') as kube:
            with self.assertRaises(RuntimeError): cluster_fixture.cleanup()
            kube.assert_not_called()
