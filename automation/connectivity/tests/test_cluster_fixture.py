"""Failure injection must target only redundant, healthy access components."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from automation.connectivity import cluster_fixture


class FailureBoundaryTests(unittest.TestCase):
    def test_canary_names_and_unknown_purpose_cannot_delete_regular_fixtures(self):
        self.assertEqual(cluster_fixture.fixture_names({'purpose': 'identity-canary'}), cluster_fixture.CANARY_NAMES)
        self.assertTrue(set(cluster_fixture.CANARY_NAMES).isdisjoint(cluster_fixture.NAMES))
        with patch.object(cluster_fixture, 'get') as get, patch.object(cluster_fixture, 'cleanup') as cleanup:
            with self.assertRaises(ValueError): cluster_fixture.prepare({'purpose': 'foreign'})
            get.assert_not_called(); cleanup.assert_not_called()
        with patch.object(cluster_fixture, 'kube') as kube:
            with self.assertRaises(ValueError): cluster_fixture.cleanup(['cloudlab-identity'])
            kube.assert_not_called()

    def test_disposable_routes_never_claim_application_root_paths(self):
        documents = []
        def write(*args, **kwargs):
            if args[0] == 'apply': documents.extend(kwargs['document']['items'])
        certificate = {'metadata': {'generation': 1}, 'spec': {'dnsNames': ['*.example.invalid']}, 'status': {'conditions': [
            {'type': 'Ready', 'status': 'True'}]}}
        for purpose, path, namespaces in (('access', cluster_fixture.PROOF_PATH, cluster_fixture.NAMES),
                                         ('identity-canary', cluster_fixture.CANARY_PATH, cluster_fixture.CANARY_NAMES[:1])):
            documents.clear()
            with self.subTest(purpose=purpose), patch.object(cluster_fixture, 'get', return_value=certificate), \
                    patch.object(cluster_fixture, 'cleanup') as cleanup, patch.object(cluster_fixture, 'kube', side_effect=write), \
                    patch.object(cluster_fixture, 'wait'):
                cluster_fixture.prepare({'purpose': purpose, 'public': [{'name': 'fixture', 'access': 'public'}],
                                         'private': ['cd'] if purpose == 'access' else [],
                                         'smoke_image': 'fixture@sha256:' + 'a' * 64})
                cleanup.assert_called_once_with(cluster_fixture.fixture_names({'purpose': purpose}))
            self.assertEqual([obj['metadata']['name'] for obj in documents if obj['kind'] == 'Namespace'], namespaces)
            routes = [obj for obj in documents if obj['kind'] == 'HTTPRoute']
            self.assertEqual(len(routes), len(namespaces))
            self.assertTrue(all(obj['spec']['rules'][0]['matches'] == [
                {'path': {'type': 'Exact', 'value': path}}] for obj in routes))
            for deployment in (obj for obj in documents if obj['kind'] == 'Deployment'):
                command = deployment['spec']['template']['spec']['containers'][0]['command'][2]
                with tempfile.TemporaryDirectory() as directory:
                    subprocess.run(['sh', '-ec', command.split('; exec httpd')[0].replace('/www', directory)], check=True)
                    self.assertEqual((Path(directory) / path.lstrip('/')).read_bytes(), b'mesh-ok')
                    self.assertEqual((Path(directory) / 'index.html').read_bytes(), b'mesh-ok')

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

    def test_stateful_proxy_failure_retains_pod_identity(self):
        component = 'tailscale/cloudlab.io/proxy=cloudlab-ingress'
        pod = self.pods()[0]
        pod['status']['containerStatuses'] = [{'ready': True, 'containerID': 'containerd://' + 'a' * 64}]
        with patch.object(cluster_fixture, 'snapshot', return_value={component: [{'name': 'cloudlab-ingress-0', 'uid': 'pod-uid'}]}), \
                patch.object(cluster_fixture, 'get', return_value=pod), \
                patch.object(cluster_fixture, 'kube') as kube:
            result = cluster_fixture.fail_one({'component': component})
            kube.assert_not_called()
            self.assertEqual(result['crash_target'], {'name': 'cloudlab-ingress-0', 'uid': 'pod-uid', 'container_id': 'a' * 64})
