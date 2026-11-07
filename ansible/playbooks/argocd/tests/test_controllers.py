"""Argo image pin covers controllers, never run-to-completion job pods."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'files'))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / 'verification/integration'))
spec = importlib.util.spec_from_file_location(
    'argocd_controllers_verify', Path(__file__).parents[1] / 'files/verify.py')
argocd_verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(argocd_verify)

LOCKED = 'quay.io/argoproj/argocd:v3@sha256:locked'


def pod(name, image, phase='Running', owner='ReplicaSet'):
    return {'kind': 'Pod', 'metadata': {'name': name, 'ownerReferences': [
                {'kind': owner, 'name': name + '-owner'}]} if owner else
            {'name': name},
            'spec': {'containers': [{'image': image}]},
            'status': {'phase': phase}}


class ControllerImageTests(unittest.TestCase):
    def run_controllers(self, items):
        with patch.object(argocd_verify, 'kube',
                          return_value=json.dumps({'items': items})):
            with patch.object(argocd_verify, 'fingerprint', return_value='print'):
                return argocd_verify.controllers({'image_refs': [LOCKED]})

    def test_running_job_pod_with_unlocked_image_passes(self):
        self.assertEqual(self.run_controllers(
            [pod('system', LOCKED),
             pod('job', 'python:3.13@sha256:workload', owner='Job')]), 'print')

    def test_controller_pod_with_unlocked_image_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'committed digest lock'):
            self.run_controllers(
                [pod('system', 'quay.io/argoproj/argocd:v9@sha256:evil')])

    def test_unowned_pod_with_unlocked_image_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'committed digest lock'):
            self.run_controllers(
                [pod('system', LOCKED),
                 pod('stray', 'python:3.13@sha256:workload', owner=None)])


if __name__ == '__main__':
    unittest.main()
