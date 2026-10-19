"""Exercise the native controller chart and its private input boundary."""
import subprocess
import unittest

from playbooks.ci.files.chart import check, render


class ControllerChartTests(unittest.TestCase):
    def test_native_controller_roles_resources_crds_and_credential_scope(self):
        self.assertEqual(check()['cluster_role_grants'], 0)

    def test_chart_rejects_missing_or_mutable_images_and_cross_namespace_watch(self):
        for values in ({}, {'arc': {'image': {'repository': 'ghcr.io/actions/gha-runner-scale-set-controller',
                                             'tag': '0.15.0'}}},
                       {'arc': {'image': {'repository': 'registry.example.invalid/cloudlab-public/ci-controller',
                                         'tag': '0.15.0@sha256:' + 'a' * 64},
                                'flags': {'watchSingleNamespace': 'other'}}}):
            with self.subTest(values=values), self.assertRaises(subprocess.CalledProcessError):
                render(values)
