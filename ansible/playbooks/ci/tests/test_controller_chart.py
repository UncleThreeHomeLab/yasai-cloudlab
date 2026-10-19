"""Exercise the native controller chart and its private input boundary."""
import subprocess
import unittest

from playbooks.ci.files.chart import check, render


class ControllerChartTests(unittest.TestCase):
    def test_native_controller_roles_resources_crds_and_credential_scope(self):
        self.assertEqual(check()['cluster_role_grants'], 0)

    def test_native_read_only_root_keeps_one_writable_tmp_without_duplicate_patch_keys(self):
        objects = render({'arc': {'image': {
            'repository': 'registry.example.invalid/cloudlab-public/ci-controller',
            'tag': '0.15.0@sha256:' + 'a' * 64}}})
        deployment, = [row for row in objects if row['kind'] == 'Deployment']
        pod = deployment['spec']['template']['spec']
        names = [volume['name'] for volume in pod['volumes']]
        self.assertEqual(len(names), len(set(names)))
        for container in pod['containers']:
            paths = [mount['mountPath'] for mount in container['volumeMounts']]
            self.assertEqual(len(paths), len(set(paths)))
            self.assertEqual(paths.count('/tmp'), 1)
            self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])

    def test_chart_rejects_missing_or_mutable_images_and_cross_namespace_watch(self):
        for values in ({}, {'arc': {'image': {'repository': 'ghcr.io/actions/gha-runner-scale-set-controller',
                                             'tag': '0.15.0'}}},
                       {'arc': {'image': {'repository': 'registry.example.invalid/cloudlab-public/ci-controller',
                                         'tag': '0.15.0@sha256:' + 'a' * 64},
                                'flags': {'watchSingleNamespace': 'other'}}}):
            with self.subTest(values=values), self.assertRaises(subprocess.CalledProcessError):
                render(values)
