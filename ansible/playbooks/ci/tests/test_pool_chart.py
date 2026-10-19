"""Exercise the native ARC pool and deny unsafe registration inputs."""
import json
import subprocess
import unittest

from playbooks.ci.files.chart import POOL, check_pool, render
from playbooks.ci.tests.fixtures import pool_values


class PoolChartTests(unittest.TestCase):
    def test_public_repository_pools_share_charts_but_never_private_app_credentials(self):
        values = pool_values()
        values['arc']['githubConfigSecret'] = 'github-arc-public'
        namespace = 'cloudlab-ci-public-example'
        objects = render(values, chart=POOL, namespace=namespace)
        secret, = [row for row in objects if row['kind'] == 'ExternalSecret']
        self.assertEqual(secret['metadata']['namespace'], namespace)
        self.assertEqual(secret['spec']['dataFrom'], [{'extract': {'key': 'github-arc-public'}}])
        binding, = [row for row in objects if row['kind'] == 'ClusterRoleBinding']
        self.assertEqual(binding['metadata']['name'], namespace + '-health')
        self.assertEqual(binding['subjects'][0]['namespace'], namespace)
        for bad_namespace, secret in ((namespace, 'github-arc'), ('cloudlab-ci-private', 'github-arc-public')):
            values['arc']['githubConfigSecret'] = secret
            with self.subTest(namespace=bad_namespace), self.assertRaises(subprocess.CalledProcessError):
                render(values, chart=POOL, namespace=bad_namespace)
        values['arc']['githubConfigSecret'] = 'github-arc'
        with self.assertRaises(subprocess.CalledProcessError):
            render(values, chart=POOL, namespace='kube-system')

    def test_native_pool_preserves_builder_profile_and_bounded_health_permissions(self):
        self.assertEqual(check_pool(pool_values())['runner_api_write_permissions'], 0)
        objects = render(pool_values(), chart=POOL)
        secret, = [row for row in objects if row['kind'] == 'ExternalSecret']
        self.assertEqual(secret['spec']['dataFrom'], [{'extract': {'key': 'github-arc'}}])
        binding, = [row for row in objects if row['kind'] == 'ClusterRoleBinding']
        self.assertEqual(binding['subjects'], [
            {'kind': 'ServiceAccount', 'name': 'cloudlab-ci-health', 'namespace': 'cloudlab-ci-private'}])
        policy, = [row for row in objects if row['kind'] == 'ConfigMap' and
                   row['metadata']['name'] == 'cloudlab-ci-eligibility']
        self.assertEqual(json.loads(policy['data']['eligibility.json'])['workflows'], pool_values()['eligibility'])

    def test_pool_rejects_missing_inputs_mutable_images_forks_and_foreign_repository(self):
        for change in ('missing', 'mutable', 'fork', 'foreign', 'revision', 'concurrency'):
            values = pool_values()
            if change == 'missing':
                values = {}
            elif change == 'mutable':
                values['arc']['template']['spec']['containers'][0]['image'] = 'registry.example.invalid/tool:latest'
            elif change == 'fork':
                values['eligibility'][0]['event_name'] = 'pull_request'
            elif change == 'foreign':
                values['eligibility'][0]['repository'] = 'example/other'
            elif change == 'revision':
                values['eligibility'][0]['sha'] = 'main'
            else:
                values['arc']['maxRunners'] = 2
            with self.subTest(change=change), self.assertRaises(subprocess.CalledProcessError):
                render(values, chart=POOL)

    def test_pool_rejects_builder_privilege_and_detached_lifecycle(self):
        for field, value in (('restartPolicy', 'OnFailure'), ('activeDeadlineSeconds', 7200)):
            values = pool_values()
            values['arc']['template']['spec'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_pool(values)
        values = pool_values()
        values['arc']['template']['spec']['initContainers'][0]['securityContext']['privileged'] = True
        with self.assertRaises(ValueError):
            check_pool(values)
