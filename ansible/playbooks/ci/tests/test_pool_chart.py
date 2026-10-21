"""Exercise the native ARC pool and deny unsafe registration inputs."""
import json
import copy
import base64
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import yaml

from playbooks.ci.files.chart import POOL, check_pool, render
from playbooks.ci.tests.fixtures import pool_values, bootstrap_document


class PoolChartTests(unittest.TestCase):
    def test_two_roles_share_one_namespace_budget_and_one_owner_for_shared_objects(self):
        namespace = 'cloudlab-ci-public-example'
        values = pool_values()
        values['arc']['githubConfigSecret'] = 'github-arc-public'
        primary = render(values, chart=POOL, namespace=namespace)
        publisher = copy.deepcopy(values)
        publisher.update(manageSharedResources=False, policyName='cloudlab-ci-eligibility-publish')
        publisher['arc']['runnerScaleSetName'] = 'cloudlab-example-publish'
        next(v for v in publisher['arc']['template']['spec']['volumes'] if v['name'] == 'eligibility')['configMap']['name'] = publisher['policyName']
        second = render(publisher, chart=POOL, namespace=namespace, release='publisher')
        shared = {'ServiceAccount', 'ClusterRole', 'ClusterRoleBinding', 'ExternalSecret'}
        self.assertFalse(any(x['kind'] in shared or x['metadata']['name'] == 'cloudlab-buildkit-ids' for x in second))
        identities = [(x['kind'], x['metadata'].get('namespace', namespace), x['metadata']['name']) for x in primary + second]
        self.assertEqual(len(identities), len(set(identities)))
        repository, digest = bootstrap_document()['images']['controller'].split('@')
        controller = render({'network': {'enforce': False}, 'runnerPools': 2, 'arc': {'image': {'repository': repository, 'tag': '0.15.0@' + digest}}})
        quota = next(x for x in controller if x['kind'] == 'ResourceQuota' and x['metadata']['namespace'] == 'cloudlab-ci-private')
        self.assertEqual(quota['spec']['hard']['pods'], '1')
        self.assertEqual(quota['spec']['hard']['count/autoscalingrunnersets.actions.github.com'], '2')
        publisher['manageSharedResources'] = True
        with self.assertRaises(subprocess.CalledProcessError):
            render(publisher, chart=POOL, namespace=namespace)

    def test_delivered_app_key_preserves_rsa_material_through_both_template_stages(self):
        secret, = [row for row in render(pool_values(), chart=POOL) if row['kind'] == 'ExternalSecret']
        template = secret['spec']['target']['template']['data']['github_app_private_key']
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for form in (serialization.PrivateFormat.TraditionalOpenSSL, serialization.PrivateFormat.PKCS8):
            pem = key.private_bytes(serialization.Encoding.PEM, form, serialization.NoEncryption()).decode()
            for text in (pem, ' '.join(pem.splitlines()), pem.replace('\n', '\r\n')):
                with self.subTest(format=form), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory)
                    (path / 'Chart.yaml').write_text('apiVersion: v2\nname: pem\nversion: 0.1.0\n')
                    (path / 'values.yaml').write_text(yaml.safe_dump({'PRIVATE_KEY': text}))
                    (path / 'templates').mkdir()
                    code = '{{ define "pem" }}' + template.replace('.PRIVATE_KEY', '.Values.PRIVATE_KEY') + '{{ end }}'
                    code += '\napiVersion: v1\nkind: Secret\nmetadata: {name: fixture}\ndata:\n  key: {{ include "pem" . | b64enc | quote }}\n'
                    (path / 'templates/key.yaml').write_text(code)
                    rendered = subprocess.run(['helm', 'template', 'fixture', str(path)], capture_output=True, check=True)
                    delivered = base64.b64decode(yaml.safe_load(rendered.stdout)['data']['key'])
                    parsed = serialization.load_pem_private_key(delivered, password=None)
                    self.assertEqual(parsed.private_numbers(), key.private_numbers())

    def test_reviewed_pull_request_policy_can_authorize_only_its_exact_merge_test(self):
        values = pool_values()
        row = values['eligibility'][0]
        row.update(event_name='pull_request', job='test', ref='refs/pull/42/merge',
                   workflow_ref=row['repository'] + '/.github/workflows/ci.yaml@refs/pull/42/merge')
        self.assertTrue(render(values, chart=POOL))
        for field, bad in (('job', 'publish'), ('ref', 'refs/pull/42/head'), ('sha', 'c' * 40),
                           ('workflow_ref', row['repository'] + '/.github/workflows/ci.yaml@refs/pull/43/merge')):
            original = row[field]
            row[field] = bad
            with self.subTest(field=field), self.assertRaises(subprocess.CalledProcessError):
                render(values, chart=POOL)
            row[field] = original

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
