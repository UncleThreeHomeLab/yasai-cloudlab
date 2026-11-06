"""Reject unsafe chart changes before any ownership transition."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('eso_chart', Path(__file__).parents[1] / 'files/chart.py')
chart = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chart)
parity_spec = importlib.util.spec_from_file_location(
    'eso_chart_parity', Path(__file__).parents[4] / 'verification/integration/chart_parity.py')
parity = importlib.util.module_from_spec(parity_spec)
parity_spec.loader.exec_module(parity)


class ChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.objects = chart.render()
        cls.lock = json.loads((chart.ROOT / 'artifact.lock.json').read_text())

    def render_objects(self, objects):
        raw = '\n---\n'.join(json.dumps(item) for item in objects).encode()
        with patch.object(chart.subprocess, 'check_output', side_effect=[self.lock['helm_version'], raw, raw]):
            return chart.render()

    def test_same_release_excludes_bootstrap_secret(self):
        self.assertEqual(len(self.objects), 42)
        self.assertEqual(sum(x['kind'] == 'CustomResourceDefinition' for x in self.objects), 21)
        secrets = [x for x in self.objects if x['kind'] == 'Secret']
        self.assertEqual([x['metadata']['name'] for x in secrets], ['external-secrets-webhook'])
        self.assertEqual(set(secrets[0]), {'apiVersion', 'kind', 'metadata'})

    def test_rendered_payload_matches_reviewed_semantics(self):
        payload = json.loads(subprocess.check_output([sys.executable, chart.__file__], timeout=180))
        objects = payload['items'] + payload.get('generated', [])
        self.assertEqual(parity.semantic_digest(objects, 'external_secrets'), self.lock['semantic_sha256'])

    def test_required_read_only_apis_and_three_controllers_remain(self):
        names = {obj['metadata']['name'] for obj in self.objects if obj['kind'] == 'CustomResourceDefinition'}
        self.assertTrue({'externalsecrets.external-secrets.io', 'secretstores.external-secrets.io',
                         'clustersecretstores.external-secrets.io'} <= names)
        self.assertNotIn('pushsecrets.external-secrets.io', names)
        deployments = [obj for obj in self.objects if obj['kind'] == 'Deployment']
        self.assertEqual(len(deployments), 3)
        for obj in deployments:
            for container in obj['spec']['template']['spec']['containers']:
                self.assertRegex(container['image'], r'@sha256:[0-9a-f]{64}$')

    def test_controller_reconciles_without_minting_service_account_tokens(self):
        objects = {(obj['kind'], obj['metadata']['name']): obj for obj in self.objects}
        controller = objects['ClusterRole', 'external-secrets-controller']
        binding = objects['ClusterRoleBinding', 'external-secrets-controller']
        self.assertEqual(binding['roleRef'], {
            'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole',
            'name': controller['metadata']['name']})
        self.assertEqual(binding['subjects'], [{
            'kind': 'ServiceAccount', 'name': 'external-secrets', 'namespace': 'external-secrets'}])

        def grants(role, group, resource, verb):
            matches = {'*', resource}
            if '/' in resource:
                matches.add('*/' + resource.split('/', 1)[1])
            return any(set(rule['apiGroups']) & {group, '*'}
                       and set(rule['resources']) & matches
                       and set(rule['verbs']) & {verb, '*'} for rule in role['rules'])

        self.assertFalse(grants(controller, '', 'serviceaccounts/token', 'create'))
        for verb in ('get', 'list', 'watch', 'create', 'update', 'delete', 'patch'):
            self.assertTrue(grants(controller, '', 'secrets', verb))
        for resource in ('externalsecrets/status', 'clustersecretstores/status'):
            for verb in ('get', 'update', 'patch'):
                self.assertTrue(grants(controller, 'external-secrets.io', resource, verb))
        leader = objects['Role', 'external-secrets-leaderelection']
        for verb in ('get', 'create', 'update', 'patch'):
            self.assertTrue(grants(leader, 'coordination.k8s.io', 'leases', verb))

    def test_tampered_archive_is_rejected_before_render(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'artifact.lock.json').write_text(json.dumps(dict(self.lock, archive='chart.tgz')))
            (root / 'chart.tgz').write_bytes(b'changed archive')
            with patch.object(chart, 'ROOT', root), self.assertRaisesRegex(ValueError, 'checksum'):
                chart.render()

    def test_mutable_image_is_rejected(self):
        objects = copy.deepcopy(self.objects)
        deployment = next(x for x in objects if x['kind'] == 'Deployment')
        deployment['spec']['template']['spec']['containers'][0]['image'] = 'example/operator:latest'
        with self.assertRaisesRegex(ValueError, 'images differ'):
            self.render_objects(objects)

    def test_bootstrap_secret_and_duplicate_are_rejected(self):
        for extra, message in [(dict(apiVersion='v1', kind='Secret', metadata=dict(name='onepassword-token')), 'bootstrap credential'),
                               (self.objects[0], 'duplicate')]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.render_objects(self.objects + [extra])

    def test_hooks_and_broad_sync_options_are_rejected(self):
        for annotations, message in [({'helm.sh/hook': 'pre-delete'}, 'hook'),
                                      ({'argocd.argoproj.io/sync-options': 'Replace=true'}, 'sync options')]:
            objects = copy.deepcopy(self.objects)
            objects[0]['metadata']['annotations'] = annotations
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.render_objects(objects)


if __name__ == '__main__':
    unittest.main()
