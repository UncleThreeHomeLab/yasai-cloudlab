"""Reject unsafe chart changes before any ownership transition."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('eso_chart', Path(__file__).with_name('chart.py'))
chart = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chart)


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
