"""Validate the active chart's image, storage identity and lifecycle boundaries."""
import copy
import json
import unittest
from unittest.mock import patch

import chart


class StorageChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.objects = chart.render()
        cls.lock = json.loads((chart.ROOT / 'artifact.lock.json').read_text())

    def altered(self, objects):
        data = '\n---\n'.join(json.dumps(obj) for obj in objects).encode()
        with patch.object(chart.subprocess, 'check_output', side_effect=[self.lock['helm_version'], data, data]):
            return chart.render()

    def test_controller_generated_storageclass_keeps_exact_source_bytes(self):
        storage = chart.generated()[0]
        self.assertEqual(storage['parameters']['numberOfReplicas'], '2')
        self.assertEqual(storage['metadata']['annotations']['storageclass.kubernetes.io/is-default-class'], 'false')
        self.assertFalse(any(obj['kind'] == 'StorageClass' for obj in self.objects))
        config = next(obj for obj in self.objects if obj['kind'] == 'ConfigMap'
                      and obj['metadata']['name'] == 'longhorn-storageclass')
        self.assertEqual(config['data']['storageclass.yaml'], (chart.ROOT / 'storageclass.yaml').read_text())

    def test_mutable_direct_or_generated_image_is_rejected(self):
        for kind in ['Deployment', 'DaemonSet']:
            objects = copy.deepcopy(self.objects)
            obj = next(obj for obj in objects if obj['kind'] == kind)
            obj['spec']['template']['spec']['containers'][0]['image'] = 'example/unsafe:latest'
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'image'):
                self.altered(objects)
        objects = copy.deepcopy(self.objects)
        text = json.dumps(objects).replace(next(iter(self.lock['images'].values())), 'sha256:' + '0' * 64)
        with self.assertRaisesRegex(ValueError, 'image'):
            self.altered(json.loads(text))

    def test_crd_retention_cannot_be_disabled(self):
        objects = copy.deepcopy(self.objects)
        next(obj for obj in objects if obj['kind'] == 'CustomResourceDefinition')['metadata']['annotations'].pop('argocd.argoproj.io/sync-options')
        with self.assertRaisesRegex(ValueError, 'retention'):
            self.altered(objects)

    def test_data_objects_and_lifecycle_hooks_are_rejected(self):
        for kind in ['Job', 'Secret', 'PersistentVolumeClaim', 'PersistentVolume']:
            extra = {'apiVersion': 'v1', 'kind': kind, 'metadata': {'name': 'unsafe'}}
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'data object'):
                self.altered(self.objects + [extra])
        objects = copy.deepcopy(self.objects)
        objects[0]['metadata'].setdefault('annotations', {})['helm.sh/hook'] = 'pre-delete'
        with self.assertRaisesRegex(ValueError, 'lifecycle hook'):
            self.altered(objects)


if __name__ == '__main__':
    unittest.main()
