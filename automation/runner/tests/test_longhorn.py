"""Guard reproducibility and prevent silent weakening of the storage proof."""

import copy
import importlib.util
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2] / 'longhorn'
sys.path.insert(0, str(ROOT))


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


renderer = module('longhorn_render', 'render.py')
proof = module('longhorn_verify_health', 'verify_health.py')


class LonghornTests(unittest.TestCase):
    def test_release_rejects_changed_manifest_and_missing_image_pin(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('release.json', 'policy.json', 'upstream.yaml'):
                (root / name).write_bytes((ROOT / name).read_bytes())
            with patch.object(renderer, 'ROOT', root):
                with (root / 'upstream.yaml').open('ab') as stream:
                    stream.write(b'\n')
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    renderer.render()
                (root / 'upstream.yaml').write_bytes((ROOT / 'upstream.yaml').read_bytes())
                lock = json.loads((root / 'release.json').read_text())
                del lock['images'][next(iter(lock['images']))]
                (root / 'release.json').write_text(json.dumps(lock))
                with self.assertRaisesRegex(ValueError, 'image lock'):
                    renderer.render()

    def test_all_direct_and_controller_spawned_images_are_locked(self):
        resources = renderer.render()
        text = json.dumps(resources)
        for match in renderer.IMAGE.finditer(text):
            self.assertTrue(text[match.end():].startswith('@sha256:'))
        classes = [r for r in resources['policy'] if r['kind'] == 'StorageClass']
        self.assertEqual(classes[0]['parameters']['numberOfReplicas'], '2')
        self.assertEqual(classes[0]['metadata']['annotations']['storageclass.kubernetes.io/is-default-class'], 'false')

    def test_custom_storage_policy_reaches_settings_and_storageclass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('release.json', 'policy.json', 'upstream.yaml'):
                (root / name).write_bytes((ROOT / name).read_bytes())
            policy = json.loads((root / 'policy.json').read_text())
            policy['storage_class'] = 'custom-storage'
            policy['settings']['default-data-path'] = '/srv/storage'
            (root / 'policy.json').write_text(json.dumps(policy))
            with patch.object(renderer, 'ROOT', root):
                resources = renderer.render()
            storage_class = next(r for r in resources['policy'] if r['kind'] == 'StorageClass')
            self.assertEqual(storage_class['metadata']['name'], 'custom-storage')
            setting = next(r for r in resources['policy'] if r['metadata']['name'] == 'default-data-path')
            self.assertEqual(setting['value'], '/srv/storage')
            defaults = next(r for r in resources['system'] if r['metadata']['name'] == 'longhorn-default-setting')
            self.assertIn('/srv/storage', defaults['data']['default-setting.yaml'])

    def test_healthy_label_alone_cannot_pass_replication_proof(self):
        data = {
            'volumes.longhorn.io': {'status': {'robustness': 'healthy'}},
            'replicas.longhorn.io': {'items': [
                {'spec': {'volumeName': 'test', 'nodeID': node}, 'status': {'currentState': 'running'}}
                for node in ('one', 'two')]},
            'engines.longhorn.io': {'items': [{'spec': {'volumeName': 'test'},
                'status': {'currentState': 'running', 'replicaModeMap': {'r1': 'RW', 'r2': 'RW'}}}]},
        }
        def read(kind, *args):
            return data[kind]
        with patch.object(proof, 'get', side_effect=read):
            self.assertTrue(proof.healthy_volume('test', ['one', 'two']))
            original = copy.deepcopy(data)
            data['replicas.longhorn.io']['items'][1]['spec']['nodeID'] = 'one'
            self.assertFalse(proof.healthy_volume('test', ['one', 'two']))
            data = original
            data['engines.longhorn.io']['items'][0]['status']['replicaModeMap']['r2'] = 'WO'
            self.assertFalse(proof.healthy_volume('test', ['one', 'two']))
