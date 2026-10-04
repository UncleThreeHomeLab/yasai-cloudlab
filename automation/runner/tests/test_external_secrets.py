"""Reject modified artifacts and unpinned workloads before touching the cluster."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[2] / 'external_secrets'
spec = importlib.util.spec_from_file_location('eso_render', ROOT / 'render.py')
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class ExternalSecretsTests(unittest.TestCase):
    def test_release_has_pinned_controllers_and_required_apis(self):
        groups = renderer.render()
        deployments = [x for x in groups['system'] if x['kind'] == 'Deployment']
        self.assertEqual(len(deployments), 3)
        for deployment in deployments:
            for container in deployment['spec']['template']['spec']['containers']:
                self.assertRegex(container['image'], r'@sha256:[0-9a-f]{64}$')
        names = {x['metadata']['name'] for x in groups['crds']}
        self.assertTrue({
            'externalsecrets.external-secrets.io', 'secretstores.external-secrets.io',
            'clustersecretstores.external-secrets.io'} <= names)
        self.assertNotIn('pushsecrets.external-secrets.io', names)

    def test_modified_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release.json').write_bytes((ROOT / 'release.json').read_bytes())
            (root / 'upstream.yaml').write_text('tampered')
            with patch.object(renderer, 'ROOT', root), self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                renderer.render()
