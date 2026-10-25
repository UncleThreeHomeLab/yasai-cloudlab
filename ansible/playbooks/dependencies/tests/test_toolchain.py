"""Privileged fixture images require an official tag identity before launch."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.dependencies.files import toolchain


class ToolchainTests(unittest.TestCase):
    def test_privileged_fixture_rejects_candidate_digest_with_valid_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'ansible/playbooks/keycloak/tests/compose.identity-operator-proof.yaml'
            source.parent.mkdir(parents=True)
            image = 'rancher/k3s:v1.36.5-k3s1@sha256:' + 'a' * 64
            source.write_text('services:\n  cluster:\n    image: ' + image + '\n')
            with patch('playbooks.dependencies.files.ci_tools.image_digest',
                       return_value=image.split('@')[0] + '@sha256:' + 'b' * 64):
                with self.assertRaises(ValueError):
                    toolchain.k3s_image(root)
            with patch('playbooks.dependencies.files.ci_tools.image_digest',
                       side_effect=[image.split('@')[0] + '@sha256:' + 'b' * 64, image]) as resolve:
                self.assertEqual(toolchain.k3s_image(root), image)
                self.assertEqual(resolve.call_args.kwargs, {'platform': 'linux/amd64'})
