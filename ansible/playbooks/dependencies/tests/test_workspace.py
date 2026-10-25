"""Initial PR ownership is checked before any candidate code can execute."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from playbooks.dependencies.files.workspace import owned_diff, remote_tree, export, supports_modes


class WorkspaceTests(unittest.TestCase):
    def test_mode_capability_uses_real_chmod_observations_and_removes_only_its_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertTrue(supports_modes(root))
            with patch.object(Path, 'chmod', return_value=None):
                self.assertFalse(supports_modes(root))
            self.assertEqual(list(root.iterdir()), [])

    def test_final_head_reexport_requires_exact_bytes_and_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'pin.json'
            path.write_bytes(b'complete pin')
            path.chmod(0o644)
            expected = {'pin.json': {'mode': '100644'}}
            with patch('playbooks.dependencies.files.workspace.snapshot', return_value={'pin.json': b'complete pin'}):
                self.assertIn('pin.json', export(root, 'example/platform', 'a' * 40, expected=expected))
                path.write_bytes(b'changed after publication')
                with self.assertRaises(ValueError):
                    export(root, 'example/platform', 'a' * 40, expected=expected)

    def test_initial_test_edit_addition_deletion_or_mode_change_is_rejected(self):
        base = {'pins.json': {'sha': 'pin', 'mode': '100644'},
                'tests/test_owner.py': {'sha': 'test', 'mode': '100644'}}
        cases = [dict(base, **{'tests/test_owner.py': {'sha': 'malicious', 'mode': '100644'}}),
                 dict(base, **{'extra.py': {'sha': 'extra', 'mode': '100644'}}),
                 {'pins.json': base['pins.json']},
                 dict(base, **{'tests/test_owner.py': {'sha': 'test', 'mode': '100755'}})]
        for head in cases:
            with self.subTest(head=head), self.assertRaises(ValueError):
                owned_diff(base, head, {'pins.json'})
        self.assertEqual(owned_diff(base, dict(base, **{'pins.json': {'sha': 'new', 'mode': '100644'}}),
                                    {'pins.json'}), {'pins.json'})

    def test_git_tree_refuses_truncation_and_symlinks(self):
        class API:
            def __init__(self, document):
                self.document = document

            def request(self, method, path):
                return {'tree': {'sha': 'tree'}} if '/commits/' in path else self.document

        for document in ({'truncated': True, 'tree': []}, {'truncated': False, 'tree': [
                {'path': 'link', 'type': 'blob', 'mode': '120000', 'sha': 'link'}]}):
            with self.assertRaises(ValueError):
                remote_tree(API(document), 'example/platform', '1' * 40)
