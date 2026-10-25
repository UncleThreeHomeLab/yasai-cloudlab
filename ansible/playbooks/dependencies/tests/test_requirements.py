"""Python maintenance accepts wheel pins, never package commands or alternate indexes."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.dependencies.files import requirements
from playbooks.dependencies.files.validate import file_change


class RequirementTests(unittest.TestCase):
    def test_all_matching_compatible_files_receive_version_and_wheel_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = b'example==1.2.3 --hash=sha256:' + b'a' * 64 + b'\n'
            for relative in requirements.FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(before)
            metadata = {'info': {'name': 'example', 'version': '1.2.4'}, 'urls': [
                {'packagetype': 'bdist_wheel', 'digests': {'sha256': 'b' * 64}}]}
            with patch.object(requirements.subprocess, 'run', return_value=Mock(returncode=0)) as run:
                result = requirements.update(root, {'versions': {'example': '1.2.4'}},
                                             fetch=lambda *args, **kwargs: json.dumps(metadata).encode())
            self.assertEqual(run.call_count, 4)
            self.assertEqual(result['status'], 'pending-build')
            for relative in requirements.FILES:
                raw = (root / relative).read_bytes()
                self.assertEqual(requirements.parse(raw)['example']['hashes'], ['b' * 64])
                file_change(relative, before, raw)
            with self.assertRaises(ValueError):
                requirements.update(root, {'versions': {'example': '1.3.0'}},
                                    fetch=lambda *args, **kwargs: self.fail('incompatible release download'))

    def test_options_urls_unhashed_or_added_packages_are_rejected(self):
        before = b'example==1.2.3 --hash=sha256:' + b'a' * 64 + b'\n'
        for raw in (b'--extra-index-url https://attacker\n', b'example @ https://attacker\n',
                    b'example==1.2.3\n', before + b'--editable .\n'):
            with self.assertRaises(ValueError):
                requirements.parse(raw)
        with self.assertRaises(ValueError):
            file_change('requirements.txt', before, before + b'new-package==1.0 --hash=sha256:' + b'b' * 64 + b'\n')
