"""The storage adoption patch must never silently change operator behavior."""
import io
import tarfile
import unittest

from vendor_chart import ANNOTATION, CRDS, HOOKS, ROOT, package, verify


def members(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        return {entry.name: archive.extractfile(entry).read() for entry in archive}


class VendorPatchTests(unittest.TestCase):
    def test_only_reviewed_hooks_and_crd_annotations_differ(self):
        original = members((ROOT / 'upstream.tgz').read_bytes())
        patched = members(verify())
        self.assertEqual(original.keys() - patched.keys(), HOOKS)
        self.assertFalse(patched.keys() - original.keys())
        for name, data in patched.items():
            with self.subTest(member=name):
                self.assertEqual(data.replace(ANNOTATION, b'') if name == CRDS else data, original[name])
        self.assertEqual(patched[CRDS].count(ANNOTATION), 28)

    def test_repackaging_an_already_patched_chart_is_rejected(self):
        with self.assertRaises(ValueError):
            package(verify())
