"""Exact legacy provenance, retained data and repeatable native retirement."""
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.data.files import control, handoff, native, retirement


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.base = Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir='/root')))
        self.writer = self.base / 'runtime' / 'configuration.py'
        self.writer.parent.mkdir(mode=0o700)
        self.writer.write_bytes(b'VALUE = 1\n'); self.writer.chmod(0o600)
        self.raw = {'maintenance': False, 'database': 'notes'}
        self.owner = {'settings_uid': 'registered', 'applications': {native.APP: 'app', native.SEAWEED: 'seaweed'},
            'handoff': {'phase': 'completed', 'target': {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40},
                'pins': {'revision': 'a' * 40, 'seaweedfsRevision': 'c' * 40}, 'owners': {},
                'specs': {native.APP: {'source': {'helm': {'valuesObject': self.raw}}}, native.SEAWEED: {}},
                'settings': dict(self.raw, postgresImage='declared-default'), 'resources': {},
                'absence': [native.SETTINGS, native.APP + '-source']}}
        control.atomic(self.base / 'ownership.json', self.owner)
        self.cache = self.base / 'desired.json'; control.atomic(self.cache, self.raw)
        self.stack.enter_context(patch.object(control, 'BASE', self.base))
        self.stack.enter_context(patch.object(retirement, 'WRITER', self.writer))
        self.stack.enter_context(patch.object(retirement, 'WRITER_SHA256', hashlib.sha256(self.writer.read_bytes()).hexdigest()))
        self.observe = self.stack.enter_context(patch.object(native, 'operation', return_value=Mock()))

    def bytecode(self, *, foreign=False):
        path = self.writer.parent / '__pycache__' / 'configuration.cpython-313.pyc'
        path.parent.mkdir(mode=0o700)
        code = compile('VALUE = 2' if foreign else self.writer.read_bytes(), str(self.writer), 'exec', dont_inherit=True)
        path.write_bytes(importlib.util.MAGIC_NUMBER + b'\0' * 12 + marshal.dumps(code)); path.chmod(0o600)
        return path

    def test_raw_cache_without_declared_default_and_matching_bytecode_retire_once(self):
        bytecode = self.bytecode()
        retained = self.base / 'keep-receipt.json'; control.atomic(retained, {'retained': True})
        self.assertTrue(retirement.retire())
        self.assertFalse(self.writer.exists()); self.assertFalse(bytecode.exists()); self.assertFalse(self.cache.exists())
        self.assertTrue(retained.exists()); self.assertTrue((self.base / 'ownership.json').exists())
        self.assertFalse(retirement.retire())
        self.assertEqual(self.observe.call_count, 2)

    def test_foreign_or_unproven_provenance_never_deletes_any_target(self):
        for case in ('writer', 'bytecode', 'normalized-cache', 'json-type', 'duplicate', 'cache-symlink', 'writer-symlink',
                     'ancestor-symlink', 'incomplete', 'source-failure'):
            self.setUp()
            with self.subTest(case=case):
                bytecode = self.bytecode(foreign=case == 'bytecode')
                if case == 'writer': self.writer.write_bytes(b'foreign')
                if case == 'normalized-cache': control.atomic(self.cache, self.owner['handoff']['settings'])
                if case == 'json-type': control.atomic(self.cache, dict(self.raw, maintenance=0))
                if case == 'duplicate': self.cache.write_text('{"maintenance":false,"database":"foreign","database":"notes"}')
                if case == 'cache-symlink': self.cache.unlink(); self.cache.symlink_to(self.base / 'missing')
                if case == 'writer-symlink': self.writer.unlink(); self.writer.symlink_to(self.base / 'missing')
                if case == 'ancestor-symlink':
                    link = self.base / 'redirected'; link.symlink_to(self.writer.parent, target_is_directory=True)
                    self.stack.enter_context(patch.object(retirement, 'WRITER', link / 'configuration.py'))
                if case == 'incomplete':
                    self.owner.pop('settings_uid'); self.owner['handoff']['phase'] = 'armed'
                    control.atomic(self.base / 'ownership.json', self.owner)
                if case == 'source-failure': self.observe.side_effect = RuntimeError('source unavailable')
                with self.assertRaises((RuntimeError, ValueError)):
                    retirement.retire()
                self.assertTrue(self.writer.exists() or self.writer.is_symlink())
                self.assertTrue(bytecode.exists())
                self.assertTrue(self.cache.exists() or self.cache.is_symlink())

    def test_missing_writer_with_leftover_bytecode_blocks_unauthenticated_cleanup(self):
        bytecode = self.bytecode(); self.writer.unlink()
        with self.assertRaisesRegex(RuntimeError, 'provenance'): retirement.retire()
        self.assertTrue(bytecode.exists()); self.assertTrue(self.cache.exists())


if __name__ == '__main__':
    unittest.main()
