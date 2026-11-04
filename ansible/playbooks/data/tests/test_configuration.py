"""Bootstrap shares runtime exclusion and keeps durable adoption receipts."""
from contextlib import contextmanager
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.data.files import configuration, control


class ConfigurationTests(unittest.TestCase):
    def test_identical_receipt_keeps_inode_and_reports_no_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.assertTrue(control.atomic(path, {'revision': 'first'}))
            before = path.stat()
            self.assertFalse(control.atomic(path, {'revision': 'first'}))
            self.assertEqual(path.stat().st_ino, before.st_ino)
            self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertTrue(control.atomic(path, {'revision': 'second'}))
            self.assertEqual(json.loads(path.read_text()), {'revision': 'second'})
            path.chmod(0o644)
            self.assertTrue(control.atomic(path, {'revision': 'second'}))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_interrupted_second_application_preserves_first_uid_and_resumes(self):
        payload = {'repository': 'https://example.test/lab.git', 'branch': 'main', 'revision': 'a' * 40,
                   'values': {'s3Host': 's3.internal.example.test', 'database': 'notes',
                              'applicationRole': 'notes_app', 'migrationRole': 'notes_migration',
                              'backupRole': 'backup', 'bucket': 'notes'}}
        applications = {}
        applied = []
        interrupted = True

        def get(kind, name=None, namespace=None):
            if kind == 'application.argoproj.io':
                return applications.get(name)
            if kind == 'certificate.cert-manager.io':
                return {'spec': {'dnsNames': ['*.internal.example.test', 'login.example.test']}}
            return {}

        def kube(*args, document=None, **kwargs):
            nonlocal interrupted
            name = document['metadata']['name']
            if name == 'cloudlab-seaweedfs' and interrupted:
                interrupted = False
                raise RuntimeError('interrupted second apply')
            applications[name] = deepcopy(document)
            applications[name]['metadata']['uid'] = 'uid-' + name
            applied.append(name)

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            base = Path(directory)
            accepted = base / 'accepted.json'
            accepted.write_text('{"phase":"accepted"}')
            stack.enter_context(patch.object(control, 'BASE', base))
            stack.enter_context(patch.object(configuration, 'BASE', base))
            stack.enter_context(patch.object(configuration, 'Path', return_value=accepted))
            stack.enter_context(patch.object(configuration, 'get', side_effect=get))
            stack.enter_context(patch.object(configuration, 'kube', side_effect=kube))
            stack.enter_context(patch.object(configuration, 'condition', return_value=True))
            stack.enter_context(patch.object(configuration, 'application_ready', return_value=True))
            stack.enter_context(patch.object(configuration, 'wait', side_effect=lambda predicate, *a, **k: predicate()))
            stack.enter_context(patch.object(configuration, 'primary'))
            stack.enter_context(patch('playbooks.data.files.volumes.inventory'))
            with self.assertRaisesRegex(RuntimeError, 'interrupted second apply'):
                configuration.configure(payload)
            before = json.loads((base / 'ownership.json').read_text())
            self.assertEqual(before['applications'], {'cloudlab-data-configuration': 'uid-cloudlab-data-configuration'})
            self.assertFalse((base / 'desired.json').exists())
            self.assertTrue(configuration.configure(payload))
            self.assertEqual(applied, ['cloudlab-data-configuration', 'cloudlab-seaweedfs'])
            self.assertFalse(configuration.configure(payload))
            after = json.loads((base / 'ownership.json').read_text())
            self.assertEqual(after['applications']['cloudlab-data-configuration'], before['applications']['cloudlab-data-configuration'])

    def test_active_runtime_operation_blocks_bootstrap_before_cluster_access(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(control, 'BASE', Path(directory)):
            with control.locked(), patch.object(configuration, 'get') as get:
                with self.assertRaisesRegex(RuntimeError, 'owner lock'):
                    configuration.configure({})
                get.assert_not_called()

    def test_bootstrap_holds_shared_lock_through_failures(self):
        events = []
        @contextmanager
        def locked():
            events.append('locked')
            try:
                yield
            finally:
                events.append('released')
        with patch.object(configuration, 'locked', locked), patch.object(configuration, 'Path') as path:
            path.return_value.read_text.side_effect = RuntimeError('interrupted')
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                configuration.configure({})
        self.assertEqual(events, ['locked', 'released'])

    def test_registered_native_receipt_cannot_reenter_legacy_writer(self):
        payload = {'revision': 'a' * 40, 'values': {'s3Host': 's3.internal.example.test'}}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); accepted = base / 'accepted.json'
            accepted.write_text('{"phase":"accepted"}')
            (base / 'ownership.json').write_text('{"settings_uid":"native-settings", "applications":{}}')
            def read(kind, *args):
                if kind == 'certificate.cert-manager.io':
                    return {'spec': {'dnsNames': ['*.internal.example.test', 'login.example.test']}}
                return {'metadata': {'labels': {'cloudlab.io/owner': control.OWNER}}, 'spec': {'source': {'helm': {'valuesObject': {}}}}}
            with patch.object(control, 'BASE', base), patch.object(configuration, 'BASE', base), \
                    patch.object(configuration, 'Path', return_value=accepted), patch.object(configuration, 'get', side_effect=read), \
                    patch.object(configuration, 'condition', return_value=True), patch.object(configuration, 'wait'), \
                    patch.object(configuration, 'kube') as write:
                with self.assertRaisesRegex(RuntimeError, 'cannot downgrade'): configuration.configure(payload)
                write.assert_not_called()

    def test_recognized_native_configuration_is_read_only(self):
        payload = {'revision': 'a' * 40, 'values': {'s3Host': 's3.internal.example.test'}}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); accepted = base / 'accepted.json'
            accepted.write_text('{"phase":"accepted"}')
            (base / 'ownership.json').write_text('{"settings_uid":"native-settings", "applications":{}}')
            def read(kind, *args):
                if kind == 'certificate.cert-manager.io':
                    return {'spec': {'dnsNames': ['*.internal.example.test', 'login.example.test']}}
                return {'metadata': {'labels': {'cloudlab.io/owner': 'data-platform'}}, 'spec': {'sources': [{}]}}
            with patch.object(control, 'BASE', base), patch.object(configuration, 'BASE', base), \
                    patch.object(configuration, 'Path', return_value=accepted), patch.object(configuration, 'get', side_effect=read), \
                    patch.object(configuration, 'condition', return_value=True), patch.object(configuration, 'wait'), \
                    patch('playbooks.data.files.native.operation') as observe, \
                    patch.object(configuration, 'atomic') as receipt, patch.object(configuration, 'kube') as write:
                self.assertFalse(configuration.configure(payload))
                observe.assert_called_once_with(read=configuration.get)
                write.assert_not_called(); receipt.assert_not_called()
                self.assertFalse((base / 'desired.json').exists())
