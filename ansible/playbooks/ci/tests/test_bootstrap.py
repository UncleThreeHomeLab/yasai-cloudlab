"""Check scan-before-write, immutable publishing and interruption recovery."""
from contextlib import nullcontext
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from playbooks.ci.files import bootstrap
from playbooks.harbor.files.registry import Registry


class BootstrapTests(unittest.TestCase):
    def test_api_drift_or_incomplete_scan_set_cannot_write_publication_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            client = SimpleNamespace(path=directory, plan=Mock(return_value={'changes': 1}))
            with patch.object(bootstrap, 'Registry', side_effect=AssertionError('Registry accessed')):
                with self.assertRaisesRegex(ValueError, 'exactly three'):
                    bootstrap.publish(client, directory, {'runner': 'sha256:' + 'a' * 64})
                client.plan.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'API drift'):
                    bootstrap.publish(client, directory, dict.fromkeys(bootstrap.KINDS, 'sha256:' + 'a' * 64))
            self.assertEqual(list(directory.iterdir()), [])

    def test_scan_only_never_loads_service_credentials_or_constructs_api_client(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(bootstrap.api, 'WORK', Path(temporary)), \
                patch.object(bootstrap, 'prepare', return_value=dict.fromkeys(bootstrap.KINDS, 'synthetic')), \
                patch.object(bootstrap.api, 'Client', side_effect=AssertionError('Service credentials loaded')), \
                patch('sys.argv', ['bootstrap', '--scan-only']), patch('sys.stdout', new_callable=io.StringIO) as output:
            bootstrap.main()
            self.assertEqual(json.loads(output.getvalue()), {'scanned_tools': 3, 'service_credentials_used': False})

    def test_missing_archive_or_failed_scan_stops_before_publication_and_sanitizes_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaises(ValueError):
                bootstrap.prepare(directory, directory / 'scans')
            (directory / 'controller.tar').write_bytes(b'synthetic archive')
            with patch.object(Registry, 'command', return_value=('sha256:' + 'a' * 64).encode()), \
                    patch.object(bootstrap.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        [], 1, b'', b'synthetic private diagnostics')) as scan, \
                    patch.dict(bootstrap.os.environ, {'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'synthetic-writer',
                                                     'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic-reader'}):
                with self.assertRaisesRegex(RuntimeError, 'no registry publication'):
                    bootstrap.prepare(directory, directory / 'scans')
            self.assertNotIn('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', scan.call_args.kwargs['env'])
            self.assertNotIn('OP_SERVICE_ACCOUNT_TOKEN', scan.call_args.kwargs['env'])
            self.assertIn(bootstrap.SCAN['database'], scan.call_args.args[0])

    def test_scan_requires_complete_report_and_rechecks_archive_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in bootstrap.KINDS:
                (directory / (kind + '.tar')).write_bytes(b'synthetic archive')
            def scan(command, **kwargs):
                self.assertEqual(kwargs['env'].keys() - {'PATH', 'HOME'}, set())
                Path(command[command.index('--output') + 1]).write_text(json.dumps({
                    'SchemaVersion': 2, 'ArtifactType': 'container_image', 'Results': [{'Target': 'synthetic'}]}))
                return subprocess.CompletedProcess(command, 0, b'', b'')
            with patch.object(Registry, 'command', return_value=('sha256:' + 'a' * 64).encode()), \
                    patch.object(bootstrap.subprocess, 'run', side_effect=scan):
                self.assertEqual(set(bootstrap.prepare(directory, directory / 'scans')), set(bootstrap.KINDS))
            with patch.object(Registry, 'command', side_effect=[('sha256:' + 'a' * 64).encode(),
                                                              ('sha256:' + 'b' * 64).encode()]), \
                    patch.object(bootstrap.subprocess, 'run', side_effect=scan):
                with self.assertRaisesRegex(ValueError, 'changed while'):
                    bootstrap.prepare(directory, directory / 'scans')

    def test_scan_cannot_use_repository_ignores_or_accept_findings_hidden_by_success_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'controller.tar').write_bytes(b'synthetic archive')
            def scan(command, **kwargs):
                self.assertEqual(command[command.index('--config') + 1], '/dev/null')
                self.assertEqual(command[command.index('--ignorefile') + 1], '/dev/null')
                self.assertIn('--ignore-unfixed=false', command)
                self.assertEqual(command[command.index('--timeout') + 1], '15m')
                self.assertEqual(command[command.index('--parallel') + 1], '2')
                Path(command[command.index('--output') + 1]).write_text(json.dumps({
                    'SchemaVersion': 2, 'ArtifactType': 'container_image',
                    'Results': [{'Vulnerabilities': [{'Severity': 'HIGH'}]}]}))
                return subprocess.CompletedProcess(command, 0, b'', b'')
            with patch.object(Registry, 'command', return_value=('sha256:' + 'a' * 64).encode()), \
                    patch.object(bootstrap.subprocess, 'run', side_effect=scan):
                with self.assertRaisesRegex(ValueError, 'complete scan'):
                    bootstrap.prepare(directory, directory / 'scans')

    def test_interruption_repeat_and_changed_inputs_preserve_original_artifacts_and_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            images = {kind: 'sha256:' + digit * 64 for kind, digit in zip(bootstrap.KINDS, 'abc')}
            client = SimpleNamespace(path=directory, revision='d' * 40, env={}, plan=Mock(return_value={'changes': 0}),
                private={'host': 'harbor.internal.example.invalid', 'robots': {
                    bootstrap.PROJECT + '-push': {'username': 'public-push'},
                    bootstrap.PROJECT + '-pull': {'username': 'public-pull'}}})
            registry = Registry(client.private['host'], {}, directory / 'diagnostics')
            stored = {}
            pushed = []
            interrupted = [False]
            def digest(reference, missing=False):
                return stored.get(reference) if missing else (
                    reference.split('@')[1] if '@' in reference else stored[reference])
            def command(*arguments):
                kind = Path(arguments[2] if arguments[0] == 'digest' else arguments[1]).stem
                if arguments[0] == 'digest':
                    return images[kind].encode()
                self.assertEqual(arguments[0], 'push')
                if kind == 'runner' and not interrupted[0]:
                    interrupted[0] = True
                    raise RuntimeError('synthetic interruption')
                stored[arguments[2]] = images[kind]
                pushed.append(kind)
            with patch.object(bootstrap, 'Registry', return_value=registry), \
                    patch.object(registry, 'identity', return_value=nullcontext()) as identity, \
                    patch.object(registry, 'digest', side_effect=digest), \
                    patch.object(registry, 'command', side_effect=command):
                with self.assertRaisesRegex(RuntimeError, 'synthetic interruption'):
                    bootstrap.publish(client, directory, images)
                receipt = directory / 'ci' / client.revision / 'receipt.json'
                original = receipt.read_bytes()
                self.assertFalse((directory / 'ci/images.json').exists())
                self.assertEqual(bootstrap.publish(client, directory, images)['published_tools'], 3)
                bootstrap.publish(client, directory, images)
                self.assertEqual(pushed, list(bootstrap.KINDS))
                self.assertEqual(receipt.read_bytes(), original)
                self.assertEqual({call.args[0]['username'] for call in identity.call_args_list},
                                 {'public-push', 'public-pull'})
                with self.assertRaisesRegex(ValueError, 'inputs changed'):
                    bootstrap.publish(client, directory, dict(images, runner='sha256:' + 'f' * 64))
                self.assertEqual(receipt.read_bytes(), original)
            client.plan.assert_called_with(verify=True)
