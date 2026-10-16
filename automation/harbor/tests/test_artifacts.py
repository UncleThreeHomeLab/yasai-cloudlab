import hashlib
from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
from unittest.mock import Mock, patch

from automation.harbor import artifacts


class ArtifactTests(unittest.TestCase):
    def test_rollback_interruption_preserves_archive_and_refuses_foreign_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            registry = Mock()
            registry.identity.side_effect = lambda *args: nullcontext(registry)
            registry.reference.return_value = 'harbor.internal.example.invalid/cloudlab-public/bootstrap:deploy-bootstrap'
            registry.digest.return_value = None
            project = 'cloudlab-public'
            entry = {'digest': 'sha256:' + 'a' * 64, 'payload_bytes': artifacts.LARGE_LAYER, 'payload_sha256': 'b' * 64}
            record = {'recipe': 1, 'base': artifacts.PYTHON, 'projects': {project: entry}, 'verified_at': 123}
            recorded = directory / 'receipt.json'
            archive = directory / (project + '-' + artifacts.ROLLBACK_TAGS[0] + '.tar')
            credentials = {project + '-push': {'username': 'synthetic', 'password': 'synthetic'}}
            def command(*arguments):
                if arguments[0] == 'append':
                    archive.write_bytes(b'original-rollback-image')
                    return b''
                if arguments[0] == 'digest': return ('sha256:' + 'c' * 64).encode()
                if arguments[0] == 'push':
                    self.assertNotIn('verified_at', artifacts.receipt(recorded))
                    self.assertEqual(artifacts.receipt(recorded)['projects'][project]['rollback'][artifacts.ROLLBACK_TAGS[0]]['digest'],
                                     'sha256:' + 'c' * 64)
                    raise RuntimeError('interrupted rollback upload')
                self.fail('Unexpected OCI operation')
            registry.command.side_effect = command
            with patch.object(artifacts, 'payload', return_value=(directory / 'layer.tar', 'd' * 64)):
                with self.assertRaisesRegex(RuntimeError, 'interrupted rollback upload'):
                    artifacts.rollback_artifacts(registry, credentials, directory, recorded, record, project)
                self.assertEqual(archive.read_bytes(), b'original-rollback-image')
                registry.digest.return_value = 'sha256:' + 'e' * 64
                registry.command.reset_mock()
                with self.assertRaisesRegex(RuntimeError, 'rollback tag changed'):
                    artifacts.rollback_artifacts(registry, credentials, directory, recorded, record, project)
                registry.command.assert_not_called()
                self.assertEqual(archive.read_bytes(), b'original-rollback-image')

    def test_rollback_receipt_rejects_duplicate_digests_and_unknown_tags(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'receipt.json'
            row = {'digest': 'sha256:' + 'a' * 64, 'payload_bytes': 4096, 'payload_sha256': 'b' * 64}
            entry = dict(row, payload_bytes=artifacts.LARGE_LAYER)
            for rollback in ({'foreign': row}, {tag: row for tag in artifacts.ROLLBACK_TAGS[:2]},
                             {artifacts.ROLLBACK_TAGS[0]: dict(row, payload_bytes=1)}):
                path.write_text(json.dumps({'recipe': 1, 'base': artifacts.PYTHON,
                                            'projects': {'cloudlab-public': dict(entry, rollback=rollback)}}))
                with self.assertRaises(ValueError): artifacts.receipt(path)

    def test_native_oci_append_is_reproducible_without_a_registry_or_docker_socket(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            layer, first = artifacts.payload(directory, 4096)
            _, second = artifacts.payload(directory, 4096)
            self.assertEqual(first, second)
            digests = []
            for index in range(2):
                image = directory / ('image-' + str(index) + '.tar')
                result = subprocess.run(['crane', 'append', '--oci-empty-base', '--new_layer', str(layer),
                    '--new_tag', 'example.invalid/bootstrap:fixture', '--output', str(image)], capture_output=True)
                self.assertEqual(result.returncode, 0, 'Native offline OCI append failed')
                result = subprocess.run(['crane', 'digest', '--tarball', str(image)], capture_output=True)
                self.assertEqual(result.returncode, 0, 'Native offline OCI digest failed')
                digests.append(result.stdout)
            self.assertEqual(digests[0], digests[1])
            _, other = artifacts.payload(directory, 4096, 'cloudlab-private')
            self.assertNotEqual(first, other)

    def test_upload_interruption_preserves_original_archive_and_blocks_another_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            client, registry = Mock(), Mock()
            client.path, client.env = Path(temporary), {}
            client.private = {'host': 'harbor.internal.example.invalid',
                              'robots': {'cloudlab-public-push': {'username': 'synthetic', 'password': 'synthetic'}}}
            client.native.return_value.stdout = b'{}'
            client.accepted.return_value = {}
            registry.identity.side_effect = lambda *args: nullcontext(registry)
            registry.reference.return_value = 'harbor.internal.example.invalid/cloudlab-public/bootstrap:deploy-bootstrap'
            registry.digest.return_value = None
            archive = client.path / 'artifacts/cloudlab-public.tar'
            recorded = client.path / 'artifacts/receipt.json'
            def command(*arguments):
                if arguments[0] == 'append':
                    archive.write_bytes(b'original-generated-image')
                    return b''
                if arguments[0] == 'digest': return ('sha256:' + 'a' * 64).encode()
                if arguments[0] == 'push':
                    self.assertEqual(artifacts.receipt(recorded)['projects']['cloudlab-public']['digest'], 'sha256:' + 'a' * 64)
                    raise RuntimeError('interrupted upload')
                self.fail('Unexpected OCI operation')
            registry.command.side_effect = command
            with patch.object(artifacts, 'Registry', return_value=registry), \
                    patch.object(artifacts, 'ciphertext'), patch.object(artifacts.api_policy, 'inventory', return_value={}), \
                    patch.object(artifacts, 'payload', return_value=(Path(temporary) / 'layer.tar', 'b' * 64)):
                with self.assertRaisesRegex(RuntimeError, 'interrupted upload'): artifacts.run(client)
                self.assertEqual(archive.read_bytes(), b'original-generated-image')
                registry.digest.return_value = 'sha256:' + 'c' * 64
                registry.command.reset_mock()
                with self.assertRaisesRegex(RuntimeError, 'another digest'): artifacts.run(client)
                registry.command.assert_not_called()
                self.assertEqual(archive.read_bytes(), b'original-generated-image')

    def test_generated_payload_is_verified_without_extracting_archive_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            layer, digest = artifacts.payload(Path(temporary), 4096)
            expected = {'payload_bytes': 4096, 'payload_sha256': digest}
            artifacts.verify_payload(layer, expected)
            self.assertEqual(hashlib.sha256((Path(temporary) / 'payload.bin').read_bytes()).hexdigest(), digest)
            for change in ({'payload_bytes': 4097}, {'payload_sha256': '0' * 64}):
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    artifacts.verify_payload(layer, dict(expected, **change))

    def test_receipt_preserves_exact_artifact_input_and_rejects_scope_or_size_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'receipt.json'
            self.assertEqual(artifacts.receipt(path)['projects'], {})
            entry = {'digest': 'sha256:' + 'a' * 64, 'payload_bytes': artifacts.LARGE_LAYER, 'payload_sha256': 'b' * 64}
            record = {'recipe': 1, 'base': artifacts.PYTHON, 'projects': {'cloudlab-public': entry}}
            path.write_text(json.dumps(record))
            self.assertEqual(artifacts.receipt(path), record)
            for invalid in (dict(record, base='unreviewed'), dict(record, projects={'foreign': entry}),
                            dict(record, projects={'cloudlab-public': dict(entry, payload_bytes=1)})):
                path.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError): artifacts.receipt(path)
