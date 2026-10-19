import json
import base64
from contextlib import nullcontext
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from playbooks.harbor.files import signatures
from playbooks.harbor.files import recovery, restore
from playbooks.harbor.tests.fixtures import unsigned_registry


class SignatureTests(unittest.TestCase):
    def test_native_image_bundle_signing_needs_no_experimental_flags_or_public_services(self):
        with unsigned_registry() as host, tempfile.TemporaryDirectory() as temporary:
            registry = SimpleNamespace(host=host, environment={'PATH': os.environ['PATH'], 'HOME': temporary,
                'HTTPS_PROXY': 'http://127.0.0.1:9', 'NO_PROXY': '127.0.0.1'})
            signer = signatures.Cosign(registry)
            private = signatures.private_key()
            public = signatures.public_key(private)
            bundle = Path(temporary) / 'image-bundle.json'
            original = signer.command
            def command(*arguments, **kwargs):
                if arguments[0] == 'sign':
                    # Exercise the production arguments through native image signing,
                    # retaining its bundle locally instead of uploading to this stub.
                    arguments = (*arguments[:-1], '--allow-http-registry=true', '--upload=false',
                                 '--bundle', str(bundle), arguments[-1])
                return original(*arguments, **kwargs)
            reference = host + '/cloudlab-public/bootstrap@sha256:' + 'a' * 64
            with signer.key(private, public) as (key, verifier, password), \
                    patch.object(signer, 'command', side_effect=command), \
                    patch.object(signer, 'verify', side_effect=(False, True)):
                signer.sign(reference, key, verifier, password)
                verified = subprocess.run(['cosign', 'verify-blob-attestation', '--key', str(verifier), '--bundle', str(bundle),
                    '--insecure-ignore-tlog', '--digest', 'a' * 64, '--digestAlg', 'sha256',
                    '--type', 'https://sigstore.dev/cosign/sign/v1'], env=registry.environment,
                    capture_output=True, input=b'', timeout=30)
                self.assertEqual(verified.returncode, 0, verified.stderr.decode())
                self.assertFalse(original('verify-blob-attestation', '--key', str(verifier), '--bundle', str(bundle),
                    '--insecure-ignore-tlog', '--digest', 'b' * 64, '--digestAlg', 'sha256',
                    '--type', 'https://sigstore.dev/cosign/sign/v1', required=False))
                verifier.write_text(signatures.public_key(signatures.private_key()))
                self.assertFalse(original('verify-blob-attestation', '--key', str(verifier), '--bundle', str(bundle),
                    '--insecure-ignore-tlog', '--digest', 'a' * 64, '--digestAlg', 'sha256',
                    '--type', 'https://sigstore.dev/cosign/sign/v1', required=False))

    def proof(self):
        digests = ['sha256:' + format(number, '064x') for number in range(1, 13)]
        return {'format': 1, 'image': json.loads((recovery.ARTIFACTS / 'cosign.lock.json').read_text())['image'],
                'verifier_sha256': 'f' * 64,
                'projects': {'cloudlab-public': digests[:6], 'cloudlab-private': digests[6:]}}, digests

    def test_capture_rejects_missing_rollback_digest_or_changed_verifier_image(self):
        proof, digests = self.proof()
        self.assertEqual(recovery.signature_record(proof, {'artifact_digests': digests}), proof)
        for mutation in ('missing', 'duplicate', 'scope', 'image'):
            value = json.loads(json.dumps(proof))
            if mutation == 'missing': value['projects']['cloudlab-public'].pop()
            if mutation == 'duplicate': value['projects']['cloudlab-public'][0] = value['projects']['cloudlab-public'][1]
            if mutation == 'scope': value['projects']['foreign'] = value['projects'].pop('cloudlab-public')
            if mutation == 'image': value['image'] = 'unreviewed'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                recovery.signature_record(value, {'artifact_digests': digests})
        with self.assertRaises(ValueError): recovery.signature_record(proof, {'artifact_digests': digests[:-1]})

    def test_verifier_update_preserves_receipt_bytes_and_rejects_changed_signer_or_images(self):
        proof, _ = self.proof()
        previous = json.loads((recovery.ARTIFACTS / 'cosign.lock.json').read_text())['compatible_images'][0]
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / 'receipt.json'
            self.assertEqual(signatures.preserve_receipt(journal, proof), proof)
            recorded = dict(proof, image=previous)
            journal.write_text(json.dumps(recorded, indent=2))
            original = journal.read_bytes()
            for _ in range(2):
                self.assertEqual(signatures.preserve_receipt(journal, proof), recorded)
                self.assertEqual(journal.read_bytes(), original)
            with self.assertRaises(ValueError):
                signatures.preserve_receipt(journal, dict(proof, verifier_sha256='0' * 64))
            self.assertEqual(journal.read_bytes(), original)
            changed = json.loads(json.dumps(proof))
            changed['projects']['cloudlab-private'][0] = 'sha256:' + 'e' * 64
            with self.assertRaises(ValueError):
                signatures.preserve_receipt(journal, changed)
            self.assertEqual(journal.read_bytes(), original)
            with self.assertRaises(ValueError):
                signatures.preserve_receipt(journal, dict(proof, image='unreviewed'))
            self.assertEqual(journal.read_bytes(), original)
            journal.write_text(json.dumps(dict(recorded, image='unreviewed')))
            invalid = journal.read_bytes()
            with self.assertRaises(ValueError):
                signatures.preserve_receipt(journal, proof)
            self.assertEqual(journal.read_bytes(), invalid)

    def test_remote_journal_rejects_changed_signer_and_does_not_receive_private_material(self):
        proof, digests = self.proof()
        public = signatures.public_key(signatures.private_key())
        proof['verifier_sha256'] = hashlib.sha256(public.encode()).hexdigest()
        with patch.object(recovery, 'secret', return_value={'public_key': base64.b64encode(public.encode()).decode()}) as secret:
            recovery.signature_binding(proof)
            secret.assert_called_once_with(signatures.VERIFIER)
            with self.assertRaises(RuntimeError): recovery.signature_binding(dict(proof, verifier_sha256='0' * 64))
        with tempfile.TemporaryDirectory() as temporary, patch.object(recovery, 'BASE', Path(temporary)), \
                patch.object(recovery, 'locked', return_value=nullcontext()), patch.object(recovery, 'resume'), \
                patch.object(recovery, 'inventory', return_value={'artifact_digests': digests}), \
                patch.object(recovery, 'signature_binding'):
            with patch('sys.stdin', io.StringIO(json.dumps(proof))):
                self.assertEqual(recovery.run('record-signatures'),
                                 {'signature_digests_recorded': 12, 'private_key_received': False})
            original = (Path(temporary) / 'signed-artifacts.json').read_bytes()
            changed = dict(proof, verifier_sha256='0' * 64)
            with patch('sys.stdin', io.StringIO(json.dumps(changed))), self.assertRaisesRegex(RuntimeError, 'replacement refused'):
                recovery.run('record-signatures')
            self.assertEqual((Path(temporary) / 'signed-artifacts.json').read_bytes(), original)

    def test_restore_probe_has_only_public_verifier_and_isolated_ephemeral_auth(self):
        proof, digests = self.proof()
        verifier = json.loads((recovery.ARTIFACTS / 'cosign.lock.json').read_text())
        proof['image'] = verifier['compatible_images'][0]
        pod = restore.signature_probe(proof)
        spec = pod['spec']
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertTrue(spec['securityContext']['runAsNonRoot'])
        self.assertEqual(spec['securityContext']['seccompProfile']['type'], 'RuntimeDefault')
        self.assertEqual(spec['volumes'][0]['emptyDir'], {'medium': 'Memory', 'sizeLimit': '1Mi'})
        self.assertEqual(spec['volumes'][1]['secret']['secretName'], signatures.VERIFIER)
        self.assertNotIn(signatures.SIGNER, json.dumps(pod))
        native = spec['containers'][0]
        self.assertEqual(native['image'], verifier['image'])
        self.assertNotEqual(native['image'], proof['image'])
        self.assertEqual(native['args'].count('--allow-http-registry=true'), 1)
        self.assertEqual(len([value for value in native['args'] if '/bootstrap@sha256:' in value]), 12)
        self.assertTrue(all(value.startswith('harbor.cloudlab-harbor-restore.svc/')
                            for value in native['args'] if '/bootstrap@' in value))
        self.assertTrue(all(mount['readOnly'] for mount in native['volumeMounts']))
        for container in [*spec['containers'], *spec['initContainers']]:
            self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
            self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
            self.assertEqual(container['securityContext']['capabilities']['drop'], ['ALL'])
        init = spec['initContainers'][0]
        self.assertTrue(all('valueFrom' in value for value in init['env']))
        with tempfile.TemporaryDirectory() as directory:
            script = init['command'][-1].replace('/auth/config.json', directory + '/config.json')
            result = subprocess.run([os.sys.executable, '-c', script], capture_output=True,
                                    env={'USERNAME': 'synthetic-admin', 'PASSWORD': 'synthetic-private-recovery-password'})
            self.assertEqual(result.returncode, 0, 'Native memory-auth initialization failed')
            self.assertEqual(result.stdout, b'')
            self.assertEqual((Path(directory) / 'config.json').stat().st_mode & 0o777, 0o600)

    def test_interrupted_public_delivery_preserves_original_private_key_on_repeat(self):
        items = {}
        interruption = True
        def ensure(token, definitions):
            nonlocal interruption
            result = {'created': [], 'preserved': []}
            for name, fields in definitions.items():
                if name == signatures.VERIFIER and interruption:
                    interruption = False
                    raise RuntimeError('interrupted before public delivery')
                if name in items:
                    result['preserved'].append(name)
                else:
                    items[name] = {field: factory() for field, (_, factory) in fields.items()}
                    result['created'].append(name)
            return result
        with patch.object(signatures, 'ensure_items', side_effect=ensure), \
                patch.object(signatures, 'durable', side_effect=lambda token, title, field, kind: items[title][field]):
            with self.assertRaisesRegex(RuntimeError, 'interrupted'): signatures.provision('synthetic-local-token')
            original = dict(items[signatures.SIGNER])
            result = signatures.provision('synthetic-local-token')
            self.assertEqual(items[signatures.SIGNER], original)
            self.assertEqual(result['preserved'], [signatures.SIGNER])
            self.assertEqual(result['created'], [signatures.VERIFIER])
            self.assertEqual(items[signatures.VERIFIER], {
                'public_key': signatures.public_key(original['private_key'])})
            self.assertFalse(signatures.provision('synthetic-local-token')['created'])
            items[signatures.VERIFIER]['public_key'] = signatures.public_key(signatures.private_key())
            with self.assertRaisesRegex(ValueError, 'replacement refused'): signatures.provision('synthetic-local-token')
            self.assertEqual(items[signatures.SIGNER], original)

    def test_native_import_and_blob_verification_work_without_public_services(self):
        registry = SimpleNamespace(environment={'PATH': os.environ['PATH'], 'HOME': '/tmp',
            'HTTPS_PROXY': 'http://127.0.0.1:9', 'NO_PROXY': '', 'OP_SERVICE_ACCOUNT_TOKEN': 'must-not-forward',
            'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'must-not-forward'})
        signer = signatures.Cosign(registry)
        private = signatures.private_key()
        public = signatures.public_key(private)
        with tempfile.TemporaryDirectory() as temporary, signer.key(private, public) as (key, verifier, password):
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            directory = key.parent
            self.assertFalse((directory / 'private.pem').exists())
            payload, bundle = Path(temporary) / 'payload', Path(temporary) / 'bundle.json'
            payload.write_bytes(b'CloudLab immutable recovery proof')
            signer.command('sign-blob', '--yes', '--use-signing-config=false', '--tlog-upload=false',
                           '--key', str(key), '--bundle', str(bundle), str(payload), password=password)
            signer.command('verify-blob', '--key', str(verifier), '--bundle', str(bundle),
                           '--insecure-ignore-tlog', str(payload))
            verifier.write_text(signatures.public_key(signatures.private_key()))
            self.assertFalse(signer.command('verify-blob', '--key', str(verifier), '--bundle', str(bundle),
                                           '--insecure-ignore-tlog', str(payload), required=False))
        self.assertFalse(directory.exists())

    def test_private_key_binding_and_child_environment_fail_closed(self):
        registry = SimpleNamespace(host='harbor.internal.example.invalid', environment={'PATH': '/usr/local/bin', 'DOCKER_CONFIG': '/tmp/fixture',
            'HARBOR_PASSWORD': 'do-not-forward', 'TF_HTTP_PASSWORD': 'do-not-forward',
            'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'do-not-forward'})
        signer = signatures.Cosign(registry)
        with patch.object(signatures.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as process:
            signer.command('version', password='synthetic-ephemeral-password')
            self.assertEqual(process.call_args.kwargs['env'], {'PATH': '/usr/local/bin',
                'DOCKER_CONFIG': '/tmp/fixture', 'COSIGN_PASSWORD': 'synthetic-ephemeral-password'})
            self.assertNotIn('synthetic-ephemeral-password', process.call_args.args[0])
            with self.assertRaisesRegex(ValueError, 'do not match'):
                with signer.key(signatures.private_key(), signatures.public_key(signatures.private_key())):
                    self.fail('Mismatched key reached the native tool')
            self.assertEqual(process.call_count, 1)
            for reference in ('harbor.internal.example.invalid/cloudlab-public/bootstrap:latest',
                              'harbor.internal.example.invalid/foreign/bootstrap@sha256:' + 'a' * 64,
                              'other.internal.example.invalid/cloudlab-public/bootstrap@sha256:' + 'a' * 64):
                with self.subTest(reference=reference), self.assertRaises(ValueError):
                    signer.verify(reference, '/tmp/public.pem')
            self.assertEqual(process.call_count, 1)

    def test_restore_and_local_tool_use_the_same_external_digest(self):
        root = Path(__file__).resolve().parents[4]
        image = json.loads((root / 'platform/harbor/cosign.lock.json').read_text())['image']
        self.assertRegex(image, r'^cgr[.]dev/chainguard/cosign@sha256:[a-f0-9]{64}$')
        dockerfile = (root / 'ansible/runner/Dockerfile').read_text()
        self.assertIn('FROM ' + image + ' AS cosign', dockerfile)
        self.assertIn('COPY --from=cosign /usr/bin/cosign /usr/local/bin/cosign', dockerfile)
