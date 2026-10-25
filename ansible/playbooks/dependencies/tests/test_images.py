"""Image maintenance keeps full references and digest-field companions coherent."""
import unittest
import json
import base64
from pathlib import Path
import tempfile
from unittest.mock import patch

from playbooks.dependencies.files.images import transform, reference, compatible_tag, compatible_postgresql
from playbooks.dependencies.files import images


class ImageTests(unittest.TestCase):
    def test_final_verification_requires_all_active_copies_and_preserves_independent_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = 'docker.io/istio/pilot:1.31.1@sha256:' + 'a' * 64
            new = 'docker.io/istio/pilot:1.31.2@sha256:' + 'b' * 64
            independent = 'docker.io/istio/pilot:1.30.1@sha256:' + 'c' * 64
            base = {'source.json': {'image': old}, 'preview.json': {'image': old},
                    'independent.json': {'image': independent}}
            plan = {'baseFiles': {path: base64.b64encode(json.dumps(value).encode()).decode() for path, value in base.items()}}
            for path, value in base.items():
                (root / path).write_text(json.dumps(value))
            (root / 'source.json').write_text(json.dumps({'image': new}))
            with self.assertRaisesRegex(ValueError, 'active immutable companion'):
                images.provenance(root, plan, resolve=None)
            (root / 'preview.json').write_text(json.dumps({'image': new}))
            self.assertEqual(images.provenance(root, plan, resolve=None), 1)

    def test_cosign_historical_images_remain_valid_after_active_image_update(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = 'platform/harbor/cosign.lock.json'
            old = 'cgr.dev/chainguard/cosign@sha256:' + 'a' * 64
            new = 'cgr.dev/chainguard/cosign@sha256:' + 'b' * 64
            history = 'ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:' + 'c' * 64
            before = {'image': old, 'compatible_images': [history], 'version': '3.1.3'}
            target = root / path
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(dict(before, image=new, compatible_images=[history, old])))
            (root / 'Dockerfile').write_text('FROM ' + new + ' AS cosign\n')
            plan = {'baseFiles': {path: base64.b64encode(json.dumps(before).encode()).decode(),
                                 'Dockerfile': base64.b64encode(('FROM ' + old + ' AS cosign\n').encode()).decode()}}
            self.assertEqual(images.provenance(root, plan, resolve=None), 0)
    def test_final_verification_rejects_partial_coupled_release_update(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = 'platform/connectivity/istio/images.lock.json'
            target = root / path
            target.parent.mkdir(parents=True)
            old = {'pilot': 'docker.io/istio/pilot:1.31.1@sha256:' + 'a' * 64,
                   'proxy': 'docker.io/istio/proxyv2:1.31.1@sha256:' + 'b' * 64}
            new = dict(old, pilot=old['pilot'].replace('1.31.1', '1.31.2'))
            target.write_text(json.dumps(new))
            plan = {'baseFiles': {path: base64.b64encode(json.dumps(old).encode()).decode()}}
            with self.assertRaisesRegex(ValueError, 'Coupled'):
                images.provenance(root, plan, resolve=None)
            target.write_text(json.dumps({key: value.replace('1.31.1', '1.31.2') for key, value in old.items()}))
            self.assertEqual(images.provenance(root, plan, resolve=None), 2)

    def test_monitoring_couples_only_operator_and_reloader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = 'platform/observability/images.lock.json'
            target = root / path
            target.parent.mkdir(parents=True)
            old = {'operator': 'quay.io/prometheus-operator/prometheus-operator:v0.94.1@sha256:' + 'a' * 64,
                   'reloader': 'quay.io/prometheus-operator/prometheus-config-reloader:v0.94.1@sha256:' + 'b' * 64,
                   'prometheus': 'quay.io/prometheus/prometheus:v3.15.0-distroless@sha256:' + 'c' * 64}
            plan = {'baseFiles': {path: base64.b64encode(json.dumps(old).encode()).decode()}}
            new = dict(old, operator=old['operator'].replace('v0.94.1', 'v0.94.2'))
            target.write_text(json.dumps(new))
            with self.assertRaisesRegex(ValueError, 'Coupled monitoring'):
                images.provenance(root, plan, resolve=None)
            new['reloader'] = new['reloader'].replace('v0.94.1', 'v0.94.2')
            target.write_text(json.dumps(new))
            self.assertEqual(images.provenance(root, plan, resolve=None), 2)
    def test_verification_resolves_complete_changed_pins_and_rejects_borrowed_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = 'quay.io/argoproj/argocd:v3.5.2@sha256:' + 'a' * 64
            new = 'quay.io/argoproj/argocd:v3.5.3@sha256:' + 'b' * 64
            before = json.dumps({'images': {'nested': old}}).encode()
            target = root / 'images.lock.json'
            target.write_text(json.dumps({'images': {'nested': new}, 'copy': new}))
            plan = {'baseFiles': {'images.lock.json': base64.b64encode(before).decode()}}
            resolve = lambda tag, **kwargs: tag + '@sha256:' + 'b' * 64
            self.assertEqual(images.provenance(root, plan, resolve=resolve), 1)
            target.write_text(json.dumps({'images': {'nested': new.replace('b' * 64, 'a' * 64)}}))
            with self.assertRaises(ValueError):
                images.provenance(root, plan, resolve=resolve)

    def test_verification_reads_split_helm_pins_and_accepts_exact_amd64_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = b'image: {repository: quay.io/argoproj/argocd, tag: v3.5.2, digest: sha256:' + b'a' * 64 + b'}\n'
            (root / 'values.yaml').write_bytes(before.replace(b'v3.5.2', b'v3.5.3').replace(b'a' * 64, b'b' * 64))
            plan = {'baseFiles': {'values.yaml': base64.b64encode(before).decode()}}
            def resolve(tag, *, platform=None):
                return tag + '@sha256:' + ('b' if platform == 'linux/amd64' else 'c') * 64
            self.assertEqual(images.provenance(root, plan, resolve=resolve), 1)
    def test_postgresql_patch_keeps_major_and_distribution(self):
        self.assertTrue(compatible_postgresql('18.4-standard-trixie', '18.5-standard-trixie'))
        self.assertFalse(compatible_postgresql('18.4-standard-trixie', '19.0-standard-trixie'))
        self.assertFalse(compatible_postgresql('18.4-standard-trixie', '18.5-standard-bookworm'))

    def test_native_tag_key_update_repairs_digest_and_complete_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted, candidate = Path(directory) / 'trusted', Path(directory) / 'candidate'
            trusted.mkdir()
            candidate.mkdir()
            old = 'quay.io/argoproj/argocd:v3.5.2'
            new = 'quay.io/argoproj/argocd:v3.5.3'
            (trusted / 'artifact.lock.json').write_text(json.dumps({'images': {old: 'sha256:' + 'a' * 64}}))
            (candidate / 'artifact.lock.json').write_text(json.dumps({'images': {new: 'sha256:' + 'a' * 64}}))
            (candidate / 'values.yaml').write_text('image: ' + old + '@sha256:' + 'a' * 64 + '\n')
            owner = {'sources': ['artifact.lock.json'], 'writePaths': ['artifact.lock.json', 'values.yaml'], 'selectors': [old]}
            with patch.object(images, 'ROOT', trusted), patch.object(images, 'selected', return_value={'image:argocd': owner}), \
                    patch.object(images, 'image_digest', side_effect=lambda image: image + '@sha256:' + 'b' * 64):
                images.update(candidate, 'argocd', {'selector': old, 'version': 'v3.5.3'})
            self.assertEqual(json.loads((candidate / 'artifact.lock.json').read_bytes())['images'], {new: 'sha256:' + 'b' * 64})
            self.assertIn(new + '@sha256:' + 'b' * 64, (candidate / 'values.yaml').read_text())
    def test_tested_minor_and_distribution_are_required(self):
        self.assertTrue(compatible_tag('3.13-slim-bookworm', '3.13.9-slim-bookworm'))
        self.assertTrue(compatible_tag('v1.36.5-k3s1', 'v1.36.6-k3s2'))
        self.assertFalse(compatible_tag('3.13-slim-bookworm', '3.14-slim-bookworm'))
        self.assertFalse(compatible_tag('3.13-slim-bookworm', '3.13-alpine'))
        self.assertFalse(compatible_tag('v1.36.5-k3s1', 'v1.37.1-k3s1'))
    def test_updates_full_reference_tag_digest_and_keyed_lock_together(self):
        old = 'docker.io/example/tool:v1.0.1@sha256:' + 'a' * 64
        new = 'docker.io/example/tool:v1.0.2@sha256:' + 'b' * 64
        value = {'full': old, 'image': {'repository': 'example/tool', 'tag': 'v1.0.1', 'digest': 'sha256:' + 'a' * 64},
                 'compound': 'v1.0.1@sha256:' + 'a' * 64,
                 'locks': {'docker.io/example/tool:v1.0.1': 'sha256:' + 'a' * 64}}
        updated = transform(value, {old: new})
        self.assertEqual(updated['full'], new)
        self.assertEqual(updated['image']['tag'], 'v1.0.2')
        self.assertEqual(updated['image']['digest'], 'sha256:' + 'b' * 64)
        self.assertEqual(updated['compound'], 'v1.0.2@sha256:' + 'b' * 64)
        self.assertEqual(updated['locks'], {'docker.io/example/tool:v1.0.2': 'sha256:' + 'b' * 64})

    def test_arbitrary_registry_and_mutable_reference_are_rejected(self):
        for value in ('private.example/tool:v1@sha256:' + 'a' * 64, 'docker.io/example/tool:latest'):
            with self.assertRaises(ValueError):
                reference(value)
