"""Public fixture scope, native derivation and dormant Loki patch boundaries."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import yaml

from playbooks.observability.files.package import loki_declarative
from playbooks.observability.tests import storage_fixture as fixture


class StorageFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources, cls.pins = fixture.source_objects()
        cls.files = fixture.build(cls.sources, cls.pins)
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        for name, raw in cls.files.items():
            (cls.directory / name).parent.mkdir(parents=True, exist_ok=True)
            (cls.directory / name).write_bytes(raw)
        cls.operations = ('a1b2c3d4e5f60789', '0123456789abcdef')
        cls.rendered = {(operation, phase): fixture.render_fixture(cls.directory, operation, phase)
                        for operation in cls.operations for phase in ('running', 'scaled-down', 'removed')}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_committed_artifacts_are_exact_native_derivation(self):
        self.assertEqual(fixture.build(self.sources, self.pins), self.files)
        self.assertEqual({str(path.relative_to(fixture.FIXTURE)) for path in fixture.FIXTURE.rglob('*') if path.is_file()}, set(self.files))
        for name, raw in self.files.items():
            self.assertEqual((fixture.FIXTURE / name).read_bytes(), raw, name)
        lock = json.loads(self.files['derivation.lock.json'])
        self.assertEqual(lock['checksumBasis']['input'], 'Helm toJson(projected ConfigMap.data)')
        self.assertIn('not the upstream', lock['checksumBasis']['semantics'])

    def test_two_operation_scopes_and_only_declared_phase_changes(self):
        identities = []
        for operation in self.operations:
            for phase in ('running', 'scaled-down', 'removed'):
                fixture.validate_rendered(self.rendered[operation, phase], operation, phase)
            running = copy.deepcopy(self.rendered[operation, 'running'])
            scaled = self.rendered[operation, 'scaled-down']
            for obj in running:
                if obj['kind'] in ('StatefulSet', 'Deployment'):
                    obj['spec']['replicas'] = 0
            self.assertEqual(running, scaled)
            self.assertEqual(len(self.rendered[operation, 'removed']), 1)
            identities.append({obj['metadata']['name'] for obj in running})
        self.assertFalse(identities[0] & identities[1])

    def test_checksum_is_exact_projected_data_and_credentials_are_dummy_only(self):
        operation = self.operations[0]
        rows = self.rendered[operation, 'running']
        indexed = {fixture.key(obj): obj for obj in rows}
        prefix = 'obs-storage-' + operation
        for component in ('loki', 'tempo', 'grafana'):
            data = indexed['ConfigMap', prefix + '-' + component + '-config']['data']
            # Go's encoding/json used by Helm escapes these characters in JSON strings.
            raw = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
            for character, escape in [('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'),
                                      ('\u2028', '\\u2028'), ('\u2029', '\\u2029')]:
                raw = raw.replace(character, escape)
            kind = 'Deployment' if component == 'grafana' else 'StatefulSet'
            annotation = indexed[kind, prefix + '-' + component]['spec']['template']['metadata']['annotations']['checksum/config']
            self.assertEqual(annotation, hashlib.sha256(raw.encode()).hexdigest())
        for name, data in fixture.DUMMY_SECRETS.items():
            self.assertEqual(indexed['Secret', prefix + '-' + name]['stringData'], data)
        data = yaml.safe_load(indexed['ConfigMap', prefix + '-grafana-config']['data']['datasources.yaml'])
        self.assertEqual(data['datasources'][0]['url'], 'http://unused.fixture.invalid:9090')

    def test_source_profile_preserved_and_forbidden_transforms_fail(self):
        projected = fixture.project(self.sources)
        fixture.validate_projection(self.sources, projected)
        for change in ('command', 'security', 'mount', 'image', 'secret', 'service', 'config', 'metadata'):
            bad = copy.deepcopy(projected)
            workload = next(obj for obj in bad if obj['kind'] == 'StatefulSet')
            container = workload['spec']['template']['spec']['containers'][0]
            if change == 'command': container['command'] = ['/bin/false']
            if change == 'security': workload['spec']['template']['spec']['securityContext']['runAsUser'] = 0
            if change == 'mount': container['volumeMounts'][0]['mountPath'] = '/unexpected'
            if change == 'image': container['image'] = 'example.invalid/other@sha256:' + 'f' * 64
            if change == 'secret': next(obj for obj in bad if obj['kind'] == 'Secret')['stringData']['password'] = 'different'
            if change == 'service': next(obj for obj in bad if obj['kind'] == 'Service')['spec']['type'] = 'LoadBalancer'
            if change == 'config': next(obj for obj in bad if obj['kind'] == 'ConfigMap')['data']['injected'] = 'value'
            if change == 'metadata': workload['metadata']['annotations'] = {'argocd.argoproj.io/hook': 'Sync'}
            with self.subTest(change=change), self.assertRaises(ValueError):
                fixture.validate_projection(self.sources, bad)

    def test_unknown_sources_token_secrets_and_dangling_mounts_fail_closed(self):
        bad = copy.deepcopy(self.sources)
        bad.append({'apiVersion': 'batch/v1', 'kind': 'Job', 'metadata': {'name': 'unknown'}})
        with self.assertRaisesRegex(ValueError, 'Unknown excluded'):
            fixture.project(bad)
        bad = copy.deepcopy(self.sources)
        root = next(obj for obj in bad if fixture.key(obj) == ('StatefulSet', 'cloudlab-loki'))
        root['spec']['serviceName'] = 'absent-headless'
        with self.assertRaisesRegex(ValueError, 'governing Service'):
            fixture.project(bad)
        projected = fixture.project(self.sources)
        for change in ('token', 'pull', 'mount', 'owner'):
            bad = copy.deepcopy(projected)
            if change == 'token': next(obj for obj in bad if obj['kind'] == 'Secret')['type'] = 'kubernetes.io/service-account-token'
            if change == 'pull': next(obj for obj in bad if obj['kind'] == 'ServiceAccount')['imagePullSecrets'] = [{'name': 'private'}]
            if change == 'mount': next(obj for obj in bad if obj['kind'] == 'StatefulSet')['spec']['template']['spec']['containers'][0]['volumeMounts'][0]['name'] = 'absent'
            if change == 'owner': bad[0]['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
            with self.subTest(change=change), self.assertRaises(ValueError):
                fixture.validate_closure(bad)

    def test_values_and_namespace_reject_scope_escape_and_template_injection(self):
        operation = self.operations[0]
        cases = [('cloudlab-observability', operation, 'running', None),
                 (None, 'A' * 16, 'running', None), (None, 'a' * 15, 'running', None),
                 (None, '../' + 'a' * 16, 'running', None), (None, '{{fail "x"}}', 'running', None),
                 (None, operation, 'unknown', None), (None, operation, 'running', {'namespace': 'production'}),
                 (None, operation, 'running', {'operationId': 1234}),
                 (None, operation, 'running', {'phase': None})]
        for namespace, identifier, phase, extra in cases:
            with self.subTest(namespace=namespace, identifier=identifier, phase=phase, extra=extra), self.assertRaises(ValueError):
                fixture.render_fixture(self.directory, identifier, phase, namespace=namespace, extra=extra)

    def test_native_template_text_remains_literal_and_marker_collisions_reject(self):
        changed = copy.deepcopy(self.sources)
        dashboard = next(obj for obj in changed if fixture.key(obj) == ('ConfigMap', 'cloudlab-dashboards'))
        dashboard['data']['literal.txt'] = '{{ fail "must remain data" }}'
        files = fixture.build(changed, self.pins)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, raw in files.items():
                (directory / name).parent.mkdir(parents=True, exist_ok=True)
                (directory / name).write_bytes(raw)
            rows = fixture.render_fixture(directory, self.operations[0], 'running')
            actual = next(obj for obj in rows if obj['metadata']['name'].endswith('-grafana-dashboards'))
            self.assertEqual(actual['data']['literal.txt'], dashboard['data']['literal.txt'])
        dashboard['data']['literal.txt'] = '@@OPERATION@@'
        with self.assertRaisesRegex(ValueError, 'collides'):
            fixture.build(changed, self.pins)

    def test_scope_validation_remains_enforced_when_schema_validation_is_skipped(self):
        for values in ({'operationId': '{{ fail "escape" }}', 'phase': 'running'},
                       {'operationId': self.operations[0], 'phase': 'running', 'namespace': 'production'},
                       {'operationId': self.operations[0], 'phase': 'unexpected'}):
            result = subprocess.run(['helm', 'template', 'fixture', str(self.directory), '--namespace',
                'obs-storage-' + self.operations[0], '--skip-schema-validation', '-f', '-'],
                input=yaml.safe_dump(values), text=True, capture_output=True, timeout=30)
            with self.subTest(values=values):
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(result.stdout.strip())

    def test_failed_discovery_never_changes_existing_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            accepted = path / 'Chart.yaml'
            accepted.write_bytes(b'accepted content')
            with patch.object(fixture, 'FIXTURE', path), patch.object(fixture, 'source_objects', side_effect=ValueError('incomplete source')):
                with self.assertRaisesRegex(ValueError, 'incomplete source'):
                    fixture.prepare(check=False)
            self.assertEqual(accepted.read_bytes(), b'accepted content')
            self.assertEqual(list(path.iterdir()), [accepted])


class PreparationPathTests(unittest.TestCase):
    def test_single_link_outputs_can_be_generated_and_checked(self):
        files = {str(path.relative_to(fixture.FIXTURE)): path.read_bytes()
                 for path in fixture.FIXTURE.rglob('*') if path.is_file()}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'fixture'
            with patch.object(fixture, 'FIXTURE', output), patch.object(fixture, 'build', return_value=files):
                self.assertEqual(fixture.prepare(check=False), {'artifacts': len(files), 'liveActions': 0})
                self.assertEqual(fixture.prepare(check=True), {'artifacts': len(files), 'liveActions': 0})
            self.assertEqual({str(path.relative_to(output)): path.read_bytes()
                              for path in output.rglob('*') if path.is_file()}, files)
            self.assertTrue(all(path.stat().st_nlink == 1 for path in output.rglob('*') if path.is_file()))

    def test_hardlinked_destination_rejects_before_root_or_external_content_changes(self):
        files = {str(path.relative_to(fixture.FIXTURE)): path.read_bytes()
                 for path in fixture.FIXTURE.rglob('*') if path.is_file()}
        for check in (False, True):
            with self.subTest(check=check), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = root / 'fixture'
                output.mkdir()
                (output / 'Chart.yaml').write_bytes(b'accepted chart')
                outside = root / 'outside-values.yaml'
                outside.write_bytes(b'outside accepted values')
                (output / 'values.yaml').hardlink_to(outside)
                self.assertEqual(outside.stat().st_nlink, 2)
                with patch.object(fixture, 'FIXTURE', output), patch.object(fixture, 'build', return_value=files):
                    with self.assertRaisesRegex(ValueError, 'multiple hard links'):
                        fixture.prepare(check=check)
                self.assertEqual((output / 'Chart.yaml').read_bytes(), b'accepted chart')
                self.assertEqual((output / 'values.yaml').read_bytes(), b'outside accepted values')
                self.assertEqual(outside.read_bytes(), b'outside accepted values')
                self.assertEqual(outside.stat().st_nlink, 2)
                self.assertEqual({path.name for path in output.iterdir()}, {'Chart.yaml', 'values.yaml'})

    def test_nested_symlink_or_non_directory_rejects_before_any_output_changes(self):
        files = {str(path.relative_to(fixture.FIXTURE)): path.read_bytes()
                 for path in fixture.FIXTURE.rglob('*') if path.is_file()}
        for kind, check in (('symlink', False), ('symlink', True), ('non-directory', False)):
            with self.subTest(kind=kind, check=check), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, outside = root / 'fixture', root / 'outside'
                output.mkdir()
                outside.mkdir()
                prior = {'Chart.yaml': b'accepted root chart', 'values.yaml': b'accepted root values'}
                external = {'_configuration.tpl': b'outside configuration', 'resources.yaml': b'outside resources'}
                for name, data in prior.items():
                    (output / name).write_bytes(data)
                for name, data in external.items():
                    (outside / name).write_bytes(data)
                if kind == 'symlink':
                    (output / 'templates').symlink_to(outside, target_is_directory=True)
                else:
                    (output / 'templates').write_bytes(b'not a directory')
                with patch.object(fixture, 'FIXTURE', output), patch.object(fixture, 'build', return_value=files):
                    with self.assertRaisesRegex(ValueError, 'symbolic link|non-directory parent'):
                        fixture.prepare(check=check)
                self.assertEqual({name: (output / name).read_bytes() for name in prior}, prior)
                self.assertEqual({name: (outside / name).read_bytes() for name in external}, external)
                if kind == 'non-directory':
                    self.assertEqual((output / 'templates').read_bytes(), b'not a directory')


class LokiNativePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = fixture.BASE / 'loki'
        cls.raw = (cls.path / 'upstream.tgz').read_bytes()
        cls.lock = json.loads((cls.path / 'artifact.lock.json').read_bytes())
        cls.temporary = tempfile.TemporaryDirectory()
        cls.original, cls.patched = (Path(cls.temporary.name) / name for name in ('original', 'patched'))
        for directory in (cls.original, cls.patched):
            shutil.copytree(cls.path, directory)
        (cls.original / cls.lock['archive']).write_bytes(cls.raw)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def helm(self, directory, overlay=None):
        result = subprocess.run(['helm', 'template', 'cloudlab-loki', str(directory), '--namespace', fixture.NAMESPACE,
            '--kube-version', '1.36.5', '--include-crds', '-f', str(directory / 'values.json'), '-f', '-'],
            input=yaml.safe_dump(overlay or {}), capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError('Loki input rejected')
        return result.stdout

    def test_patch_reproducible_and_only_exact_target_member_changes(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.lock['upstream_sha256'])
        patched = loki_declarative(self.raw)
        self.assertEqual(patched, loki_declarative(self.raw))
        self.assertEqual(patched, (self.path / self.lock['archive']).read_bytes())
        with tarfile.open(fileobj=io.BytesIO(self.raw)) as archive:
            before = {member.name: archive.extractfile(member).read() for member in archive}
        with tarfile.open(fileobj=io.BytesIO(patched)) as archive:
            after = {member.name: archive.extractfile(member).read() for member in archive}
        self.assertEqual(set(before), set(after))
        changed = [name for name in before if before[name] != after[name]]
        self.assertEqual(changed, ['loki/templates/single-binary/service-headless.yaml'])

    def test_legacy_is_byte_identical_and_native_changes_only_governing_service_name(self):
        old = self.helm(self.original)
        self.assertEqual(self.helm(self.patched), old)
        self.assertEqual(self.helm(self.patched, {'loki': {'cloudlabNativeLifecycle': False}}), old)
        native = list(yaml.safe_load_all(self.helm(self.patched, {'loki': {'cloudlabNativeLifecycle': True}})))
        original = list(yaml.safe_load_all(old))
        service = next(obj for obj in native if obj and obj['kind'] == 'Service' and obj['metadata']['name'] == 'cloudlab-loki-headless')
        service['metadata']['name'] = 'loki-headless'
        self.assertEqual(native, original)

    def test_native_mode_rejects_non_boolean_types(self):
        for value in ('false', 'true', 0, 1, None, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.helm(self.patched, {'loki': {'cloudlabNativeLifecycle': value}})

    def test_unsafe_duplicate_missing_and_changed_target_are_rejected(self):
        target = 'loki/templates/single-binary/service-headless.yaml'
        with tarfile.open(fileobj=io.BytesIO(self.raw)) as archive:
            source = [(member.name, archive.extractfile(member).read()) for member in archive]
        for change in ('missing', 'changed', 'duplicate', 'traversal', 'link'):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w:gz') as archive:
                for name, data in source:
                    if change == 'missing' and name == target:
                        continue
                    if change == 'changed' and name == target:
                        data += b'\n'
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                if change in ('duplicate', 'traversal', 'link'):
                    member = tarfile.TarInfo(target if change == 'duplicate' else '../outside')
                    if change == 'link':
                        member.type = tarfile.SYMTYPE
                        member.linkname = '/outside'
                    archive.addfile(member, io.BytesIO())
            with self.subTest(change=change), self.assertRaises(ValueError):
                loki_declarative(output.getvalue())


if __name__ == '__main__':
    unittest.main()
