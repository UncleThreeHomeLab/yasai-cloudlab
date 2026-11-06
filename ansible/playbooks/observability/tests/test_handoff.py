"""Offline host custody and finite stdlib bundle boundaries; no native writes."""
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from playbooks.observability.files import handoff, handoff_source, writer_guard


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cloudlab-handoff-', dir='/root')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.package = self.directory / 'runtime'
        self.operation = 'a' * 16
        self.bundle = handoff_source.bundle(self.operation)
        for name, raw in self.bundle['files'].items():
            self.private('runtime/' + name, base64.b64decode(raw))
        self.manifest = self.private('bundle.json', handoff.canonical(self.bundle['manifest']))
        self.journal = self.directory / 'journal.json'
        self.identity = {'version': 1, 'receipt': {}, 'objects': {}}
        self.source = {'version': handoff.SOURCE_VERSION, 'operationId': self.operation,
            'stage': 'source-inspected', 'bundleSHA256': self.bundle['bundleSHA256'],
            'identityObservationSHA256': handoff.digest(handoff.canonical(self.identity))}
        self.source_path = self.private('source.json', handoff.canonical(self.source))
        self.addCleanup(patch.stopall)
        patch.object(writer_guard, 'MAIN_LOCK', str(self.directory / 'main.lock')).start()
        patch.object(writer_guard, 'HISTORY_LOCK', str(self.directory / 'history.lock')).start()
        patch.object(writer_guard, 'RETIREMENT_FENCE', self.directory / 'retired.json').start()

    def private(self, name, raw):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
        path.chmod(0o600)
        return path

    def inspect(self):
        return handoff.inspect_prepared(self.package, self.manifest, self.source_path, self.journal,
            self.bundle['bundleSHA256'], handoff.digest(handoff.canonical(self.source)))

    def test_clean_bundle_loads_without_runner_modules_or_site_packages(self):
        script = ('import importlib,sys;sys.path.insert(0,sys.argv[1]);'
            'from playbooks.observability.files import handoff;'
            'handoff.verify_bundle(sys.argv[1],sys.argv[2]);'
            '[importlib.import_module(name[:-3].replace("/",".")) for name in handoff.HOST_FILES];'
            'print("stdlib-only bundle verified")')
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script, str(self.package), str(self.manifest)],
            cwd='/', capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'stdlib-only bundle verified')
        self.assertEqual(set(self.bundle['manifest']['moduleDigests']), set(handoff.HOST_FILES + handoff.PACKAGE_INITS))
        self.assertNotIn('handoff_source.py', ' '.join(self.bundle['files']))

    def test_bundle_rejects_tampering_extra_files_and_executable_package_initializers(self):
        path = self.package / handoff.HOST_FILES[1]
        path.write_text('# changed after staging\n')
        with self.assertRaisesRegex(RuntimeError, 'integrity changed'):
            handoff.verify_bundle(self.package, self.manifest)
        self.private('runtime/' + handoff.HOST_FILES[1], base64.b64decode(self.bundle['files'][handoff.HOST_FILES[1]]))
        shadow = self.private('runtime/json.py', b'raise RuntimeError("unreviewed shadow module")')
        with self.assertRaisesRegex(RuntimeError, 'unreviewed files'):
            handoff.verify_bundle(self.package, self.manifest)
        shadow.unlink()
        changed = copy.deepcopy(self.bundle['manifest'])
        changed['moduleDigests']['../outside.py'] = '1' * 64
        self.manifest.write_bytes(handoff.canonical(changed))
        with self.assertRaisesRegex(RuntimeError, 'file set changed'):
            handoff.verify_bundle(self.package, self.manifest)
        changed = copy.deepcopy(self.bundle['manifest'])
        changed['runnerModuleDigests']['../outside.py'] = '1' * 64
        self.manifest.write_bytes(handoff.canonical(changed))
        with self.assertRaisesRegex(RuntimeError, 'runner provenance file set changed'):
            handoff.verify_bundle(self.package, self.manifest)
        changed = copy.deepcopy(self.bundle['manifest'])
        initializer = handoff.PACKAGE_INITS[0]
        self.private('runtime/' + initializer, b'raise RuntimeError("untrusted initializer")')
        changed['moduleDigests'][initializer] = handoff.digest((self.package / initializer).read_bytes())
        self.manifest.write_bytes(handoff.canonical(changed))
        with self.assertRaisesRegex(RuntimeError, 'initializer is not empty'):
            handoff.verify_bundle(self.package, self.manifest)

    def test_inspection_freezes_source_and_fails_changed_identity_before_journal_write(self):
        with patch.object(handoff, 'observe_identity', return_value=self.identity):
            first, second = self.inspect(), self.inspect()
            self.assertTrue(first['changed'])
            self.assertFalse(second['changed'])
            self.assertFalse(first['ready'])
            self.assertEqual(first['sourceSHA256'], second['sourceSHA256'])
            original = self.journal.read_bytes()
            self.source['publicRevision'] = 'b' * 40
            self.source_path.write_bytes(handoff.canonical(self.source))
            with self.assertRaisesRegex(RuntimeError, 'Frozen handoff source changed'):
                self.inspect()
            self.assertEqual(self.journal.read_bytes(), original)
        with patch.object(handoff, 'observe_identity', return_value=dict(self.identity, receipt={'phase': 'changed'})):
            with self.assertRaisesRegex(RuntimeError, 'Native identity changed'):
                self.inspect()
        self.assertFalse(writer_guard.RETIREMENT_FENCE.exists())

    def test_retirement_fence_busy_history_and_runner_digest_block_observation(self):
        with patch.object(handoff, 'observe_identity') as observe:
            writer_guard.RETIREMENT_FENCE.write_text('{}')
            with self.assertRaises(RuntimeError): self.inspect()
            writer_guard.RETIREMENT_FENCE.unlink()
            with open(writer_guard.HISTORY_LOCK, 'a') as busy:
                fcntl.flock(busy, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError): self.inspect()
            with self.assertRaisesRegex(RuntimeError, 'Runner and host prepared sources differ'):
                handoff.inspect_prepared(self.package, self.manifest, self.source_path, self.journal,
                    self.bundle['bundleSHA256'], '0' * 64)
            observe.assert_not_called()
            self.assertFalse(self.journal.exists())
            locks, real_flock = [], fcntl.flock
            def record_lock(descriptor, operation):
                locks.append(Path(os.readlink('/proc/self/fd/' + str(descriptor))).name)
                return real_flock(descriptor, operation)
            with patch.object(fcntl, 'flock', side_effect=record_lock), handoff.writer_locks():
                with self.assertRaises(BlockingIOError), handoff.writer_locks():
                    self.fail('Main lock was not held')
            self.assertEqual(locks[:2], ['main.lock', 'history.lock'])

    def test_identity_observation_reads_only_protected_receipt_and_exact_owners(self):
        receipt = self.private('identity.json', b'{"phase":"accepted"}')
        calls = []
        def execute(argv, **options):
            calls.append(argv)
            self.assertEqual(options, {'capture_output': True, 'timeout': 20})
            return SimpleNamespace(returncode=0, stdout=json.dumps({'metadata': {
                'name': argv[5], 'namespace': 'argocd'}}).encode())
        with patch.object(handoff, 'IDENTITY_RECEIPT', receipt), patch.object(subprocess, 'run', side_effect=execute):
            result = handoff.observe_identity()
        self.assertEqual(result['receipt'], {'phase': 'accepted'})
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(argv[3] == 'get' and argv[-4:] == ['-n', 'argocd', '-o', 'json'] for argv in calls))

    def test_private_paths_staging_and_json_refuse_ambiguous_custody(self):
        path = self.private('private.json', '{}')
        link = self.directory / 'link'
        link.symlink_to(path)
        with self.assertRaises(RuntimeError): handoff.read_private(link)
        os.link(path, self.directory / 'hardlink')
        with self.assertRaises(RuntimeError): handoff.read_private(path)
        self.directory.chmod(0o777)
        with self.assertRaises(RuntimeError): handoff.read_private(self.manifest)
        self.directory.chmod(0o700)
        runtime_link = self.directory / 'unsafe' / 'runtime'
        runtime_link.parent.mkdir(mode=0o700)
        runtime_link.symlink_to(self.package, target_is_directory=True)
        with patch.object(handoff, 'operation_directory', return_value=runtime_link.parent):
            with self.assertRaises(RuntimeError): handoff.stage_preflight(self.operation)
        for raw in (b'{"stage":1,"stage":2}', b'{"stage":NaN}', b'[] trailing'):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError): handoff.strict_json(raw)

    def test_atomic_journal_flushes_file_and_directory_without_temporary_files(self):
        with patch.object(os, 'fsync', wraps=os.fsync) as flush:
            handoff.atomic_private(self.journal, {'stage': 'source-inspected'})
            self.assertEqual(flush.call_count, 2)
        self.assertEqual(handoff.strict_json(handoff.read_private(self.journal)), {'stage': 'source-inspected'})
        self.assertFalse(list(self.directory.glob('.journal.json.*')))

    def test_phase_draft_requires_owned_record_and_actual_collect_dispatch_before_patch_intent(self):
        from playbooks.observability.files import native_transport as transport
        references = {}
        for profile in handoff.QUALIFICATIONS:
            raw = ('Reviewed fixture ' + profile).encode()
            references[profile] = {'artifactDigests': {'proof.bin': handoff.digest(raw)}}
            self.private('qualifications/' + profile + '/proof.bin', raw)
        names = transport.CHILDREN
        applications = {name: {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
            'metadata': {'name': name, 'namespace': 'argocd', 'annotations': {
                'cloudlab.io/observability-handoff-target-cluster-uid': '00000063-0000-0000-0000-000000000000'}},
            'spec': {'fixture': name}} for name in names}
        applications['cloudlab-observability']['spec']['source'] = {'helm': {'valuesObject': {'ownershipHandoffInternal': {}}}}
        bindings = copy.deepcopy(applications)
        for number, app in enumerate(bindings.values(), 10):
            app['metadata'].update(uid='%08x-0000-0000-0000-000000000000' % number, resourceVersion=str(number))
        intent = {'version': handoff.PHASE_VERSION, 'phase': 'baseline', 'operationId': self.operation,
            'previousPhaseSHA256': None, 'applicationBindings': bindings,
            'prepared': {'bundleSHA256': self.bundle['bundleSHA256'], 'profiles': {'acceptedArtifacts': references}},
            'qualifications': {'references': references}}
        intent['resourcePolicy'] = json.loads((Path(__file__).resolve().parents[4] /
            'platform/observability/contract.json').read_text())['ownership_handoff']['phases']['baseline']
        value = {'operation': self.operation,
            'codeSHA256': self.bundle['manifest']['moduleDigests']['playbooks/observability/files/native_transport.py'], 'profile': 'phase-parent'}
        native = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'fixture', 'namespace': 'argocd',
            'uid': '00000001-0000-0000-0000-000000000000', 'resourceVersion': '1'}, 'spec': {}}
        value['source'] = {'set': copy.deepcopy(native), 'parent': copy.deepcopy(native), 'pods': {}}
        value['api'] = {'serviceRV': '1', 'endpointsRV': '1'}
        self.private('private/0-baseline.intent.json', handoff.canonical(intent))
        self.private('private/0-baseline.input.json', handoff.canonical(value))
        context = {'operation': self.operation, 'codeSHA256': value['codeSHA256'], 'inputSHA256': handoff.digest(handoff.canonical(value))}
        record = {'context': context, 'objects': {'job': {'identity': {'uid': 'fixture-job'}}}}
        record_path = self.private('private/0-baseline.transport.json', handoff.canonical(record))
        original = {name: [{'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': name, 'namespace': 'cloudlab-observability'}, 'data': {}}] for name in handoff.inventory_apps()}
        # Mock only the independently tested collector API; no native qualification is asserted here.
        def collected(request, execute, journal, persist, inputs, pod, status):
            journal['collected'] = {'sha256': '1' * 64, 'bytes': 256, 'podUID': 'fixture-pod'}
            persist()
            return {'parent': list(applications.values()), 'baseline': original}
        with patch.object(transport, 'collect', side_effect=collected) as collect:
            wrong = copy.deepcopy(record)
            wrong['context']['inputSHA256'] = '0' * 64
            record_path.write_bytes(handoff.canonical(wrong))
            with self.assertRaisesRegex(RuntimeError, 'collector record source changed'):
                handoff.collect_phase(self.directory, 'baseline', Mock(), Mock(), {}, {})
            collect.assert_not_called()
            record_path.write_bytes(handoff.canonical(record))
            result = handoff.collect_phase(self.directory, 'baseline', Mock(), Mock(), {}, {})
            self.assertEqual(collect.call_count, 1)
            self.assertEqual(result['stage'], 'phase-draft')
            self.assertFalse(result['ready'])
        patches = handoff.strict_json(handoff.read_private(handoff.phase_file(self.directory, 'baseline', 'patch-intent')))
        self.assertEqual(set(patches['applications']), set(names))
        self.assertEqual(patches['stage'], 'mutation-not-authorized')
        observation = {'set': copy.deepcopy(native), 'parent': copy.deepcopy(native), 'pods': {},
            'api': {'serviceRV': '2', 'endpointsRV': '2'}, 'applications': copy.deepcopy(bindings)}
        for obj in (observation['set'], observation['parent'], *observation['applications'].values()):
            obj['metadata']['resourceVersion'] = 'fresh-version'
        with patch.object(transport, 'validate_input') as validate:
            self.assertEqual(handoff.downstream_input(self.directory, 'baseline', observation)['stage'], 'downstream-prepared')
            validate.assert_called_once()
            for name in names:
                replaced = copy.deepcopy(observation)
                replaced['applications'][name]['metadata']['uid'] = '000000ff-0000-0000-0000-000000000000'
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'exact drafted intent changed'):
                    handoff.downstream_input(self.directory, 'baseline', replaced)
            changed = copy.deepcopy(observation)
            changed['applications']['cloudlab-alloy']['spec']['fixture'] = 'substitution'
            with self.assertRaisesRegex(RuntimeError, 'exact drafted intent changed'):
                handoff.downstream_input(self.directory, 'baseline', changed)
        journal = handoff.strict_json(handoff.read_private(record_path))
        draft = handoff.strict_json(handoff.read_private(handoff.phase_file(self.directory, 'baseline', 'draft')))
        journal['cleanupStarted'] = True
        self.assertEqual(handoff.collection_binding(journal), draft['custody'])
        downstream = dict(value, profile='downstream')
        downstream_path = self.private('private/0-baseline.downstream-input.json', handoff.canonical(downstream))
        downstream_record = copy.deepcopy(record)
        downstream_record['context']['inputSHA256'] = handoff.digest(handoff.canonical(downstream))
        self.private('private/0-baseline.downstream-transport.json', handoff.canonical(downstream_record))
        def collected_resources(request, execute, record, persist, value, pod, status):
            record['collected'] = {'sha256': '2' * 64, 'bytes': 512, 'podUID': 'fixture-downstream-pod'}
            persist()
            return {'parent': list(applications.values()), **original}
        with patch.object(transport, 'collect', side_effect=collected_resources):
            handoff.collect_phase(self.directory, 'baseline', Mock(), Mock(), {}, {}, downstream=True)
        packet = handoff.phase_export(self.directory, 'baseline')
        proposal = handoff_source.finalize_phase(packet)
        proposal_path = self.private('private/0-baseline.final-proposal.json', handoff.canonical(proposal))
        result = handoff.commit_phase(self.directory, 'baseline', proposal_path, handoff.digest(handoff.canonical(proposal)))
        self.assertTrue(result['changed'])
        self.assertFalse(result['ready'])
        self.assertFalse(handoff.commit_phase(self.directory, 'baseline', proposal_path,
            handoff.digest(handoff.canonical(proposal)))['changed'])
        self.assertEqual(handoff.phase_head(self.directory)['record'], proposal)
        # Cleanup journal changes preserve custody; changed collected objects do not.
        resource_path = handoff.phase_file(self.directory, 'baseline', 'resources')
        resources = handoff.phase_json(resource_path)
        resources['objects']['cloudlab-kiali'][0]['data']['substitution'] = 'rejected'
        resource_path.write_bytes(handoff.canonical(resources))
        with self.assertRaisesRegex(RuntimeError, 'objects changed after collection'):
            handoff.phase_export(self.directory, 'baseline')
        body_path = handoff.phase_file(self.directory, 'baseline', 'draft-payload')
        body = handoff.strict_json(handoff.read_private(body_path))
        body['phaseApplications'][names[0]]['spec']['fixture'] = 'substituted'
        body_path.write_bytes(handoff.canonical(body))
        with self.assertRaisesRegex(RuntimeError, 'Native draft custody changed'):
            handoff.downstream_input(self.directory, 'baseline', {})
        with self.assertRaisesRegex(RuntimeError, 'not caller receipts'):
            handoff.collect_phase(self.directory, 'baseline', {'qualified': True}, Mock(), {}, {})


if __name__ == '__main__':
    unittest.main()
