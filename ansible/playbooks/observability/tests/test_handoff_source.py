"""Runner source and host-observation protocol without network or credentials."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from playbooks.observability.files import handoff, handoff_source as source

ROOT = Path(__file__).resolve().parents[4]


class HandoffSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cloudlab-handoff-source-', dir='/root')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.operation, self.revision = 'a' * 16, 'e' * 40
        self.bundle = source.bundle(self.operation)
        for name, raw in self.bundle['files'].items():
            self.write('ansible/' + name, base64.b64decode(raw))
        self.write('gitops/roots/public/values.yaml', b'repository: https://github.com/example/public.git\nrevision: main\n')
        self.binding = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
        self.binding_path = self.write('binding.yaml', yaml.safe_dump(self.binding).encode())
        self.write('ansible/playbooks/observability/files/handoff_source.py', (ROOT / 'ansible/playbooks/observability/files/handoff_source.py').read_bytes())
        self.write('ansible/playbooks/observability/handoff.yml', (ROOT / 'ansible/playbooks/observability/handoff.yml').read_bytes())
        self.public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
        self.public['repository'] = 'https://github.com/example/public.git'
        self.public['identity'].pop('argo', None)
        self.public['services']['revision'] = 'a' * 40
        self.public['observability']['configuration'] = {'enabled': True, 'paused': True,
            'revision': 'c' * 40, 'acceptanceCommitment': 'd' * 64}
        chart = ROOT / 'gitops/roots/public'
        self.files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        self.files['values.yaml'] = yaml.safe_dump(self.public).encode()
        self.registry = (ROOT / 'platform/observability/gitops/handoff-profiles.json').read_bytes()
        self.identity = self.identity_observation()
        self.observation = {'version': 1, 'operationId': self.operation,
            'bundleSHA256': self.bundle['bundleSHA256'], 'identity': self.identity}

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def identity_observation(self):
        declaration = {'repoURL': 'https://github.com/example/public.git', 'path': 'gitops/roots/public',
            'targetRevision': 'main', 'helm': {'valuesObject': {'identity': {'enabled': True, 'argo': self.binding}}}}
        root = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
            'metadata': {'uid': 'root', 'resourceVersion': '1', 'name': 'cloudlab-public-root', 'namespace': 'argocd'},
            'spec': {'project': 'cloudlab-root', 'source': declaration},
            'status': {'sync': {'status': 'Synced', 'revision': self.revision, 'comparedTo': {'source': declaration}},
                'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
        project = {'metadata': {'uid': 'project', 'name': 'cloudlab-root', 'namespace': 'argocd'},
            'spec': {'sourceRepos': [declaration['repoURL']],
                'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
                'clusterResourceWhitelist': [{'group': '', 'kind': 'Namespace'}],
                'namespaceResourceWhitelist': [{'group': 'argoproj.io', 'kind': kind} for kind in ('Application', 'AppProject')]
                    + [{'group': 'external-secrets.io', 'kind': 'ExternalSecret'}]}}
        controller = {'metadata': {'uid': 'controller', 'name': 'argocd-application-controller', 'namespace': 'argocd'},
            'spec': {'replicas': 1}}
        return {'version': 1, 'receipt': {'phase': 'accepted', 'target': self.binding,
            'root_uid': 'root', 'controller_uid': 'controller', 'project_uid': 'project'},
            'objects': {'root_uid': root, 'controller_uid': controller, 'project_uid': project}}

    def prepare(self):
        return source.prepare(self.operation, self.binding_path, self.observation, root=self.root)

    def snapshot(self, coordinates, **_):
        self.assertEqual(coordinates['repository'], 'https://github.com/example/public.git')
        if coordinates['path'] == 'gitops/roots/public':
            self.assertEqual(coordinates['revision'], self.revision)
            return self.files
        self.assertEqual(coordinates, {'repository': 'https://github.com/example/public.git',
            'revision': 'c' * 40, 'path': 'platform/observability/gitops'})
        return {'handoff-profiles.json': self.registry}

    def test_real_owner_callback_protocol_never_reads_runner_receipt_or_kubernetes(self):
        from playbooks.argocd.files import source_transition as owner
        with patch.object(owner, 'get', side_effect=AssertionError('runner Kubernetes read')), \
                patch.object(Path, 'read_text', side_effect=AssertionError('runner receipt read')):
            self.assertEqual(source.accepted_binding(self.identity, self.binding,
                {'repository': 'https://github.com/example/public.git'}, self.revision), self.binding)
            changed = copy.deepcopy(self.identity)
            changed['objects']['root_uid']['metadata']['uid'] = 'replacement'
            with self.assertRaises(RuntimeError):
                source.accepted_binding(changed, self.binding,
                    {'repository': 'https://github.com/example/public.git'}, self.revision)

    def test_authenticates_public_root_native_registry_and_exact_private_binding(self):
        with patch('playbooks.data.files.native.published_source', return_value=(self.public, self.revision)) as published, \
                patch('playbooks.argocd.files.source_snapshot.chart_files', side_effect=self.snapshot):
            result = self.prepare()
            self.assertEqual(published.call_args.args[0], {'publicSource': {
                'repository': 'https://github.com/example/public.git', 'branch': 'main'}})
            self.assertEqual(result['privateBinding'], self.binding)
            self.assertEqual(result['expectedSet']['kind'], 'ApplicationSet')
            self.assertEqual(result['expectedSet']['metadata']['name'], 'cloudlab-observability-gitops')
            self.assertEqual(result['profilesSHA256'], handoff.digest(self.registry))
            self.assertEqual(result['profiles']['acceptedArtifacts'], {})
            self.assertNotIn('ready', result)
            self.assertEqual(result['identityObservationSHA256'], handoff.digest(handoff.canonical(self.identity)))
            self.binding_path.write_text(yaml.safe_dump(dict(self.binding, valuesRevision='f' * 40)))
            with self.assertRaisesRegex(RuntimeError, 'differs from protected intent'):
                self.prepare()

    def test_source_substitution_unpaused_intent_and_foreign_bundle_are_refused(self):
        with patch('playbooks.data.files.native.published_source', return_value=(self.public, self.revision)), \
                patch('playbooks.argocd.files.source_snapshot.chart_files', side_effect=self.snapshot):
            replacement = copy.deepcopy(self.public)
            replacement['repository'] = 'https://github.com/attacker/substitution.git'
            self.files['values.yaml'] = yaml.safe_dump(replacement).encode()
            with self.assertRaisesRegex(RuntimeError, 'chart and public source differ'):
                self.prepare()
            self.public['observability']['configuration']['paused'] = False
            self.files['values.yaml'] = yaml.safe_dump(self.public).encode()
            with self.assertRaisesRegex(RuntimeError, 'approved paused'):
                self.prepare()
            self.observation['bundleSHA256'] = '0' * 64
            with self.assertRaisesRegex(RuntimeError, 'another bundle'):
                self.prepare()

    def test_bundle_is_finite_and_never_contains_runner_source_or_credentials(self):
        self.assertEqual(set(self.bundle['files']), set(handoff.HOST_FILES + handoff.PACKAGE_INITS))
        self.assertTrue(all(base64.b64decode(self.bundle['files'][name]) == b'' for name in handoff.PACKAGE_INITS))
        self.assertNotIn('handoff_source', json.dumps(self.bundle['files']))
        self.assertEqual(set(self.bundle['manifest']['runnerModuleDigests']), set(source.RUNNER_FILES))
        for invalid in ('../outside', 'A' * 16, 'a' * 15):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError): source.bundle(invalid)
        target = self.root / 'ansible' / handoff.HOST_FILES[0]
        target.unlink()
        target.symlink_to(ROOT / 'ansible' / handoff.HOST_FILES[0])
        with self.assertRaisesRegex(RuntimeError, 'symbolic link'):
            source.bundle(self.operation, root=self.root / 'ansible')

    def phase_fixture(self):
        from playbooks.observability.files import bootstrap, native_transport as transport
        native = ROOT / 'platform/observability/gitops'
        files = {path.relative_to(native).as_posix(): path.read_bytes() for path in native.rglob('*') if path.is_file()}
        contract = (ROOT / 'platform/observability/contract.json').read_bytes()
        image_lock = (ROOT / 'platform/observability/images.lock.json').read_bytes()
        images = json.loads(image_lock)
        needed = {'checkpoint': ['ansible/playbooks/observability/files/checkpoint.py'],
            'lifecycle': ['ansible/playbooks/observability/tests/lifecycle_controller_proof.py',
                'ansible/playbooks/observability/tests/lifecycle_stack_proof.py'],
            'storage': ['ansible/playbooks/observability/tests/storage_lifecycle_proof.py',
                'ansible/playbooks/observability/tests/storage_fixture.py'],
            'transport': ['ansible/playbooks/observability/files/native_transport.py'],
            'source': ['ansible/playbooks/observability/files/handoff_source.py', 'platform/observability/gitops/templates/_handoff.tpl'],
            'handoff': ['ansible/' + name for name in (*handoff.HOST_FILES, *source.RUNNER_FILES)]
                + ['platform/observability/contract.json']}
        references, artifacts = {}, {}
        for name in needed['handoff']:
            if name.startswith('ansible/') and not (self.root / name).is_file():
                self.write(name, (ROOT / name).read_bytes())
        for name in needed['lifecycle'] + needed['storage']:
            # The CSI proof dependency is absent here; only isolated fixture bytes stand in for its owner.
            raw = b'# Synthetic storage lifecycle owner fixture\n' if name.endswith('/storage_lifecycle_proof.py') else (ROOT / name).read_bytes()
            self.write(name, raw)
        for profile in source.PROFILES:
            modules = {}
            for name in needed.get(profile, ['ansible/playbooks/observability/files/checkpoint.py']):
                modules[name] = handoff.digest((self.root / name).read_bytes() if name.startswith('ansible/') else (ROOT / name).read_bytes())
            pins = {'alertmanager': images['alertmanager']}
            if profile == 'checkpoint': pins['operator'] = images['operator']
            if profile == 'transport': pins = {'argo': transport.ARGO_IMAGE, 'python': transport.PYTHON_IMAGE, 'redis': transport.REDIS_IMAGE}
            if profile == 'lifecycle': pins = dict(images)
            if profile == 'storage': pins = {name: images[name] for name in ('loki', 'tempo', 'grafana')}
            raw = ('Previously reviewed synthetic ' + profile + ' bytes').encode()
            references[profile] = {'version': 'cloudlab-observability-qualification/v1', 'profile': profile,
                'codeRevision': 'c' * 40, 'moduleDigests': modules, 'imagePins': pins,
                'artifactDigests': {'proof.bin': handoff.digest(raw)}}
            artifacts[profile] = {'proof.bin': base64.b64encode(raw).decode()}
        reports = {
            'runtimeHandoff': ('lifecycle', {'runtimeHandoff': 'passed', 'parentUIDPreserved': True,
                'sixChildUIDsPreserved': True, 'pausedNativeManifests': True, 'explicitGitRelease': True,
                'driftRepair': True, 'cleanup': 'complete',
                'scope': 'disposable controller ownership only; production transport unsupported'}),
            'transport': ('transport', {'transport': 'passed', 'declaredSources': 'two distinct HTTPS URLs, full SHAs',
                'rewrite': 'read-only repo-server-only GIT_CONFIG_GLOBAL', 'externalGitHub': 'denied',
                'rootSourceApproval': 'not qualified; pinned-private fixture adaptation only'}),
            'checkpoint': ('checkpoint', {'qualified': True, 'checkpointQualified': True, 'nativeRetentionVerified': True,
                'sourceAliveUntilValidation': True, 'sameCSIIdentity': True, 'backingFilesVerified': True, 'coverage': 'complete'})}
        report_keys = {}
        for name, (profile, report) in reports.items():
            key, raw = name + '.json', handoff.canonical(report)
            report_keys[name] = key
            for target in (profile, 'handoff'):
                artifacts[target][key] = base64.b64encode(raw).decode()
                references[target]['artifactDigests'][key] = handoff.digest(raw)
        observed = '00000003-0000-0000-0000-000000000000'
        scope = {'kind': 'mechanism-rehearsal', 'targetClusterUIDSHA256': handoff.digest(observed.encode())}
        references['handoff']['scope'] = scope
        evidence = {'version': 'cloudlab-observability-handoff-evidence/v1', 'scope': scope,
            'observedClusterUID': observed, 'componentReferencesSHA256': {
                name: handoff.digest(handoff.canonical(reference)) for name, reference in references.items() if name != 'handoff'},
            'coverage': {'kind': 'native-component-mechanisms', 'codeRevision': references['handoff']['codeRevision'],
                'reports': report_keys}}
        raw = handoff.canonical(evidence)
        artifacts['handoff']['handoff-evidence.json'] = base64.b64encode(raw).decode()
        references['handoff']['artifactDigests']['handoff-evidence.json'] = handoff.digest(raw)
        registry = json.loads(self.registry)
        registry['acceptedArtifacts'] = references
        files['handoff-profiles.json'] = json.dumps(registry).encode()
        prepared = {'profiles': registry}
        configuration = {'enabled': True, 'monitoringEnabled': True, 'grafanaHost': 'grafana.internal.example.invalid',
            'kialiHost': 'kiali.internal.example.invalid', 'query': '<>&\u2028\u2029'}
        payload = {'repository': self.public['repository'], 'revision': 'a' * 40, 'configuration': configuration,
            'components': {'prometheus': {'kube-prometheus-stack': {'alertmanager': {'config': {
                'route': {'receiver': 'fixture'}, 'receivers': [{'name': 'fixture'}]}}}},
                'loki': {}, 'tempo': {}, 'alloy': {}, 'kiali': {'kiali-server': {'auth': {'strategy': 'openid'}}}}}
        baseline = {('cloudlab-observability' if name == 'configuration' else 'cloudlab-' + name): bootstrap.application(payload, name)
            for name in ('configuration', 'prometheus', 'loki', 'tempo', 'alloy', 'kiali')}
        return files, prepared, artifacts, baseline, contract, image_lock

    def test_public_go_helper_and_exact_artifact_bytes_reject_python_hash_and_tampering(self):
        files, prepared, artifacts, baseline, contract, image_lock = self.phase_fixture()
        digest = source.baseline_digest(files, baseline)
        self.assertNotEqual(digest, handoff.digest(handoff.canonical(baseline)))
        self.assertNotIn('annotations', baseline['cloudlab-observability']['metadata'])
        self.assertNotIn('valuesObject', baseline['cloudlab-alloy']['spec']['source']['helm'])
        qualified = source.qualification_inputs(prepared, files, artifacts, self.root, image_lock, contract)
        self.assertEqual(qualified['references'], prepared['profiles']['acceptedArtifacts'])
        for profile, owner in (('lifecycle', 'ansible/playbooks/observability/tests/lifecycle_stack_proof.py'),
                               ('storage', 'ansible/playbooks/observability/tests/storage_lifecycle_proof.py')):
            with self.subTest(profile=profile):
                omitted = copy.deepcopy(prepared)
                del omitted['profiles']['acceptedArtifacts'][profile]['moduleDigests'][owner]
                with self.assertRaisesRegex(RuntimeError, 'omits current source boundary code'):
                    source.qualification_inputs(omitted, files, artifacts, self.root, image_lock, contract)
                unpinned = copy.deepcopy(prepared)
                del unpinned['profiles']['acceptedArtifacts'][profile]['imagePins']['loki']
                with self.assertRaisesRegex(RuntimeError, 'omits current runtime owner image pins'):
                    source.qualification_inputs(unpinned, files, artifacts, self.root, image_lock, contract)
                path, raw = self.root / owner, (self.root / owner).read_bytes()
                path.write_bytes(raw + b'\n# Changed owner\n')
                try:
                    with self.assertRaisesRegex(RuntimeError, 'module is unsupported or changed'):
                        source.qualification_inputs(prepared, files, artifacts, self.root, image_lock, contract)
                    path.unlink()
                    with self.assertRaisesRegex(RuntimeError, 'owner source is unavailable'):
                        source.qualification_inputs(prepared, files, artifacts, self.root, image_lock, contract)
                finally:
                    self.write(owner, raw)
        # Opaque proof bytes are compared, not parsed for a success boolean.
        artifacts['source']['proof.bin'] = base64.b64encode(b'{"qualified":true}').decode()
        with self.assertRaisesRegex(RuntimeError, 'artifact bytes differ'):
            source.qualification_inputs(prepared, files, artifacts, self.root, image_lock, contract)
        prepared['profiles']['acceptedArtifacts'] = {}
        with self.assertRaisesRegex(RuntimeError, 'Every reviewed qualification'):
            source.qualification_inputs(prepared, files, {}, self.root, image_lock, contract)

    def test_phase_order_and_frozen_public_binding_context_require_explicit_next_revision(self):
        files, _, _, baseline, _, _ = self.phase_fixture()
        context = {'version': 'cloudlab-observability-handoff/v1', 'operationId': self.operation,
            'phase': 'baseline', 'baselineDigest': source.baseline_digest(files, baseline), 'baselineRevision': 'a' * 40,
            'privateRevision': 'b' * 40, 'qualificationsSHA256': '1' * 64, 'approvedStorageTarget': 'alertmanager-retained-1gi-v1'}
        keys = ('bundleSHA256', 'publicSource', 'privateBinding', 'sourceBindingSHA256', 'publicIntentSHA256',
            'rootCodeSHA256', 'identityUIDs', 'nativeFilesSHA256', 'profilesSHA256', 'profiles')
        prepared = {key: 'frozen' for key in keys} | {'publicRevision': 'c' * 40}
        old = {'operationId': self.operation, 'phase': 'baseline', 'baseline': baseline, 'qualifications': {},
            'resourcePolicySHA256': '2' * 64, 'prepared': prepared, 'phaseContext': context,
            'applicationBindings': {name: {'metadata': {'uid': name}} for name in baseline}}
        record = {'version': handoff.PHASE_VERSION, 'stage': 'phase-recorded', 'operationId': self.operation,
            'phase': 'baseline', 'intentSHA256': handoff.digest(handoff.canonical(old))}
        previous = {'record': record, 'intent': old}
        handoff.phase_order('maintenance', previous, self.operation)
        for invalid in ('native', 'persistent-maintenance'):
            with self.assertRaises(RuntimeError): handoff.phase_order(invalid, previous, self.operation)
        current = copy.deepcopy(old)
        current['phase'] = current['phaseContext']['phase'] = 'maintenance'
        current['phaseContext']['privateRevision'], current['prepared']['publicRevision'] = 'd' * 40, 'e' * 40
        handoff.frozen_phase(current, old)
        for field in ('privateBinding', 'profilesSHA256', 'nativeFilesSHA256'):
            changed = copy.deepcopy(current)
            changed['prepared'][field] = 'substitution'
            with self.assertRaises(RuntimeError): handoff.frozen_phase(changed, old)
        changed = copy.deepcopy(current)
        changed['phaseContext']['baselineDigest'] = '0' * 64
        with self.assertRaises(RuntimeError): handoff.frozen_phase(changed, old)

    def test_scoped_handoff_artifact_cannot_be_upgraded_or_replace_full_backend_evidence(self):
        files, prepared, artifacts, _, contract, image_lock = self.phase_fixture()
        source.qualification_inputs(prepared, files, artifacts, self.root, image_lock, contract)
        changed = copy.deepcopy(prepared)
        changed['profiles']['acceptedArtifacts']['handoff']['scope'] = {'kind': 'full-entrypoint-integration'}
        with self.assertRaisesRegex(RuntimeError, 'scope, revision or component references differ'):
            source.qualification_inputs(changed, files, artifacts, self.root, image_lock, contract)
        changed_artifacts = copy.deepcopy(artifacts)
        evidence = handoff.strict_json(base64.b64decode(artifacts['handoff']['handoff-evidence.json']))
        evidence['scope'] = {'kind': 'full-entrypoint-integration'}
        evidence['coverage'] = {'kind': 'full-c2-entrypoint', 'codeRevision': 'c' * 40,
            'entrypoint': 'ansible/playbooks/observability/handoff.yml', 'execution': 'entrypoint.json',
            'phases': {phase: 'phase-' + phase + '.json' for phase in handoff.PHASES[:-1]}}
        raw = handoff.canonical(evidence)
        changed_artifacts['handoff']['handoff-evidence.json'] = base64.b64encode(raw).decode()
        changed['profiles']['acceptedArtifacts']['handoff']['artifactDigests']['handoff-evidence.json'] = handoff.digest(raw)
        with self.assertRaisesRegex(RuntimeError, 'exactly five source phases'):
            source.qualification_inputs(changed, files, changed_artifacts, self.root, image_lock, contract)
        flags = dict.fromkeys(('denied', 'checkpointWritten', 'nativeDiskValidated', 'checkpointValidated',
            'storageSyncComplete', 'restored'), True)
        flags['nativeDiskValidated'] = False
        with self.assertRaisesRegex(RuntimeError, 'backend proof is incomplete'):
            source.full_backend_evidence(flags, self.operation, self.bundle['bundleSHA256'], '0' * 64)
        with self.assertRaisesRegex(RuntimeError, 'backend proof is incomplete'):
            source.full_backend_evidence({'qualified': True}, self.operation, self.bundle['bundleSHA256'], '0' * 64)

    def test_private_target_requires_all_six_native_markers(self):
        from playbooks.observability.files import native_transport
        uid = '00000003-0000-0000-0000-000000000000'
        apps = {name: {'metadata': {'annotations': {'cloudlab.io/observability-handoff-target-cluster-uid': uid}}}
            for name in native_transport.CHILDREN}
        self.assertEqual(source.phase_target(apps), uid)
        apps['cloudlab-kiali']['metadata']['annotations']['cloudlab.io/observability-handoff-target-cluster-uid'] = '00000004-0000-0000-0000-000000000000'
        with self.assertRaisesRegex(RuntimeError, 'disagree'):
            source.phase_target(apps)
        apps['cloudlab-kiali']['metadata']['annotations'].clear()
        with self.assertRaisesRegex(RuntimeError, 'Invalid private qualification cluster UID'):
            source.phase_target(apps)

    def test_full_mutation_evidence_preserves_metadata_only_acknowledgement_and_real_noop(self):
        from playbooks.observability.files.handoff_execute import owned_metadata
        before = {'metadata': {'annotations': {'argocd.argoproj.io/skip-reconcile': 'false'},
            'labels': {'cloudlab.io/owner': 'observability-platform', 'unowned.example/name': 'fixture'}}}
        after = copy.deepcopy(before)
        after['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'] = 'true'
        row = {'intent': {'path': '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/cloudlab-prometheus',
            'uid': '00000003-0000-0000-0000-000000000000', 'beforeSpecSHA256': 'b' * 64,
            'afterSpecSHA256': 'b' * 64, 'beforeResourceVersion': '123', 'beforeMetadata': owned_metadata(before),
            'afterMetadata': owned_metadata(after), 'annotations': after['metadata']['annotations']},
            'acknowledged': True, 'patchRequested': True, 'outcome': 'observed-after', 'resultSHA256': 'c' * 64}
        source.full_mutation_evidence(row)
        row['outcome'] = 'patch-acknowledged'
        source.full_mutation_evidence(row)
        row['outcome'], row['patchRequested'] = 'no-op', False
        with self.assertRaisesRegex(RuntimeError, 'contradicts'):
            source.full_mutation_evidence(row)
        row['intent']['afterMetadata'] = copy.deepcopy(row['intent']['beforeMetadata'])
        row['intent']['annotations'] = copy.deepcopy(row['intent']['afterMetadata']['annotations'])
        source.full_mutation_evidence(row)
        row['patchRequested'] = True
        with self.assertRaisesRegex(RuntimeError, 'contradicts'):
            source.full_mutation_evidence(row)
        del row['intent']['beforeMetadata']
        with self.assertRaisesRegex(RuntimeError, 'intent is incomplete'):
            source.full_mutation_evidence(row)

    def test_public_activation_pointer_changes_desired_state_without_changing_qualified_root_code(self):
        with patch('playbooks.data.files.native.published_source', side_effect=lambda *_args, **_kwargs: (self.public, self.revision)), \
                patch('playbooks.argocd.files.source_snapshot.chart_files', side_effect=self.snapshot):
            before = self.prepare()
            self.public['observability']['configuration']['activationQualification'] = 'd' * 64
            self.files['values.yaml'] = yaml.safe_dump(self.public).encode()
            self.revision = 'f' * 40
            self.identity['objects']['root_uid']['status']['sync']['revision'] = self.revision
            after = self.prepare()
        self.assertEqual(before['rootCodeSHA256'], after['rootCodeSHA256'])
        self.assertNotIn('values.yaml', after['rootCodeSHA256'])
        self.assertEqual(before['nativeFilesSHA256'], after['nativeFilesSHA256'])
        self.assertNotEqual(before['publicRevision'], after['publicRevision'])
        self.assertEqual(after['expectedSet']['spec']['template']['spec']['sources'][0]['helm']['valuesObject']
            ['nativeSource']['activationQualification'], 'd' * 64)
        self.assertNotEqual(before['publicIntentSHA256'], after['publicIntentSHA256'])

    def test_complete_phase_preparation_uses_actual_owner_and_no_self_expected_applications(self):
        from playbooks.observability.files import native_transport as transport
        files, _, artifacts, baseline, contract, image_lock = self.phase_fixture()
        def snapshot(coordinates, **_):
            return self.files if coordinates['path'] == 'gitops/roots/public' else files
        with patch('playbooks.data.files.native.published_source', return_value=(self.public, self.revision)), \
                patch('playbooks.argocd.files.source_snapshot.chart_files', side_effect=snapshot):
            prepared = self.prepare()
        expected = prepared['expectedSet']
        observed = copy.deepcopy(expected)
        observed['metadata'].update(uid='00000001-0000-0000-0000-000000000000', resourceVersion='1')
        parent = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application'} | copy.deepcopy(expected['spec']['template'])
        parent['metadata'].update(namespace='argocd', uid='00000002-0000-0000-0000-000000000000', resourceVersion='2', ownerReferences=[{
            'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': transport.PARENT,
            'uid': observed['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}])
        parent['spec']['sources'][1]['targetRevision'] = 'f' * 40
        pods = {}
        for number, component, name, image in ((3, 'repo', 'repo-server', transport.ARGO_IMAGE), (4, 'redis', 'redis', transport.REDIS_IMAGE)):
            pods[component] = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'argocd-' + name + '-abcde-12345',
                'namespace': 'argocd', 'uid': '%08x-0000-0000-0000-000000000000' % number, 'resourceVersion': str(number),
                'labels': {'app.kubernetes.io/component': name}}, 'spec': {'containers': [{'name': name, 'image': image}]},
                'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        applications = copy.deepcopy(baseline)
        for number, app in enumerate(applications.values(), 10):
            app['metadata'].update(uid='%08x-0000-0000-0000-000000000000' % number, resourceVersion=str(number))
        api = {'serviceIP': '10.43.0.1', 'servicePort': 443, 'endpointIPs': ['192.0.2.10'], 'endpointPort': 6443,
            'serviceUID': '00000005-0000-0000-0000-000000000000', 'serviceRV': '5',
            'endpointsUID': '00000006-0000-0000-0000-000000000000', 'endpointsRV': '6',
            'serviceSHA256': '1' * 64, 'endpointsSHA256': '2' * 64}
        packet = {'observation': self.observation, 'baseline': baseline, 'previous': None, 'artifacts': artifacts,
            'native': {'set': observed, 'parent': parent, 'pods': pods, 'applications': applications, 'api': api}}
        with patch('playbooks.data.files.native.published_source', return_value=(self.public, self.revision)), \
                patch('playbooks.argocd.files.source_snapshot.chart_files', side_effect=snapshot), \
                patch.object(source, 'public_file', side_effect=lambda _, __, name, ___: contract if name.endswith('contract.json') else image_lock):
            proposal = source.prepare_phase(self.operation, self.binding_path, packet, 'baseline', root=self.root)
            value = proposal['transportInput']
            self.assertEqual(value['profile'], 'phase-parent')
            self.assertNotIn('phaseApplications', value['source'])
            self.assertEqual(set(value['source']['originalBaselineApps']), set(transport.DOWNSTREAM))
            self.assertEqual(proposal['intent']['phaseContext']['privateRevision'], 'f' * 40)
            self.assertNotEqual(proposal['intent']['phaseContext']['privateRevision'], self.binding['valuesRevision'])
            altered = copy.deepcopy(value)
            altered['source']['parent']['spec']['sources'][1]['targetRevision'] = 'd' * 40
            with self.assertRaises(RuntimeError): transport.validate_input(altered)

    def test_resource_deltas_preserve_receiver_routes_and_exact_normal_configuration(self):
        _, _, _, _, contract, _ = self.phase_fixture()
        policy = json.loads(contract)['ownership_handoff']['phases']
        def obj(api, kind, name, **content):
            return {'apiVersion': api, 'kind': kind, 'metadata': {'name': name, 'namespace': 'cloudlab-observability'}, **content}
        original = {'route': {'receiver': 'mail', 'continue': False, 'routes': [{'receiver': 'hook'}]},
            'receivers': [{'name': 'mail', 'email_configs': [{'to': 'fixture@example.invalid'}]},
                {'name': 'hook', 'webhook_configs': [{'url': 'https://fixture.invalid/notify'}]}]}
        encode = lambda value: base64.b64encode(yaml.safe_dump(value).encode()).decode()
        baseline = {'cloudlab-observability': [obj('v1', 'Secret', 'alertmanager-cloudlab',
            data={'alertmanager.yaml': encode(original)})],
            'cloudlab-prometheus': [obj('monitoring.coreos.com/v1', 'Alertmanager', 'cloudlab',
                spec={'storage': {'emptyDir': {'sizeLimit': '64Mi'}}})],
            'cloudlab-kiali': [obj('v1', 'Service', 'cloudlab-kiali', spec={'ports': [{'port': 20001}]})]}
        current = copy.deepcopy(baseline)
        maintenance = copy.deepcopy(original)
        maintenance['receivers'] = [{'name': row['name']} for row in original['receivers']]
        current['cloudlab-observability'][0]['data']['alertmanager.yaml'] = encode(maintenance)
        current['cloudlab-observability'].append(obj('security.istio.io/v1', 'AuthorizationPolicy',
            'cloudlab-observability-handoff-write-deny', spec={'action': 'DENY',
                'rules': [{'to': [{'operation': {'ports': ['9093']}}]}]}))
        apps = {'cloudlab-observability': {'spec': {'source': {'helm': {'valuesObject': {'ownershipHandoffInternal': {}}}}}}}
        intent = {'phase': 'maintenance', 'resourcePolicy': policy['maintenance']}
        source.verify_resource_deltas(intent, baseline, current, apps)
        changed = copy.deepcopy(current)
        maintenance['route']['receiver'] = 'hook'
        changed['cloudlab-observability'][0]['data']['alertmanager.yaml'] = encode(maintenance)
        with self.assertRaisesRegex(RuntimeError, 'routes, receiver identities'):
            source.verify_resource_deltas(intent, baseline, changed, apps)
        maintenance['route']['receiver'], maintenance['route']['continue'] = 'mail', 0
        changed['cloudlab-observability'][0]['data']['alertmanager.yaml'] = encode(maintenance)
        with self.assertRaisesRegex(RuntimeError, 'routes, receiver identities'):
            source.verify_resource_deltas(intent, baseline, changed, apps)
        from playbooks.observability.files import checkpoint
        normal = copy.deepcopy(baseline)
        normal['cloudlab-prometheus'][0]['spec'] = {'storage': {'volumeClaimTemplate': {
            'metadata': {'annotations': checkpoint.CLAIM_ANNOTATIONS}, 'spec': checkpoint.CLAIM_SPEC}},
            'persistentVolumeClaimRetentionPolicy': checkpoint.RETENTION}
        intent = {'phase': 'persistent-normal', 'resourcePolicy': policy['persistent-normal']}
        source.verify_resource_deltas(intent, baseline, normal, apps)
        normal['cloudlab-observability'][0]['data']['alertmanager.yaml'] = current['cloudlab-observability'][0]['data']['alertmanager.yaml']
        with self.assertRaisesRegex(RuntimeError, 'outside the exact approved delta'):
            source.verify_resource_deltas(intent, baseline, normal, apps)
        with self.assertRaisesRegex(RuntimeError, 'Raw caller receipts'):
            source.finalize_phase({'qualified': True})

    def test_dynamic_transfer_inventory_includes_catalog_rules_kiali_and_preserved_uid(self):
        _, _, _, baseline_apps, _, _ = self.phase_fixture()
        baseline = {name: [] for name in handoff.inventory_apps()}
        current = copy.deepcopy(baseline)
        for owner in handoff.inventory_apps():
            obj = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': owner, 'namespace': 'cloudlab-observability'}, 'data': {}}
            baseline[owner].append(obj)
            current[owner].append(copy.deepcopy(obj))
        identities = [('monitoring.coreos.com/v1', 'PodMonitor', name) for name in ('notes', 'mesh-control', 'mesh-ambient', 'mesh-gateways')]
        identities += [('monitoring.coreos.com/v1', 'ServiceMonitor', name) for name in ('alloy', 'native-dns')]
        identities += [('gateway.networking.k8s.io/v1', 'HTTPRoute', name) for name in ('grafana', 'kiali')]
        identities += [('monitoring.coreos.com/v1', 'PrometheusRule', 'catalog-synthetic')]
        bindings = {'baseline': {}, 'current': {}}
        for number, (api, kind, name) in enumerate(identities, 1):
            namespace = 'cloudlab-observability'
            obj = {'apiVersion': api, 'kind': kind, 'metadata': {'name': name, 'namespace': namespace,
                'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-observability:' + api.split('/')[0] + '/' + kind + ':' + namespace + '/' + name}},
                'spec': {'fixture': name}}
            baseline['cloudlab-observability'].append(obj)
            native = copy.deepcopy(obj)
            owner = 'cloudlab-kiali' if name == 'kiali' else 'cloudlab-prometheus'
            native['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = owner + ':' + api.split('/')[0] + '/' + kind + ':' + namespace + '/' + name
            current[owner].append(native)
            key = '|'.join((api, kind, namespace, name))
            live = copy.deepcopy(obj)
            live['metadata'].update(uid='%08x-0000-0000-0000-000000000000' % number, resourceVersion=str(number))
            bindings['baseline'][key] = live
            bindings['current'][key] = copy.deepcopy(live)
        result = source.verify_transfers({'baseline': baseline_apps}, baseline, current, bindings)
        self.assertEqual(len(result), 9)
        self.assertTrue(any('PrometheusRule' in key for key in result))
        incomplete = copy.deepcopy(current)
        del incomplete['cloudlab-kiali']
        with self.assertRaises(RuntimeError): source.verify_transfers({'baseline': baseline_apps}, baseline, incomplete, bindings)
        key = next(key for key in result if key.endswith('|kiali'))
        changed = copy.deepcopy(bindings)
        changed['current'][key]['metadata']['uid'] = 'replacement'
        with self.assertRaisesRegex(RuntimeError, 'backing UID'):
            source.verify_transfers({'baseline': baseline_apps}, baseline, current, changed)
        current['cloudlab-kiali'][-1]['spec']['fixture'] = 'changed-route'
        with self.assertRaisesRegex(RuntimeError, 'outside exact tracking'):
            source.verify_transfers({'baseline': baseline_apps}, baseline, current, bindings)

    def test_native_configuration_classification_preserves_routes_settings_and_original_bytes(self):
        # Offline parser checks only; these dictionaries are not native normalization evidence.
        original = {'route': {'receiver': 'mail', 'continue': False}, 'global': {'resolve_timeout': '1m'},
            'receivers': [{'name': 'mail', 'email_configs': [{'to': 'fixture@example.invalid'}]},
                {'name': 'hook', 'webhook_configs': [{'url': 'https://fixture.invalid/notify'}]}]}
        def status(value):
            text = yaml.safe_dump(value)
            return base64.b64encode(json.dumps({'config': {'original': text}}).encode()).decode(), handoff.digest(text.encode())
        def inventory(value):
            result = {name: [{'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': name,
                'namespace': 'cloudlab-observability'}, 'data': {}}] for name in handoff.inventory_apps()}
            result['cloudlab-prometheus'].append({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {
                'name': 'alertmanager-cloudlab', 'namespace': 'cloudlab-observability'},
                'data': {'alertmanager.yaml': base64.b64encode(yaml.safe_dump(value).encode()).decode()}})
            return result
        original_status, original_digest = status(original)
        for purpose, phase in (('original', 'baseline'), ('muted', 'maintenance'), ('restored', 'persistent-normal')):
            with self.subTest(purpose=purpose):
                expected = copy.deepcopy(original)
                if purpose == 'muted': expected['receivers'] = [{'name': row['name']} for row in original['receivers']]
                raw, digest = status(expected)
                intent = {'operationId': self.operation, 'phase': phase, 'previousPhaseSHA256': None,
                    'prepared': {'bundleSHA256': self.bundle['bundleSHA256']}}
                challenge = {'operationId': self.operation, 'phase': phase, 'purpose': purpose,
                    'bundleSHA256': self.bundle['bundleSHA256'], 'intentSHA256': handoff.digest(handoff.canonical(intent)),
                    'previousPhaseSHA256': None, 'source': {'name': 'alertmanager-cloudlab-0',
                        'namespace': 'cloudlab-observability', 'uid': '00000001-0000-0000-0000-000000000000',
                        'containerID': 'containerd://' + 'a' * 64, 'startedAt': '2026-11-06T10:00:00Z'},
                    'configSHA256': digest, 'reloadTimestamp': 1.0, 'nonce': 'a' * 32,
                    'bootID': '00000002-0000-0000-0000-000000000000', 'deadlineMonotonic': 30.0}
                packet = {'version': 'cloudlab-native-config-challenge/v1', 'challenge': challenge,
                    'rawStatus': raw, 'originalStatus': None if purpose == 'original' else original_status,
                    'sourcePhase': {}}
                with patch.object(source, 'original_config_inventory', return_value=(intent, inventory(original))), \
                        patch.object(source, 'classification_config_inventory', return_value=(intent, inventory(original), inventory(expected))), \
                        patch.object(source, 'native_config_profile', side_effect=lambda value, _: handoff.digest(handoff.canonical(value))):
                    result = source.validate_native_config(packet)
                    self.assertEqual(set(result), {'version', 'challengeSHA256', 'challenge', 'classification',
                        'originalConfigSHA256', 'configSHA256'})
                    self.assertEqual(result['classification'], purpose)
                    self.assertEqual(result['originalConfigSHA256'], original_digest)
                    self.assertEqual(result['challenge'], challenge)
                    altered = copy.deepcopy(packet)
                    changed = copy.deepcopy(expected)
                    changed['route']['continue'] = 0
                    altered['rawStatus'], altered['challenge']['configSHA256'] = status(changed)
                    with self.assertRaisesRegex(RuntimeError, 'differs from'):
                        source.validate_native_config(altered)
                    altered = copy.deepcopy(packet)
                    altered['challenge']['intentSHA256'] = '0' * 64
                    with self.assertRaisesRegex(RuntimeError, 'another protected source phase'):
                        source.validate_native_config(altered)
                    altered = copy.deepcopy(packet)
                    altered['challenge']['approved'] = True
                    with self.assertRaisesRegex(RuntimeError, 'framing differs'):
                        source.validate_native_config(altered)
        for value in ('receivers: &receiver [{name: fixture}]\nroute: *receiver\n',
                      'receivers: [{name: fixture}]\nroute: {}\nroute: {}\n'):
            raw = base64.b64encode(json.dumps({'config': {'original': value}}).encode()).decode()
            with self.assertRaises(ValueError): source.loaded_native_config(raw)
        with self.assertRaisesRegex(RuntimeError, 'protected collector ancestry'):
            source.original_config_inventory({'expectedInventory': inventory(original)})
        with self.assertRaisesRegex(RuntimeError, 'protected phase ancestry'):
            source.classification_config_inventory({'expectedInventory': inventory(original)})

    def test_public_native_configuration_profile_matches_observed_pinned_alertmanager(self):
        from playbooks.data.files.native import PrivateLoader
        from playbooks.observability.files.chart import render
        _, prepared, _, _, _, _ = self.phase_fixture()
        references = prepared['profiles']['acceptedArtifacts']
        intent = {'qualifications': {'references': references}, 'prepared': prepared}
        objects = render('prometheus')
        secrets = [obj for obj in objects if obj['apiVersion'] == 'v1' and obj['kind'] == 'Secret'
            and obj['metadata']['namespace'] == 'cloudlab-observability' and obj['metadata']['name'] == 'alertmanager-cloudlab']
        self.assertEqual(len(secrets), 1)
        value = yaml.load(base64.b64decode(secrets[0]['data']['alertmanager.yaml'], validate=True), Loader=PrivateLoader)
        self.assertEqual(handoff.digest(handoff.canonical(value)), '53441667fd2dd1cff1239f34892a94efe99146cbe8bad093df1edaf9e6c7edf6')
        # Independently captured from the pinned native process; raw output stays private.
        self.assertEqual(source.native_config_profile(value, intent), '2781a6755a59dbe238c53258ca18aab542ce1ea383dbea7ebf94363d325d9eef')
        changed = copy.deepcopy(value)
        changed['receivers'][0]['webhook_configs'] = [{'url': 'https://fixture.invalid/notify'}]
        with self.assertRaisesRegex(RuntimeError, 'capability gap'):
            source.native_config_profile(changed, intent)
        changed = copy.deepcopy(value)
        changed['route']['group_wait'] = '11s'
        with self.assertRaisesRegex(RuntimeError, 'capability gap'):
            source.native_config_profile(changed, intent)
        changed = copy.deepcopy(intent)
        changed['qualifications']['references']['checkpoint']['imagePins']['alertmanager'] = 'fixture@sha256:' + '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'image or qualification changed'):
            source.native_config_profile(value, changed)

    def test_original_native_config_inventory_binds_actual_collector_code_and_payload(self):
        from playbooks.observability.files import native_transport as transport
        baseline = {name: [{'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': name,
            'namespace': 'cloudlab-observability'}, 'data': {}}] for name in handoff.inventory_apps()}
        applications = {name: {'metadata': {'name': name}, 'spec': {}} for name in transport.CHILDREN}
        context = {'phase': 'baseline'}
        intent = {'version': handoff.PHASE_VERSION, 'operationId': self.operation, 'phase': 'baseline',
            'previousPhaseSHA256': None, 'phaseContext': context, 'baseline': applications,
            'prepared': {'bundleSHA256': self.bundle['bundleSHA256'], 'expectedSet': {}}}
        value = {'operation': self.operation, 'profile': 'phase-parent', 'codeSHA256':
            self.bundle['manifest']['moduleDigests']['playbooks/observability/files/native_transport.py'],
            'source': {'phaseContext': context, 'expectedSet': {}, 'originalBaselineApps': {
                name: {'accepted': applications[name], 'observed': {}} for name in handoff.inventory_apps()}}}
        payload = {'baseline': baseline, 'phaseApplications': applications, 'applicationOrder': list(transport.CHILDREN)}
        actual = {'parent': list(applications.values()), 'baseline': baseline}
        collector = {'context': {'operation': self.operation, 'codeSHA256': value['codeSHA256'],
            'inputSHA256': handoff.digest(handoff.canonical(value))}, 'collected': {},
            'objects': {'job': {'identity': {'uid': 'fixture'}}}, 'namespaceAbsent': True,
            'sourcePayloadSHA256': handoff.digest(handoff.canonical(actual))}
        draft = {'version': handoff.PHASE_VERSION, 'stage': 'phase-draft', 'operationId': self.operation,
            'phase': 'baseline', 'intentSHA256': handoff.digest(handoff.canonical(intent)),
            'payloadSHA256': handoff.digest(handoff.canonical(payload)), 'custody': handoff.collection_binding(collector)}
        envelope = {'intent': intent, 'draft': draft, 'draftPayload': payload, 'collector': collector,
            'transportInput': value, 'bundle': self.bundle['manifest'], 'previous': None}
        # Native declarations are covered by transport tests; exercise this export's own custody boundary.
        with patch.object(transport, 'validate_input'), patch.object(transport, 'phase_applications'):
            self.assertEqual(source.original_config_inventory(envelope), (intent, baseline))
            changed = copy.deepcopy(envelope)
            changed['collector']['context']['inputSHA256'] = '0' * 64
            with self.assertRaisesRegex(RuntimeError, 'collector binding changed'):
                source.original_config_inventory(changed)
            changed = copy.deepcopy(envelope)
            changed['draftPayload']['baseline']['cloudlab-kiali'].append({'unreviewed': True})
            changed['draft']['payloadSHA256'] = handoff.digest(handoff.canonical(changed['draftPayload']))
            with self.assertRaisesRegex(RuntimeError, 'objects changed after collection'):
                source.original_config_inventory(changed)
            changed = copy.deepcopy(envelope)
            changed['transportInput']['codeSHA256'] = '0' * 64
            with self.assertRaisesRegex(RuntimeError, 'source binding changed'):
                source.original_config_inventory(changed)


if __name__ == '__main__':
    unittest.main()
