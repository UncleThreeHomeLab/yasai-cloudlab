import copy
from contextlib import nullcontext
import base64
import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / 'verification/integration'))
from private_verify import healthy, configuration_healthy, credential_owner, controller_items, run
from private_activation import APP, OWNER, TRACKING
from controller_stability import fingerprint
from fixtures import source_approval, first_binding_observation


class FirstBindingVerificationTests(unittest.TestCase):
    def test_run_explicitly_derives_anonymous_first_binding_before_permissions_reads(self):
        from playbooks.data.files import native
        from playbooks.argocd.files import github_app, source_transition
        for patched, replicas, phase in ((False, 0, 'paused'), (True, 0, 'paused'), (True, 1, 'resumed')):
            public, objects, binding = first_binding_observation(patched=patched, replicas=replicas)
            binding['phase'] = phase
            repository = binding['target']['valuesRepository']
            permissions = {'contract': {'context': {'repository': public['repository']}}}
            payload = {'configuration_repository': repository, 'configuration_revision': 'a' * 40, 'permissions': permissions}
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory); path = base / 'identity-values-binding.json'; path.write_text(json.dumps(binding))
                def declaration(evidence, selected, *, first_binding, recovery):
                    self.assertIsNone(recovery)
                    self.assertEqual(selected, repository); self.assertEqual(first_binding['checkpoint'], binding)
                    self.assertEqual(first_binding['sourceState'], 'patched' if patched else 'original')
                    with native.public_metadata({'publicSource': {'repository': public['repository'], 'branch': 'main'}},
                            deadline=280, first_binding=first_binding) as fetch:
                        self.assertIs(fetch, native.source_snapshot.request)
                    source_transition.pending_root_context(first_binding, public, first_binding=True)
                    raise RuntimeError('first binding checked')
                with patch.object(source_transition, 'BASE', base), patch.object(native, 'BINDING', path), \
                        patch.object(native, 'receipt', side_effect=lambda path, **kwargs: json.loads(path.read_text())), \
                        patch.object(source_transition, 'get', side_effect=lambda *key: objects.get(key)), \
                        patch.object(native, 'kube', return_value='{"items": []}'), \
                        patch.object(native, 'source_credentials') as credentials, patch.object(github_app, 'public_metadata') as mint, \
                        patch('private_verify.kube', return_value='{"items": []}'), \
                        patch('private_verify.permissions_declaration', side_effect=declaration) as declared:
                    with self.assertRaisesRegex(RuntimeError, 'first binding checked'): run(payload)
                    declared.assert_called_once(); credentials.assert_not_called(); mint.assert_not_called()

    def test_run_derives_established_pending_recovery_and_uses_original_reader(self):
        from playbooks.data.files import native
        from playbooks.argocd.files import github_app, source_transition
        for patched, replicas in ((False, 0), (True, 0), (True, 1)):
            public, objects, binding = first_binding_observation(patched=patched, replicas=replicas)
            old = dict(binding['target'], valuesRevision='c' * 40)
            binding['originalSource']['helm']['valuesObject']['identity']['argo'] = old
            root = objects['application.argoproj.io', 'cloudlab-public-root']
            root['spec']['source'] = copy.deepcopy(binding['patchedSource'] if patched else binding['originalSource'])
            repository = binding['target']['valuesRepository']
            payload = {'configuration_repository': repository, 'configuration_revision': 'a' * 40,
                'permissions': {'contract': {'context': {'repository': public['repository']}}}}
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory); path = base / 'identity-values-binding.json'; path.write_text(json.dumps(binding))
                def declaration(evidence, selected, *, first_binding, recovery):
                    self.assertIsNone(first_binding); self.assertEqual(recovery['checkpoint'], binding)
                    self.assertEqual(recovery['sourceState'], 'patched' if patched else 'original')
                    coordinates = {'publicSource': {'repository': public['repository'], 'branch': 'main'}}
                    with self.assertRaises(RuntimeError), native.public_metadata(coordinates, deadline=280, first_binding=recovery): pass
                    credentials.assert_not_called(); mint.assert_not_called()
                    with native.public_metadata(coordinates, deadline=280, recovery=recovery) as fetch:
                        self.assertEqual(fetch, 'authenticated-fetch')
                    credentials.assert_called_once_with(old['valuesRepository'])
                    source_transition.pending_root_context(recovery, public)
                    raise RuntimeError('established recovery checked')
                with patch.object(source_transition, 'BASE', base), patch.object(native, 'BINDING', path), \
                        patch.object(native, 'receipt', side_effect=lambda path, **kwargs: json.loads(path.read_text())), \
                        patch.object(source_transition, 'get', side_effect=lambda *key: objects.get(key)), \
                        patch.object(native, 'kube', return_value='{"items": []}'), \
                        patch.object(native, 'source_credentials', return_value={'synthetic': True}) as credentials, \
                        patch.object(github_app, 'public_metadata', side_effect=lambda *a, **k: nullcontext('authenticated-fetch')) as mint, \
                        patch('private_verify.kube', return_value='{"items": []}'), \
                        patch('private_verify.permissions_declaration', side_effect=declaration) as declared:
                    with self.assertRaisesRegex(RuntimeError, 'established recovery checked'): run(payload)
                    declared.assert_called_once(); mint.assert_called_once_with({'synthetic': True}, deadline=280)

    def test_first_binding_refuses_changed_authority_sources_and_unconfirmed_quiescence(self):
        from playbooks.data.files import native
        from playbooks.argocd.files import github_app, source_transition
        from private_verify import pending_verification_context
        for change in ('patch', 'uid', 'target-ref', 'public-ref', 'pods', 'foreign-target', 'source'):
            public, objects, binding = first_binding_observation(patched=True, replicas=0)
            repository = binding['target']['valuesRepository']
            if change == 'patch': binding['patchedSource']['helm']['valuesObject']['foreign'] = True
            if change == 'uid': objects['statefulset', 'argocd-application-controller']['metadata']['uid'] = 'changed'
            if change == 'target-ref': binding['target']['valuesRevision'] = 'main'
            if change == 'public-ref': binding['publicRevision'] = 'main'
            if change == 'foreign-target': binding['target']['valuesRepository'] = 'https://github.com/other/private.git'
            if change == 'source': objects['application.argoproj.io', 'cloudlab-public-root']['spec']['source']['path'] = 'other'
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory); path = base / 'identity-values-binding.json'; path.write_text(json.dumps(binding))
                pods = {'items': [{'metadata': {'ownerReferences': [{'uid': 'controller'}]}}]} if change == 'pods' else {'items': []}
                with patch.object(source_transition, 'BASE', base), patch.object(native, 'BINDING', path), \
                        patch.object(native, 'receipt', side_effect=lambda path, **kwargs: json.loads(path.read_text())), \
                        patch.object(source_transition, 'get', side_effect=lambda *key: objects.get(key)), \
                        patch.object(native, 'kube', return_value=json.dumps(pods)), \
                        patch.object(native, 'source_credentials') as credentials, patch.object(github_app, 'public_metadata') as mint:
                    with self.assertRaises((RuntimeError, ValueError)):
                        pending_verification_context({'contract': {'context': {'repository': public['repository']}}}, repository)
                    credentials.assert_not_called(); mint.assert_not_called()


class PermissionsConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import yaml
        from private_sources import CONSUMER_ACCEPTANCE_VERSION, acceptance_spec, consumer_contract
        from private_verify import permissions_declaration
        root = Path(__file__).resolve().parents[4]
        cls.snapshots = {}
        for directory in ('gitops/roots/public', 'platform/connectivity/permissions', 'platform/delivery/admission/policies'):
            chart = root / directory
            cls.snapshots[directory] = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        cls.files = cls.snapshots['gitops/roots/public']
        cls.public = yaml.safe_load(cls.files['values.yaml'])
        cls.public['repository'] = 'https://github.com/example/platform.git'
        cls.repository = 'https://github.com/example/private.git'
        receipt = {'version': CONSUMER_ACCEPTANCE_VERSION, 'consumer': 'permissions',
            'paths': ['platform/permissions.yaml'], 'revision': 'b' * 40, 'nonce': '1' * 64}
        commitment = hashlib.sha256(('\n'.join([receipt['version'], receipt['consumer'], cls.repository, '1',
            *receipt['paths'], receipt['revision'], receipt['nonce'], ''])).encode()).hexdigest()
        cls.public['permissions'] = {'enabled': True, 'revision': 'a' * 40, 'acceptanceCommitment': commitment}
        cls.spec = acceptance_spec(cls.public, cls.repository, 'd' * 40, consumer='permissions')
        cls.evidence = {'publicRevision': 'c' * 40, 'acceptedRevision': receipt['revision'],
            'acceptanceCommitment': commitment, 'acceptanceReceipt': receipt,
            'contract': consumer_contract(cls.public, 'permissions'), 'applicationSet': cls.spec}
        with patch('playbooks.data.files.native.public_metadata', side_effect=lambda *a, **k: nullcontext()), \
                patch('playbooks.data.files.native.published_source', return_value=(cls.public, 'c' * 40)), \
                patch('playbooks.data.files.native.source_snapshot.chart_files', side_effect=lambda source, **kwargs: cls.snapshots[source['path']]):
            cls.guard = permissions_declaration(cls.evidence, cls.repository)

    def objects(self):
        name = 'cloudlab-permissions'
        spec = copy.deepcopy(self.spec['template']['spec'])
        spec['source']['helm']['valuesObject'] = {'permissions': {'state': 'active', 'assignments': []}}
        parent = {'metadata': {'name': name, 'uid': 'parent', 'labels': {'cloudlab.io/owner': 'permissions-platform'},
            'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + name}},
            'spec': copy.deepcopy(self.spec), 'status': {'conditions': [{'type': 'ParametersGenerated', 'status': 'True'}]}}
        child = {'metadata': copy.deepcopy(self.spec['template']['metadata']) | {'uid': 'child', 'ownerReferences': [{
            'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': name,
            'uid': 'parent', 'controller': True, 'blockOwnerDeletion': True}]}, 'spec': spec,
            'status': {'sync': {'status': 'Synced', 'revision': 'a' * 40, 'comparedTo': {'source': copy.deepcopy(spec['source']), 'destination': copy.deepcopy(spec['destination'])}},
                'health': {'status': 'Healthy'}}}
        child['metadata']['annotations']['cloudlab.io/permission-revision'] = 'b' * 40
        root = {'metadata': {'uid': 'root'}, 'spec': {'project': 'cloudlab-root', 'source': {
            'repoURL': self.public['repository'], 'targetRevision': 'main', 'path': 'gitops/roots/public',
            'helm': {'valuesObject': {'identity': {'argo': {'valuesRepository': self.repository, 'valuesRevision': 'd' * 40}}}}}},
            'status': {'sync': {'status': 'Synced', 'revision': 'c' * 40}, 'health': {'status': 'Healthy'}}}
        profile = copy.deepcopy(self.guard['profileApplication'])
        profile['metadata']['uid'] = 'profiles'
        profile['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'cloudlab-public-root:argoproj.io/Application:argocd/cloudlab-permissions-profiles'
        profile['status'] = {'sync': {'status': 'Synced', 'revision': 'a' * 40, 'comparedTo': {'source': copy.deepcopy(profile['spec']['source']), 'destination': copy.deepcopy(profile['spec']['destination'])}},
            'health': {'status': 'Healthy'}}
        projection = copy.deepcopy(self.guard['projection'])
        projection['metadata'].update(uid='projection', annotations={'argocd.argoproj.io/tracking-id':
            'cloudlab-permissions-profiles:/ConfigMap:argocd/cloudlab-permissions-profiles'})
        objects = {('applicationset.argoproj.io', name): parent, ('application.argoproj.io', name): child,
            ('application.argoproj.io', 'cloudlab-public-root'): root,
            ('application.argoproj.io', 'cloudlab-permissions-profiles'): profile,
            ('configmap', 'cloudlab-permissions-profiles'): projection}
        for reference in self.guard['policies']:
            policy = copy.deepcopy(reference)
            kind, policy_name = policy['kind'], policy['metadata']['name']
            policy['metadata'].update(uid=policy_name + kind, generation=2, annotations={'argocd.argoproj.io/tracking-id':
                'cloudlab-workload-policy:admissionregistration.k8s.io/' + kind + ':cloudlab-policy/' + policy_name})
            if kind == 'ValidatingAdmissionPolicy': policy['status'] = {'observedGeneration': 2, 'typeChecking': {}}
            objects[kind.lower() + '.admissionregistration.k8s.io', policy_name] = policy
        return objects

    def test_exact_parent_child_root_projection_and_current_guard_are_required(self):
        from private_verify import permissions_healthy
        for case in ('valid', 'parent-error', 'owner', 'accepted-revision', 'compared-source', 'root-revision', 'root-override',
                'projection', 'profile-source', 'policy', 'policy-readiness', 'policy-stale', 'policy-missing-generation', 'binding', 'missing-profile-guard'):
            objects = self.objects()
            parent = objects['applicationset.argoproj.io', 'cloudlab-permissions']
            child = objects['application.argoproj.io', 'cloudlab-permissions']
            root = objects['application.argoproj.io', 'cloudlab-public-root']
            policy = objects['validatingadmissionpolicy.admissionregistration.k8s.io', 'cloudlab-permissions-input']
            if case == 'parent-error': parent['status']['conditions'].append({'type': 'ErrorOccurred', 'status': 'True'})
            if case == 'owner': child['metadata']['ownerReferences'][0]['uid'] = 'foreign'
            if case == 'accepted-revision': child['metadata']['annotations']['cloudlab.io/permission-revision'] = 'e' * 40
            if case == 'compared-source': child['status']['sync'].pop('comparedTo')
            if case == 'root-revision': root['status']['sync']['revision'] = 'e' * 40
            if case == 'root-override': root['spec']['source']['helm']['valuesObject']['permissions'] = {'enabled': False}
            if case == 'projection': objects['configmap', 'cloudlab-permissions-profiles']['data'] = {}
            if case == 'profile-source': objects['application.argoproj.io', 'cloudlab-permissions-profiles']['status']['sync'].pop('comparedTo')
            if case == 'policy': policy['spec']['failurePolicy'] = 'Ignore'
            if case == 'policy-readiness': policy['status']['typeChecking']['expressionWarnings'] = [{'warning': 'synthetic'}]
            if case == 'policy-stale': policy['metadata']['generation'] = 3
            if case == 'binding': objects['validatingadmissionpolicybinding.admissionregistration.k8s.io', 'cloudlab-permissions-input']['spec']['paramRef']['parameterNotFoundAction'] = 'Allow'
            if case == 'missing-profile-guard': objects.pop(('validatingadmissionpolicy.admissionregistration.k8s.io', 'cloudlab-permissions-profiles'))
            if case == 'policy-missing-generation': policy['status'].pop('observedGeneration')
            with self.subTest(case=case), patch('private_verify.get', side_effect=lambda kind, name: objects.get((kind, name))):
                self.assertEqual(bool(permissions_healthy(self.evidence, self.repository, self.guard)), case == 'valid')

    def test_declaration_authenticates_current_public_intent_and_native_snapshots(self):
        from private_verify import permissions_declaration
        with patch('playbooks.data.files.native.public_metadata', side_effect=lambda *a, **k: nullcontext()), \
                patch('playbooks.data.files.native.published_source', return_value=(self.public, 'c' * 40)), \
                patch('playbooks.data.files.native.source_snapshot.chart_files', side_effect=lambda source, **kwargs: self.snapshots[source['path']]):
            self.assertEqual(permissions_declaration(self.evidence, self.repository), self.guard)
            for field, value in (('publicRevision', 'e' * 40), ('acceptedRevision', 'e' * 40), ('applicationSet', {})):
                with self.subTest(field=field), self.assertRaises((RuntimeError, ValueError)):
                    permissions_declaration(dict(self.evidence, **{field: value}), self.repository)

    def test_first_binding_declaration_revalidates_fresh_public_compatibility_before_return(self):
        from private_verify import permissions_declaration
        envelope = {'checkpoint': {'phase': 'resumed'}}
        with patch('playbooks.data.files.native.public_metadata', side_effect=lambda *a, **k: nullcontext()) as session, \
                patch('playbooks.data.files.native.published_source', return_value=(self.public, 'c' * 40)), \
                patch('playbooks.data.files.native.source_snapshot.chart_files', side_effect=lambda source, **kwargs: self.snapshots[source['path']]), \
                patch('playbooks.argocd.files.source_transition.pending_root_context') as guard:
            self.assertEqual(permissions_declaration(self.evidence, self.repository, first_binding=envelope), self.guard)
            self.assertEqual(guard.call_count, 2)
            guard.assert_called_with(envelope, self.public, first_binding=True)
            self.assertIs(session.call_args.kwargs['first_binding'], envelope)
            guard.reset_mock()
            self.assertEqual(permissions_declaration(self.evidence, self.repository, recovery=envelope), self.guard)
            self.assertEqual(guard.call_count, 2)
            guard.assert_called_with(envelope, self.public, first_binding=False)
            self.assertIs(session.call_args.kwargs['recovery'], envelope)
            guard.side_effect = RuntimeError('changed public authority')
            with self.assertRaisesRegex(RuntimeError, 'changed public authority'):
                permissions_declaration(self.evidence, self.repository, first_binding=envelope)

    def test_root_alternative_helm_inputs_cannot_override_authenticated_values(self):
        from private_verify import permissions_healthy
        for channel, value in ((None, None), ('parameters', [{'name': 'permissions.enabled', 'value': 'false'}]),
                ('fileParameters', [{'name': 'permissions.enabled', 'path': 'override.txt'}]),
                ('values', 'permissions: {enabled: false}'), ('valueFiles', ['override.yaml'])):
            objects = self.objects()
            helm = objects['application.argoproj.io', 'cloudlab-public-root']['spec']['source']['helm']
            helm['valuesObject']['data'] = {'configuration': {'enabled': True}}
            if channel is not None: helm[channel] = value
            with self.subTest(channel=channel), patch('private_verify.get', side_effect=lambda kind, name: objects.get((kind, name))):
                self.assertEqual(bool(permissions_healthy(self.evidence, self.repository, self.guard)), channel is None)

    def test_pub_only_child_or_parent_without_evidence_never_uses_generic_pin_health(self):
        objects = self.objects()
        for present in ('child', 'parent'):
            child = objects['application.argoproj.io', 'cloudlab-permissions']
            consumer = child if present == 'child' else {'metadata': {'name': 'other'}, 'spec': {'source': {'repoURL': self.repository}}}
            payload = {'configuration_repository': self.repository, 'configuration_revision': 'd' * 40, 'sources': []}
            with self.subTest(present=present), patch('private_verify.kube', return_value=json.dumps({'items': [consumer]})), \
                    patch('private_verify.get', side_effect=lambda kind, name: objects.get((kind, name))), patch('private_verify.configuration_healthy') as health:
                with self.assertRaisesRegex(RuntimeError, 'authenticated consumer approval evidence'): run(payload)
                health.assert_not_called()


class PrivateControllerStabilityTests(unittest.TestCase):
    def setUp(self):
        self.controller = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
            'metadata': {'name': 'controller', 'namespace': 'argocd', 'uid': 'controller-uid', 'generation': 1},
            'spec': {'replicas': 1},
            'status': {'observedGeneration': 1, 'readyReplicas': 1, 'updatedReplicas': 1}}
        self.pod = {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': 'controller-pod', 'namespace': 'argocd', 'uid': 'pod-uid'},
            'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}],
                       'containerStatuses': [{'name': 'controller', 'restartCount': 0, 'containerID': 'container-1'}]}}
        self.job = {'apiVersion': 'batch/v1', 'kind': 'Job',
                    'metadata': {'name': 'scheduled', 'namespace': 'argocd', 'uid': 'job-uid'}}
        self.job_pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {
            'name': 'scheduled-pod', 'namespace': 'argocd', 'uid': 'job-pod-uid', 'ownerReferences': [
                {'apiVersion': 'batch/v1', 'kind': 'Job', 'controller': True, 'name': 'scheduled', 'uid': 'job-uid'}]},
            'status': {'phase': 'Pending'}}

    def test_proven_job_pod_start_completion_and_disappearance_preserve_controller_fingerprint(self):
        baseline = fingerprint([self.controller, self.pod])
        completed = copy.deepcopy(self.job_pod)
        completed['status']['phase'] = 'Succeeded'
        for transient in ([], [self.job], [self.job, self.job_pod], [self.job, completed], []):
            with self.subTest(transient=transient):
                self.assertEqual(fingerprint(controller_items([self.controller, self.pod] + transient)), baseline)

    def test_missing_or_mismatched_job_ownership_cannot_hide_an_unready_pod(self):
        changes = [{}, {'ownerReferences': []}, {'ownerReferences': ['malformed']},
                   {'ownerReferences': {'kind': 'Job'}}]
        owner = self.job_pod['metadata']['ownerReferences'][0]
        for field, value in (('kind', 'ReplicaSet'), ('apiVersion', 'apps/v1'), ('controller', False),
                             ('controller', 1), ('uid', 'foreign'), ('uid', None), ('name', 'other')):
            changes.append({'ownerReferences': [owner | {field: value}]})
        changes.append({'namespace': 'other'})
        for change in changes:
            pod = copy.deepcopy(self.job_pod)
            pod['metadata'].pop('ownerReferences')
            pod['metadata'].update(change)
            pod['metadata']['name'] = 'cloudlab-previews-scheduled-looking-pod'
            with self.subTest(change=change):
                filtered = controller_items([self.controller, self.pod, self.job, pod])
                self.assertIn(pod, filtered)
                with self.assertRaisesRegex(RuntimeError, 'not ready'): fingerprint(filtered)

    def test_missing_or_malformed_listed_job_does_not_prove_pod_ownership(self):
        jobs = [None, self.job | {'apiVersion': 'batch/v1beta1'}]
        for field, value in (('uid', ''), ('uid', None), ('name', ''), ('namespace', 'other')):
            jobs.append(self.job | {'metadata': self.job['metadata'] | {field: value}})
        for job in jobs:
            with self.subTest(job=job):
                filtered = controller_items([self.controller, self.pod, self.job_pod] + ([job] if job else []))
                self.assertIn(self.job_pod, filtered)
                with self.assertRaisesRegex(RuntimeError, 'not ready'): fingerprint(filtered)

    def test_persistent_pod_restart_replacement_and_unreadiness_remain_visible(self):
        baseline = fingerprint(controller_items([self.controller, self.pod, self.job, self.job_pod]))
        restarted = copy.deepcopy(self.pod)
        restarted['status']['containerStatuses'][0]['restartCount'] = 1
        replaced = self.pod | {'metadata': self.pod['metadata'] | {'uid': 'replacement'}}
        for pod in (restarted, replaced):
            self.assertNotEqual(fingerprint(controller_items([self.controller, pod, self.job, self.job_pod])), baseline)
        unready = copy.deepcopy(self.pod)
        unready['status']['conditions'][0]['status'] = 'False'
        with self.assertRaisesRegex(RuntimeError, 'not ready'):
            fingerprint(controller_items([self.controller, unready, self.job, self.job_pod]))
        controller = self.controller | {'status': self.controller['status'] | {'readyReplicas': 0}}
        with self.assertRaisesRegex(RuntimeError, 'rollout is not complete'):
            fingerprint(controller_items([controller, self.pod, self.job, self.job_pod]))


class PrivateConvergenceTests(unittest.TestCase):
    def test_declared_symbolic_refs_require_the_authenticated_snapshot_and_preserve_input(self):
        for ref in ('feature/prices', 'release/v2'):
            app = {'spec': {'source': {'repoURL': 'private-source', 'targetRevision': ref}},
                   'status': {'sync': {'revision': 'b' * 40, 'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
            original = copy.deepcopy(app)
            with patch('private_verify.get', return_value=app):
                self.assertTrue(configuration_healthy('consumer', 'private-source', 'a' * 40, {ref: 'b' * 40}))
                for snapshot in (None, {}, {'undeclared': 'b' * 40}, {ref: 'c' * 40}, {ref: 'main'},
                                 {ref: None}, [], {'-flag': 'b' * 40}):
                    with self.subTest(ref=ref, snapshot=snapshot):
                        self.assertFalse(configuration_healthy('consumer', 'private-source', 'a' * 40, snapshot))
            self.assertEqual(app, original)

    def test_symbolic_map_cannot_override_main_or_immutable_pins(self):
        for ref, expected in (('main', 'a' * 40), ('b' * 40, 'b' * 40)):
            app = {'spec': {'source': {'repoURL': 'private-source', 'targetRevision': ref}},
                   'status': {'sync': {'revision': expected, 'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
            with patch('private_verify.get', return_value=app):
                self.assertTrue(configuration_healthy('consumer', 'private-source', 'a' * 40))
                self.assertFalse(configuration_healthy('consumer', 'private-source', 'a' * 40, {ref: expected}))
                app['status']['sync']['revision'] = 'c' * 40
                self.assertFalse(configuration_healthy('consumer', 'private-source', 'a' * 40, {ref: 'c' * 40}))

    def test_mixed_sources_keep_main_and_every_pin_bound_while_comparing_symbolic_private_refs(self):
        app = {'spec': {'sources': [
            {'repoURL': 'public-source', 'targetRevision': 'main'},
            {'repoURL': 'private-source', 'targetRevision': 'feature/prices'},
            {'repoURL': 'private-source', 'targetRevision': 'c' * 40},
            {'repoURL': 'private-source', 'targetRevision': 'main'},
            {'repoURL': 'other-source', 'targetRevision': 'd' * 40}]},
            'status': {'sync': {'status': 'Synced', 'revisions': ['e' * 40, 'b' * 40, 'c' * 40, 'a' * 40, 'd' * 40]},
                       'health': {'status': 'Healthy'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(configuration_healthy('consumer', 'private-source', 'a' * 40, {'feature/prices': 'b' * 40}))
            for index in range(1, 5):
                original = app['status']['sync']['revisions'][index]
                app['status']['sync']['revisions'][index] = 'f' * 40
                self.assertFalse(configuration_healthy('consumer', 'private-source', 'a' * 40, {'feature/prices': 'b' * 40}))
                app['status']['sync']['revisions'][index] = original

    def test_symbolic_snapshot_reaches_initial_consumer_child_and_stability_checks(self):
        snapshots = {'feature/prices': 'b' * 40}
        payload = {'configuration_repository': 'private-source', 'configuration_revision': 'a' * 40,
                   'symbolic_revisions': snapshots, 'sources': [{'name': 'example', 'repository': 'private-source'}]}
        consumer = {'metadata': {'name': 'cloudlab-private-example'}, 'spec': {'source': {'repoURL': 'private-source'}}}
        def request(*args): return json.dumps({'items': [consumer] if args[1] == 'applications.argoproj.io' else []})
        def healthy(name, repository, revision, symbols):
            self.assertIs(symbols, snapshots)
            return True
        with patch('private_verify.kube', side_effect=request), patch('private_verify.get', return_value=consumer), \
                patch('private_verify.configuration_healthy', side_effect=healthy) as checks, \
                patch('private_verify.credential_owner'), patch('private_verify.foundation_sample', return_value=()), \
                patch('private_verify.fingerprint', return_value=()), \
                patch('private_verify.wait', side_effect=lambda check, description: self.assertTrue(check())), \
                patch('private_verify.time.sleep'), patch('private_verify.time.monotonic', side_effect=[0, 1, 61, 62]):
            self.assertTrue(run(payload)['private_access_verified'])
        self.assertEqual(checks.call_count, 4)

    def test_external_registered_child_degradation_fails_stability_observation(self):
        payload = {'configuration_repository': 'private-source', 'configuration_revision': 'b' * 40,
                   'sources': [{'name': 'example', 'repository': 'other-source'}]}
        consumer = {'metadata': {'name': 'configuration-consumer'},
                    'spec': {'source': {'repoURL': 'private-source'}}}
        def request(*args):
            self.assertEqual(args[0], 'get')
            return json.dumps({'items': [consumer] if args[1] == 'applications.argoproj.io' else []})
        with patch('private_verify.kube', side_effect=request), patch('private_verify.get', return_value={}), \
                patch('private_verify.configuration_healthy', return_value=True), \
                patch('private_verify.healthy', side_effect=[True, False]) as child_health, \
                patch('private_verify.credential_owner'), patch('private_verify.foundation_sample', return_value=()), \
                patch('private_verify.fingerprint', return_value=()), \
                patch('private_verify.wait', side_effect=lambda check, description: self.assertTrue(check())), \
                patch('private_verify.time.sleep'), patch('private_verify.time.monotonic', side_effect=[0, 1]):
            with self.assertRaisesRegex(RuntimeError, 'changed during stability observation'):
                run(payload)
        self.assertEqual([call.args for call in child_health.call_args_list], [('cloudlab-private-example',)] * 2)

    def test_native_empty_catalog_requires_exact_owned_source_and_does_not_write(self):
        payload = {'configuration_repository': 'https://github.com/example/private.git',
            'configuration_revision': 'b' * 40, 'catalog_enabled': True, 'sources': [], 'objects': [],
            'public_repository': 'https://github.com/example/platform.git', 'platform_revision': 'a' * 40}
        public = {'repository': payload['public_repository'], 'privateSources': {'enabled': True, 'revision': 'a' * 40},
            'admission': {'enabled': True}, 'externalSecrets': {'enabled': True, 'reconcile': True}}
        approval = source_approval(public, payload['configuration_repository'])
        from private_sources import acceptance_spec
        spec = acceptance_spec(public, payload['configuration_repository'], payload['configuration_revision'])
        payload.update(approval, applicationSet=spec)
        parent = {'metadata': {'uid': 'parent', 'labels': {'cloudlab.io/owner': OWNER},
            'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + APP}}, 'spec': spec}
        root = {'metadata': {'uid': 'root'}, 'spec': {'project': 'cloudlab-root', 'source': {
            'repoURL': public['repository'], 'targetRevision': 'main', 'path': 'gitops/roots/public',
            'helm': {'valuesObject': {'identity': {'argo': {'valuesRepository': payload['configuration_repository'],
                'valuesRevision': payload['configuration_revision']}}}}}}}
        chart = Path(__file__).resolve().parents[4] / 'gitops/roots/public'
        files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        app = {'metadata': {'name': APP, 'labels': {'cloudlab.io/owner': OWNER},
            'annotations': {'argocd.argoproj.io/tracking-id': TRACKING}},
            'spec': {'project': APP, 'sources': [
                {'repoURL': payload['public_repository'], 'targetRevision': 'a' * 40,
                 'path': 'platform/delivery/private-sources', 'helm': {'valueFiles': ['$values/platform/sources.yaml']}},
                {'repoURL': payload['configuration_repository'], 'targetRevision': approval['acceptedRevision'], 'ref': 'values'}],
                'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                'syncPolicy': {'automated': {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': True},
                    'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true', 'PruneLast=true']}},
            'status': {'sync': {'status': 'Synced', 'revisions': ['a' * 40, approval['acceptedRevision']]},
                       'health': {'status': 'Healthy'}}}
        app['metadata']['ownerReferences'] = [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
            'name': APP, 'uid': 'parent', 'controller': True, 'blockOwnerDeletion': True}]
        project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
            'metadata': {'name': 'cloudlab-private-example', 'labels': {'cloudlab.io/owner': 'private-gitops'}},
            'spec': {'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-private-example'}]}}
        payload['objects'] = [project]
        def request(*args):
            self.assertEqual(args[0], 'get')
            if args[1] == 'appproject.argoproj.io': return json.dumps(actual_project)
            return json.dumps({'items': [app] if args[1] == 'applications.argoproj.io' else []})
        for bad in ('none', 'catalog', 'project'):
            changed = copy.deepcopy(app)
            actual_project = copy.deepcopy(project)
            actual_project['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
                APP + ':argoproj.io/AppProject:argocd/cloudlab-private-example'}
            if bad == 'catalog': changed['metadata']['annotations'] = {}
            if bad == 'project': actual_project['spec']['destinations'][0]['namespace'] = 'argocd'
            def read(kind, name):
                if name == 'cloudlab-public-root': return root
                return parent if kind == 'applicationset.argoproj.io' else changed
            with patch('private_verify.get', side_effect=read), patch('private_verify.kube', side_effect=request), \
                    patch('playbooks.data.files.native.published_source', return_value=(public, 'e' * 40)), \
                    patch('playbooks.data.files.native.source_snapshot.chart_files', return_value=files), \
                    patch('private_verify.credential_owner'), patch('private_verify.foundation_sample', return_value=()), \
                    patch('private_verify.wait', side_effect=lambda check, description: self.assertTrue(check())), \
                    patch('private_verify.fingerprint', return_value=()), patch('private_verify.time.monotonic', side_effect=[0, 0, 61, 62]):
                if bad != 'none':
                    with self.assertRaisesRegex(RuntimeError, 'ownership or source|native declaration'): run(payload)
                else:
                    self.assertTrue(run(payload)['private_access_verified'])

    def test_main_must_resolve_to_authenticated_configuration_head(self):
        app = {'spec': {'source': {'repoURL': 'private-source', 'targetRevision': 'main'}},
               'status': {'sync': {'revision': 'a' * 40, 'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(configuration_healthy('consumer', 'private-source', 'a' * 40))
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'b' * 40))
            self.assertFalse(configuration_healthy('consumer', 'other-source', 'a' * 40))
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'main'))

    def test_native_private_values_main_requires_authenticated_head_without_relaxing_other_sources(self):
        app = {'spec': {'sources': [{'repoURL': 'public-source', 'targetRevision': 'main'},
                                   {'repoURL': 'private-source', 'targetRevision': 'main', 'ref': 'values'}]},
               'status': {'sync': {'status': 'Synced', 'revisions': ['a' * 40, 'b' * 40]},
                          'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
        original = copy.deepcopy(app)
        with patch('private_verify.get', return_value=app):
            self.assertTrue(configuration_healthy('consumer', 'private-source', 'b' * 40))
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'c' * 40))
        self.assertEqual(app, original)
        for target in ('c' * 40, 'unapproved-branch'):
            changed = copy.deepcopy(app)
            changed['spec']['sources'][1]['targetRevision'] = target
            with patch('private_verify.get', return_value=changed):
                self.assertFalse(configuration_healthy('consumer', 'private-source', 'b' * 40))
        changed = copy.deepcopy(app)
        changed['spec']['sources'].append({'repoURL': 'other-source', 'targetRevision': 'main'})
        changed['status']['sync']['revisions'].append('d' * 40)
        with patch('private_verify.get', return_value=changed):
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'b' * 40))

    def test_private_credential_requires_exact_project_and_ready_eso_owner(self):
        app = {'spec': {'project': 'approved'}}
        secret = {'metadata': {'name': 'source', 'labels': {'argocd.argoproj.io/secret-type': 'repository'},
                               'ownerReferences': [{'kind': 'ExternalSecret', 'name': 'source', 'uid': 'owner', 'controller': True}]},
                  'data': {key: base64.b64encode(value.encode()).decode() for key, value in {
                      'url': 'private-source', 'project': 'approved', 'githubAppID': '1',
                      'githubAppInstallationID': '2', 'githubAppPrivateKey': 'synthetic'}.items()}}
        external = {'metadata': {'name': 'source', 'uid': 'owner'},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        credential_owner(app, 'private-source', [secret], [external])
        for changed, externals in ((dict(secret, data=dict(secret['data'], project='')), [external]),
                                   (dict(secret, metadata=dict(secret['metadata'], ownerReferences=[])), [external]),
                                   (secret, [dict(external, status={})])):
            with self.subTest(changed=changed['metadata']['name']), self.assertRaises(RuntimeError):
                credential_owner(app, 'private-source', [changed], externals)
        with self.assertRaises(RuntimeError):
            credential_owner(app, 'private-source', [secret, secret], [external])

    def test_missing_private_capability_never_passes_as_verified(self):
        with self.assertRaises(RuntimeError):
            run({'sources': []})
        with patch('private_verify.kube', return_value='{"items": []}'), self.assertRaises(RuntimeError):
            run({'sources': [], 'configuration_repository': 'private-source'})

    def test_native_multiple_sources_require_every_pinned_values_revision(self):
        app = {'spec': {'sources': [{'targetRevision': 'main'}, {'targetRevision': 'b' * 40}]},
               'status': {'sync': {'status': 'Synced', 'revisions': ['a' * 40, 'b' * 40]},
                          'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(healthy('cloudlab-argocd'))
        for revisions, target in ((['a' * 40], 'b' * 40), (['a' * 40, 'c' * 40], 'b' * 40),
                                  (['a' * 40, 'main'], 'main')):
            changed = copy.deepcopy(app)
            changed['status']['sync']['revisions'] = revisions
            changed['spec']['sources'][1]['targetRevision'] = target
            with self.subTest(revisions=revisions), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('cloudlab-argocd'))

    def test_retained_resources_can_converge_without_a_new_sync_operation(self):
        app = {'status': {'sync': {'status': 'Synced', 'revision': 'resolved-commit'},
                          'health': {'status': 'Healthy'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(healthy('fixture'))
        for phase in ('Running', 'Failed', 'Error', 'Terminating'):
            changed = copy.deepcopy(app)
            changed['status']['operationState'] = {'phase': phase}
            with self.subTest(phase=phase), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('fixture'))
        for change in ({'sync': {'status': 'Synced'}}, {'conditions': [{'type': 'ComparisonError'}]},
                       {'sync': {'status': 'Unknown', 'revision': 'old'}}):
            changed = copy.deepcopy(app)
            changed['status'].update(change)
            with self.subTest(change=change), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('fixture'))
