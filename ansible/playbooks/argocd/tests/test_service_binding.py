import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bootstrap
import source_transition as migration
from fixtures import binding_fixture, private_policies, private_probe


class ServiceBindingTests(unittest.TestCase):
    def setUp(self):
        self.objects, self.payload, self.target, self.checkpoint = binding_fixture()
        self.calls = []
        self.patch_failure = None
        self.fail_guard_after_patch = False
        self.fail_private_after_patch = False
        self.payload['argo']['serviceActivation']['catalog']['catalog'] = [
            {'definition': {}, 'publication': 'ready',
             'approval': {'name': 'synthetic', 'namespace': 'cloudlab-app-synthetic'}}]

    def read(self, kind, name):
        return self.objects.get((kind, name))

    def pause(self):
        self.calls.append(('pause',))
        self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'] = 0

    def write(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == 'scale':
            self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'] = int(args[-1].split('=')[1])
        if args[0] == 'patch':
            if args[1] == 'application.argoproj.io' and self.patch_failure == 'before':
                raise RuntimeError('synthetic patch failure')
            obj = self.objects[args[1], args[2]]
            body = json.loads(args[-1])
            for operation in body:
                if operation['op'] == 'add':
                    keys = operation['path'].strip('/').split('/')
                    target = obj
                    for key in keys[:-1]: target = target.setdefault(key, {})
                    target[keys[-1]] = copy.deepcopy(operation['value'])
            if args[1] == 'application.argoproj.io':
                if self.fail_guard_after_patch:
                    self.objects['namespace', 'cloudlab-app-synthetic'] = {'metadata': {'uid': 'foreign'}}
                if self.fail_private_after_patch:
                    self.objects['namespace', 'cloudlab-private-synthetic'] = {'metadata': {'uid': 'foreign'}}
                if self.patch_failure == 'after': raise RuntimeError('synthetic patch failure')
        return ''

    def contexts(self, base):
        import contextlib
        stack = contextlib.ExitStack()
        for module in (migration, bootstrap):
            stack.enter_context(patch.object(module, 'BASE', base))
            stack.enter_context(patch.object(module, 'get', side_effect=self.read))
            stack.enter_context(patch.object(module, 'kube', side_effect=self.write))
        stack.enter_context(patch.object(migration, 'pause', side_effect=self.pause))
        stack.enter_context(patch.object(migration, 'wait_application'))
        stack.enter_context(patch.object(migration, 'private_server_probe', side_effect=lambda document:
            private_probe(self.payload['argo']['privateActivation'], document)))
        return stack

    def test_guard_precedes_root_patch_and_acceptance_drops_temporary_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            with self.contexts(base):
                self.assertTrue(migration.bind_identity(self.payload, self.target)['changed'])
                before = len(self.calls)
                self.assertFalse(migration.bind_identity(self.payload, self.target)['changed'])
                self.assertEqual(len(self.calls), before)
            state = json.loads((base / 'identity-values-binding.json').read_text())
            self.assertEqual(set(state), {'phase', 'target', 'root_uid', 'controller_uid', 'project_uid'})
            self.assertEqual(state['phase'], 'accepted')

    def test_foreign_resource_refuses_before_patch_and_safely_resumes_original_root(self):
        self.objects['namespace', 'cloudlab-app-synthetic'] = {'metadata': {'uid': 'foreign'}}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            with self.contexts(base), self.assertRaisesRegex(RuntimeError, 'another owner'):
                migration.bind_identity(self.payload, self.target)
            self.assertFalse(any(call[0] == 'patch' for call in self.calls))
            self.assertEqual(self.calls[-1][-1], '--replicas=1')

    def test_failed_patch_that_did_not_commit_resumes_original_source(self):
        self.patch_failure = 'before'
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            with self.contexts(base), self.assertRaisesRegex(RuntimeError, 'synthetic patch failure'):
                migration.bind_identity(self.payload, self.target)
            self.assertEqual(self.calls[-1][-1], '--replicas=1')
            state = json.loads((base / 'identity-values-binding.json').read_text())
            self.assertEqual(state['phase'], 'paused')
            self.assertIn('serviceActivation', state)

    def test_failed_patch_that_committed_cannot_resume_after_guard_failure(self):
        self.patch_failure = 'after'
        self.fail_guard_after_patch = True
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            with self.contexts(base), self.assertRaisesRegex(RuntimeError, 'another owner'):
                migration.bind_identity(self.payload, self.target)
            self.assertFalse(any(call[0] == 'scale' for call in self.calls))
            self.assertEqual(self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'], 0)

    def pending(self, base, *, legacy=False):
        state = copy.deepcopy(self.checkpoint)
        state['serviceActivation'] = copy.deepcopy(self.payload['argo']['serviceActivation'])
        state['privateActivation'] = copy.deepcopy(self.payload['argo']['privateActivation'])
        self.objects['application.argoproj.io', migration.ROOT_APP]['spec']['source'] = copy.deepcopy(state['patchedSource'])
        self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'] = 0
        if legacy:
            for key in ('serviceActivation', 'originalSource', 'patchedSource'): state.pop(key)
        (base / 'identity-values-binding.json').write_text(json.dumps(state))
        return state

    def test_standalone_resume_uses_checkpoint_only_and_repairs_permissions_after_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.pending(base)
            with self.contexts(base):
                self.assertTrue(bootstrap.resume_identity_binding())
            self.assertEqual(self.calls[-1][-1], '--replicas=1')
            self.assertTrue(any(call[:2] == ('patch', 'appproject.argoproj.io') for call in self.calls))

    def test_missing_or_mismatched_pending_activation_never_resumes(self):
        for change in ('missing', 'sha', 'target', 'uid', 'root-source', 'root-project', 'topology'):
            self.setUp()
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                state = self.pending(base)
                if change == 'missing': state.pop('serviceActivation')
                if change == 'sha': state['serviceActivation']['private_revision'] = 'd' * 40
                if change == 'target': state['target']['valuesRevision'] = 'd' * 40
                if change == 'uid': state['controller_uid'] = 'foreign'
                if change == 'root-source': self.objects['application.argoproj.io', migration.ROOT_APP]['spec']['source']['repoURL'] = 'foreign'
                if change == 'root-project': self.objects['application.argoproj.io', migration.ROOT_APP]['spec']['project'] = 'foreign'
                if change == 'topology': self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'] = 2
                (base / 'identity-values-binding.json').write_text(json.dumps(state))
                with self.contexts(base), self.assertRaises(RuntimeError): bootstrap.resume_identity_binding()
                self.assertFalse(any(call[0] == 'scale' for call in self.calls))

    def test_permission_repair_guard_failure_stops_running_controller_without_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.pending(base)
            self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'] = 1
            self.objects['namespace', 'cloudlab-app-synthetic'] = {'metadata': {'uid': 'foreign'}}
            with self.contexts(base), self.assertRaisesRegex(RuntimeError, 'another owner'):
                bootstrap.resume_identity_binding()
            self.assertEqual(self.calls, [('pause',)])

    def test_retry_hydrates_legacy_checkpoint_only_at_recorded_target_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = self.pending(base, legacy=True)
            with self.contexts(base):
                migration.hydrate_binding(base / 'identity-values-binding.json', state, self.payload, self.target)
                self.assertIn('serviceActivation', json.loads((base / 'identity-values-binding.json').read_text()))
                with self.assertRaisesRegex(RuntimeError, 'recorded private revision'):
                    migration.hydrate_binding(base / 'identity-values-binding.json', state, self.payload,
                                             dict(self.target, valuesRevision='d' * 40))
                self.objects['statefulset', migration.CONTROLLER]['metadata']['uid'] = 'foreign'
                with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                    migration.hydrate_binding(base / 'identity-values-binding.json', state, self.payload, self.target)

    def test_recovery_target_requires_pending_exact_coordinates_and_all_live_uids(self):
        for change in ('valid', 'missing', 'accepted', 'target', 'root_uid', 'controller_uid', 'project_uid'):
            self.setUp()
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                state = self.pending(base)
                path = base / 'identity-values-binding.json'
                if change == 'missing': path.unlink()
                elif change == 'accepted': state['phase'] = 'accepted'
                elif change == 'target': state['target'] = dict(self.target, valuesRevision='d' * 40)
                elif change.endswith('_uid'): state[change] = 'foreign'
                if change != 'missing': path.write_text(json.dumps(state))
                with self.contexts(base):
                    if change == 'valid': self.assertEqual(migration.pending_identity_target(self.target), self.target['valuesRevision'])
                    else:
                        with self.assertRaises(RuntimeError): migration.pending_identity_target(self.target)
                self.assertEqual(self.calls, [])

    def enable_private(self):
        from private_activation import prepare
        public = {'repository': self.payload['repository'], 'privateSources': {'enabled': True, 'revision': 'c' * 40},
                  'admission': {'enabled': True}, 'externalSecrets': {'enabled': True, 'reconcile': True}}
        self.payload['argo']['privateActivation'] = prepare(public, self.target['valuesRepository'], self.target['valuesRevision'],
            {'sources': [{'name': 'synthetic', 'repository': self.target['valuesRepository'], 'revision': 'main', 'path': 'gitops'}]})
        self.objects.update(private_policies(self.payload['argo']['privateActivation']))

    def test_private_collision_after_committed_patch_keeps_controller_paused(self):
        self.enable_private()
        self.patch_failure = 'after'
        self.fail_private_after_patch = True
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            with self.contexts(base), self.assertRaisesRegex(RuntimeError, 'another owner'):
                migration.bind_identity(self.payload, self.target)
            self.assertFalse(any(call[0] == 'scale' for call in self.calls))

    def test_legacy_missing_private_evidence_requires_exact_target_hydration(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = self.pending(base)
            state.pop('privateActivation')
            path = base / 'identity-values-binding.json'
            path.write_text(json.dumps(state))
            with self.contexts(base):
                with self.assertRaisesRegex(RuntimeError, 'private activation inputs'): bootstrap.resume_identity_binding()
                self.assertFalse(any(call[0] == 'scale' for call in self.calls))
                migration.hydrate_binding(path, state, self.payload, self.target)
                self.assertIn('privateActivation', json.loads(path.read_text()))
                self.assertTrue(bootstrap.resume_identity_binding())

    def test_explicit_retry_refreshes_only_trusted_policy_specs(self):
        self.enable_private()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = self.pending(base)
            state['privateActivation']['identities'] = {'secret': 'retained-secret'}
            state['privateActivation']['policyIdentities'] = {'cloudlab-private-source-ownership': 'retained-policy'}
            state['privateActivation']['existing'] = {'uid': 'retained-catalog', 'sources': ['recorded-sources']}
            state['serviceActivation']['existing'] = {'uid': 'retained-service-catalog', 'sources': [], 'adoption': True}
            before = copy.deepcopy(state)
            proposed = copy.deepcopy(self.payload)
            proposed['argo']['privateActivation']['policies']['cloudlab-private-source-ownership']['validations'][0]['message'] += ' Updated.'
            path = base / 'identity-values-binding.json'
            with self.contexts(base):
                migration.hydrate_binding(path, state, proposed, self.target)
                after = json.loads(path.read_text())
                expected = copy.deepcopy(before)
                expected['privateActivation']['policies'] = proposed['argo']['privateActivation']['policies']
                self.assertEqual(after, expected)
                for change in ('registry', 'revision'):
                    invalid = copy.deepcopy(proposed)
                    if change == 'registry': invalid['argo']['privateActivation']['registry'] = {'sources': []}
                    else: invalid['argo']['privateActivation']['revision'] = 'd' * 40
                    with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'recorded registry or sources'):
                        migration.hydrate_binding(path, state, invalid, self.target)
