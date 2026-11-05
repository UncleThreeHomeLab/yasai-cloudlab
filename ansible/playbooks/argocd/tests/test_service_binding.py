import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bootstrap
import source_transition as migration
from fixtures import binding_fixture, private_policies, private_probe, access_evidence, access_authority
import access_activation
import data_activation
from playbooks.data.files import control as data_control, native as data_native, handoff as data_handoff


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
        stack.enter_context(patch.object(data_control, 'BASE', base))
        stack.enter_context(patch.object(data_native, 'receipt', side_effect=lambda path, **kwargs: json.loads(path.read_text()) if path.exists() else {}))
        for module in (migration, bootstrap):
            stack.enter_context(patch.object(module, 'BASE', base))
            stack.enter_context(patch.object(module, 'get', side_effect=self.read))
            stack.enter_context(patch.object(module, 'kube', side_effect=self.write))
        stack.enter_context(patch.object(migration, 'pause', side_effect=self.pause))
        stack.enter_context(patch.object(migration, 'wait_application'))
        stack.enter_context(patch.object(migration, 'capture_public_revision', return_value=self.payload['revision']))
        stack.enter_context(patch.object(data_native, 'published_source', side_effect=lambda *a, **k: (
            {'repository': self.payload['repository'], 'data': {'enabled': True, 'configuration': dict(
                self.payload['argo']['dataActivation'], enabled=True)}}, self.payload['revision'])))
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
                expected['publicRevision'] = self.payload['revision']
                expected['privateActivation']['policies'] = proposed['argo']['privateActivation']['policies']
                self.assertEqual(after, expected)
                for change in ('registry', 'revision'):
                    invalid = copy.deepcopy(proposed)
                    if change == 'registry': invalid['argo']['privateActivation']['registry'] = {'sources': []}
                    else: invalid['argo']['privateActivation']['revision'] = 'd' * 40
                    with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'recorded registry or sources'):
                        migration.hydrate_binding(path, state, invalid, self.target)

    def test_access_candidate_denial_precedes_new_and_already_accepted_binding_writes(self):
        administrator, receipt, objects = access_authority(self.payload['repository'])
        self.objects.update(objects)
        self.payload['argo']['accessActivation'] = access_evidence(self.payload['repository'], self.target, administrator)
        self.payload['argo']['accessActivation']['administratorHash'] = '0' * 64
        for accepted in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory); (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
                if accepted:
                    state = {k: self.checkpoint[k] for k in ('target', 'root_uid', 'controller_uid', 'project_uid')}
                    state['phase'] = 'accepted'
                    (base / 'identity-values-binding.json').write_text(json.dumps(state))
                    self.objects['application.argoproj.io', migration.ROOT_APP]['spec']['source'] = copy.deepcopy(self.checkpoint['patchedSource'])
                with self.contexts(base), patch.object(access_activation, 'receipt', return_value=receipt), self.assertRaises(RuntimeError):
                    migration.bind_identity(self.payload, self.target)
                self.assertEqual(self.calls, [])

    def test_patched_legacy_access_evidence_requires_exact_authenticated_rehydration(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); state = self.pending(base); state.pop('accessActivation')
            path = base / 'identity-values-binding.json'; path.write_text(json.dumps(state))
            with self.contexts(base):
                with self.assertRaises(RuntimeError): bootstrap.resume_identity_binding()
                self.assertFalse(any(call[0] in ('patch', 'scale') for call in self.calls))
                migration.hydrate_binding(path, state, self.payload, self.target)
                self.assertIn('accessActivation', json.loads(path.read_text()))
                self.assertTrue(bootstrap.resume_identity_binding())

    def test_rehydration_cannot_replace_a_captured_administrator(self):
        administrator, receipt, objects = access_authority(self.payload['repository']); self.objects.update(objects)
        captured = access_evidence(self.payload['repository'], self.target, administrator)
        with patch.object(access_activation, 'receipt', return_value=receipt):
            self.checkpoint['accessActivation'] = access_activation.guard(captured, self.target, self.read)
        proposed = copy.deepcopy(self.payload)
        proposed['argo']['accessActivation'] = access_evidence(self.payload['repository'], self.target)
        with tempfile.TemporaryDirectory() as directory, self.contexts(Path(directory)), self.assertRaisesRegex(RuntimeError, 'captured authority'):
            migration.hydrate_binding(Path(directory) / 'identity-values-binding.json', self.checkpoint, proposed, self.target)

    def test_original_source_legacy_access_checkpoint_can_resume_unchanged_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); state = self.pending(base); state.pop('accessActivation')
            self.objects['application.argoproj.io', migration.ROOT_APP]['spec']['source'] = copy.deepcopy(state['originalSource'])
            (base / 'identity-values-binding.json').write_text(json.dumps(state))
            with self.contexts(base): self.assertTrue(bootstrap.resume_identity_binding())
            self.assertEqual(self.calls, [('scale', 'statefulset/argocd-application-controller', '-n', 'argocd', '--replicas=1')])

    def data_owner(self, base, *, native=False):
        import yaml
        from playbooks.data.files.initial_bootstrap import application
        root = Path(__file__).resolve().parents[4]
        current = yaml.safe_load((root / 'platform/data/configuration/values.yaml').read_text())
        current['identity'] = {'enabled': True, 'database': 'keycloak', 'role': 'keycloak'}
        proposed = copy.deepcopy(current)
        proposed['serviceRequests'] = [{'service': 'synthetic', 'namespace': 'cloudlab-app-synthetic',
            'database': {'name': 'synthetic', 'applicationRole': 'synthetic_app', 'migrationRole': 'synthetic_migration',
                         'applicationItem': 'cnpg-synthetic-production', 'migrationItem': 'cnpg-synthetic-migration'}}]
        evidence = {'required': native, 'enabled': True, 'repository': self.payload['repository'],
            'revision': 'c' * 40, 'seaweedfsRevision': 'd' * 40, 'private_repository': self.target['valuesRepository'],
            'private_revision': self.target['valuesRevision'], 'settings': proposed}
        self.payload['argo']['dataActivation'] = evidence
        applications = {}
        for component in ('data-configuration', 'seaweedfs'):
            obj = application(self.payload, component, current if component == 'data-configuration' else None)
            name = obj['metadata']['name']; obj['metadata']['uid'] = name + '-uid'
            if native:
                obj['metadata']['labels']['cloudlab.io/owner'] = 'data-platform'
                obj['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/Application:argocd/' + name}
                if component == 'data-configuration':
                    obj['spec']['source'] = None
                    obj['spec']['sources'] = [{'repoURL': self.payload['repository'], 'targetRevision': 'c' * 40,
                        'path': 'platform/data/configuration', 'helm': {'releaseName': name,
                        'valueFiles': ['$values/platform/certificates.yaml', '$values/platform/data.yaml', '$values/services/catalog.json'],
                        'valuesObject': {'sharedInputs': True, 'maintenance': False, 'hibernated': False}}},
                        {'repoURL': self.target['valuesRepository'], 'targetRevision': 'e' * 40, 'ref': 'values'}]
                else:
                    obj['spec']['source']['targetRevision'] = 'd' * 40
                    obj['spec']['source']['helm']['valuesObject'] = {'seaweedfs': {c: {'replicas': 1} for c in ('master', 'volume', 'filer', 's3')}}
            self.objects['application.argoproj.io', name] = obj
            applications[name] = obj['metadata']['uid']
        state = {'applications': applications}
        if native:
            state['settings_uid'] = 'settings-uid'
        (base / 'ownership.json').write_text(json.dumps(state))
        return current

    def test_data_no_adoption_fails_before_source_or_sql_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); self.data_owner(base)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            with self.contexts(base), patch.object(data_control, 'get', side_effect=lambda k, n, ns=None: self.read(k, n)), \
                    patch.object(data_control, 'sql', return_value='1') as sql, patch.object(data_control, 'grants') as grant:
                with self.assertRaisesRegex(RuntimeError, 'cannot adopt'): migration.bind_identity(self.payload, self.target)
                self.assertEqual(len(self.calls), 0)
                self.assertTrue(all(call.args[0].startswith('SELECT ') for call in sql.call_args_list))
                grant.assert_not_called()

    def test_data_guard_captures_before_patch_and_takes_exclusion_once(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); self.data_owner(base)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            def write(*args, **kwargs):
                if args[:2] == ('patch', 'application.argoproj.io'):
                    saved = json.loads((base / 'identity-values-binding.json').read_text())['dataActivation']['authority']
                    self.assertEqual(saved['absent'], ['database/synthetic'])
                return self.write(*args, **kwargs)
            with self.contexts(base), patch.object(data_control, 'get', side_effect=lambda k, n, ns=None: self.read(k, n)), \
                    patch.object(data_control, 'sql', return_value='0'), \
                    patch.object(data_control, 'locked', wraps=data_control.locked) as locked, \
                    patch.object(migration, 'kube', side_effect=write):
                self.assertTrue(migration.bind_identity(self.payload, self.target)['changed'])
                self.assertEqual(locked.call_count, 1)
                self.assertFalse(migration.bind_identity(self.payload, self.target)['changed'])
                self.assertEqual(locked.call_count, 2)

    def test_hydration_and_bootstrap_resume_reuse_durable_native_creation_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); current = self.data_owner(base, native=True)
            snapshot = unittest.mock.Mock(); snapshot.settings.return_value = current
            with self.contexts(base), patch.object(data_control, 'operation', return_value=snapshot), \
                    patch.object(data_control, 'sql', return_value='0'):
                captured = data_activation.guard(self.payload['argo']['dataActivation'], self.target, self.read)
            self.checkpoint['dataActivation'] = captured
            state = self.pending(base)
            self.objects['application.argoproj.io', data_activation.APP]['spec']['sources'][1]['targetRevision'] = self.target['valuesRevision']
            cm = {'metadata': {'uid': 'settings-uid', 'annotations': {'argocd.argoproj.io/tracking-id':
                data_activation.APP + ':/ConfigMap:cloudlab-data/cloudlab-data-settings'}},
                'data': {'settings': json.dumps(self.payload['argo']['dataActivation']['settings'])}}
            import subprocess
            import yaml
            rendered = subprocess.run(['helm', 'template', 'data', str(Path(__file__).resolve().parents[4] / 'platform/data/configuration'),
                '-n', 'cloudlab-data', '-f', '-'], input=json.dumps(self.payload['argo']['dataActivation']['settings']),
                text=True, capture_output=True, check=True, timeout=30)
            database = next(obj for obj in yaml.safe_load_all(rendered.stdout) if obj and obj['kind'] == 'Database' and obj['metadata']['name'] == 'synthetic')
            database['metadata'].update(uid='database-uid', namespace='cloudlab-data', generation=1)
            database['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = data_activation.APP + ':postgresql.cnpg.io/Database:cloudlab-data/synthetic'
            database['status'] = {'applied': True, 'observedGeneration': 1}
            namespaces = []
            def get(kind, name, namespace=None):
                namespaces.append((kind, name, namespace))
                if kind == 'configmap': return cm
                if kind == 'database.postgresql.cnpg.io': return database
                return self.read(kind, name)
            with self.contexts(base), patch.object(data_control, 'get', side_effect=get), \
                    patch.object(data_control, 'sql', return_value='1'), \
                    patch.object(data_control, 'operation', side_effect=AssertionError('Must reuse durable authority')):
                migration.hydrate_binding(base / 'identity-values-binding.json', state, self.payload, self.target)
                self.assertTrue(bootstrap.resume_identity_binding())
                self.assertIn(('database.postgresql.cnpg.io', 'synthetic', 'cloudlab-data'), namespaces)
                self.assertEqual(state['dataActivation']['authority'], captured['authority'])
                for change in ('foreign-cluster', 'unapplied', 'deleting'):
                    invalid = copy.deepcopy(database)
                    if change == 'foreign-cluster': database['spec']['cluster']['name'] = 'foreign'
                    if change == 'unapplied': database['status']['applied'] = False
                    if change == 'deleting': database['metadata']['deletionTimestamp'] = 'synthetic'
                    with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'cannot adopt'):
                        migration.hydrate_binding(base / 'identity-values-binding.json', state, self.payload, self.target)
                    database.clear(); database.update(invalid)


    def test_hydration_cannot_reconstruct_lost_data_evidence_after_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); self.data_owner(base)
            state = self.pending(base); state.pop('dataActivation')
            with self.contexts(base), patch.object(data_control, 'sql') as sql:
                with self.assertRaisesRegex(RuntimeError, 'lost its durable'): migration.hydrate_binding(
                    base / 'identity-values-binding.json', state, self.payload, self.target)
                sql.assert_not_called()

    def armed_first_binding(self, base):
        current = self.data_owner(base)
        evidence = self.payload['argo']['dataActivation']
        evidence.update(required=True, settings=current)
        owner = json.loads((base / 'ownership.json').read_text())
        owner['publicSource'] = {'repository': self.payload['repository'], 'branch': 'main'}
        self.objects['application.argoproj.io', migration.ROOT_APP]['spec']['destination'] = {
            'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
        (base / 'ownership.json').write_text(json.dumps(owner))
        for name in (data_native.APP, data_native.SEAWEED):
            obj = self.objects['application.argoproj.io', name]
            obj['status'] = {'sync': {'status': 'Synced'}, 'health': {'status': 'Healthy'}}
            project = {'metadata': {'uid': name + '-project', 'annotations': {'argocd.argoproj.io/tracking-id':
                data_native.TRACKING + 'AppProject:argocd/' + name}},
                'spec': data_native.project_spec(name, self.payload, self.target)}
            if name == data_native.APP:
                project['spec']['sourceRepos'] = [self.payload['repository']]
                project['spec']['namespaceResourceWhitelist'].remove({'group': '', 'kind': 'ConfigMap'})
            self.objects['appproject.argoproj.io', name] = project
        captured = data_activation.guard(evidence, self.target, self.read,
            self.read('application.argoproj.io', migration.ROOT_APP))
        self.checkpoint['dataActivation'] = captured
        self.checkpoint['publicRevision'] = self.payload['revision']
        self.assertEqual(data_handoff.state()['handoff']['phase'], 'armed')
        return self.pending(base)

    def test_bootstrap_resume_allows_only_armed_partial_native_rollout_without_registering(self):
        for both in (False, True):
            self.setUp()
            with self.subTest(both_native=both), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                with self.contexts(base), patch.object(data_native, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                        patch.object(data_control, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                        patch.object(data_handoff, 'resources', return_value={'preserved': {'uid': 'original'}}), \
                        patch.object(data_control, 'sql') as sql, patch.object(data_control, 'grants') as grants:
                    state = self.armed_first_binding(base)
                    journal = data_handoff.state()['handoff']
                    public = {'repository': self.payload['repository'], 'data': {'configuration': journal['pins']}}
                    for name in (data_native.APP, data_native.SEAWEED) if both else (data_native.APP,):
                        obj = self.objects['application.argoproj.io', name]
                        obj['spec'].update(data_native.application_sources(name, public, self.target,
                            {'maintenance': False, 'hibernated': False}, {c: 1 for c in data_native.COMPONENTS}))
                        if name == data_native.APP:
                            obj['spec'].pop('source')  # API omission is equivalent to explicit null.
                        obj['metadata']['labels']['cloudlab.io/owner'] = 'data-platform'
                        obj['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
                            data_native.TRACKING + 'Application:argocd/' + name}
                    self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'] = 1
                    self.assertTrue(bootstrap.resume_identity_binding())
                    self.assertEqual(self.calls[-1][-1], '--replicas=1')
                    self.assertNotIn('settings_uid', data_handoff.state())
                    sql.assert_not_called(); grants.assert_not_called()
                    obj = self.objects['application.argoproj.io', data_native.APP]
                    obj['spec']['sources'][0]['path'] = 'foreign'
                    with self.assertRaisesRegex(RuntimeError, 'armed rollout'):
                        bootstrap.resume_identity_binding()

    def test_paused_armed_resume_rejects_foreign_readers_projects_and_root_without_writes(self):
        cases = ('absent', 'not-ready', 'valid', 'root-running', 'root-queued', 'foreign-eso', 'eso-finalizer',
                 'secret-finalizer', 'owner', 'url', 'project', 'fields', 'competitor', 'broadened-project',
                 'foreign-project', 'root-tracking', 'root-scope', 'queued-empty', 'running-empty',
                 'queued-manual', 'running-manual', 'queued-prune', 'running-prune', 'queued-selective',
                 'running-selective', 'queued-foreign', 'running-foreign', 'both-foreign', 'running-source')
        for case in cases:
            self.setUp()
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                with self.contexts(base), patch.object(data_native, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                        patch.object(data_control, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                        patch.object(data_handoff, 'resources', return_value={'preserved': {'uid': 'original'}}), \
                        patch.object(data_native, 'published_source', side_effect=lambda *a, **k: ({'data': {'enabled': True,
                            'configuration': dict(self.payload['argo']['dataActivation'], enabled=True)}}, self.payload['revision'])), \
                        patch.object(migration, 'record', wraps=migration.record) as record, \
                        patch.object(data_control, 'sql') as sql, patch.object(data_control, 's3') as s3:
                    self.armed_first_binding(base)
                    name = data_native.APP + '-source'
                    external = {'metadata': {'uid': 'reader', 'finalizers': [data_native.ESO_FINALIZER], 'annotations': {'argocd.argoproj.io/tracking-id':
                        'cloudlab-public-root:external-secrets.io/ExternalSecret:argocd/' + name}},
                        'spec': data_native.reader_spec(self.target['valuesRepository'], name, data_native.APP)}
                    secret = {'metadata': {'uid': 'credential', 'labels': {'argocd.argoproj.io/secret-type': 'repository'},
                        'ownerReferences': [{'uid': 'reader', 'name': name, 'kind': 'ExternalSecret',
                            'apiVersion': 'external-secrets.io/v1', 'controller': True}]},
                        'data': {key: base64.b64encode(value.encode()).decode() for key, value in {
                            'type': 'git', 'url': self.target['valuesRepository'], 'project': data_native.APP,
                            'githubAppID': '1', 'githubAppInstallationID': '2', 'githubAppPrivateKey': 'synthetic'}.items()}}
                    if case != 'absent':
                        self.objects['externalsecret.external-secrets.io', name] = external
                    if case not in ('absent', 'not-ready'):
                        self.objects['secret', name] = secret
                        self.objects['secrets', None] = {'items': [secret]}
                    if case == 'foreign-eso': external['spec']['secretStoreRef']['name'] = 'foreign'
                    if case == 'eso-finalizer': external['metadata']['finalizers'].append('foreign')
                    if case == 'secret-finalizer': secret['metadata']['finalizers'] = [data_native.ESO_FINALIZER]
                    if case == 'owner': secret['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                    if case in ('url', 'project'): secret['data'][case] = base64.b64encode(b'foreign').decode()
                    if case == 'fields': secret['data']['password'] = base64.b64encode(b'foreign').decode()
                    if case == 'competitor':
                        duplicate = copy.deepcopy(secret); duplicate['metadata']['uid'] = 'other'
                        self.objects['secrets', None]['items'].append(duplicate)
                    project = self.objects['appproject.argoproj.io', data_native.APP]
                    if case == 'broadened-project': project['spec']['sourceRepos'].append('*')
                    if case == 'foreign-project': project['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
                    root = self.objects['application.argoproj.io', migration.ROOT_APP]
                    if case == 'root-tracking': root['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': 'foreign'}
                    if case == 'root-scope': root['spec']['destination']['namespace'] = 'foreign'
                    operation = {'initiatedBy': {'automated': True}, 'sync': {'revision': self.payload['revision'], 'prune': False}}
                    if case.startswith('queued-') or case == 'root-queued':
                        root['operation'] = copy.deepcopy(operation)
                    if case.startswith('running-') or case in ('root-running', 'both-foreign'):
                        root['status'] = {'operationState': {'phase': 'Running', 'operation': copy.deepcopy(operation),
                            'syncResult': {'revision': self.payload['revision'], 'source': copy.deepcopy(root['spec']['source'])}}}
                    if case == 'both-foreign':
                        root['operation'] = copy.deepcopy(operation)
                        root['status']['operationState']['operation']['sync']['revision'] = 'f' * 40
                    if case.startswith(('queued-', 'running-')):
                        selected = root['operation'] if case.startswith('queued-') else root['status']['operationState']['operation']
                        if case.endswith('-empty'): selected.clear()
                        if case.endswith('-manual'): selected['initiatedBy'] = {'username': 'foreign'}
                        if case.endswith('-prune'): selected['sync']['prune'] = True
                        if case.endswith('-selective'): selected['sync']['resources'] = [{'kind': 'Secret', 'name': 'foreign'}]
                        if case.endswith('-foreign'): selected['sync']['revision'] = 'f' * 40
                        if case == 'running-source': root['status']['operationState']['syncResult']['source']['path'] = 'foreign'
                    self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'] = 0
                    self.calls.clear()
                    if case in ('absent', 'not-ready', 'valid', 'root-running', 'root-queued'):
                        self.assertTrue(bootstrap.resume_identity_binding())
                    else:
                        with self.assertRaises(RuntimeError): bootstrap.resume_identity_binding()
                        self.assertEqual(self.calls, [])
                        record.assert_not_called()
                        self.assertEqual(self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'], 0)
                    self.assertNotIn('settings_uid', data_handoff.state())
                    sql.assert_not_called(); s3.assert_not_called()

    def test_capture_substantiates_public_revision_and_records_it_before_pause(self):
        capture = migration.capture_public_revision
        with patch.object(data_native, 'published_source', return_value=({}, self.payload['revision'])):
            self.assertEqual(capture(self.payload), self.payload['revision'])
            with self.assertRaisesRegex(RuntimeError, 'independently protected'):
                capture(dict(self.payload, revision='f' * 40))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            def pause():
                checkpoint = json.loads((base / 'identity-values-binding.json').read_text())
                self.assertEqual(checkpoint['publicRevision'], self.payload['revision'])
                self.pause()
            with self.contexts(base), patch.object(migration, 'pause', side_effect=pause):
                self.assertTrue(migration.bind_identity(self.payload, self.target)['changed'])

    def test_captured_original_running_source_survives_main_advance_only_with_exact_authority(self):
        for original in (False, True):
            for case in ('accepted', 'manual', 'prune', 'foreign-revision', 'foreign-source', 'missing-evidence', 'missing-quiet', 'scope-drift', 'source-failure'):
                self.setUp()
                with self.subTest(original_spec=original, case=case), tempfile.TemporaryDirectory() as directory:
                    base = Path(directory)
                    with self.contexts(base), patch.object(data_native, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                            patch.object(data_control, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                            patch.object(data_handoff, 'resources', return_value={'preserved': {'uid': 'original'}}), \
                            patch.object(migration, 'record', wraps=migration.record) as record, patch.object(data_control, 'sql') as sql:
                        state = self.armed_first_binding(base)
                        root = self.objects['application.argoproj.io', migration.ROOT_APP]
                        if original: root['spec']['source'] = copy.deepcopy(state['originalSource'])
                        operation = {'initiatedBy': {'automated': True}, 'sync': {'revision': state['publicRevision'], 'prune': False}}
                        root['status'] = {'operationState': {'phase': 'Running', 'operation': operation,
                            'syncResult': {'revision': state['publicRevision'], 'source': copy.deepcopy(state['originalSource'])}}}
                        if case == 'manual': operation['initiatedBy'] = {'username': 'foreign'}
                        if case == 'prune': operation['sync']['prune'] = True
                        if case == 'foreign-revision': operation['sync']['revision'] = 'f' * 40
                        if case == 'foreign-source': root['status']['operationState']['syncResult']['source']['path'] = 'foreign'
                        if case in ('missing-evidence', 'missing-quiet'):
                            state.pop('publicRevision'); (base / 'identity-values-binding.json').write_text(json.dumps(state))
                        if case == 'missing-quiet': root['status'] = {}
                        public = {'repository': self.payload['repository'], 'data': {'enabled': True,
                            'configuration': dict(data_handoff.state()['handoff']['pins'], enabled=True)}}
                        if case == 'scope-drift':
                            root['status'] = {}  # Quiet Root still requires current protected scope.
                            public['data']['configuration']['revision'] = 'f' * 40
                        self.objects['statefulset', migration.CONTROLLER]['spec']['replicas'] = 0
                        self.calls.clear(); record.reset_mock()
                        with patch.object(data_native, 'published_source', side_effect=RuntimeError('source unavailable')
                                if case == 'source-failure' else None, return_value=(public, 'e' * 40)):
                            if case == 'accepted':
                                self.assertTrue(bootstrap.resume_identity_binding())
                                self.assertEqual(self.calls[-1][-1], '--replicas=1')
                            else:
                                with self.assertRaises(RuntimeError): bootstrap.resume_identity_binding()
                                self.assertEqual(self.calls, []); record.assert_not_called()
                        sql.assert_not_called(); self.assertNotIn('settings_uid', data_handoff.state())

    def test_missing_public_checkpoint_hydrates_only_authenticated_matching_current_authority(self):
        capture = migration.capture_public_revision
        for case in ('matching', 'unprovable-history', 'invalid-record'):
            self.setUp()
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                with self.contexts(base), patch.object(data_native, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                        patch.object(data_control, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                        patch.object(data_handoff, 'resources', return_value={'preserved': {'uid': 'original'}}):
                    state = self.armed_first_binding(base)
                    state.pop('publicRevision')
                    current = self.payload['revision'] if case == 'matching' else 'e' * 40
                    payload = dict(self.payload, revision=current)
                    if case == 'invalid-record': state['publicRevision'] = 'mutable-main'
                    root = self.objects['application.argoproj.io', migration.ROOT_APP]
                    root['status'] = {'operationState': {'phase': 'Running',
                        'operation': {'initiatedBy': {'automated': True}, 'sync': {'revision': self.payload['revision'], 'prune': False}},
                        'syncResult': {'revision': self.payload['revision'], 'source': copy.deepcopy(state['originalSource'])}}}
                    path = base / 'identity-values-binding.json'; path.write_text(json.dumps(state))
                    before = path.read_bytes()
                    public = {'repository': self.payload['repository'], 'data': {'enabled': True,
                        'configuration': dict(data_handoff.state()['handoff']['pins'], enabled=True)}}
                    with patch.object(migration, 'capture_public_revision', side_effect=capture), \
                            patch.object(data_native, 'published_source', return_value=(public, current)):
                        if case == 'matching':
                            migration.hydrate_binding(path, state, payload, self.target)
                            self.assertEqual(json.loads(path.read_text())['publicRevision'], current)
                        else:
                            with self.assertRaises(RuntimeError): migration.hydrate_binding(path, state, payload, self.target)
                            self.assertEqual(path.read_bytes(), before)

    def test_armed_target_fences_noop_hydrate_and_original_source_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with self.contexts(base), patch.object(data_native, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                    patch.object(data_control, 'get', side_effect=lambda kind, name=None, namespace=None: self.read(kind, name)), \
                    patch.object(data_handoff, 'resources', return_value={'preserved': {'uid': 'original'}}):
                state = self.armed_first_binding(base)
                foreign = dict(self.target, valuesRevision='f' * 40)
                self.objects['application.argoproj.io', migration.ROOT_APP]['spec']['source'] = copy.deepcopy(state['originalSource'])
                for action in (lambda: migration.bind_identity_locked(self.payload, foreign),
                               lambda: migration.hydrate_binding(base / 'identity-values-binding.json', state, self.payload, foreign),
                               lambda: migration.safe_identity_resume(dict(state, target=foreign), self.read)):
                    with self.assertRaisesRegex(RuntimeError, 'different private binding'):
                        action()
                state['target'] = foreign
                (base / 'identity-values-binding.json').write_text(json.dumps(state))
                with self.assertRaisesRegex(RuntimeError, 'different private binding'):
                    bootstrap.resume_identity_binding()

    def test_binding_cannot_downgrade_registered_native_data_before_any_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); self.data_owner(base)
            state = json.loads((base / 'ownership.json').read_text())
            state['settings_uid'] = 'registered-native-settings'
            (base / 'ownership.json').write_text(json.dumps(state))
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            with self.contexts(base), patch.object(data_control, 'get', side_effect=lambda k, n, ns=None: self.read(k, n)), \
                    patch.object(data_control, 'sql') as sql:
                with self.assertRaisesRegex(RuntimeError, 'cannot downgrade'):
                    migration.bind_identity(self.payload, self.target)
                self.assertEqual(self.calls, [])
                sql.assert_not_called()
