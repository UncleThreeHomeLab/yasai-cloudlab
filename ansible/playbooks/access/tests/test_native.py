"""Configured access never falls back to an imperative administrator snapshot."""
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from playbooks.access.files import initial_bootstrap, native
from playbooks.istio.files import kube
from fixtures import native_access


class NativeAccessTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.payload, self.state, self.objects, self.binding_receipt, self.client = native_access()

    def cluster(self):
        stack = ExitStack()
        read = lambda kind, name=None, namespace=None: copy.deepcopy(self.objects.get((kind, name, namespace)))
        for module in (native, kube, initial_bootstrap): stack.enter_context(patch.object(module, 'get', side_effect=read))
        stack.enter_context(patch.object(native.authority, 'receipt', side_effect=lambda: copy.deepcopy(self.state)))
        file = Mock(); file.parents = []
        file.exists.return_value = 'argo' in self.objects['application.argoproj.io', 'cloudlab-public-root', 'argocd']['spec']['source']['helm']['valuesObject'].get('identity', {})
        file.is_symlink.return_value = False
        file.lstat.return_value = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600)
        file.read_text.side_effect = lambda: json.dumps(self.binding_receipt)
        stack.enter_context(patch.object(native, 'BINDING_RECEIPT', file))
        secrets = lambda *a, **k: json.dumps({'items': [o for (kind, _, ns), o in self.objects.items() if kind == 'secret' and ns == 'argocd']})
        stack.enter_context(patch.object(native, 'kube', side_effect=secrets))
        return stack

    def test_native_sources_distinguish_public_chart_active_main_and_approved_private_commit(self):
        self.assertNotEqual(self.contract['public_revision'], self.contract['configuration_revision'])
        self.assertEqual(self.client.request.call_args.args[1].rsplit('=', 1)[1], 'b' * 40)
        with self.cluster(): result = native.guard(self.contract)
        self.assertTrue(result['native_owner_verified'])
        self.assertEqual(set(result['credentials']), {'tailscale/operator-oauth', 'cloudlab-connectors/cloudflared-runtime'})
        self.assertTrue(all(set(v) == {'uid', 'content'} for v in result['credentials'].values()))
        with self.cluster(): self.assertTrue(native.prerequisite(self.payload)['native_owner_verified'])

    def test_missing_foreign_and_stale_sources_or_operations_never_pass(self):
        baseline = copy.deepcopy(self.objects)
        for change in ('missing', 'uid', 'spec', 'status', 'pending', 'running', 'terminating', 'skip', 'root-repo', 'unapproved'):
            self.objects = copy.deepcopy(baseline)
            app = self.objects['application.argoproj.io', native.APP, 'argocd']
            root = self.objects['application.argoproj.io', 'cloudlab-public-root', 'argocd']
            if change == 'missing': del self.objects['application.argoproj.io', native.APP, 'argocd']
            if change == 'uid': app['metadata']['uid'] = 'replacement'
            if change == 'spec': app['spec']['ignoreDifferences'] = [{'jsonPointers': ['/spec']}]
            if change == 'status': app['status']['sync']['revisions'][1] = 'e' * 40
            if change == 'pending': app['operation'] = {}
            if change in ('running', 'terminating'): app['status']['operationState'] = {'phase': change.title()}
            if change == 'skip': app['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'] = 'true'
            if change == 'root-repo': root['spec']['source']['repoURL'] = 'https://github.com/example/foreign.git'
            if change == 'unapproved': root['spec']['source']['helm']['valuesObject']['identity']['argo']['valuesRevision'] = 'e' * 40
            with self.subTest(change=change), self.cluster(), self.assertRaises(RuntimeError): native.guard(self.contract)

    def test_template_slots_cannot_select_foreign_repository_or_wrong_public_pin(self):
        for change in ('pin', 'repository', 'sha'):
            payload = copy.deepcopy(self.payload)
            template = payload['access_observation']
            if change == 'pin': template['revision'] = 'e' * 40
            if change == 'repository': template['application']['spec']['sources'][1]['repoURL'] = 'https://github.com/example/foreign.git'
            if change == 'sha': template['application']['spec']['sources'][1]['targetRevision'] = 'b' * 40
            with self.subTest(change=change), self.cluster(), self.assertRaises(RuntimeError): native.prerequisite(payload)

    def test_reader_ownership_scope_and_runtime_credentials_remain_guarded(self):
        with self.cluster(): baseline = native.guard(self.contract)['credentials']
        objects = copy.deepcopy(self.objects)
        for change in ('runtime-uid', 'runtime-data', 'reader-spec', 'reader-owner', 'duplicate', 'administrator', 'proxy-generation', 'node-port'):
            self.objects = copy.deepcopy(objects)
            if change == 'runtime-uid': self.objects['secret', 'operator-oauth', 'tailscale']['metadata']['uid'] = 'replacement'
            if change == 'runtime-data': self.objects['secret', 'operator-oauth', 'tailscale']['data']['token'] = 'Y2hhbmdlZA=='
            if change == 'reader-spec': self.objects['externalsecret.external-secrets.io', native.APP + '-source', 'argocd']['spec']['target']['deletionPolicy'] = 'Delete'
            if change == 'reader-owner': self.objects['secret', native.APP + '-source', 'argocd']['metadata']['ownerReferences'][0]['uid'] = 'foreign'
            if change == 'duplicate': self.objects['secret', 'duplicate', 'argocd'] = copy.deepcopy(self.objects['secret', native.APP + '-source', 'argocd'])
            if change == 'administrator': self.objects['clusterrolebinding.rbac.authorization.k8s.io', native.authority.BINDING, 'argocd']['subjects'][0]['name'] = 'foreign@example.invalid'
            if change == 'proxy-generation': self.objects['proxygroup', 'cloudlab-api', None]['metadata']['generation'] = 2
            if change == 'node-port': self.objects['service', 'cloudlab-tailnet', 'cloudlab-gateway-private']['spec']['ports'][0]['nodePort'] = 30443
            with self.subTest(change=change), self.cluster(), self.assertRaises(RuntimeError): native.guard(self.contract, expected_credentials=baseline)

    def test_legacy_precheck_requires_reader_absence_and_prebinding_never_adopts_native(self):
        native_objects = copy.deepcopy(self.objects)
        self.contract, self.payload, self.state, self.objects, self.binding_receipt, _ = native_access('legacy')
        with self.cluster(): self.assertFalse(native.guard(self.contract, stage='legacy')['native_owner_verified'])
        for kind in ('secret', 'externalsecret.external-secrets.io'):
            key = (kind, native.APP + '-source', 'argocd'); self.objects[key] = native_objects[key]
            with self.cluster(), self.assertRaises(RuntimeError): native.guard(self.contract, stage='legacy')
            del self.objects[key]
        with self.cluster(), self.assertRaisesRegex(RuntimeError, 'fallback refused'): native.observe(self.payload)
        self.objects = native_objects
        self.objects['application.argoproj.io', 'cloudlab-public-root', 'argocd']['spec']['source']['helm']['valuesObject'] = {}
        with self.cluster(), self.assertRaises(RuntimeError): native.observe(self.payload)

    def test_configured_seed_observes_without_bootstrap_administrator_or_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'ownership.json').write_text(json.dumps(self.state))
            (Path(directory) / 'ownership.json').chmod(0o600)
            with self.cluster(), patch.object(initial_bootstrap, 'BASE', Path(directory)), \
                    patch.object(initial_bootstrap, 'application', side_effect=AssertionError('snapshot builder')), \
                    patch.object(initial_bootstrap, 'kube') as write, patch.object(initial_bootstrap, 'record') as record:
                self.assertFalse(initial_bootstrap.run(self.payload | {'native': self.contract})['changed'])
                write.assert_not_called(); record.assert_not_called()
                (Path(directory) / 'ownership.json').chmod(0o644)
                with self.assertRaisesRegex(RuntimeError, 'receipt ownership is unsafe'):
                    initial_bootstrap.run(self.payload | {'native': self.contract})
                write.assert_not_called(); record.assert_not_called()

    def test_partial_seed_resumes_but_missing_receipt_never_adopts_existing_app(self):
        self.contract, self.payload, self.state, self.objects, self.binding_receipt, _ = native_access('legacy', bound=False)
        for name in ('proxyclasses', 'proxygroups'):
            self.objects['customresourcedefinition', name + '.tailscale.com', None] = {'metadata': {'generation': 1}, 'status': {'conditions': [{'type': 'Established', 'status': 'True'}]}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ownership.json'
            preparing = copy.deepcopy(self.state); preparing['phase'] = 'preparing'; path.write_text(json.dumps(preparing)); path.chmod(0o600)
            with self.cluster(), patch.object(initial_bootstrap, 'BASE', Path(directory)), \
                    patch.object(initial_bootstrap, 'wait', side_effect=lambda p, *a, **k: p()), patch.object(initial_bootstrap, 'kube') as write:
                self.assertTrue(initial_bootstrap.run(self.payload | {'administrator': 'admin@example.invalid'})['changed'])
                self.assertFalse(initial_bootstrap.run(self.payload)['changed'])
                write.assert_not_called()
                path.unlink()
                with self.assertRaisesRegex(RuntimeError, 'without its ownership checkpoint'):
                    initial_bootstrap.run(self.payload | {'administrator': 'admin@example.invalid'})
                write.assert_not_called()

    def test_keycloak_actual_prerequisites_accept_pinned_access_and_keep_backup_gates(self):
        from playbooks.keycloak.files import ownership
        payload = self.payload | {'values': {'database': 'keycloak', 'databaseRole': 'keycloak'}}
        for name in ('cloudlab-keycloak-operator', 'cloudlab-data-configuration', 'cloudlab-argocd'):
            self.objects['application.argoproj.io', name, 'argocd'] = {'status': {'sync': {'status': 'Synced', 'revision': 'd' * 40}, 'health': {'status': 'Healthy'}}}
        self.objects['application.argoproj.io', 'cloudlab-data-configuration', 'argocd']['spec'] = {'source': {'helm': {'valuesObject': {'identity': {'enabled': True, 'database': 'keycloak', 'role': 'keycloak'}}}}}
        self.objects['database.postgresql.cnpg.io', 'keycloak', 'cloudlab-data'] = {'metadata': {'generation': 1}, 'status': {'applied': True, 'observedGeneration': 1}}
        def evidence(path):
            return json.dumps({'retention_complete': True, 'restore': {'physical_restore': True}} if 'longhorn' in str(path) else {'verified_at': 'verified', 'external_binding': 'approved'})
        read = lambda kind, name=None, namespace=None: copy.deepcopy(self.objects.get((kind, name, namespace)))
        with self.cluster(), patch.object(ownership, 'get', side_effect=read), patch.object(Path, 'read_text', evidence):
            ownership.prerequisites(payload)
            with patch.object(Path, 'read_text', return_value='{}'), self.assertRaisesRegex(RuntimeError, 'physical recovery'):
                ownership.prerequisites(payload)
            self.objects['application.argoproj.io', 'cloudlab-argocd', 'argocd']['status']['sync']['revision'] = 'e' * 40
            with self.assertRaisesRegex(RuntimeError, 'prerequisite Application'): ownership.prerequisites(payload)

    def test_standalone_observer_imports_without_seed_workstation_or_optional_packages(self):
        import os
        import subprocess
        import sys
        root = Path(__file__).resolve().parents[4]
        with tempfile.TemporaryDirectory() as directory:
            for owner, name in [('access', 'native.py'), ('argocd', 'access_activation.py'), ('istio', 'kube.py'), ('argocd', 'source_revision.py')]:
                (Path(directory) / name).write_bytes((root / 'ansible/playbooks' / owner / 'files' / name).read_bytes())
            result = subprocess.run([sys.executable, '-S', '-c', 'import native,sys; assert callable(native.prerequisite); assert "initial_bootstrap" not in sys.modules'],
                cwd=directory, env=dict(os.environ, PYTHONPATH=directory), capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_authenticated_approved_input_failure_is_not_a_legacy_fallback(self):
        from playbooks.access.files import inputs
        import yaml
        root = Path(__file__).resolve().parents[4]
        public = yaml.safe_load((root / 'gitops/roots/public/values.yaml').read_text())
        public['repository'] = self.payload['repository']
        values = {'PRIVATE_CONFIG_REPOSITORY': self.payload['private_repository']}
        target = self.binding_receipt['target']
        for response in (None, {'type': 'symlink'}):
            client = Mock(request=Mock(return_value=response))
            with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=lambda v, read: read(client, 'c' * 40)), self.assertRaisesRegex(ValueError, 'unavailable or invalid'):
                inputs.prepare(values, public, target, 'd' * 40)
        with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=RuntimeError('private diagnostic')), self.assertRaisesRegex(ValueError, 'unavailable or invalid'):
            inputs.prepare(values, public, target, 'd' * 40)

    def actual_recovery(self, source_state='patched', change=None):
        import importlib
        runtime = importlib.import_module('playbooks.keycloak.files.argo')
        from playbooks.keycloak.files import ownership
        from playbooks.argocd.files import bootstrap, source_transition, service_activation, private_activation
        from playbooks.keycloak.files.integrations import argo
        self.contract, self.payload, self.state, self.objects, _, _ = native_access('legacy' if source_state == 'original' else 'native')
        root = self.objects['application.argoproj.io', 'cloudlab-public-root', 'argocd']
        original = copy.deepcopy(root['spec']['source']); original['helm']['valuesObject'] = {}
        patched = copy.deepcopy(root['spec']['source'])
        if source_state == 'original': root['spec']['source'] = copy.deepcopy(original)
        else:
            child = self.objects['application.argoproj.io', native.APP, 'argocd']
            child['status'].update(sync={'status': 'OutOfSync'}, health={'status': 'Progressing'})
        project = self.objects['appproject.argoproj.io', 'cloudlab-root', 'argocd']
        project['metadata']['resourceVersion'] = '1'
        project['spec'] = {'sourceRepos': [self.payload['repository']],
            'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
            'clusterResourceWhitelist': [{'group': '', 'kind': 'Namespace'}],
            'namespaceResourceWhitelist': [{'group': 'argoproj.io', 'kind': k} for k in ('Application', 'AppProject')]}
        controller = self.objects['statefulset', 'argocd-application-controller', 'argocd']; controller['spec'] = {'replicas': 0}
        root['metadata']['resourceVersion'] = '1'
        target = {'valuesRepository': self.payload['private_repository'], 'valuesRevision': 'b' * 40}
        self.binding_receipt = {'phase': 'paused', 'target': target, 'root_uid': 'root', 'project_uid': 'root-project',
            'controller_uid': 'controller', 'originalSource': original, 'patchedSource': patched}
        contract = argo('https://login.example.invalid/realms/platform', 'https://console.example.invalid', ['https://cd.internal.example.invalid'])
        self.payload['values'] = {'loginHost': 'login.example.invalid', 'database': 'keycloak', 'databaseRole': 'keycloak'}
        self.payload['argo'] = {'target': copy.deepcopy(target), 'configuration': contract['helm'], 'client': contract['client'], 'recovery': True,
            'currentSecurityProjection': {'revision': 'c' * 40, 'configuration': copy.deepcopy(contract['helm']), 'client': copy.deepcopy(contract['client'])},
            'accessActivation': copy.deepcopy(self.contract['evidence'])}
        public = {'repository': self.payload['repository'], 'services': {'enabled': False}}
        self.payload['argo']['serviceActivation'] = service_activation.prepare(public, target['valuesRepository'], target['valuesRevision'])
        self.payload['argo']['privateActivation'] = private_activation.prepare(public, target['valuesRepository'], target['valuesRevision'])
        self.binding_receipt.update({k: self.payload['argo'][k] for k in ('serviceActivation', 'privateActivation')})
        for name in ('cloudlab-keycloak-operator', 'cloudlab-data-configuration', 'cloudlab-argocd', runtime.APP):
            self.objects['application.argoproj.io', name, 'argocd'] = {'metadata': {'uid': 'identity' if name == runtime.APP else name,
                'labels': {'cloudlab.io/owner': runtime.OWNER}}, 'status': {'sync': {'status': 'Synced', 'revision': 'd' * 40}, 'health': {'status': 'Healthy'}}}
        self.objects['application.argoproj.io', 'cloudlab-data-configuration', 'argocd']['spec'] = {'source': {'helm': {'valuesObject': {'identity': {'enabled': True, 'database': 'keycloak', 'role': 'keycloak'}}}}}
        self.objects['database.postgresql.cnpg.io', 'keycloak', 'cloudlab-data'] = {'metadata': {'generation': 1}, 'status': {'applied': True, 'observedGeneration': 1}}
        if change == 'target': self.payload['argo']['target']['valuesRevision'] = 'e' * 40
        if change == 'uid': controller['metadata']['uid'] = 'foreign'
        if change == 'source': root['spec']['source']['repoURL'] = 'https://github.com/example/foreign.git'
        if change == 'administrator': self.payload['argo']['accessActivation']['administratorHash'] = '0' * 64
        if change == 'rbac': self.objects['clusterrolebinding.rbac.authorization.k8s.io', native.authority.BINDING, 'argocd']['subjects'][0]['name'] = 'foreign@example.invalid'
        if change == 'reader': self.objects['externalsecret.external-secrets.io', native.APP + '-source', 'argocd']['metadata']['annotations'] = {}
        if change == 'ordinary': self.payload['argo']['recovery'] = False
        if change == 'skip': root['metadata']['annotations'] = {'argocd.argoproj.io/skip-reconcile': 'TrUe'}
        if change == 'other-app': self.objects['application.argoproj.io', 'cloudlab-argocd', 'argocd']['status']['sync']['revision'] = 'e' * 40
        revoked = {'realms': {'platform': {'clients': ['argocd']}}} if change == 'revoked' else {'realms': {}}
        calls, records = [], []
        def read(kind, name, namespace='argocd'): return copy.deepcopy(self.objects.get((kind, name, namespace)))
        def write(*args, **kwargs):
            calls.append(args)
            if args[0] == 'scale': controller['spec']['replicas'] = int(args[-1].split('=')[1])
            if args[0] == 'patch':
                obj = self.objects[args[1], args[2], 'argocd']
                for op in json.loads(args[-1]):
                    if op['op'] == 'add':
                        keys = op['path'].strip('/').split('/'); at = obj
                        for key in keys[:-1]: at = at.setdefault(key, {})
                        at[keys[-1]] = copy.deepcopy(op['value'])
        original_read = Path.read_text
        def evidence(path, *args, **kwargs):
            if 'longhorn-monthly-receipt' in str(path): return json.dumps({'retention_complete': change != 'backup', 'restore': {'physical_restore': True}})
            if 'receipts/acceptance.json' in str(path): return json.dumps({'verified_at': 'verified', 'external_binding': change != 'acceptance'})
            return original_read(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); gitops = base / 'gitops'; identity = base / 'identity'; gitops.mkdir(); identity.mkdir()
            (gitops / 'checkpoint.json').write_text('{"phase":"accepted"}')
            (gitops / 'identity-values-binding.json').write_text(json.dumps(self.binding_receipt))
            (identity / 'ownership.json').write_text('{"phase":"scoped","uid":"identity"}')
            record = source_transition.record
            def captured(path, state): records.append(copy.deepcopy(state)); record(path, state)
            with self.cluster(), ExitStack() as stack:
                for module in (bootstrap, source_transition):
                    stack.enter_context(patch.object(module, 'BASE', gitops)); stack.enter_context(patch.object(module, 'get', side_effect=read)); stack.enter_context(patch.object(module, 'kube', side_effect=write))
                for module in (runtime, ownership): stack.enter_context(patch.object(module, 'get', side_effect=read))
                stack.enter_context(patch.object(runtime, 'BASE', identity))
                stack.enter_context(patch.object(runtime, 'private_inputs', return_value=({'realms': {'platform': {'clients': [contract['client']]}}}, revoked, 'c' * 40)))
                for name in ('check', 'proxy_privacy', 'public_address'): stack.enter_context(patch.object(runtime, name))
                stack.enter_context(patch.object(runtime, 'private_request', return_value={'error': 'invalid_grant'}))
                stack.enter_context(patch.object(source_transition, 'pause', side_effect=lambda: controller['spec'].update(replicas=0)))
                stack.enter_context(patch.object(source_transition, 'wait_application'))
                stack.enter_context(patch.object(source_transition, 'record', side_effect=captured))
                stack.enter_context(patch.object(Path, 'read_text', evidence))
                if change is None:
                    result = runtime.run(self.payload)
                    self.assertTrue(result['native_argo_values_bound'])
                    self.assertTrue(any('accessActivation' in r for r in records))
                    self.assertEqual(controller['spec']['replicas'], 1)
                else:
                    with self.assertRaises(RuntimeError): runtime.run(self.payload)
                    self.assertEqual(calls, [])
                    self.assertEqual(records, [])
                    self.assertEqual(controller['spec']['replicas'], 0)

    def test_actual_argo_recovery_preserves_original_and_pending_native_handoff(self):
        for source in ('original', 'patched'):
            with self.subTest(source=source): self.actual_recovery(source)

    def test_actual_argo_recovery_refuses_authority_source_and_other_prerequisite_changes_before_writes(self):
        for change in ('target', 'uid', 'source', 'revoked', 'administrator', 'rbac', 'reader', 'ordinary', 'backup', 'acceptance', 'other-app'):
            with self.subTest(change=change): self.actual_recovery(change=change)

    def test_recorded_binding_cannot_be_downgraded_to_initial_legacy_observation(self):
        self.contract, self.payload, self.state, self.objects, self.binding_receipt, _ = native_access('legacy', bound=False)
        for exists, symlink in ((True, False), (False, True)):
            with self.cluster():
                native.BINDING_RECEIPT.exists.return_value = exists
                native.BINDING_RECEIPT.is_symlink.return_value = symlink
                with self.assertRaisesRegex(RuntimeError, 'prebinding fallback refused'): native.observe(self.payload)

    def test_actual_recovery_refuses_skip_reconcile_for_original_and_patched_sources_without_writes(self):
        for source in ('original', 'patched'):
            with self.subTest(source=source): self.actual_recovery(source_state=source, change='skip')
