import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import access_source_drift as proof
import io
from playbooks.istio.files import kube
from fixtures import native_access


class AccessSourceDriftTests(unittest.TestCase):
    def setUp(self):
        self.contract, self.payload, self.state, self.objects, self.binding_receipt, _ = native_access()
        self.objects['application.argoproj.io', proof.APP, 'argocd']['metadata']['resourceVersion'] = '1'
        root = self.objects['application.argoproj.io', proof.ROOT, 'argocd']
        root['metadata'].update(name=proof.ROOT, namespace='argocd')
        root['spec']['syncPolicy'] = {'automated': {'prune': False, 'selfHeal': True, 'allowEmpty': False}}
        root['status']['operationState'] = {'phase': 'Succeeded'}
        self.objects['appproject.argoproj.io', proof.APP, 'argocd']['metadata']['uid'] = 'access-project'
        self.objects['appproject.argoproj.io', 'cloudlab-root', 'argocd']['spec'] = {'sourceRepos': [self.contract['repository']]}
        self.objects['statefulset', 'argocd-application-controller', 'argocd']['spec'] = {'replicas': 1}
        self.calls = []
        self.heal = True
        self.ambiguous = False
        self.before_mutation = None
        self.after_mutation = None
        self.repair_during_nonce_guard = False
        self.root_busy_while_repairing = False
        self.root_is_repairing = False

    def app(self, name=proof.APP): return self.objects['application.argoproj.io', name, 'argocd']

    def get(self, kind, name, namespace=None):
        if kind == 'application.argoproj.io':
            label = self.app()['metadata']['labels'][proof.LABEL]
            if name == proof.APP and self.repair_during_nonce_guard and label.startswith('cloudlab-proof-'):
                self.app()['metadata']['labels'][proof.LABEL] = proof.OWNER
                self.repair_during_nonce_guard = False
            if name == proof.ROOT:
                if self.heal and label.startswith('cloudlab-proof-'):
                    self.app()['metadata']['labels'][proof.LABEL] = proof.OWNER
                    self.app()['metadata']['resourceVersion'] += '1'
                    if self.root_busy_while_repairing:
                        self.app(proof.ROOT)['operation'] = {'sync': {'revision': self.contract['public_revision']}}
                        self.app(proof.ROOT)['status']['operationState']['phase'] = 'Running'
                        self.root_is_repairing = True
                elif self.root_is_repairing:
                    self.app(proof.ROOT).pop('operation')
                    self.app(proof.ROOT)['status']['operationState']['phase'] = 'Succeeded'
                    self.root_is_repairing = False
        return copy.deepcopy(self.objects.get((kind, name, namespace)))

    def request(self, *args, document=None):
        self.calls.append((args, copy.deepcopy(document)))
        if args[:2] == ('get', 'secrets'):
            return json.dumps({'items': [value for (kind, name, namespace), value in self.objects.items()
                if kind == 'secret' and namespace == 'argocd']})
        self.assertEqual(args, ('patch', 'application.argoproj.io', proof.APP, '-n', 'argocd', '--type=json',
                               '--patch-file=/dev/stdin', '-o', 'json'))
        if self.before_mutation: self.before_mutation()
        app = self.app()
        expected = {'/metadata/uid': app['metadata']['uid'], '/metadata/resourceVersion': app['metadata']['resourceVersion'],
            '/spec': app['spec'], proof.TRACKING_PATH: proof.native.TRACKING,
            proof.LABEL_PATH: app['metadata']['labels'][proof.LABEL]}
        if document[:5] != [{'op': 'test', 'path': path, 'value': value} for path, value in expected.items()]:
            raise RuntimeError('atomic conflict')
        self.assertEqual(len(document), 6)
        self.assertEqual(document[5]['op'], 'replace')
        self.assertEqual(document[5]['path'], proof.LABEL_PATH)
        app['metadata']['labels'][proof.LABEL] = document[5]['value']
        app['metadata']['resourceVersion'] += '1'
        response = json.dumps(app)
        if self.after_mutation: self.after_mutation()
        if self.ambiguous and document[5]['value'].startswith('cloudlab-proof-'):
            raise RuntimeError('committed response unavailable')
        return response

    def run_proof(self, *, timeout=180):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            self.configured_file = Path(directory) / 'ownership.json'
            self.binding_file = Path(directory) / 'identity-values-binding.json'
            self.configured_file.write_text(json.dumps(self.state)); self.configured_file.chmod(0o600)
            self.binding_file.write_text(json.dumps(self.binding_receipt)); self.binding_file.chmod(0o600)
            with patch.object(proof.native.authority, 'RECEIPT', self.configured_file), \
                    patch.object(proof.native, 'BINDING_RECEIPT', self.binding_file), \
                    patch.object(proof.native, 'get', side_effect=self.get), \
                    patch.object(kube, 'get', side_effect=self.get), patch.object(proof.native, 'kube', side_effect=self.request), \
                    patch.object(proof.time, 'sleep'):
                return proof.run(self.contract, timeout=timeout)

    def patches(self): return [document for args, document in self.calls if args[0] == 'patch']

    def test_root_repairs_persisted_nonce_and_repeat_does_not_mutate_the_contract(self):
        original = copy.deepcopy(self.contract)
        self.root_busy_while_repairing = True
        for attempt in range(2):
            result = self.run_proof()
            self.assertTrue(result['nonce_persisted'])
            self.assertTrue(result['root_repair_verified'])
            self.assertTrue(result['cleanup_complete'])
            self.assertFalse(result['cleanup_restored'])
        self.assertEqual(len(self.patches()), 2)
        self.assertNotEqual(self.patches()[0][5]['value'], self.patches()[1][5]['value'])
        self.assertEqual(self.contract, original)

    def test_root_repair_between_nonce_read_and_production_guard_is_rechecked_legitimately(self):
        self.repair_during_nonce_guard = True
        self.assertTrue(self.run_proof()['root_repair_verified'])
        self.assertEqual(len(self.patches()), 1)

    def test_parent_enabled_default_or_literal_true_is_accepted_but_false_is_refused(self):
        root = self.app(proof.ROOT)
        proof.root_gate(self.contract, root, require_idle=True)
        root['spec']['syncPolicy']['automated']['enabled'] = True
        proof.root_gate(self.contract, root, require_idle=True)
        for invalid in (False, 1, 'true', 'false'):
            root['spec']['syncPolicy']['automated']['enabled'] = invalid
            with self.subTest(enabled=invalid), self.assertRaises(proof.ProofError):
                proof.root_gate(self.contract, root, require_idle=True)

    def test_wrong_uid_policy_tracking_source_and_foreign_owner_refuse_injection(self):
        baseline = copy.deepcopy(self.objects)
        changes = [lambda: self.app()['metadata'].update(uid='foreign'),
            lambda: self.app()['spec'].update(ignoreDifferences=[{'group': 'cert-manager.io', 'kind': 'Access', 'jsonPointers': ['/spec']}]),
            lambda: self.app()['metadata']['annotations'].update({'argocd.argoproj.io/tracking-id': 'foreign'}),
            lambda: self.app()['metadata']['labels'].update({proof.LABEL: 'foreign'}),
            lambda: self.app(proof.ROOT)['spec']['source'].update(repoURL='https://github.com/example/foreign.git')]
        for change in changes:
            self.objects = copy.deepcopy(baseline)
            change()
            with self.subTest(change=change), self.assertRaises(RuntimeError): self.run_proof()
        self.assertEqual(self.patches(), [])

    def test_atomic_version_conflict_never_claims_repair_or_retries_the_write(self):
        self.before_mutation = lambda: self.app()['metadata'].update(resourceVersion='concurrent')
        result = self.run_proof()
        self.assertFalse(result['nonce_persisted'])
        self.assertFalse(result['root_repair_verified'])
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(len(self.patches()), 1)

    def test_timeout_and_committed_but_failed_response_restore_only_the_owned_nonce(self):
        baseline = copy.deepcopy(self.objects)
        for ambiguous in (False, True):
            self.objects, self.calls = copy.deepcopy(baseline), []
            self.heal, self.ambiguous = False, ambiguous
            result = self.run_proof(timeout=0)
            self.assertFalse(result['root_repair_verified'])
            self.assertTrue(result['cleanup_restored'])
            self.assertTrue(result['cleanup_complete'])
            self.assertEqual(len(self.patches()), 2)
            self.assertEqual(self.app()['metadata']['labels'][proof.LABEL], proof.OWNER)

    def test_empty_pending_and_running_or_terminating_intent_block_parent_and_child_before_write(self):
        baseline = copy.deepcopy(self.objects)
        for name in (proof.ROOT, proof.APP):
            for phase in (None, 'Running', 'Terminating'):
                self.objects = copy.deepcopy(baseline)
                if phase is None: self.app(name)['operation'] = {}
                else: self.app(name)['status'].setdefault('operationState', {})['phase'] = phase
                with self.subTest(name=name, phase=phase), self.assertRaises(RuntimeError): self.run_proof()
        self.assertEqual(self.patches(), [])

    def test_cleanup_declines_pending_parent_or_child_after_timeout_and_uncertain_patch(self):
        baseline = copy.deepcopy(self.objects)
        for name in (proof.ROOT, proof.APP):
            for phase in (None, 'Running', 'Terminating'):
                for ambiguous in (False, True):
                    self.objects, self.calls = copy.deepcopy(baseline), []
                    self.heal, self.ambiguous = False, ambiguous
                    def pending():
                        if phase is None: self.app(name)['operation'] = {}
                        else: self.app(name)['status'].setdefault('operationState', {})['phase'] = phase
                    self.after_mutation = pending
                    with self.subTest(name=name, phase=phase, ambiguous=ambiguous):
                        result = self.run_proof(timeout=0)
                        self.assertFalse(result['root_repair_verified'])
                        self.assertFalse(result['cleanup_complete'])
                        self.assertFalse(result['cleanup_restored'])
                        self.assertEqual(len(self.patches()), 1)

    def test_concurrent_root_source_reader_credentials_and_foreign_label_changes_never_get_overwritten(self):
        baseline = copy.deepcopy(self.objects)
        changes = [lambda: self.app(proof.ROOT)['spec']['source'].update(targetRevision='changed'),
            lambda: self.app(proof.ROOT)['metadata'].update(uid='replacement-root'),
            lambda: self.objects['secret', 'cloudlab-access-source', 'argocd']['metadata'].update(uid='replacement-reader'),
            lambda: self.objects['secret', 'operator-oauth', 'tailscale']['data'].update({'token': 'Y2hhbmdlZC1rZXk='}),
            lambda: self.objects['secret', 'cloudlab-access-source', 'argocd']['data'].update(githubAppPrivateKey='Y2hhbmdlZA=='),
            lambda: self.objects['externalsecret.external-secrets.io', 'cloudlab-access-source', 'argocd']['spec'].update(refreshInterval='1h'),
            lambda: self.app(proof.ROOT)['spec']['source']['helm']['valuesObject']['identity']['argo'].update(valuesRevision='e' * 40),
            lambda: self.app()['metadata']['labels'].update({proof.LABEL: 'foreign-attempt'})]
        for change in changes:
            self.objects, self.calls = copy.deepcopy(baseline), []
            self.heal, self.after_mutation = False, change
            with self.subTest(change=change):
                result = self.run_proof(timeout=0)
                self.assertFalse(result['root_repair_verified'])
                self.assertFalse(result['cleanup_complete'])
                self.assertEqual(len(self.patches()), 1)

    def test_identity_approval_must_match_even_before_baseline_capture(self):
        self.app(proof.ROOT)['spec']['source']['helm']['valuesObject']['identity']['argo']['valuesRevision'] = 'e' * 40
        with self.assertRaises(RuntimeError): self.run_proof()
        self.assertEqual(self.patches(), [])

    def test_envelope_preserves_fixed_contract_and_bounds_utf8_bytes(self):
        envelope = {'native': self.contract}
        stale = copy.deepcopy(self.contract); stale['configuration_revision'] = 'e' * 40
        with self.assertRaises(proof.ProofError): proof.read_envelope(io.BytesIO(json.dumps({'native': stale}).encode()))
        self.assertEqual(proof.read_envelope(io.BytesIO(json.dumps(envelope).encode())), envelope)
        oversized = copy.deepcopy(self.contract); oversized['application']['metadata']['annotations']['example.invalid/large'] = 'x' * proof.MAX_ENVELOPE_BYTES
        with self.assertRaises(proof.ProofError): proof.run(oversized)
        with self.assertRaises(proof.ProofError): proof.read_envelope(io.BytesIO(b' ' * (proof.MAX_ENVELOPE_BYTES + 1)))
        with self.assertRaises(proof.ProofError): proof.read_envelope(io.BytesIO(b'{"native":{}}'))
        with self.assertRaises((ValueError, UnicodeError)): proof.read_envelope(io.BytesIO(b'\xff'))
        with self.assertRaises(ValueError): proof.read_envelope(io.BytesIO(b'{'))
        # Unicode counts as UTF-8 bytes, not decoded characters.
        raw = json.dumps(envelope, ensure_ascii=False).encode()
        with self.assertRaises(proof.ProofError): proof.read_envelope(io.BytesIO(raw + ('\u00e9' * (proof.MAX_ENVELOPE_BYTES // 2 + 1)).encode()))

    def test_missing_persistence_witness_never_reports_success(self):
        request = self.request
        def no_witness(*args, **kwargs):
            raw = request(*args, **kwargs)
            if args[0] == 'patch' and kwargs['document'][5]['value'].startswith('cloudlab-proof-'):
                return '{}'
            return raw
        self.request = no_witness
        result = self.run_proof()
        self.assertFalse(result['nonce_persisted'])
        self.assertFalse(result['root_repair_verified'])

    def test_runtime_guard_stays_strict_during_the_owned_nonce_and_unrelated_metadata_survives(self):
        self.app()['metadata']['labels']['example.invalid/neighbor'] = 'keep'
        self.app()['metadata']['annotations']['example.invalid/neighbor'] = 'keep'
        def strict():
            healing = self.heal; self.heal = False
            try:
                with self.assertRaises(RuntimeError): proof.native.guard(self.contract)
            finally: self.heal = healing
        self.after_mutation = strict
        result = self.run_proof()
        self.assertTrue(result['root_repair_verified'])
        self.assertEqual(self.app()['metadata']['labels']['example.invalid/neighbor'], 'keep')
        self.assertEqual(self.app()['metadata']['annotations']['example.invalid/neighbor'], 'keep')

    def test_receipt_rbac_project_and_reader_changes_refuse_cleanup_without_overwriting(self):
        baseline = copy.deepcopy(self.objects)
        def change_configured():
            state = json.loads(self.configured_file.read_text()); state['administrator'] = '0' * 64
            self.configured_file.write_text(json.dumps(state))
        def change_binding():
            state = json.loads(self.binding_file.read_text()); state['target']['valuesRevision'] = 'e' * 40
            self.binding_file.write_text(json.dumps(state))
        changes = [change_configured, change_binding,
            lambda: self.objects['clusterrolebinding.rbac.authorization.k8s.io', proof.native.authority.BINDING, 'argocd']['subjects'][0].update(name='foreign@example.invalid'),
            lambda: self.objects['appproject.argoproj.io', proof.APP, 'argocd']['spec'].update(sourceRepos=['https://github.com/example/foreign.git']),
            lambda: self.objects['secret', 'operator-oauth', 'tailscale']['data'].update(token='Y2hhbmdlZA=='),
            lambda: self.objects['secret', 'cloudlab-access-source', 'argocd']['metadata']['ownerReferences'][0].update(uid='foreign')]
        for change in changes:
            self.objects, self.calls = copy.deepcopy(baseline), []
            self.heal, self.after_mutation = False, change
            with self.subTest(change=change):
                result = self.run_proof(timeout=0)
                self.assertFalse(result['root_repair_verified'])
                self.assertFalse(result['cleanup_complete'])
                self.assertEqual(len(self.patches()), 1)

    def test_skip_reconcile_blocks_both_initial_writes_and_owned_nonce_cleanup(self):
        baseline = copy.deepcopy(self.objects)
        for name in (proof.APP, proof.ROOT):
            self.objects = copy.deepcopy(baseline)
            self.app(name)['metadata'].setdefault('annotations', {})['argocd.argoproj.io/skip-reconcile'] = 'TrUe'
            with self.assertRaises(RuntimeError): self.run_proof()
            self.assertEqual(self.patches(), [])
            self.objects = copy.deepcopy(baseline)
            self.heal = False
            self.after_mutation = lambda: self.app(name)['metadata'].setdefault('annotations', {}).update({'argocd.argoproj.io/skip-reconcile': 'true'})
            result = self.run_proof(timeout=0)
            self.assertFalse(result['root_repair_verified'])
            self.assertFalse(result['cleanup_complete'])
            self.assertEqual(len(self.patches()), 1)
            self.calls = []; self.after_mutation = None
