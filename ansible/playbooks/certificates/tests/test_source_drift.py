import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import certificate_source_drift as proof
import kube
from fixtures import accepted, prepared


class CertificateSourceDriftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.contract = prepared()[0]

    def setUp(self):
        self.state, self.objects = accepted(self.contract, 'native')
        self.objects['application.argoproj.io', proof.APP, 'argocd']['metadata']['resourceVersion'] = '1'
        self.objects['application.argoproj.io', proof.ROOT, 'argocd'] = {'apiVersion': 'argoproj.io/v1alpha1',
            'kind': 'Application', 'metadata': {'name': proof.ROOT, 'namespace': 'argocd', 'uid': 'root-uid'},
            'spec': {'project': 'cloudlab-root', 'source': {'repoURL': self.contract['repository'],
                'targetRevision': 'main', 'path': 'gitops/roots/public', 'helm': {'valuesObject': {'identity': {
                    'argo': {'valuesRepository': self.contract['private_repository'], 'valuesRevision': 'b' * 40}}}}},
                'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                'syncPolicy': {'automated': {'prune': False, 'selfHeal': True, 'allowEmpty': False}}},
            'status': {'sync': {'status': 'Synced', 'revision': self.contract['public_revision']},
                'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
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
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'ownership.json').write_text(json.dumps(self.state))
            with patch.object(proof.native, 'BASE', Path(directory)), patch.object(proof.native, 'get', side_effect=self.get), \
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
            lambda: self.app()['spec'].update(ignoreDifferences=[{'group': 'cert-manager.io', 'kind': 'Certificate', 'jsonPointers': ['/spec']}]),
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

    def test_concurrent_root_source_reader_tls_and_foreign_label_changes_never_get_overwritten(self):
        baseline = copy.deepcopy(self.objects)
        changes = [lambda: self.app(proof.ROOT)['spec']['source'].update(targetRevision='changed'),
            lambda: self.app(proof.ROOT)['metadata'].update(uid='replacement-root'),
            lambda: self.objects['secret', 'cloudlab-certificates-source', 'argocd']['metadata'].update(uid='replacement-reader'),
            lambda: self.objects['secret', 'cloudlab-staging-tls', 'cert-manager']['data'].update({'tls.key': 'changed-key'}),
            lambda: self.app()['metadata']['labels'].update({proof.LABEL: 'foreign-attempt'})]
        for change in changes:
            self.objects, self.calls = copy.deepcopy(baseline), []
            self.heal, self.after_mutation = False, change
            with self.subTest(change=change):
                result = self.run_proof(timeout=0)
                self.assertFalse(result['root_repair_verified'])
                self.assertFalse(result['cleanup_complete'])
                self.assertEqual(len(self.patches()), 1)
