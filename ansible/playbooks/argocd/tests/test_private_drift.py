import copy
import json
import unittest
from unittest.mock import patch

import private_source_drift as proof


class PrivateSourceDriftTests(unittest.TestCase):
    def setUp(self):
        repository = 'https://github.com/example/private.git'
        namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': proof.NAMESPACE,
            'labels': {'cloudlab.io/owner': 'private-gitops'}}}
        app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {
            'name': proof.APPLICATION, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': 'private-gitops'}},
            'spec': {'project': proof.APPLICATION,
                'source': {'repoURL': repository, 'targetRevision': 'main', 'path': proof.SOURCE['path']},
                'destination': {'server': 'https://kubernetes.default.svc', 'namespace': proof.NAMESPACE},
                'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                    'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}
        manifest = {'apiVersion': 'v1', 'kind': 'ConfigMap',
            'metadata': {'name': proof.NAME, 'namespace': proof.NAMESPACE}, 'data': {'marker': 'v1'}}
        self.envelope = {'verification': {'catalog_enabled': True, 'configuration_repository': repository,
            'configuration_revision': 'a' * 40, 'sources': [proof.SOURCE | {'repository': repository}],
            'objects': [app, namespace] + [{'kind': kind, 'metadata': {'name': proof.NAMESPACE}}
                                         for kind in ('AppProject', 'ExternalSecret')]},
            'identities': {'Namespace': 'namespace-uid', 'Application': 'app-uid', 'ConfigMap': 'cm-uid'},
            'fixture': {'revision': 'a' * 40, 'manifest': manifest}}
        self.objects = {'namespace': copy.deepcopy(namespace), 'application.argoproj.io': copy.deepcopy(app),
                        'configmap': copy.deepcopy(manifest)}
        tracking = {'namespace': 'cloudlab-private-sources:/Namespace:argocd/' + proof.NAMESPACE,
                    'application.argoproj.io': 'cloudlab-private-sources:argoproj.io/Application:argocd/' + proof.APPLICATION,
                    'configmap': proof.APPLICATION + ':/ConfigMap:' + proof.NAMESPACE + '/' + proof.NAME}
        for kind, label in (('namespace', 'Namespace'), ('application.argoproj.io', 'Application'), ('configmap', 'ConfigMap')):
            self.objects[kind]['metadata'].update(uid=self.envelope['identities'][label], resourceVersion='1',
                annotations={'argocd.argoproj.io/tracking-id': tracking[kind]})
        self.objects['application.argoproj.io']['status'] = {'sync': {'revision': 'a' * 40, 'status': 'Synced'},
            'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}
        self.calls = []
        self.heal = True
        self.ambiguous = False
        self.before_mutation = None
        self.after_mutation = None
        self.wrong_witness = False

    def request(self, *args, document=None):
        self.calls.append((args, copy.deepcopy(document)))
        self.assertIn(args[0], ('get', 'patch'))
        if args[0] == 'get':
            self.assertIn(args[1], self.objects)
            if args[1] == 'configmap' and self.heal and self.objects['configmap']['data'].get('marker', '').startswith('cloudlab-drift-'):
                self.objects['configmap']['data'] = {'marker': 'v1'}
                self.objects['configmap']['metadata']['resourceVersion'] += '1'
            return json.dumps(self.objects[args[1]])
        self.assertEqual(args, ('patch', 'configmap', proof.NAME, '-n', proof.NAMESPACE,
            '--request-timeout=30s', '--type=json', '--patch-file=/dev/stdin', '-o', 'json'))
        cm = self.objects['configmap']
        if self.before_mutation: self.before_mutation(cm)
        expected_tests = [{'op': 'test', 'path': '/metadata/uid', 'value': cm['metadata']['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': cm['metadata']['resourceVersion']},
            {'op': 'test', 'path': '/data', 'value': cm['data']}]
        if document[:3] != expected_tests: raise RuntimeError('optimistic concurrency conflict')
        self.assertEqual(len(document), 4)
        self.assertEqual({key: value for key, value in document[3].items() if key != 'value'},
                         {'op': 'replace', 'path': '/data/marker'})
        cm['data']['marker'] = document[3]['value']
        cm['metadata']['resourceVersion'] += '1'
        response = json.dumps(cm)
        if self.after_mutation: self.after_mutation(cm)
        if self.ambiguous and document[3]['value'].startswith('cloudlab-drift-'):
            raise RuntimeError('committed response unavailable')
        if self.wrong_witness and document[3]['value'].startswith('cloudlab-drift-'):
            response = json.loads(response)
            response['metadata']['uid'] = 'wrong-response-uid'
            response = json.dumps(response)
        return response

    def run_proof(self, timeout=180):
        with patch.object(proof, 'kube', side_effect=self.request), patch.object(proof.time, 'sleep'):
            return proof.run(self.envelope, timeout=timeout)

    def mutations(self):
        return [document for args, document in self.calls if args[0] == 'patch']

    def test_observed_argo_repair_and_repeat_use_new_nonce_without_cleanup_writes(self):
        for attempt in range(2):
            result = self.run_proof()
            self.assertTrue(result['nonce_persisted'])
            self.assertTrue(result['self_heal_verified'])
            self.assertTrue(result['cleanup_complete'])
            self.assertFalse(result['cleanup_restored'])
            self.assertEqual(self.objects['configmap']['data'], {'marker': 'v1'})
        mutations = self.mutations()
        self.assertEqual(len(mutations), 2)
        self.assertNotEqual(mutations[0][3]['value'], mutations[1][3]['value'])

    def test_wrong_scope_revision_or_manifest_never_mutates(self):
        original = copy.deepcopy(self.envelope)
        for target, change in (('source', {'path': 'other'}), ('source', {'revision': 'other'}),
                              ('source', {'repository': 'https://github.com/example/other.git'}),
                              ('manifest', {'data': {'marker': 'production'}}),
                              ('manifest', {'binaryData': {}}),
                              ('manifest', {'metadata': {'name': proof.NAME}}),
                              ('fixture', {'revision': 'b' * 40})):
            self.envelope = copy.deepcopy(original)
            if target == 'source': self.envelope['verification']['sources'][0].update(change)
            elif target == 'manifest': self.envelope['fixture']['manifest'].update(change)
            else: self.envelope['fixture'].update(change)
            with self.subTest(target=target, change=change), self.assertRaises(proof.ProofError): self.run_proof()
        self.assertEqual(self.mutations(), [])

    def test_wrong_uid_owner_source_and_user_data_refuse_before_mutation(self):
        self.heal = False
        baseline = copy.deepcopy(self.objects)
        changes = [('namespace', 'metadata', {'uid': 'replacement'}),
            ('namespace', 'metadata', {'labels': {'cloudlab.io/owner': 'foreign'}}),
            ('application.argoproj.io', 'spec', {'source': {'repoURL': 'other'}}),
            ('application.argoproj.io', 'metadata', {'finalizers': ['cascade']}),
            ('configmap', 'metadata', {'ownerReferences': [{'uid': 'foreign'}]}),
            ('configmap', 'metadata', {'uid': 'replacement'}),
            ('configmap', 'data', {'marker': 'v1', 'other': 'user-data'}),
            ('configmap', 'data', {'marker': 'cloudlab-drift-unknown-attempt'})]
        for kind, field, change in changes:
            self.objects = copy.deepcopy(baseline)
            self.objects[kind][field].update(change)
            with self.subTest(kind=kind, change=change), self.assertRaises(proof.ProofError): self.run_proof()
        self.assertEqual(self.mutations(), [])

    def test_optimistic_resource_version_conflict_does_not_retry_or_claim_repair(self):
        self.before_mutation = lambda cm: cm['metadata'].update(resourceVersion='concurrent')
        result = self.run_proof()
        self.assertFalse(result['nonce_persisted'])
        self.assertFalse(result['self_heal_verified'])
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.objects['configmap']['data'], {'marker': 'v1'})

    def test_timeout_restores_only_owned_nonce_without_counting_self_heal(self):
        self.heal = False
        result = self.run_proof(timeout=0)
        self.assertTrue(result['nonce_persisted'])
        self.assertFalse(result['self_heal_verified'])
        self.assertTrue(result['cleanup_restored'])
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(len(self.mutations()), 2)
        self.assertEqual(self.objects['configmap']['data'], {'marker': 'v1'})

    def test_committed_but_failed_response_enters_nonce_scoped_cleanup(self):
        self.heal, self.ambiguous = False, True
        result = self.run_proof()
        self.assertFalse(result['nonce_persisted'])
        self.assertFalse(result['self_heal_verified'])
        self.assertTrue(result['cleanup_restored'])
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(len(self.mutations()), 2)
        self.assertEqual(self.objects['configmap']['data'], {'marker': 'v1'})

    def test_patch_response_must_witness_nonce_on_the_captured_identity(self):
        self.heal, self.wrong_witness = False, True
        result = self.run_proof()
        self.assertFalse(result['nonce_persisted'])
        self.assertFalse(result['self_heal_verified'])
        self.assertTrue(result['cleanup_restored'])
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(len(self.mutations()), 2)

    def test_cleanup_refuses_concurrent_marker_data_replacement_or_source_change(self):
        baseline = copy.deepcopy(self.objects)
        def source_changed(cm): self.objects['application.argoproj.io']['spec']['source']['path'] = 'changed'
        for callback in (lambda cm: cm['data'].update(marker='another-attempt'),
                         lambda cm: cm['data'].update(extra='user-data'),
                         lambda cm: cm['metadata'].update(uid='replacement'), source_changed):
            self.objects, self.calls = copy.deepcopy(baseline), []
            self.heal, self.after_mutation = False, callback
            with self.subTest(callback=callback):
                result = self.run_proof(timeout=0)
                self.assertFalse(result['self_heal_verified'])
                self.assertFalse(result['cleanup_complete'])
                self.assertFalse(result['cleanup_restored'])
                self.assertEqual(len(self.mutations()), 1)

    def test_cleanup_refuses_queued_or_active_application_intent_after_timeout_or_uncertain_patch(self):
        baseline = copy.deepcopy(self.objects)
        for ambiguous in (False, True):
            for operation in ('queued', 'Running', 'Terminating'):
                self.objects, self.calls = copy.deepcopy(baseline), []
                self.heal, self.ambiguous = False, ambiguous
                def mark_operation(cm):
                    app = self.objects['application.argoproj.io']
                    if operation == 'queued':
                        app['operation'] = {'sync': {'revision': 'b' * 40}}
                    else:
                        app['status']['operationState'] = {'phase': operation}
                self.after_mutation = mark_operation
                with self.subTest(ambiguous=ambiguous, operation=operation):
                    result = self.run_proof(timeout=0)
                    self.assertEqual(self.objects['application.argoproj.io']['status']['sync']['revision'], 'a' * 40)
                    self.assertFalse(result['self_heal_verified'])
                    self.assertFalse(result['cleanup_complete'])
                    self.assertFalse(result['cleanup_restored'])
                    self.assertEqual(len(self.mutations()), 1)
                    self.assertTrue(self.objects['configmap']['data']['marker'].startswith('cloudlab-drift-'))

    def test_full_data_precondition_preserves_concurrent_added_data(self):
        self.heal = False
        self.before_mutation = lambda cm: cm['data'].update(extra='user-data')
        result = self.run_proof()
        self.assertFalse(result['self_heal_verified'])
        self.assertFalse(result['cleanup_complete'])
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.objects['configmap']['data'], {'marker': 'v1', 'extra': 'user-data'})
