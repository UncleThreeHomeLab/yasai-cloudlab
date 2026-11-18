import copy
import base64
import contextlib
import importlib.util
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('eso_verify', Path(__file__).parents[1] / 'files/verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def consumer_scope():
    before = [{'namespaces': ['external-secrets', 'argocd']},
              {'namespaceSelector': {'matchLabels': {'cloudlab.io/service-secrets': 'approved'}}}]
    after = copy.deepcopy(before)
    after[0]['namespaces'].remove('external-secrets')
    return {'clusterUID': 'cluster', 'source': {
        'rootUID': 'root', 'publicRevision': 'a' * 40, 'privateRevision': None,
        'storeName': 'cloudlab', 'storeUID': 'production-store',
        'runtimeNamespacesChecked': True, 'declarationsChecked': None},
        'namespaces': {role: {'name': name, 'uid': 'namespace-' + role} for role, name in (
            ('operator', 'external-secrets'), ('core', 'argocd'), ('application', 'cloudlab-app-scope'))},
        'beforeConditions': before, 'afterConditions': after}


class FakeConsumerAPI:
    def __init__(self, scope, journal):
        self.scope, self.journal = scope, journal
        self.objects, self.calls, self.creates, self.deletes = {}, [], [], []
        self.event = None
        self.create_failure = None

    def __call__(self, *args, body=None, namespace=verify.NAMESPACE):
        self.calls.append((args, namespace, copy.deepcopy(body)))
        if args[0] == 'create':
            self.creates.append(copy.deepcopy(json.loads(self.journal.read_text())))
            if self.create_failure is not None:
                if isinstance(self.create_failure, Exception):
                    raise self.create_failure
                if self.create_failure == 'missing-uid':
                    return copy.deepcopy(body)
                return self.create_failure
            obj = copy.deepcopy(body)
            obj['metadata'].update(uid='owned-' + str(len(self.objects)), resourceVersion='1')
            key = (obj['kind'], namespace or '', obj['metadata']['name'])
            self.objects[key] = obj
            if obj['kind'] == 'ClusterSecretStore':
                obj['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
            if obj['kind'] == 'ExternalSecret':
                obj['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
                self.objects['Secret', namespace, obj['metadata']['name']]['data'] = {
                    'probe': base64.b64encode(b'phase1').decode()}
            return copy.deepcopy(obj)
        if args[0] == 'get':
            kind, name = args[1:3]
            if kind == 'namespace':
                if name == 'kube-system':
                    return {'metadata': {'uid': 'cluster'}}
                role = next(role for role, ref in self.scope['namespaces'].items() if ref['name'] == name)
                labels = {'kubernetes.io/metadata.name': name}
                if role == 'application':
                    labels['cloudlab.io/service-secrets'] = 'approved'
                return {'metadata': {'uid': self.scope['namespaces'][role]['uid'], 'labels': labels}}
            if kind == 'application.argoproj.io':
                return {'metadata': {'uid': 'root'}, 'spec': {},
                        'status': {'sync': {'revision': 'a' * 40, 'status': 'Synced'},
                                   'health': {'status': 'Healthy'}}}
            if kind == 'clustersecretstore' and name == 'cloudlab':
                return {'metadata': {'uid': 'production-store'},
                        'spec': {'conditions': self.scope['beforeConditions']},
                        'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
            if kind == 'externalsecrets' and name in ('-A', '-o'):
                return {'items': []}
            if kind == 'events':
                return {'items': [copy.deepcopy(self.event)] if self.event else []}
            aliases = {'secrets': 'Secret', 'externalsecrets': 'ExternalSecret',
                       'clustersecretstores': 'ClusterSecretStore'}
            return copy.deepcopy(self.objects.get((aliases[kind], namespace or '', name)))
        if args[0] == 'patch':
            store = self.objects['ClusterSecretStore', '', args[2]]
            patches = json.loads(args[-1])
            assert patches[0] == {'op': 'test', 'path': '/metadata/uid', 'value': store['metadata']['uid']}
            assert patches[1] == {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '1'}
            store['spec']['conditions'] = patches[2]['value']
            store['spec']['provider']['fake']['data'][0]['value'] = patches[3]['value']
            for (kind, ns, name), obj in self.objects.items():
                if kind != 'ExternalSecret':
                    continue
                if ns == verify.NAMESPACE:
                    obj['status'] = {'conditions': [{'type': 'Ready', 'status': 'False',
                                                     'reason': 'SecretSyncedError'}]}
                    self.event = {'metadata': {'uid': 'fresh-event'}, 'involvedObject': {
                        'uid': obj['metadata']['uid']}, 'reason': 'UpdateFailed',
                        'message': 'using cluster store "' + store['metadata']['name'] +
                                   '" is not allowed from namespace "external-secrets": denied by spec.condition'}
                else:
                    self.objects['Secret', ns, name]['data']['probe'] = base64.b64encode(b'phase2').decode()
            return copy.deepcopy(store)
        if args[0] == 'delete':
            parts = args[2].split('/')
            ns = parts[parts.index('namespaces') + 1] if 'namespaces' in parts else ''
            kind = {'secrets': 'Secret', 'externalsecrets': 'ExternalSecret',
                    'clustersecretstores': 'ClusterSecretStore'}[parts[-2]]
            key = (kind, ns, parts[-1])
            assert body['preconditions']['uid'] == self.objects[key]['metadata']['uid']
            self.deletes.append((kind, copy.deepcopy(body)))
            del self.objects[key]
            return {}
        raise AssertionError('Unexpected fixture API operation')


class ConsumerScopeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'proof.json'
        self.scope = consumer_scope()
        self.proof = verify.ConsumerScopeProof(self.scope, self.path)
        self.api = FakeConsumerAPI(self.scope, self.path)

    def immediate(self, predicate):
        if not predicate():
            raise RuntimeError('fixture not ready')

    def prepared(self):
        self.proof.prepare()
        entries = {entry['key']: entry for entry in self.proof.state['resources']}
        for role in ('operator', 'core', 'application'):
            self.proof.create(entries[role + '-Secret'])
        self.proof.create(entries['store-ClusterSecretStore'], {
            'conditions': self.scope['beforeConditions'],
            'provider': {'fake': {'data': [{'key': 'probe', 'value': 'phase1'}]}}})
        for role in ('operator', 'core', 'application'):
            self.proof.create(entries[role + '-ExternalSecret'], {
                'target': {'name': entries[role + '-Secret']['name']}})
        return entries

    def phase2(self, entries):
        store = self.proof.get(entries['store-ClusterSecretStore'])
        self.api('patch', 'clustersecretstore', store['metadata']['name'], '--type=json', '-p', json.dumps([
            {'op': 'test', 'path': '/metadata/uid', 'value': store['metadata']['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '1'},
            {'op': 'replace', 'path': '/spec/conditions', 'value': self.scope['afterConditions']},
            {'op': 'replace', 'path': '/spec/provider/fake/data/0/value', 'value': 'phase2'}]), namespace=None)

    def test_fresh_delivery_retention_and_uid_cleanup_are_required(self):
        with patch.object(verify, 'kubectl', side_effect=self.api), \
                patch.object(verify, 'wait', side_effect=self.immediate):
            result = self.proof.run()
        self.assertTrue(result['consumer_scope_qualified'])
        self.assertFalse(result['production_policy_ready'])
        self.assertIsNone(result['declarations_checked'])
        saved = json.loads(self.path.read_text())
        self.assertIsNone(saved['scope']['source']['declarationsChecked'])
        self.assertFalse(saved['productionPolicyReady'])
        self.assertTrue(saved['qualified'])
        self.assertEqual(saved['denialEventUID'], 'fresh-event')
        self.assertEqual(saved['phase2Delivered'], ['core', 'application'])
        self.assertEqual(saved['phase'], 'cleaned')
        self.assertEqual([kind for kind, _ in self.api.deletes],
                         ['ExternalSecret'] * 3 + ['Secret'] * 3 + ['ClusterSecretStore'])
        for index, intent in enumerate(self.api.creates):
            known = [row for row in intent['resources'] if row['state'] == 'known']
            self.assertEqual(len(known), index)
            self.assertTrue(all(row['uid'] for row in known))
        externals = [body for args, _, body in self.api.calls if args[0] == 'create' and body['kind'] == 'ExternalSecret']
        self.assertTrue(all(obj['spec']['target']['creationPolicy'] == 'Merge' and
                            obj['spec']['target']['deletionPolicy'] == 'Retain' for obj in externals))
        self.assertFalse(self.api.objects)

    def test_stale_values_generic_denial_and_old_events_cannot_pass(self):
        with patch.object(verify, 'kubectl', side_effect=self.api):
            entries = self.prepared()
            self.assertTrue(self.proof.delivered('phase1'))
            self.assertFalse(self.proof.delivered('phase2'))
            self.phase2(entries)
            self.assertTrue(self.proof.delivered('phase2'))
            for role in ('core', 'application'):
                key = ('Secret', self.scope['namespaces'][role]['name'], entries[role + '-Secret']['name'])
                original = copy.deepcopy(self.api.objects[key])
                self.api.objects[key]['data']['probe'] = base64.b64encode(b'phase1').decode()
                self.assertFalse(self.proof.delivered('phase2'))
                self.api.objects[key] = original
            self.assertFalse(self.proof.delivered('phase2', {'fresh-event'}))
            for field, value in (('message', 'generic provider error'), ('reason', 'Other'),
                                 ('involvedObject', {'uid': 'foreign'})):
                original = copy.deepcopy(self.api.event)
                self.api.event[field] = value
                self.assertFalse(self.proof.delivered('phase2'))
                self.api.event = original

    def test_collisions_and_uncertain_creates_stop_without_secret_get_or_cleanup(self):
        for failure in (verify.KubernetesError(collision=True), TimeoutError(), {}, 'missing-uid'):
            with self.subTest(failure=type(failure).__name__):
                self.path = Path(self.directory.name) / (str(len(self.api.calls)) + '-' + str(id(failure)) + '.json')
                self.proof = verify.ConsumerScopeProof(self.scope, self.path)
                self.api = FakeConsumerAPI(self.scope, self.path)
                self.api.create_failure = failure
                with patch.object(verify, 'kubectl', side_effect=self.api), self.assertRaisesRegex(
                        RuntimeError, 'ownership unresolved'):
                    self.proof.run()
                self.assertFalse(self.api.deletes)
                self.assertFalse(any(args[0] == 'get' and args[1] == 'secrets'
                                     for args, _, _ in self.api.calls))
                self.assertEqual(len(self.api.creates), 1)
                self.assertIn(json.loads(self.path.read_text())['resources'][0]['state'], ('collision', 'uncertain'))

    def test_failed_uid_journal_stops_before_next_effect(self):
        original = self.proof.save
        def failing(initial=False):
            if self.proof.state['resources'][0]['state'] == 'known':
                raise OSError('durability failure')
            return original(initial)
        with patch.object(verify, 'kubectl', side_effect=self.api), \
                patch.object(self.proof, 'save', side_effect=failing), self.assertRaisesRegex(
                    RuntimeError, 'ownership unresolved'):
            self.proof.run()
        self.assertEqual(len(self.api.creates), 1)
        self.assertFalse(self.api.deletes)
        self.assertFalse(any(args[0] == 'get' and args[1] == 'secrets' for args, _, _ in self.api.calls))

    def test_replacement_blocks_observation_and_uid_bound_cleanup(self):
        with patch.object(verify, 'kubectl', side_effect=self.api):
            entries = self.prepared()
            entry = entries['operator-Secret']
            self.api.objects['Secret', entry['namespace'], entry['name']]['metadata']['uid'] = 'replacement'
            with self.assertRaisesRegex(RuntimeError, 'identity or lifecycle'):
                self.proof.delivered('phase1')
            with self.assertRaisesRegex(RuntimeError, 'identity or lifecycle'):
                self.proof.cleanup()
        self.assertEqual([kind for kind, _ in self.api.deletes], ['ExternalSecret'] * 3)

    def test_cleanup_conflict_does_not_mark_resources_removed(self):
        with patch.object(verify, 'kubectl', side_effect=self.api):
            self.prepared()
        def conflict(*args, **kwargs):
            if args[0] == 'delete':
                raise verify.KubernetesError()
            return self.api(*args, **kwargs)
        with patch.object(verify, 'kubectl', side_effect=conflict), self.assertRaises(verify.KubernetesError):
            self.proof.cleanup()
        self.assertEqual(json.loads(self.path.read_text())['phase'], 'cleaning')
        self.assertTrue(all(row['state'] == 'known' for row in self.proof.state['resources']))
        self.assertFalse(self.api.deletes)

    def test_initial_durability_and_current_source_checks_precede_effects(self):
        with patch.object(verify, 'kubectl', side_effect=self.api), \
                patch.object(verify.os, 'fsync', side_effect=OSError('durability')), self.assertRaises(OSError):
            self.proof.run()
        self.assertFalse(self.api.creates)
        for change in ('consumer', 'partial', 'source', 'namespace'):
            candidate = verify.ConsumerScopeProof(self.scope, Path(self.directory.name) / (change + '.json'))
            def current(*args, **kwargs):
                value = self.api(*args, **kwargs)
                if change == 'consumer' and args[1] == 'externalsecrets':
                    value['items'] = [{'kind': 'ExternalSecret', 'metadata': {'namespace': verify.NAMESPACE}, 'spec': {
                        'secretStoreRef': {'name': 'cloudlab', 'kind': 'ClusterSecretStore', 'other': True}}}]
                if change == 'partial' and args[1] == 'externalsecrets':
                    value['metadata'] = {'continue': 'incomplete'}
                if change == 'source' and args[1] == 'application.argoproj.io':
                    value['status']['sync']['comparedTo'] = {'source': {'repoURL': 'foreign'}}
                if change == 'namespace' and args[1:3] == ('namespace', verify.NAMESPACE):
                    value['metadata']['labels']['cloudlab.io/service-secrets'] = 'approved'
                return value
            with self.subTest(change=change), patch.object(verify, 'kubectl', side_effect=current), \
                    self.assertRaises(RuntimeError):
                candidate.run()
            self.assertFalse(candidate.path.exists())
        self.assertFalse(self.api.creates)

    def test_runtime_attestation_is_separate_from_production_declaration_coverage(self):
        for coverage in (False, True):
            with self.subTest(coverage=coverage):
                scope = copy.deepcopy(self.scope)
                scope['source']['declarationsChecked'] = coverage
                path = Path(self.directory.name) / ('coverage-' + str(coverage) + '.json')
                api = FakeConsumerAPI(scope, path)
                with patch.object(verify, 'kubectl', side_effect=api), \
                        patch.object(verify, 'wait', side_effect=self.immediate):
                    result = verify.ConsumerScopeProof(scope, path).run()
                self.assertIs(result['declarations_checked'], coverage)
                self.assertFalse(result['production_policy_ready'])
                saved = json.loads(path.read_text())
                self.assertIs(saved['scope']['source']['declarationsChecked'], coverage)
                self.assertFalse(saved['productionPolicyReady'])
        for field, value in (('runtimeNamespacesChecked', False), ('runtimeNamespacesChecked', None),
                             ('declarationsChecked', 'unknown'), ('declarationsChecked', 1)):
            scope = copy.deepcopy(self.scope)
            scope['source'][field] = value
            with self.subTest(field=field, value=value), patch.object(verify, 'kubectl') as kube, \
                    self.assertRaises(RuntimeError):
                verify.ConsumerScopeProof(scope, self.path).run()
            kube.assert_not_called()
        del scope['source']['runtimeNamespacesChecked']
        with patch.object(verify, 'kubectl') as kube, self.assertRaises(RuntimeError):
            verify.ConsumerScopeProof(scope, self.path).run()
        kube.assert_not_called()

    def test_unqualified_scope_and_unknown_dispatch_have_no_effects(self):
        bad = copy.deepcopy(self.scope)
        bad['afterConditions'][0]['namespaces'].append('unreviewed')
        with patch.object(verify, 'kubectl') as kube, self.assertRaises(RuntimeError):
            verify.ConsumerScopeProof(bad, self.path).run()
        kube.assert_not_called()
        with patch.object(verify, 'main') as fresh, patch.object(verify, 'operator_drift') as drift:
            for args in (['--consumer-scope'], ['--consumer-scope', 'journal', 'extra'], ['--unknown']):
                with self.subTest(args=args), self.assertRaises(RuntimeError):
                    verify.run_cli(args)
            with patch.object(verify.ConsumerScopeProof, 'run', return_value={'fake': True}) as fake, \
                    patch.object(verify.sys, 'stdin', io.StringIO(json.dumps(self.scope))):
                self.assertEqual(verify.run_cli(['--consumer-scope', str(self.path)]), {'fake': True})
            fake.assert_called_once()
        fresh.assert_not_called()
        drift.assert_not_called()
        with patch.object(verify, 'main') as fresh, patch.object(verify, 'operator_drift') as drift:
            verify.run_cli(['cloudlab', 'argo'])
        fresh.assert_called_once_with('cloudlab')
        drift.assert_called_once_with()


class OperatorDriftTests(unittest.TestCase):
    def test_drift_fixture_changes_only_a_declared_metadata_label(self):
        original = {'metadata': {'uid': 'retained', 'labels': {'app.kubernetes.io/version': 'fixture'},
                    'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-external-secrets:fixture'}},
                    'spec': {'replicas': 1}}
        with patch.object(verify, 'kubectl', side_effect=[original, None, original, original]) as kube, \
                patch.object(verify, 'wait', side_effect=lambda check: self.assertTrue(check())), \
                contextlib.redirect_stdout(io.StringIO()):
            verify.operator_drift()
        changed = json.loads(kube.call_args_list[1].args[-1])
        self.assertEqual(changed, {'metadata': {'labels': {'app.kubernetes.io/version': 'drift-fixture'}}})

    def test_replaced_operator_cannot_pass_drift_proof(self):
        original = {'metadata': {'uid': 'retained', 'labels': {'app.kubernetes.io/version': 'fixture'},
                    'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-external-secrets:fixture'}},
                    'spec': {'replicas': 1}}
        replaced = copy.deepcopy(original)
        replaced['metadata']['uid'] = 'replacement'
        with patch.object(verify, 'kubectl', side_effect=[original, None, replaced, replaced]), \
                patch.object(verify, 'wait', side_effect=lambda check: check()), \
                self.assertRaisesRegex(RuntimeError, 'identity or spec'):
            verify.operator_drift()
