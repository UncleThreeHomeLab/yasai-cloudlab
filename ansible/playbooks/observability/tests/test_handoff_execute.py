"""Execution authority, native scope and interruption boundaries; no credentials."""
from contextlib import nullcontext
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from playbooks.observability.files import handoff as h, handoff_execute as execution


class ExecutionTests(unittest.TestCase):
    def test_native_adapter_rejects_api_escape_root_writes_and_unacknowledged_absence(self):
        io = execution.NativeIO('a' * 16)
        with patch.object(io, 'command') as command:
            for path in ('https://untrusted.invalid/api/v1/pods', '/api/v1/namespaces/../secrets',
                    '/api/v1/namespaces/private/secrets', '/api/v1/namespaces/argocd/pods?labelSelector=app=anything'):
                with self.subTest(path=path), self.assertRaises(RuntimeError): io.request(path)
            for name in ('cloudlab-public-root', 'cloudlab-observability-gitops'):
                with self.assertRaises(RuntimeError):
                    io.request(execution.transport.APPS + name, 'PATCH', [], 'application/json-patch+json')
            command.assert_not_called()
            command.return_value = b''
            self.assertIsNone(io.request('/api/v1/namespaces/argocd/pods/absent'))
            with self.assertRaises(RuntimeError): io.request('/api/v1/namespaces/argocd/pods')
            command.side_effect = RuntimeError('API unavailable')
            with self.assertRaisesRegex(RuntimeError, 'API unavailable'):
                io.request('/api/v1/namespaces/argocd/pods/absent')

    def test_caller_deadline_bounds_subprocess_and_native_request_timeout(self):
        io = execution.NativeIO('a' * 16)
        clock = Mock(return_value=100.0)
        with patch.object(execution.time, 'monotonic', clock), \
                patch.object(execution.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'{}', stderr=b'')) as run:
            with io.bounded(125.0):
                clock.return_value = 124.5
                io.command(['get', 'pods'], timeout=30)
                self.assertEqual(run.call_args.kwargs['timeout'], 0.5)
                self.assertIn('--request-timeout=0.5s', run.call_args.args[0])
                clock.return_value = 125.0
                with self.assertRaisesRegex(RuntimeError, 'deadline expired'): io.command(['get', 'pods'])
                self.assertEqual(run.call_count, 1)
        self.assertIsNone(io.deadline)

    def test_source_receipts_do_not_authorize_workload_mutation(self):
        with patch.object(execution, 'check_continuation', return_value=None), \
                patch.object(execution, 'NativeIO') as native:
            with self.assertRaisesRegex(RuntimeError, 'no execution authority'):
                execution.require_execution(Path('/var/lib/cloudlab/observability/handoff-' + 'a' * 16))
            native.assert_not_called()

    def test_failed_native_preflight_cannot_create_fence(self):
        operation = 'a' * 16
        applications = {name: {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
            'metadata': {'name': name, 'namespace': 'argocd', 'uid': '%08x-0000-0000-0000-000000000000' % i,
                'resourceVersion': str(i)},
            'spec': {'fixture': name}} for i, name in enumerate(execution.transport.CHILDREN, 1)}
        bundle = {'operationId': operation}
        intent = {'applicationBindings': applications, 'prepared': {'bundleSHA256': h.digest(h.canonical(bundle))}}
        with patch.object(h, 'writer_locks', return_value=nullcontext()), \
                patch.object(h, 'private_path', return_value=None), patch.object(h, 'phase_head', return_value=None), \
                patch.object(h, 'verify_bundle', return_value=bundle), patch.object(h, 'phase_json', return_value=intent), \
                patch.object(h, 'qualification_files'), patch.object(execution.writer_guard, 'check_fence'), \
                patch.object(execution, 'production_preflight', side_effect=RuntimeError('Operator watch could not be authenticated')), \
                patch.object(execution, 'scope_gate', return_value={'targetClusterUID': '00000063-0000-0000-0000-000000000000',
                    'qualificationScope': {'kind': 'full-entrypoint-integration'}}), \
                patch.object(execution, 'original_baseline_export'), patch.object(execution, 'NativeIO') as native, \
                patch.object(h, 'write_once') as write:
            native.return_value.request.side_effect = lambda path: copy.deepcopy(applications[path.rsplit('/', 1)[1]])
            with self.assertRaisesRegex(RuntimeError, 'Operator watch could not be authenticated'):
                execution.authorize(Path('/var/lib/cloudlab/observability/handoff-' + operation))
            write.assert_not_called()

    def scope_fixture(self):
        declared = '00000063-0000-0000-0000-000000000000'
        scope = {'kind': 'mechanism-rehearsal', 'targetClusterUIDSHA256': h.digest(declared.encode('ascii'))}
        refs = {name: {'profile': name} for name in h.QUALIFICATIONS}
        refs['handoff'].update(scope=scope, codeRevision='a' * 40)
        evidence = {'version': 'cloudlab-observability-handoff-evidence/v1', 'scope': scope, 'observedClusterUID': declared,
            'componentReferencesSHA256': {name: h.digest(h.canonical(refs[name])) for name in h.QUALIFICATIONS if name != 'handoff'},
            'coverage': {'codeRevision': 'a' * 40}}
        raw = h.canonical(evidence)
        refs['handoff']['artifactDigests'] = {h.HANDOFF_EVIDENCE: h.digest(raw)}
        bundle = {'operationId': 'a' * 16}
        intent = {'operationId': 'a' * 16, 'phase': 'baseline', 'previousPhaseSHA256': None,
            'prepared': {'bundleSHA256': h.digest(h.canonical(bundle)), 'profiles': {'acceptedArtifacts': refs}},
            'qualifications': {'references': refs}}
        binding = {'operationId': 'a' * 16, 'targetClusterUID': declared, 'intentSHA256': h.digest(h.canonical(intent))}
        discovery = {'version': 'cloudlab-observability-discovery/v1', 'operationId': 'a' * 16,
            'intentSHA256': binding['intentSHA256'], 'targetClusterUID': declared, 'qualificationScope': scope, 'stage': 'bound'}
        return intent, raw, binding, discovery, bundle

    def test_wrong_cluster_blocks_initial_read_credentials_and_permanent_fence(self):
        intent, raw, binding, discovery, bundle = self.scope_fixture()
        directory = Path('/var/lib/cloudlab/observability/handoff-' + 'a' * 16)
        wrong = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'kube-system',
            'uid': '00000064-0000-0000-0000-000000000000'}}
        def phase_json(path):
            return binding if path.name == 'target-cluster.json' else discovery if path.name == 'initial-discovery.json' else intent
        with patch.object(h, 'writer_locks', return_value=nullcontext()), patch.object(h, 'private_path', return_value=None), \
                patch.object(h, 'phase_head', return_value=None), patch.object(h, 'verify_bundle', return_value=bundle), \
                patch.object(h, 'phase_json', side_effect=phase_json), patch.object(h, 'qualification_files'), \
                patch.object(h, 'read_private', return_value=raw), patch.object(execution, 'target_from_draft', return_value=binding), \
                patch.object(execution.writer_guard, 'check_fence'), patch.object(execution, 'NativeIO') as native, \
                patch.object(execution.transport, 'prepare') as grant, patch.object(execution, 'production_preflight') as preflight, \
                patch.object(h, 'write_once') as write:
            native.return_value.request.return_value = wrong
            with self.assertRaisesRegex(RuntimeError, 'Mechanism qualification cannot grant discovery on this cluster'):
                execution.collect_phase(directory, 'baseline')
            with self.assertRaisesRegex(RuntimeError, 'Live target cluster identity differs'):
                execution.authorize(directory)
            grant.assert_not_called(); preflight.assert_not_called(); write.assert_not_called()
            self.assertTrue(all(call.args == ('/api/v1/namespaces/kube-system',) for call in native.return_value.request.call_args_list))

    def test_continuation_rechecks_live_cluster_and_rejects_unknown_scope(self):
        intent, raw, binding, discovery, bundle = self.scope_fixture()
        directory = Path('/var/lib/cloudlab/observability/handoff-' + 'a' * 16)
        authorization = {'version': execution.VERSION, 'operationId': 'a' * 16, 'expires': 1000,
            'bundleSHA256': h.digest(h.canonical(bundle)), 'sourceSHA256': h.digest(b'{}'), 'baselineSHA256': h.digest(b'{}'),
            'targetClusterUID': binding['targetClusterUID'], 'qualificationScope': discovery['qualificationScope']}
        def private(path, *args):
            if path == execution.writer_guard.RETIREMENT_FENCE: return h.canonical(authorization)
            return raw if path.name == h.HANDOFF_EVIDENCE else b'{}'
        def phase_json(path):
            return binding if path.name == 'target-cluster.json' else discovery if path.name == 'initial-discovery.json' else intent
        with patch.object(h, 'private_path', return_value=True), patch.object(execution, 'state', return_value={
                'authorization': authorization, 'steps': {}, 'phases': {}}), patch.object(h, 'read_private', side_effect=private), \
                patch.object(h, 'verify_bundle', return_value=bundle), patch.object(h, 'phase_json', side_effect=phase_json), \
                patch.object(h, 'qualification_files'), patch.object(execution, 'target_from_draft', return_value=binding), \
                patch.object(execution.time, 'time', return_value=500), patch.object(execution, 'NativeIO') as native:
            native.return_value.request.return_value = {'apiVersion': 'v1', 'kind': 'Namespace',
                'metadata': {'name': 'kube-system', 'uid': '00000064-0000-0000-0000-000000000000'}}
            with self.assertRaisesRegex(RuntimeError, 'Live target cluster identity differs'):
                execution.check_continuation(directory)
            evidence = h.strict_json(raw)
            evidence['scope']['kind'] = 'unsupported'
            intent['prepared']['profiles']['acceptedArtifacts']['handoff']['scope'] = evidence['scope']
            raw = h.canonical(evidence)
            intent['prepared']['profiles']['acceptedArtifacts']['handoff']['artifactDigests'][h.HANDOFF_EVIDENCE] = h.digest(raw)
            native.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'Unknown handoff qualification scope'):
                execution.check_continuation(directory)
            native.return_value.request.assert_not_called()

    def test_failed_initial_discovery_cannot_grant_credentials_again(self):
        intent, raw, binding, discovery, bundle = self.scope_fixture()
        discovery['stage'] = 'failed'
        directory = Path('/var/lib/cloudlab/observability/handoff-' + 'a' * 16)
        io = Mock()
        io.request.return_value = {'apiVersion': 'v1', 'kind': 'Namespace',
            'metadata': {'name': 'kube-system', 'uid': binding['targetClusterUID']}}
        with patch.object(h, 'phase_head', return_value=None), patch.object(h, 'private_path', side_effect=lambda path, **_:
                True if path.name == 'initial-discovery.json' else None), patch.object(h, 'phase_json', return_value=discovery), \
                patch.object(h, 'read_private', return_value=raw), patch.object(h, 'write_once') as write:
            with self.assertRaisesRegex(RuntimeError, 'Initial discovery is terminal or changed'):
                execution.initial_discovery(io, directory, intent, {})
            write.assert_not_called()

    def test_cas_records_intent_before_request_and_refuses_changed_uid_on_resume(self):
        before = self.application('cloudlab-prometheus', 1)
        before['metadata']['resourceVersion'] = '7'
        before['spec'] = {'held': False}
        after = copy.deepcopy(before)
        after['spec'] = {'held': True}; after['metadata']['annotations']['operation'] = 'accepted'
        returned = copy.deepcopy(after); returned['metadata']['resourceVersion'] = '8'
        journal = {'steps': {}}
        saved = []
        io = Mock()
        def request(path, method='GET', body=None, content_type=None):
            if method == 'GET': return copy.deepcopy(before)
            self.assertEqual(saved[-1]['steps']['hold']['acknowledged'], False)
            self.assertEqual(body[:3], [{'op': 'test', 'path': '/metadata/uid', 'value': before['metadata']['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'},
                {'op': 'test', 'path': '/spec', 'value': {'held': False}}])
            return returned
        io.request.side_effect = request
        with patch.object(execution, 'persist', side_effect=lambda _directory, value: saved.append(copy.deepcopy(value))):
            execution.mutation(Path('/unused'), journal, 'hold', io, '/accepted', before, after,
                [{'op': 'add', 'path': '/metadata/annotations', 'value': after['metadata']['annotations']},
                 {'op': 'replace', 'path': '/spec', 'value': after['spec']}])
            self.assertTrue(journal['steps']['hold']['acknowledged'])
            io.request.side_effect = None
            io.request.return_value = dict(returned, metadata=dict(returned['metadata'], uid='foreign'))
            with self.assertRaisesRegex(RuntimeError, 'UID changed'):
                execution.mutation(Path('/unused'), journal, 'hold', io, '/accepted', before, after, [])

    def application(self, name, number):
        return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
            'metadata': {'name': name, 'namespace': 'argocd', 'uid': '%08x-0000-0000-0000-000000000000' % number,
                'resourceVersion': str(number), 'labels': {'cloudlab.io/owner': 'observability-platform'},
                'annotations': {'argocd.argoproj.io/skip-reconcile': 'false'}},
            'spec': {'source': {'targetRevision': 'a' * 40}, 'syncPolicy': {'automated': copy.deepcopy(execution.HOLD)}}}

    def test_metadata_only_committed_patch_lost_ack_resumes_without_another_write(self):
        before = self.application('cloudlab-prometheus', 1)
        after = copy.deepcopy(before)
        after['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'] = 'true'
        live = copy.deepcopy(before)
        journal = {'steps': {}}
        writes = []
        def request(path, method='GET', body=None, content_type=None):
            if method == 'GET': return copy.deepcopy(live)
            writes.append(copy.deepcopy(body))
            self.assertEqual(body[1]['value'], live['metadata']['resourceVersion'])
            live['metadata']['annotations'] = copy.deepcopy(body[3]['value'])
            live['metadata']['resourceVersion'] = '2'
            raise RuntimeError('PATCH acknowledgement lost')
        io = Mock(); io.request.side_effect = request
        patch_body = [{'op': 'add', 'path': '/metadata/annotations', 'value': after['metadata']['annotations']}]
        with patch.object(execution, 'persist'):
            with self.assertRaisesRegex(RuntimeError, 'PATCH acknowledgement lost'):
                execution.mutation(Path('/unused'), journal, 'hold', io, '/accepted', before, after, patch_body)
            row = journal['steps']['hold']
            self.assertFalse(row['acknowledged']); self.assertTrue(row['patchRequested'])
            self.assertEqual(row['intent']['beforeSpecSHA256'], row['intent']['afterSpecSHA256'])
            self.assertNotEqual(row['intent']['beforeMetadata'], row['intent']['afterMetadata'])
            committed = copy.deepcopy(live)
            live['metadata']['annotations']['foreign.example/change'] = 'unaccepted'
            with self.assertRaisesRegex(RuntimeError, 'Mutation precondition changed'):
                execution.mutation(Path('/unused'), journal, 'hold', io, '/accepted', before, after, patch_body)
            live.clear(); live.update(committed)
            execution.mutation(Path('/unused'), journal, 'hold', io, '/accepted', before, after, patch_body)
            self.assertTrue(row['acknowledged']); self.assertEqual(row['outcome'], 'observed-after')
            self.assertEqual(len(writes), 1)

    def test_true_no_op_is_observed_without_claiming_a_patch_acknowledgement(self):
        before = self.application('cloudlab-prometheus', 1)
        current = copy.deepcopy(before); current['metadata']['resourceVersion'] = '9'
        io = Mock(); io.request.return_value = current
        journal = {'steps': {}}
        with patch.object(execution, 'persist'):
            for _ in range(2):
                execution.mutation(Path('/unused'), journal, 'hold', io, '/accepted', before, before, [])
        row = journal['steps']['hold']
        self.assertEqual(row['outcome'], 'no-op'); self.assertFalse(row['patchRequested'])
        self.assertEqual(row['intent']['beforeResourceVersion'], '9')
        self.assertTrue(all(call.args == ('/accepted',) for call in io.request.call_args_list))

    def test_apply_holds_use_fresh_status_rv_and_reject_changed_uid_or_spec(self):
        accepted = {name: self.application(name, i) for i, name in enumerate(execution.transport.CHILDREN, 1)}
        desired = copy.deepcopy(accepted)
        for obj in desired.values(): obj['spec']['source']['targetRevision'] = 'b' * 40
        intent = {'operationId': 'a' * 16, 'applicationBindings': accepted}
        payload = {'phaseApplications': desired}
        collector = {'context': {}, 'collected': {}, 'objects': {'job': {'identity': {}}}, 'sourcePayloadSHA256': '1' * 64}
        draft = {'intentSHA256': h.digest(h.canonical(intent)), 'payloadSHA256': h.digest(h.canonical(payload)),
            'custody': h.collection_binding(collector)}
        def phase_json(path):
            return payload if path.name.endswith('.draft-payload.json') else draft if path.name.endswith('.draft.json') else collector
        for changed in (None, 'uid', 'spec'):
            journal = {'steps': {}, 'phases': {}}
            live = copy.deepcopy(accepted)
            for obj in live.values(): obj['metadata']['resourceVersion'] = str(int(obj['metadata']['resourceVersion']) + 100)
            if changed == 'uid': live[execution.transport.CHILDREN[-1]]['metadata']['uid'] = '000003e7-0000-0000-0000-000000000000'
            if changed == 'spec': live[execution.transport.CHILDREN[-1]]['spec']['source']['targetRevision'] = 'f' * 40
            writes = []
            def request(path, method='GET', body=None, content_type=None):
                obj = live[path.rsplit('/', 1)[1]]
                if method == 'GET': return copy.deepcopy(obj)
                writes.append(copy.deepcopy(body))
                for row in body:
                    if row['op'] == 'test':
                        actual = obj['metadata'][row['path'].split('/')[-1]] if row['path'].startswith('/metadata/') else obj['spec']
                        self.assertEqual(actual, row['value'])
                    elif row['path'] == '/spec': obj['spec'] = copy.deepcopy(row['value'])
                    elif row['path'] == '/metadata/annotations': obj['metadata']['annotations'] = copy.deepcopy(row['value'])
                obj['metadata']['resourceVersion'] = str(int(obj['metadata']['resourceVersion']) + 1)
                return copy.deepcopy(obj)
            io = Mock(); io.request.side_effect = request
            original = h.canonical(accepted)
            with self.subTest(changed=changed), patch.object(h, 'writer_locks', return_value=nullcontext()), \
                    patch.object(execution, 'phase_authority', return_value=(journal, intent)), \
                    patch.object(h, 'phase_json', side_effect=phase_json), patch.object(execution, 'NativeIO', return_value=io), \
                    patch.object(execution, 'persist'):
                if changed:
                    expected_error = 'Application source escaped the fixed held closure' if changed == 'uid' else 'Application metadata or specification changed before holds'
                    with self.assertRaisesRegex(RuntimeError, expected_error): execution.apply_applications(Path('/unused'), 'baseline')
                    self.assertFalse(writes)
                else:
                    execution.apply_applications(Path('/unused'), 'baseline')
                    for name, obj in accepted.items():
                        row = journal['steps']['baseline:hold:' + name]
                        self.assertEqual(row['intent']['beforeResourceVersion'], str(int(obj['metadata']['resourceVersion']) + 100))
                        self.assertEqual(live[name]['spec'], desired[name]['spec'])
                    self.assertEqual(len(writes), 12)
                self.assertEqual(h.canonical(accepted), original)

    def test_cleanup_accepts_only_native_housekeeping_api_groups_and_discovery(self):
        operation = 'a' * 16
        namespace = execution.transport.namespace(operation)
        def metadata(name, number):
            return {'name': name, 'namespace': namespace, 'uid': '%08x-0000-0000-0000-000000000000' % number,
                'resourceVersion': str(number), 'managedFields': [{'manager': 'kube-controller-manager'}]}
        ns = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': metadata(namespace, 1), 'spec': {}}
        ns['metadata'].pop('namespace')
        ns['metadata']['labels'] = {'cloudlab.io/owner': execution.transport.OWNER, execution.transport.LABEL: operation,
            'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
            'istio-injection': 'disabled'}
        root = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'kube-root-ca.crt', 'namespace': 'argocd'},
            'data': {'ca.crt': 'fixture-root'}}
        reference = {'kind': 'Pod', 'name': 'native-manifests-fixture', 'namespace': namespace,
            'uid': '00000006-0000-0000-0000-000000000000'}
        native = {'serviceaccounts': {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': metadata('default', 2)},
            'configmaps': {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata('kube-root-ca.crt', 3), 'data': root['data']},
            'events': {'apiVersion': 'v1', 'kind': 'Event', 'metadata': metadata('core-event', 4), 'involvedObject': reference},
            'events.events.k8s.io': {'apiVersion': 'events.k8s.io/v1', 'kind': 'Event', 'metadata': metadata('native-event', 5), 'regarding': reference}}
        cases = [(None, False, decoding) for decoding in ('explicit', 'absent', 'wrong-version', 'wrong-kind', 'empty-version', 'empty-kind')]
        cases += [(foreign, injected, 'explicit') for foreign in ('serviceaccounts', 'configmaps', 'events') for injected in (False, True)]
        for foreign, injected, decoding in cases:
            inventory = copy.deepcopy(native if foreign is None else {foreign: native[foreign]})
            if foreign:
                inventory[foreign]['apiVersion'] = 'foreign.example/v1'
                inventory[foreign + '.foreign.example'] = inventory.pop(foreign)
            record = {'context': {'operation': operation}, 'objects': {'namespace': {'path': '/api/v1/namespaces/' + namespace,
                'identity': execution.transport.identity(ns), 'fingerprint': execution.transport.fingerprint(ns)}},
                'cleanupPodUIDs': [reference['uid']]}
            deleted = []
            def request(path, method='GET', body=None, content_type=None):
                if path == '/api/v1/namespaces/' + namespace:
                    if method == 'DELETE': deleted.append(path); return {'status': 'Success'}
                    return None if deleted else copy.deepcopy(ns)
                if path == '/api/v1/namespaces/argocd/configmaps/kube-root-ca.crt': return root
                raise AssertionError('Unexpected cleanup target ' + path)
            def command(args, **options):
                if args[0] == 'api-resources': return ('\n'.join(inventory) + '\n').encode()
                resource = args[2].rsplit('/', 1)[1] if args[1] == '--raw' else args[1]
                key = 'events.events.k8s.io' if args[1] == '--raw' and '/apis/events.k8s.io/' in args[2] else resource
                obj = inventory[key]
                item = copy.deepcopy(obj)
                if decoding == 'absent':
                    item.pop('apiVersion'); item.pop('kind')
                if decoding == 'wrong-version': item['apiVersion'] = 'foreign.example/v1'
                if decoding == 'wrong-kind': item['kind'] = 'ForeignObject'
                if decoding == 'empty-version': item['apiVersion'] = ''
                if decoding == 'empty-kind': item['kind'] = ''
                return h.canonical({'apiVersion': obj['apiVersion'],
                    'kind': obj['kind'] + 'List', 'metadata': {}, 'items': [item]})
            io = Mock(operation=operation, namespace=namespace)
            io.request.side_effect = request; io.command.side_effect = command
            boundary = patch.object(execution, 'namespace_inventory', return_value=list(inventory.values())) if injected else nullcontext()
            with self.subTest(foreign=foreign, injected=injected, decoding=decoding), patch.object(h, 'atomic_private'), boundary:
                if foreign or decoding not in ('explicit', 'absent'):
                    error = 'Unknown transport namespace object retained' if injected else 'Foreign API group or kind remains'
                    with self.assertRaisesRegex(RuntimeError, error): execution.finish_transport(Path('/unused'), Path('/unused/record'), io, record)
                    self.assertFalse(deleted)
                else:
                    execution.finish_transport(Path('/unused'), Path('/unused/record'), io, record)
                    self.assertEqual(deleted, ['/api/v1/namespaces/' + namespace])
                    self.assertTrue(record['namespaceAbsent'])


if __name__ == '__main__':
    unittest.main()
