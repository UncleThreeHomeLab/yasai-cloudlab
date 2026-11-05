"""Fresh-client and SRV controls distinguish captured forwarding from cached A."""
import base64
import copy
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from verification.integration import workload_egress as proof

RUN = 'a' * 32
OLD = '11111111-1111-1111-1111-111111111111'
NEW = '22222222-2222-2222-2222-222222222222'
NAMESPACE = '33333333-3333-3333-3333-333333333333'


class FreshClientTests(unittest.TestCase):
    def exercise(self, receipt, address, *, lost_delete=False, capture=True):
        row = receipt.value['namespaces']['source']
        row.update(uid=NAMESPACE, phase='created', objects={'v1/Pod/allowed': OLD})
        ns = copy.deepcopy(row['profile'])
        ns['metadata']['uid'] = NAMESPACE
        namespace = ns['metadata']['name']
        source = proof.placed_pod(namespace, 'allowed', 'image', 'allowed', 'second-host', RUN)
        source['metadata'].update(uid=OLD, labels={proof.MARKER: RUN})
        source['status'] = {'phase': 'Running', 'podIP': '10.42.1.2', 'conditions': [{'type': 'Ready', 'status': 'True'}]}
        state = {'allowed': source}
        receipt.value['proof']['client'] = {'active': 'allowed', 'seen_ips': ['10.42.1.2'], 'retirements': []}
        receipt.save()
        rpc = Mock(deadline=time.monotonic() + 60)
        rpc.pods = {(namespace, 'allowed'): (OLD, RUN)}
        rpc.pod_ips = {(namespace, 'allowed'): '10.42.1.2'}
        def get(kind, name, selected_namespace=None):
            return ns if kind == 'namespace' else state.get(name)
        rpc.get.side_effect = get
        def call(arguments, document):
            self.assertTrue(arguments[2].endswith('/pods/allowed'))
            self.assertEqual(document['preconditions'], {'uid': OLD})
            saved = json.loads(receipt.path.read_text())
            self.assertEqual(saved['proof']['client']['retirements'][-1]['phase'], 'retire-pending')
            state.pop('allowed')
            if lost_delete: raise RuntimeError('response lost')
        rpc.call.side_effect = call
        def write(verb, pod):
            self.assertEqual(verb, 'create')
            self.assertNotIn('allowed', state)
            saved = json.loads(receipt.path.read_text())
            self.assertIsNone(saved['namespaces']['source']['objects']['v1/Pod/' + pod['metadata']['name']])
            current = copy.deepcopy(pod)
            current['metadata'].update(uid=NEW, resourceVersion='1')
            current['metadata'].setdefault('annotations', {})['ambient.istio.io/redirection'] = 'enabled'
            if not capture: current['metadata']['annotations']['ambient.istio.io/dns-capture'] = 'false'
            current['spec']['nodeName'] = 'second-node'
            current['spec']['dnsPolicy'] = 'ClusterFirst'
            current['status'] = {'phase': 'Running', 'podIP': address,
                                 'conditions': [{'type': 'Ready', 'status': 'True'}]}
            state[current['metadata']['name']] = current
            self.assertLessEqual(len(state), 1)
            return current
        rpc.write.side_effect = write
        return rpc, state

    def test_replacement_is_intent_first_uid_bound_and_keeps_late_report_history(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                rpc, state = self.exercise(receipt, '10.42.1.3')
                current = proof.fresh_client(rpc, receipt, 'image', {'hostname': 'second-host', 'name': 'second-node'})
                self.assertNotEqual(current, 'allowed')
                self.assertEqual(proof.current_client(receipt), current)
                self.assertEqual(receipt.value['namespaces']['source']['objects']['v1/Pod/allowed'], OLD)
                self.assertEqual(receipt.value['namespaces']['source']['objects']['v1/Pod/' + current], NEW)
                self.assertEqual(set(state), {current})
                proof.validate_history(receipt.value)
                report = {'owners': [{'apiVersion': 'v1', 'kind': 'Pod', 'name': 'allowed', 'uid': OLD}], 'manager': 'kyverno'}
                self.assertTrue(proof.mesh_or_policy_child('wgpolicyk8s.io/v1alpha2/PolicyReport/late', '', report,
                                                          [], receipt.value['namespaces']['source']['objects'], RUN))
            finally: receipt.close()

    def test_reused_ip_fails_with_candidate_still_recorded_for_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                rpc, state = self.exercise(receipt, '10.42.1.2')
                with self.assertRaisesRegex(proof.ProofFailure, 'IP reused'):
                    proof.fresh_client(rpc, receipt, 'image', {'hostname': 'second-host', 'name': 'second-node'})
                current = next(iter(state))
                self.assertEqual(receipt.value['namespaces']['source']['objects']['v1/Pod/' + current], NEW)
                self.assertEqual(receipt.value['proof']['client']['retirements'][-1]['new_ip'], '10.42.1.2')
                proof.validate_history(receipt.value)
            finally: receipt.close()

    def test_lost_delete_response_never_starts_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                rpc, state = self.exercise(receipt, '10.42.1.3', lost_delete=True)
                with self.assertRaisesRegex(RuntimeError, 'response lost'):
                    proof.fresh_client(rpc, receipt, 'image', {'hostname': 'second-host', 'name': 'second-node'})
                rpc.write.assert_not_called()
                self.assertEqual(receipt.value['proof']['client']['retirements'][-1]['phase'], 'retire-pending')
                proof.validate_history(receipt.value)
            finally: receipt.close()

    def test_replacement_cannot_turn_the_captured_proof_into_an_optout_client(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                rpc, state = self.exercise(receipt, '10.42.1.3', capture=False)
                with self.assertRaisesRegex(proof.ProofFailure, 'capture differs'):
                    proof.fresh_client(rpc, receipt, 'image', {'hostname': 'second-host', 'name': 'second-node'})
                self.assertEqual(len(state), 1)
                proof.validate_history(receipt.value)
            finally: receipt.close()

    def test_version_one_cleanup_receipts_remain_loadable(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                receipt.value['version'] = 1
                receipt.value.pop('proof')
                receipt.save()
                receipt.load('target')
                self.assertEqual(receipt.value['version'], 1)
            finally: receipt.close()

    def test_ip_changes_during_a_phase_abort_instead_of_becoming_a_denial(self):
        rpc = proof.RPC('host', time.monotonic() + 60)
        rpc.pods[('source', 'allowed')] = (OLD, RUN)
        rpc.pod_ips[('source', 'allowed')] = '10.42.1.2'
        current = {'metadata': {'uid': OLD, 'labels': {proof.MARKER: RUN}},
                   'status': {'phase': 'Running', 'podIP': '10.42.1.3',
                              'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        with patch.object(rpc, 'get', return_value=current), patch.object(rpc, 'call') as call:
            with self.assertRaisesRegex(proof.ProofFailure, 'IP changed'):
                rpc.exec('source', 'allowed', 'fixed-probe')
        call.assert_not_called()


class NamedPortTests(unittest.TestCase):
    def test_only_port_name_changes_with_uid_version_and_full_spec_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                row = receipt.value['namespaces']['plain']
                row.update(uid=NAMESPACE, phase='created', objects={'v1/Service/backend': OLD})
                ns = copy.deepcopy(row['profile'])
                ns['metadata']['uid'] = NAMESPACE
                service = proof.fixtures.service(ns['metadata']['name'])
                service['metadata'].update(uid=OLD, resourceVersion='1', labels={proof.MARKER: RUN})
                service['spec'].update(clusterIP='10.43.0.8', clusterIPs=['10.43.0.8'], type='ClusterIP')
                service['spec']['ports'][0]['protocol'] = 'TCP'
                original = copy.deepcopy(service['spec'])
                rpc = Mock()
                rpc.get.side_effect = lambda kind, name, namespace=None: copy.deepcopy(ns if kind == 'namespace' else service)
                def call(arguments, patch):
                    self.assertEqual(patch[:3], [{'op': 'test', 'path': '/metadata/uid', 'value': OLD},
                                               {'op': 'test', 'path': '/metadata/resourceVersion', 'value': service['metadata']['resourceVersion']},
                                               {'op': 'test', 'path': '/spec', 'value': service['spec']}])
                    self.assertEqual(patch[3]['path'], '/spec/ports/0/name')
                    saved = json.loads(receipt.path.read_text())
                    self.assertEqual(saved['proof']['service']['intended'], patch[3]['value'])
                    service['spec']['ports'][0]['name'] = patch[3]['value']
                    service['metadata']['resourceVersion'] = str(int(service['metadata']['resourceVersion']) + 1)
                    return json.dumps(service)
                rpc.call.side_effect = call
                qname = proof.rename_service_port(rpc, receipt, 'h-' + 'b' * 12)
                self.assertTrue(qname.startswith('_h-' + 'b' * 12 + '._tcp.'))
                expected = copy.deepcopy(original)
                expected['ports'][0]['name'] = 'h-' + 'b' * 12
                self.assertEqual(service['spec'], expected)
                with self.assertRaisesRegex(proof.ProofFailure, 'reused'):
                    proof.rename_service_port(rpc, receipt, 'h-' + 'b' * 12)
                service['spec']['clusterIPs'] = ['10.43.0.9']
                rpc.call.reset_mock()
                with self.assertRaisesRegex(proof.ProofFailure, 'immutable'):
                    proof.rename_service_port(rpc, receipt, 'h-' + 'c' * 12)
                rpc.call.assert_not_called()
            finally: receipt.close()


class SrvTests(unittest.TestCase):
    name = '_h-abcdef123456._tcp.backend.plain.svc.cluster.local'
    target = 'backend.plain.svc.cluster.local'

    def response(self, *, port=8080, target=None, code=0):
        query = proof.question(self.name, qtype=33)
        raw = bytearray(query)
        raw[2:4] = struct.pack('!H', 0x8180 | code)
        if not code:
            raw[6:8] = struct.pack('!H', 1)
            target = target or self.target
            encoded = b''.join(bytes([len(label)]) + label.encode() for label in target.split('.')) + b'\0'
            value = struct.pack('!HHH', 0, 100, port) + encoded
            raw += b'\xc0\x0c' + struct.pack('!HHIH', 33, 1, 5, len(value)) + value
        return query, struct.pack('!H', len(raw)) + raw

    def test_tcp_exact_srv_servfail_and_closed_error_cases(self):
        query, raw = self.response()
        self.assertEqual(proof.dns_response(raw, query, self.target, 8080), 'success')
        query, raw = self.response(code=2)
        self.assertEqual(proof.dns_response(raw, query, self.target, 8080), 'candidate')
        for options in ({'port': 8081}, {'target': 'foreign.svc.cluster.local'}, {'code': 3}, {'code': 5}):
            query, raw = self.response(**options)
            with self.subTest(options=options), self.assertRaises(proof.ProofFailure):
                proof.dns_response(raw, query, self.target, 8080)
        query, raw = self.response()
        with self.assertRaises(proof.ProofFailure): proof.dns_response(raw[:-1], query, self.target, 8080)

    def test_udp_exact_srv_and_candidate_failures_do_not_accept_cached_a_or_nxdomain(self):
        valid = (self.name + ' service = 0 100 8080 ' + self.target + '.\n').encode()
        self.assertEqual(proof.srv_text(0, valid, self.name, self.target, 8080), 'success')
        for code, text in ((1, b'SERVFAIL'), (1, b'connection timed out'), (124, b'')):
            self.assertEqual(proof.srv_text(code, text, self.name, self.target, 8080), 'candidate')
        for code, text in ((0, b'Address: 10.43.0.8'), (1, b'NXDOMAIN'), (0, valid.replace(b'8080', b'8081')),
                           (0, valid.replace(self.target.encode(), b'foreign.svc.cluster.local')), (127, b'not found')):
            with self.subTest(text=text), self.assertRaises(proof.ProofFailure):
                proof.srv_text(code, text, self.name, self.target, 8080)

    def test_every_source_retry_uses_a_new_named_port_and_question(self):
        rpc = Mock(deadline=time.monotonic() + 60)
        receipt = Mock()
        receipt.value = {'proof': {'client': {'active': 'allowed-current'}}}
        names = {'plain': 'plain', 'source': 'source'}
        questions, source_names = [], []
        outcomes = iter(('candidate', 'candidate', 'success'))
        def rename(rpc, receipt, name):
            self.assertNotIn(name, questions)
            questions.append(name)
            return '_' + name + '._tcp.backend.plain.svc.cluster.local'
        def probe(rpc, namespace, pod, resolver, name, target, tcp):
            if namespace == 'plain': return 'success'
            self.assertNotIn(name, source_names)
            source_names.append(name)
            return next(outcomes)
        with patch.object(proof, 'rename_service_port', side_effect=rename), patch.object(proof, 'srv_probe', side_effect=probe), \
                patch.object(proof.time, 'sleep'):
            proof.positive_srv(rpc, receipt, names, '10.43.0.10', False)
        self.assertEqual(len(set(source_names)), 3)
        self.assertEqual(len(questions), 3)

    def test_control_nxdomain_waits_for_propagation_before_source_is_queried(self):
        rpc = Mock(deadline=time.monotonic() + 60)
        receipt = Mock()
        receipt.value = {'proof': {'client': {'active': 'allowed-current'}}}
        probe = Mock(side_effect=[proof.ProofFailure('Unexpected NXDOMAIN; name propagation is not denial'),
                                  'success', 'candidate', 'success'])
        with patch.object(proof, 'rename_service_port', return_value=self.name), \
                patch.object(proof, 'srv_probe', probe), patch.object(proof.time, 'sleep'):
            result = proof.fresh_srv_attempt(rpc, receipt, {'plain': 'plain', 'source': 'source'}, '10.43.0.10', True)
        self.assertEqual(result, 'candidate')
        self.assertEqual([call.args[1] for call in probe.call_args_list], ['plain', 'plain', 'source', 'plain'])

    def test_captured_sequence_requires_failure_and_restoration_on_the_same_b_client(self):
        cases = ((['success', 'candidate', 'candidate', 'candidate', 'success'], True),
                 (['success', 'success', 'success'], False),
                 (['success', 'candidate', 'candidate', 'candidate', proof.ProofFailure('bad restore')], False))
        for tcp, outcomes, qualifies in ((tcp, outcomes, qualifies) for tcp in (False, True) for outcomes, qualifies in cases):
            with self.subTest(tcp=tcp, outcomes=outcomes):
                rpc = Mock(deadline=time.monotonic() + 600, evidence={})
                receipt = Mock()
                receipt.value = {'proof': {'client': {'active': 'allowed-a'}}}
                def replace(*args):
                    receipt.value['proof']['client']['active'] = 'allowed-b'
                    return 'allowed-b'
                policy = Mock()
                with patch.object(proof, 'apply_policy', policy), patch.object(proof, 'fresh_client', side_effect=replace), \
                        patch.object(proof, 'fresh_srv_attempt', side_effect=outcomes), patch.object(proof, 'dns_probe', return_value=True), \
                        patch.object(proof, 'rename_service_port') as rename:
                    call = lambda: proof.captured_dns(rpc, receipt, {'plain': 'plain', 'source': 'source'},
                                                      '10.43.0.10', 'image', {}, [], {'namespace': 'kube-system'}, tcp, '10.43.0.8')
                    if qualifies:
                        result = call()
                        self.assertEqual(result['classification'], 'observed-policy-correlated-captured-forwarding-failure')
                        self.assertTrue(result['known_service_a_after_withdrawal'])
                        self.assertEqual(result['upstream_wire_protocol'], 'not-inferred')
                    else:
                        with self.assertRaises(proof.ProofFailure): call()
                        self.assertEqual(rpc.evidence['captured_dns_client_' + ('tcp' if tcp else 'udp')]['classification'], 'unqualified')
                    rename.assert_called_once_with(rpc, receipt, 'http')
                    self.assertEqual(policy.call_count, 3)

    def test_failed_controls_stay_unqualified_even_when_restoration_succeeds(self):
        outer = time.monotonic() + 600
        rpc = Mock(deadline=outer, evidence={})
        receipt = Mock()
        receipt.value = {'proof': {'client': {'active': 'allowed-a'}}}
        def replace(*args):
            self.assertEqual(rpc.deadline, outer - 90)
            receipt.value['proof']['client']['active'] = 'allowed-b'
            return 'allowed-b'
        def attempt(*args):
            if rpc.stage == 'dns-withdrawal-tcp': proof.fail('SRV control failed after source probe; proof unqualified')
            if rpc.stage == 'dns-restoration-tcp': self.assertEqual(rpc.deadline, outer)
            return 'success'
        with patch.object(proof, 'apply_policy'), patch.object(proof, 'fresh_client', side_effect=replace), \
                patch.object(proof, 'fresh_srv_attempt', side_effect=attempt), patch.object(proof, 'rename_service_port'):
            with self.assertRaisesRegex(proof.ProofFailure, 'control failed'):
                proof.captured_dns(rpc, receipt, {'plain': 'plain', 'source': 'source'},
                                   '10.43.0.10', 'image', {}, [], {}, True, '10.43.0.8')
        evidence = rpc.evidence['captured_dns_client_tcp']
        self.assertEqual(evidence['A_restore'], 'same-client-positive-controls-healthy')
        self.assertEqual(evidence['classification'], 'unqualified')
        self.assertEqual(rpc.stage, 'dns-withdrawal-tcp')

    def test_failed_local_service_a_control_never_qualifies_capture_and_still_restores(self):
        for tcp in (False, True):
            with self.subTest(tcp=tcp):
                rpc = Mock(deadline=time.monotonic() + 600, evidence={})
                receipt = Mock()
                receipt.value = {'proof': {'client': {'active': 'allowed-a'}}}
                def replace(*args):
                    receipt.value['proof']['client']['active'] = 'allowed-b'
                    return 'allowed-b'
                with patch.object(proof, 'apply_policy') as policy, \
                        patch.object(proof, 'fresh_client', side_effect=replace), \
                        patch.object(proof, 'fresh_srv_attempt', side_effect=['success', 'candidate', 'candidate', 'candidate', 'success']) as attempt, \
                        patch.object(proof, 'dns_probe', return_value=False) as known_a, \
                        patch.object(proof, 'rename_service_port') as rename:
                    with self.assertRaisesRegex(proof.ProofFailure, 'local-resolution control failed') as error:
                        proof.captured_dns(rpc, receipt, {'plain': 'plain', 'source': 'source'},
                                           '10.43.0.10', 'image', {}, [], {}, tcp, '10.43.0.8')
                evidence = rpc.evidence['captured_dns_client_' + ('tcp' if tcp else 'udp')]
                self.assertFalse(evidence['known_service_a_after_withdrawal'])
                self.assertEqual(evidence['classification'], 'unqualified')
                self.assertEqual(evidence['A_restore'], 'same-client-positive-controls-healthy')
                self.assertEqual(rpc.stage, 'dns-withdrawal-' + ('tcp' if tcp else 'udp'))
                self.assertEqual(proof.safe_reason(error.exception), 'local-resolution-control-failed')
                self.assertEqual(policy.call_count, 3)
                self.assertEqual(attempt.call_count, 5)
                self.assertEqual(known_a.call_args.args[2], 'allowed-b')
                self.assertIs(known_a.call_args.args[-1], tcp)
                rename.assert_called_once_with(rpc, receipt, 'http')

    def test_insufficient_restore_budget_does_not_mutate_dns_authority(self):
        rpc = Mock(deadline=time.monotonic() + 100, evidence={})
        with patch.object(proof, 'apply_policy') as apply:
            with self.assertRaisesRegex(proof.ProofFailure, 'restoration budget'):
                proof.captured_dns(rpc, Mock(), {}, '10.43.0.10', 'image', {}, [], {}, False, '10.43.0.8')
        apply.assert_not_called()


class DnsPreflightTests(unittest.TestCase):
    def test_reviewed_cni_settings_accept_literal_true_and_unrelated_direct_fields(self):
        container = {'envFrom': [{'configMapRef': {'name': 'istio-cni-config'}}],
                     'env': [{'name': 'POD_NAME', 'valueFrom': {'fieldRef': {'fieldPath': 'metadata.name'}}},
                             {'name': 'UNRELATED', 'value': 'private-sentinel'},
                             {'name': 'AMBIENT_ENABLED', 'value': 'true'},
                             {'name': 'AMBIENT_DNS_CAPTURE', 'value': 'true'}]}
        result = proof.cni_dns_settings(container, {'AMBIENT_ENABLED': 'true', 'AMBIENT_DNS_CAPTURE': 'true'})
        self.assertEqual(result, {'ambient_enabled': True, 'ambient_dns_capture': True})
        self.assertNotIn('private-sentinel', json.dumps(result))

    def test_relevant_overrides_cannot_conflict_expand_duplicate_or_read_value_sources(self):
        data = {'AMBIENT_ENABLED': 'true', 'AMBIENT_DNS_CAPTURE': 'true'}
        base = {'envFrom': [{'configMapRef': {'name': 'istio-cni-config'}}]}
        for name in data:
            for entries in ([{'name': name, 'value': 'false'}],
                            [{'name': name, 'value': '$(OTHER)'}],
                            [{'name': name}],
                            [{'name': name, 'valueFrom': {'configMapKeyRef': {'name': 'istio-cni-config', 'key': name}}}],
                            [{'name': name, 'value': 'true'}, {'name': name, 'value': 'true'}],
                            [{'name': name, 'value': 'true', 'unknown': 'ignored-before'}]):
                with self.subTest(name=name, entries=entries), self.assertRaises(proof.ProofFailure):
                    proof.cni_dns_settings(dict(base, env=entries), data)

    def test_extra_prefixed_or_unknown_envfrom_sources_are_not_assumed_safe(self):
        canonical = {'configMapRef': {'name': 'istio-cni-config'}}
        sources = (None, {}, 'istio-cni-config', [],
                   [dict(canonical, prefix='OTHER_')], [dict(canonical, prefix='')],
                   [canonical, {'configMapRef': {'name': 'another'}}],
                   [canonical, {'secretRef': {'name': 'another'}}],
                   [canonical, canonical], [{'unknown': 'source'}])
        for value in sources:
            with self.subTest(envFrom=value), self.assertRaises(proof.ProofFailure):
                proof.cni_dns_settings({'envFrom': value}, {'AMBIENT_ENABLED': 'true', 'AMBIENT_DNS_CAPTURE': 'true'})

    def test_malformed_direct_environment_fails_closed_without_general_expansion(self):
        data = {'AMBIENT_ENABLED': 'true', 'AMBIENT_DNS_CAPTURE': 'true'}
        base = {'envFrom': [{'configMapRef': {'name': 'istio-cni-config'}}]}
        for value in (None, {}, [None], [{}], [{'name': 1}], [{'name': 'OTHER', 'value': True}],
                      [{'name': 'OTHER', 'valueFrom': None}], [{'name': 'OTHER', 'valueFrom': {}}],
                      [{'name': 'OTHER', 'valueFrom': {'fieldRef': {}, 'secretKeyRef': {}}}]):
            with self.subTest(env=value), self.assertRaises(proof.ProofFailure):
                proof.cni_dns_settings(dict(base, env=value), data)

    def test_interpretation_checks_pins_capture_and_fixture_resolver_without_storing_dump(self):
        rpc = Mock()
        cni_overrides = {}
        expected = {}
        for component in ('ztunnel', 'cni'):
            expected[component] = json.loads((proof.ROOT / 'platform/connectivity/istio' / component / 'values.json').read_text())[component]['image']
        def get(kind, name, namespace=None):
            if kind == 'configmap': return {'data': {'AMBIENT_ENABLED': 'true', 'AMBIENT_DNS_CAPTURE': 'true'}}
            container = {'image': expected['ztunnel' if name == 'ztunnel' else 'cni']}
            if name != 'ztunnel':
                container['envFrom'] = [{'configMapRef': {'name': 'istio-cni-config'}}]
                container.update(copy.deepcopy(cni_overrides))
            return {'metadata': {'generation': 1}, 'spec': {'template': {'spec': {'containers': [container]}}},
                    'status': {'observedGeneration': 1, 'desiredNumberScheduled': 2, 'updatedNumberScheduled': 2, 'numberReady': 2}}
        rpc.get.side_effect = get
        pod = {'metadata': {'annotations': {}}, 'spec': {'dnsPolicy': 'ClusterFirst'}}
        rpc.exec.return_value = {'resolv': base64.b64encode(b'nameserver 10.43.0.10\nsearch private.example.invalid\n').decode()}
        receipt = Mock()
        receipt.value = {'proof': {'client': {'active': 'allowed'}, 'preflight': None}}
        with patch.object(proof, 'ready', return_value=pod):
            result = proof.dns_preflight(rpc, receipt, {'source': 'source'}, '10.43.0.10')
            self.assertTrue(result['configured_dns_capture_enabled'])
            self.assertNotIn('dns_capture_enabled', result)
            self.assertNotIn('private.example.invalid', json.dumps(receipt.value))
            rpc.exec.return_value = {'resolv': base64.b64encode(b'nameserver 10.43.0.99\n').decode()}
            with self.assertRaisesRegex(proof.ProofFailure, 'resolver'):
                proof.dns_preflight(rpc, receipt, {'source': 'source'}, '10.43.0.10')
            for name in ('AMBIENT_ENABLED', 'AMBIENT_DNS_CAPTURE'):
                cni_overrides['env'] = [{'name': name, 'value': 'false'}]
                rpc.exec.reset_mock()
                with self.subTest(name=name), self.assertRaises(proof.ProofFailure):
                    proof.dns_preflight(rpc, receipt, {'source': 'source'}, '10.43.0.10')
                rpc.exec.assert_not_called()
        rpc.write.assert_not_called()
