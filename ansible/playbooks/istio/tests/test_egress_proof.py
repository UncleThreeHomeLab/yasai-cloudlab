"""Native fixtures and receipt-bound recovery do not require VM credentials."""
import base64
import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from verification.integration import workload_egress as proof


UID = '11111111-1111-1111-1111-111111111111'
OTHER = '22222222-2222-2222-2222-222222222222'
RUN = 'a' * 32


def namespace(row):
    current = copy.deepcopy(row['profile'])
    current['metadata']['uid'] = UID
    return current


class EgressProofTests(unittest.TestCase):
    def test_actual_native_empty_allow_and_retirement_use_public_owner(self):
        ns, empty = proof.native('egress-proof', [])
        allowed = proof.peer('target')
        _, active = proof.native('egress-proof', [allowed])
        _, retired = proof.native('egress-proof', [allowed], 'retired')
        self.assertEqual(ns['metadata']['name'], 'cloudlab-app-egress-proof')
        self.assertEqual(empty['spec'], {'podSelector': {}, 'policyTypes': ['Egress'], 'egress': []})
        self.assertEqual(retired['metadata'], active['metadata'])
        self.assertEqual(retired['spec']['egress'], [])
        self.assertEqual(active['spec']['egress'][0]['to'], [{'namespaceSelector': {
            'matchLabels': {'kubernetes.io/metadata.name': 'target'}}, 'podSelector': allowed['podSelector']}])

    def test_selected_public_owner_forwards_retired_state(self):
        from playbooks.services.files import gitops
        from playbooks.services.tests.fixtures import approval, definition
        from contextlib import nullcontext
        public = {'repository': 'https://github.com/example/platform.git', 'services': {'revision': 'a' * 40}}
        approved = dict(approval(), egress=[proof.peer('target')])
        with patch('playbooks.services.files.owner.chart', return_value=nullcontext(proof.ROOT / 'platform/delivery/services')):
            rows = gitops.resources(definition(), approved, public['repository'], 'a' * 40, public=public, publication='retired')
        policy = next(row for row in rows if row['kind'] == 'NetworkPolicy' and row['metadata']['name'] == 'platform-egress')
        self.assertEqual(policy['spec']['egress'], [])

    def test_intent_precedes_create_and_lost_response_recovers_exact_uid(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                row = receipt.value['namespaces']['source']
                rpc = Mock()
                rpc.get.return_value = None
                def lost(verb, document):
                    saved = json.loads(receipt.path.read_text())
                    self.assertEqual(saved['namespaces']['source']['phase'], 'create-pending')
                    raise RuntimeError('response lost')
                rpc.write.side_effect = lost
                with self.assertRaises(RuntimeError): proof.create_namespace(rpc, receipt, 'source')
                self.assertIsNone(row['uid'])
                rpc.get.return_value = namespace(row)
                rpc.write.reset_mock()
                proof.create_namespace(rpc, receipt, 'source')
                rpc.write.assert_not_called()
                self.assertEqual(row['uid'], UID)
                self.assertEqual(json.loads(receipt.path.read_text())['namespaces']['source']['uid'], UID)
            finally: receipt.close()

    def test_receipt_lock_and_identity_recovery_refuse_foreign_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                with self.assertRaises(BlockingIOError): proof.Receipt(directory, 'b' * 32)
                row = receipt.value['namespaces']['source']
                row['phase'] = 'create-pending'
                current = namespace(row)
                current['metadata']['labels'][proof.MARKER] = 'foreign'
                rpc = Mock()
                rpc.get.return_value = current
                with self.assertRaisesRegex(RuntimeError, 'ownership'): proof.create_namespace(rpc, receipt, 'source')
                rpc.write.assert_not_called()
                receipt.save()
                with self.assertRaisesRegex(RuntimeError, 'target'): receipt.load('another-target')
            finally: receipt.close()

    def test_cleanup_rescans_pending_delete_and_blocks_new_foreign_data(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                row = receipt.value['namespaces']['source']
                row.update(uid=UID, phase='delete-pending')
                receipt.save()
                receipt.load('target')
                rpc = Mock()
                rpc.get.side_effect = lambda kind, name: namespace(row) if name == row['profile']['metadata']['name'] else None
                with patch.object(proof, 'inventory', return_value=[('v1/PersistentVolumeClaim/foreign', OTHER, '', '', {})]):
                    with self.assertRaisesRegex(RuntimeError, 'persistent'): proof.cleanup(rpc, receipt)
                rpc.call.assert_not_called()
                self.assertFalse(receipt.value['complete'])
            finally: receipt.close()

    def test_cleanup_uid_precondition_and_confirmed_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                row = receipt.value['namespaces']['source']
                row.update(uid=UID, phase='created')
                rpc = Mock()
                rpc.get.side_effect = [namespace(row), None, None, None, None]
                rpc.call.return_value = ''
                with patch.object(proof, 'inventory', return_value=[]): proof.cleanup(rpc, receipt)
                deletion = rpc.call.call_args_list[1]
                self.assertEqual(deletion.args[1]['preconditions'], {'uid': UID})
                self.assertEqual(deletion.args[0][0:2], ['delete', '--raw'])
                self.assertTrue(receipt.value['complete'])
                self.assertTrue(receipt.path.is_file())
            finally: receipt.close()

    def test_uid_replacement_and_incomplete_discovery_never_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                row = receipt.value['namespaces']['source']
                row.update(uid=UID, phase='created')
                current = namespace(row)
                current['metadata']['uid'] = OTHER
                rpc = Mock()
                rpc.get.return_value = current
                with self.assertRaisesRegex(RuntimeError, 'ownership'): proof.cleanup(rpc, receipt)
                rpc.call.assert_not_called()
                rpc.get.return_value = namespace(row)
                with patch.object(proof, 'inventory', side_effect=RuntimeError('discovery failed')):
                    with self.assertRaisesRegex(RuntimeError, 'discovery'): proof.cleanup(rpc, receipt)
                rpc.call.assert_not_called()
            finally: receipt.close()

    def test_transport_errors_are_not_not_ready_or_denial(self):
        rpc = Mock()
        rpc.deadline = 1
        rpc.get.side_effect = RuntimeError('transport failed')
        with self.assertRaisesRegex(RuntimeError, 'transport'): proof.wait_ready(rpc, 'namespace', 'pod')
        def encoded(code, body='', error=''):
            return {'code': code, 'body': base64.b64encode(body.encode()).decode(),
                    'error': base64.b64encode(error.encode()).decode()}
        self.assertTrue(proof.probe_result(encoded(0, 'nonce'), 'nonce'))
        self.assertFalse(proof.probe_result(encoded(1, error='wget: connection timed out'), 'nonce'))
        for value in (encoded(0, 'wrong'), encoded(1, error='server returned error: HTTP/1.1 500'),
                      encoded(127, error='not found'), {'code': 1}):
            with self.subTest(value=value), self.assertRaises(RuntimeError): proof.probe_result(value, 'nonce')

    def test_http_success_then_failed_wget_cannot_reuse_old_body(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'bin'
            binary.mkdir()
            wget = binary / 'wget'
            wget.write_text('#!/bin/sh\nif [ -f "$FAKE_STATE" ]; then\n'
                            'echo "wget: error getting response: Connection reset by peer" >&2\nexit 1\nfi\n'
                            'touch "$FAKE_STATE"\nprintf %s ' + RUN + ' >"$2"\n')
            wget.chmod(0o700)
            def probe(namespace, pod, script):
                environment = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'],
                                   FAKE_STATE=directory + '/state')
                result = subprocess.run(['sh', '-c', script.replace('/work/', directory + '/')],
                                        env=environment, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)
            rpc = SimpleNamespace(exec=probe)
            self.assertTrue(proof.http(rpc, 'source', 'allowed', '10.42.0.8', 8080, RUN))
            self.assertFalse(proof.http(rpc, 'source', 'allowed', '10.42.0.8', 8080, RUN))
            self.assertFalse(proof.http(rpc, 'source', 'allowed', '10.42.0.8', 8080, RUN))
            self.assertEqual((Path(directory) / 'body').read_bytes(), b'')

    def test_controller_children_need_current_recorded_service_and_exact_metadata(self):
        service = ('v1/Service/backend', UID, RUN, '', {})
        rows = [service]
        recorded = {service[0]: UID}
        endpoint = {'owners': [], 'endpoints_controller': 'endpoint-controller'}
        owner = {'apiVersion': 'v1', 'kind': 'Service', 'name': 'backend', 'uid': UID, 'controller': True}
        sliced = {'owners': [owner], 'service_name': 'backend',
                  'slices_controller': 'endpointslice-controller.k8s.io'}
        self.assertTrue(proof.service_child('v1/Endpoints/backend', RUN, endpoint, rows, recorded, RUN))
        self.assertTrue(proof.service_child('discovery.k8s.io/v1/EndpointSlice/backend-abc12', RUN,
                                           sliced, rows, recorded, RUN))
        cases = [
            ('v1/Endpoints/foreign', RUN, endpoint, rows, recorded),
            ('v1/Endpoints/backend', 'wrong', endpoint, rows, recorded),
            ('v1/Endpoints/backend', RUN, dict(endpoint, endpoints_controller='foreign'), rows, recorded),
            ('v1/Endpoints/backend', RUN, dict(endpoint, owners=[owner]), rows, recorded),
            ('v1/Endpoints/backend', RUN, endpoint, [(service[0], OTHER, RUN, '', {})], recorded),
            ('v1/Endpoints/backend', RUN, endpoint, rows, {service[0]: OTHER}),
            ('discovery.k8s.io/v1/EndpointSlice/foreign-abc12', RUN, sliced, rows, recorded),
            ('discovery.k8s.io/v1/EndpointSlice/backend-abc12', 'wrong', sliced, rows, recorded),
            ('discovery.k8s.io/v1/EndpointSlice/backend-abc12', RUN,
             dict(sliced, slices_controller='foreign'), rows, recorded),
            ('discovery.k8s.io/v1/EndpointSlice/backend-abc12', RUN,
             dict(sliced, service_name='foreign'), rows, recorded),
            ('discovery.k8s.io/v1/EndpointSlice/backend-abc12', RUN,
             dict(sliced, owners=[dict(owner, uid=OTHER)]), rows, recorded),
            ('discovery.k8s.io/v1/EndpointSlice/backend-abc12', RUN,
             dict(sliced, owners=[dict(owner, name='foreign')]), rows, recorded),
        ]
        for key, marker, metadata, current, expected in cases:
            with self.subTest(key=key, metadata=metadata):
                self.assertFalse(proof.service_child(key, marker, metadata, current, expected, RUN))

    def test_inventory_transports_only_selected_controller_metadata(self):
        rpc = Mock()
        owner = {'apiVersion': 'v1', 'kind': 'Service', 'name': 'backend', 'uid': UID, 'controller': True}
        types = 'services\nendpoints\nendpointslices.discovery.k8s.io\n'
        fields = ['discovery.k8s.io/v1', 'EndpointSlice', 'backend-abc12', OTHER, RUN, '',
                  json.dumps([owner]), '', 'backend', 'endpointslice-controller.k8s.io', '', '']
        rpc.call.side_effect = [types, '\t'.join(fields) + '\n', types]
        rows = proof.inventory(rpc, 'source')
        self.assertEqual(rows[0][4]['owners'], [owner])
        self.assertEqual(rows[0][4]['service_name'], 'backend')
        self.assertNotIn('.data', rpc.call.call_args_list[1].args[0][-1])

    def test_istio_public_trust_copy_recognition_is_name_label_and_owner_scoped(self):
        metadata = {'owners': [], 'istio_config': 'true'}
        for name in ('istio-ca-crl', 'istio-ca-root-cert'):
            self.assertTrue(proof.mesh_or_policy_child('v1/ConfigMap/' + name, '', metadata, [], {}, RUN))
        for key, marker, value in (
                ('v1/ConfigMap/foreign', '', metadata),
                ('v1/Secret/istio-ca-root-cert', '', metadata),
                ('v1/ConfigMap/istio-ca-root-cert', 'foreign', metadata),
                ('v1/ConfigMap/istio-ca-root-cert', '', dict(metadata, istio_config='false')),
                ('v1/ConfigMap/istio-ca-root-cert', '', dict(metadata, owners=[{'uid': OTHER}]))):
            with self.subTest(key=key, metadata=value):
                self.assertFalse(proof.mesh_or_policy_child(key, marker, value, [], {}, RUN))

    def test_policy_report_requires_exact_manager_and_recorded_current_pod_owner(self):
        key = 'wgpolicyk8s.io/v1alpha2/PolicyReport/report-one'
        parent = 'v1/Pod/allowed'
        recorded = {parent: UID}
        rows = [(parent, UID, RUN, '', {})]
        owner = {'apiVersion': 'v1', 'kind': 'Pod', 'name': 'allowed', 'uid': UID}
        metadata = {'owners': [owner], 'manager': 'kyverno'}
        self.assertTrue(proof.mesh_or_policy_child(key, '', metadata, rows, recorded, RUN))
        self.assertTrue(proof.mesh_or_policy_child(key, RUN, metadata, rows, recorded, RUN))
        # A deleted recorded pod may leave a report until garbage collection.
        self.assertTrue(proof.mesh_or_policy_child(key, '', metadata, [], recorded, RUN))
        cases = [
            (key.replace('v1alpha2', 'v1'), '', metadata, rows, recorded),
            (key.replace('wgpolicyk8s.io', 'foreign.io'), '', metadata, rows, recorded),
            (key, 'foreign', metadata, rows, recorded),
            (key, '', dict(metadata, manager='other'), rows, recorded),
            (key, '', dict(metadata, owners=[]), rows, recorded),
            (key, '', dict(metadata, owners=[owner, owner]), rows, recorded),
            (key, '', dict(metadata, owners=[dict(owner, kind='Service')]), rows, recorded),
            (key, '', dict(metadata, owners=[dict(owner, controller=True)]), rows, recorded),
            (key, '', dict(metadata, owners=[dict(owner, controller=False)]), rows, recorded),
            (key, '', dict(metadata, owners=[dict(owner, name='foreign')]), rows, recorded),
            (key, '', dict(metadata, owners=[dict(owner, uid=OTHER)]), rows, recorded),
            (key, '', metadata, [(parent, OTHER, RUN, '', {})], recorded),
            (key, '', metadata, [(parent, UID, 'foreign', '', {})], recorded),
            (key, '', metadata, rows, {}),
        ]
        for kind, marker, value, current, expected in cases:
            with self.subTest(kind=kind, metadata=value, current=current):
                self.assertFalse(proof.mesh_or_policy_child(kind, marker, value, current, expected, RUN))

    def test_cleanup_allows_only_the_observed_public_trust_and_pod_report_children(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            try:
                receipt.start('target')
                row = receipt.value['namespaces']['source']
                row.update(uid=UID, phase='created', objects={'v1/Pod/allowed': OTHER})
                owner = {'apiVersion': 'v1', 'kind': 'Pod', 'name': 'allowed', 'uid': OTHER}
                rows = [('v1/Pod/allowed', OTHER, RUN, '', {}),
                        ('v1/ConfigMap/istio-ca-crl', OTHER, '', '', {'owners': [], 'istio_config': 'true'}),
                        ('v1/ConfigMap/istio-ca-root-cert', OTHER, '', '', {'owners': [], 'istio_config': 'true'}),
                        ('wgpolicyk8s.io/v1alpha2/PolicyReport/report-one', OTHER, '', '',
                         {'owners': [owner], 'manager': 'kyverno'})]
                rpc = Mock()
                rpc.get.side_effect = [namespace(row), None, None, None, None]
                rpc.call.return_value = ''
                with patch.object(proof, 'inventory', return_value=rows): proof.cleanup(rpc, receipt)
                self.assertEqual(rpc.call.call_args_list[1].args[1]['preconditions'], {'uid': UID})
                self.assertTrue(receipt.value['complete'])
            finally: receipt.close()

    def test_exec_refuses_replaced_or_unrecorded_pod_before_probe(self):
        rpc = proof.RPC('host', 1)
        rpc.pods[('source', 'allowed')] = (UID, RUN)
        row = {'metadata': {'uid': OTHER, 'labels': {proof.MARKER: RUN}},
               'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        with patch.object(rpc, 'get', return_value=row), patch.object(rpc, 'call') as call:
            with self.assertRaisesRegex(RuntimeError, 'UID'): rpc.exec('source', 'allowed', 'fixed')
            call.assert_not_called()

    def test_convergence_waits_but_does_not_swallow_transport_or_probe_errors(self):
        with patch.object(proof.time, 'sleep'):
            proof.expect_connection(Mock(side_effect=[False, True]), True)
            proof.expect_connection(Mock(side_effect=[True, False, False, False, False]), False)
            with self.assertRaisesRegex(RuntimeError, 'transport'):
                proof.expect_connection(Mock(side_effect=RuntimeError('transport')), False)
            with self.assertRaisesRegex(RuntimeError, 'allowance'):
                proof.expect_connection(lambda: True, False, timeout=0)

    def test_dns_wire_response_validates_transaction_question_flags_and_answer(self):
        query = proof.question('backend.proof.svc.cluster.local')
        response = bytearray(query)
        response[2:4] = struct.pack('!H', 0x8180)
        response[6:8] = struct.pack('!H', 1)
        response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 10, 4) + bytes([10, 43, 0, 8])
        wire = struct.pack('!H', len(response)) + response
        self.assertTrue(proof.dns_answer(wire, query, '10.43.0.8'))
        for changed in (wire[:-1], b'\0\0' + wire[2:], wire[:2] + b'xx' + wire[4:]):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError): proof.dns_answer(changed, query, '10.43.0.8')
        with self.assertRaises(RuntimeError): proof.dns_answer(wire, query, '10.43.0.9')

    def test_failed_proof_uses_fresh_cleanup_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(receipts=directory, resume=None, cleanup=None)
            rpc = Mock(host='host', deadline=-1)
            with patch.object(proof, 'traffic', side_effect=RuntimeError('deadline')), \
                    patch.object(proof, 'cleanup') as cleanup:
                with self.assertRaises(proof.RunFailure) as error: proof.execute(args, rpc, 'target', 'image', ['one', 'two'])
            self.assertGreater(cleanup.call_args.args[0].deadline, 0)
            self.assertEqual(error.exception.result['cleanup'], 'complete')
            self.assertEqual(error.exception.result['verification'], 'operation-failed; private diagnostics withheld')

    def test_source_change_blocks_resume_but_keeps_explicit_cleanup_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = proof.Receipt(directory, RUN)
            receipt.start('target')
            receipt.close()
            args = SimpleNamespace(receipts=directory, resume=RUN, cleanup=None)
            rpc = Mock(host='host')
            with patch.object(proof, 'hashes', return_value={'source': 'changed', 'chart': 'changed'}), \
                    patch.object(proof, 'cleanup') as cleanup:
                with self.assertRaisesRegex(proof.RunFailure, 'source-changed'): proof.execute(args, rpc, 'target', 'image', ['one', 'two'])
                cleanup.assert_not_called()
                args.resume, args.cleanup = None, RUN
                self.assertEqual(proof.execute(args, rpc, 'target', 'image', ['one', 'two'])['cleanup'], 'complete')
                cleanup.assert_called_once()

    def test_cleanup_does_not_require_ready_nodes_or_current_image_pin(self):
        rpc = Mock()
        rpc.get.return_value = {'metadata': {'uid': UID}}
        with patch.object(proof.sys, 'argv', ['workload_egress.py', '--cleanup', RUN]), \
                patch.dict(proof.os.environ, {}, clear=True), \
                patch('dotenv.dotenv_values', return_value={'VM_HOST': 'fixture', 'VM_PASSWORD': 'synthetic'}), \
                patch.object(proof, 'RPC', return_value=rpc), patch.object(proof, 'node_targets') as nodes, \
                patch.object(proof, 'execute', return_value={'cleanup': 'complete'}), patch('builtins.print'):
            proof.main()
        nodes.assert_not_called()
        rpc.get.assert_called_once_with('namespace', 'kube-system')

    def test_traffic_and_cleanup_failures_preserve_safe_independent_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(receipts=directory, resume=None, cleanup=None)
            rpc = Mock(host='host', stage='empty-egress')
            with patch.object(proof, 'traffic', side_effect=proof.ProofFailure('Fixture probe failed unexpectedly')), \
                    patch.object(proof, 'cleanup', side_effect=RuntimeError('private-password-sentinel')):
                with self.assertRaises(proof.RunFailure) as error:
                    proof.execute(args, rpc, 'target', 'image', ['one', 'two'])
            result = error.exception.result
            self.assertEqual(result['stage'], 'empty-egress')
            self.assertEqual(result['verification'], 'unexpected-probe-outcome')
            self.assertEqual(result['cleanup'], 'operation-failed; private diagnostics withheld')
            self.assertRegex(result['run'], '[a-f0-9]{32}')
            self.assertEqual(result['recovery'], '--cleanup ' + result['run'])
            self.assertNotIn('private-password-sentinel', str(error.exception))
            self.assertTrue((Path(directory) / (result['run'] + '.json')).is_file())

    def test_cross_node_pods_are_restricted_and_have_only_ephemeral_storage(self):
        row = proof.placed_pod('proof', 'backend', 'image', 'backend', 'second', RUN, server=True)
        self.assertEqual(row['spec']['nodeSelector'], {'kubernetes.io/hostname': 'second'})
        self.assertFalse(row['spec']['automountServiceAccountToken'])
        self.assertTrue(all('emptyDir' in volume for volume in row['spec']['volumes']))
        self.assertTrue(row['spec']['securityContext']['runAsNonRoot'])

    def test_node_identity_and_hostname_are_both_distinct_and_ipv4(self):
        def node(name, uid):
            return {'metadata': {'name': name, 'uid': uid, 'labels': {'kubernetes.io/hostname': name}},
                    'spec': {'podCIDRs': ['10.42.0.0/24']},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        nodes = [node('first', UID), node('second', OTHER)]
        self.assertEqual(len(proof.node_targets(nodes)), 2)
        for field in ('name', 'uid', 'hostname', 'ipv6'):
            changed = copy.deepcopy(nodes)
            if field == 'hostname': changed[1]['metadata']['labels']['kubernetes.io/hostname'] = 'first'
            elif field == 'ipv6': changed[1]['spec']['podCIDRs'] = ['fd00::/64']
            else: changed[1]['metadata'][field] = changed[0]['metadata'][field]
            with self.subTest(field=field), self.assertRaises(RuntimeError): proof.node_targets(changed)

    def test_held_flow_requires_establishment_and_never_attributes_missing_response(self):
        rpc = Mock()
        rpc.exec.return_value = {'established': False}
        self.assertFalse(proof.hold_connection(rpc, 'source', '10.42.0.8'))
        rpc.exec.return_value = {'data': ''}
        value = proof.release_connection(rpc, 'source', False, 'nonce')
        self.assertIsNone(value['response_after_withdrawal'])
        value = proof.release_connection(rpc, 'source', True, 'nonce')
        self.assertFalse(value['response_after_withdrawal'])
        self.assertIn('not attributed', value['limit'])
        rpc.exec.return_value = {'data': base64.b64encode(b'HTTP/1.0 200 OK\r\n\r\nnonce').decode()}
        self.assertTrue(proof.release_connection(rpc, 'source', True, 'nonce')['response_after_withdrawal'])

    def traffic_simulation(self, *, broken_denied=False, lose_allowed=False, dns_failure=None):
        names = {role: role for role in proof.ROLES}
        pods = {('plain', 'backend'): '10.42.0.2', ('plain', 'other'): '10.42.0.3',
                ('wrong', 'backend'): '10.42.0.4', ('ambient', 'backend'): '10.42.0.5'}
        state = {'rules': None, 'extra': False, 'authz': False, 'calls': [], 'allowed_after_authz': 0}
        rpc, receipt = Mock(), Mock(run=RUN)
        def get(kind, name=None, namespace=None):
            if kind == 'networkpolicy':
                return {'metadata': {'uid': UID, 'labels': {proof.MARKER: RUN}}} if state['extra'] else None
            if kind == 'pods': return {'items': [{'metadata': {'labels': {'k8s-app': 'kube-dns'}},
                                                  'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}]}
            return {'spec': {'clusterIP': '10.43.0.10' if name == 'kube-dns' else '10.43.0.8'}}
        rpc.get.side_effect = get
        def policy(rpc, receipt, rules, publication='ready', extra=False):
            state['calls'].append(('policy', copy.deepcopy(rules), publication, extra))
            if extra: state['extra'] = True
            else: state['rules'] = [] if publication == 'retired' else rules
        def http(rpc, ns, pod, address, port, nonce):
            if address == '127.0.0.1': return True
            state['calls'].append(('probe', address, port, pod, state['authz']))
            if state['rules'] is None: return True
            if state['extra']: return True
            role = next((r for (r, p), ip in pods.items() if ip == address), 'plain')
            label = 'other' if address == pods[('plain', 'other')] else 'backend'
            allowed = any(rule['namespace'] == role and rule['podSelector']['matchLabels']['app'] == label and
                          any(p['port'] == (15008 if role == 'ambient' else port) for p in rule['ports'])
                          for rule in state['rules'])
            if role == 'ambient':
                if broken_denied and pod == 'denied' and not state['authz']: return False
                if state['authz']:
                    if pod == 'denied' or port != 8080: return False
                    state['allowed_after_authz'] += 1
                    if lose_allowed and state['allowed_after_authz'] > 1: return False
            return allowed
        def dns(rpc, ns, pod, resolver, name, answer, tcp):
            if ns == 'source' and rpc.stage == dns_failure:
                proof.fail('Egress traffic differs from its declared allowance')
            return ns == 'plain' or state['rules'] is None or any(r['namespace'] == 'kube-system' for r in state['rules'])
        def record(*args): state['authz'] = True
        def call(args, document=None):
            if args[:2] == ['delete', '--raw'] and args[2].endswith('/networkpolicies/proof-additive'):
                self.assertEqual(document['preconditions'], {'uid': UID})
                state['extra'] = False
        rpc.call.side_effect = call
        receipt.value = {'namespaces': {'source': {'objects': {'networking.k8s.io/v1/NetworkPolicy/proof-additive': UID}}},
                         'proof': {'client': {'active': 'allowed'}, 'service': None, 'preflight': None}}
        replacements = []
        def fresh(*args):
            name = 'allowed-' + format(len(replacements) + 1, '012x')
            replacements.append(name)
            receipt.value['proof']['client']['active'] = name
            return name
        def captured(rpc, receipt, names, resolver, image, node, allow, dns_rule, tcp, address):
            suffix = 'tcp' if tcp else 'udp'
            for stage, rules in (('dns-allow-', allow + [dns_rule]), ('dns-withdrawal-', allow),
                                 ('dns-restoration-', allow + [dns_rule])):
                rpc.stage = stage + suffix
                policy(rpc, receipt, rules)
                if stage == 'dns-withdrawal-': fresh()
                if rpc.stage == dns_failure: proof.fail('Egress traffic differs from its declared allowance')
            return {'classification': 'observed-policy-correlated-captured-forwarding-failure',
                    'upstream_wire_protocol': 'not-inferred'}
        expect = proof.expect_connection
        def run():
            with patch.object(proof, 'setup', return_value=(names, pods)), patch.object(proof, 'http', side_effect=http), \
                    patch.object(proof, 'apply_policy', side_effect=policy), patch.object(proof, 'dns_probe', side_effect=dns), \
                    patch.object(proof, 'record', side_effect=record), patch.object(proof, 'hold_connection', return_value=True), \
                    patch.object(proof, 'release_connection', return_value={'observed': True}), \
                    patch.object(proof, 'fresh_client', side_effect=fresh), patch.object(proof, 'captured_dns', side_effect=captured), \
                    patch.object(proof, 'dns_preflight', return_value={'configured_dns_capture_enabled': True}), \
                    patch.object(proof, 'expect_connection', side_effect=lambda probe, allowed: expect(probe, allowed, timeout=0)):
                return proof.traffic(rpc, receipt, 'image', ['one', 'two'])
        return run, state, rpc

    def test_phase_order_and_observed_hbone_keep_inner_authorization_separate(self):
        run, state, _ = self.traffic_simulation()
        result = run()
        first_policy = next(i for i, row in enumerate(state['calls']) if row[0] == 'policy')
        self.assertGreaterEqual(first_policy, 7)
        self.assertEqual(result['ambient_transport_observations'], {'8080': False, '15008': True})
        self.assertEqual(result['ambient_identity_inner_port'], 'passed')
        self.assertEqual(state['allowed_after_authz'], 2)
        self.assertTrue(result['dns_capture_preflight']['configured_dns_capture_enabled'])
        self.assertNotIn('dns_capture_enabled', result['dns_capture_preflight'])
        self.assertNotIn('dns_udp_tcp', result)
        self.assertEqual(result['known_service_a_resolution_observation'], {'client_udp': True, 'client_tcp': True})

    def test_mesh_qualification_rejects_preexisting_denied_client_failure(self):
        run, state, _ = self.traffic_simulation(broken_denied=True)
        with self.assertRaisesRegex(proof.ProofFailure, 'allowance'): run()
        self.assertFalse(state['authz'])

    def test_mesh_qualification_rejects_allowed_path_lost_after_negatives(self):
        run, state, _ = self.traffic_simulation(lose_allowed=True)
        with self.assertRaisesRegex(proof.ProofFailure, 'allowance'): run()
        self.assertEqual(state['allowed_after_authz'], 2)
        negatives = [row for row in state['calls'] if row[0] == 'probe' and row[4] and
                     (row[3] == 'denied' or row[2] == 8081)]
        self.assertTrue(any(row[3] == 'denied' for row in negatives))
        self.assertTrue(any(row[2] == 8081 for row in negatives))

    def test_dns_allow_and_withdrawal_failures_report_the_exact_transport_stage(self):
        for stage in ('dns-allow-udp', 'dns-allow-tcp', 'dns-withdrawal-udp', 'dns-withdrawal-tcp'):
            with self.subTest(stage=stage):
                run, _, rpc = self.traffic_simulation(dns_failure=stage)
                with self.assertRaises(proof.ProofFailure): run()
                self.assertEqual(rpc.stage, stage)
                with tempfile.TemporaryDirectory() as directory:
                    args = SimpleNamespace(receipts=directory, resume=None, cleanup=None)
                    with patch.object(proof, 'traffic', side_effect=proof.ProofFailure('Egress traffic differs from its declared allowance')), \
                            patch.object(proof, 'cleanup'):
                        with self.assertRaises(proof.RunFailure) as error:
                            proof.execute(args, rpc, 'target', 'image', ['one', 'two'])
                    self.assertEqual(error.exception.result['stage'], stage)
