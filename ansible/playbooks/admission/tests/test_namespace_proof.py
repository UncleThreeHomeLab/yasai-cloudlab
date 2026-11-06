"""Scope host-controlled restart evidence and classify bounded recovery failures."""
import copy
import json
from pathlib import Path
import ssl
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

import yaml

from playbooks.admission.tests import namespace_proof as proof


class NamespaceProofTests(unittest.TestCase):
    @staticmethod
    def initial_denial():
        message = 'initial synthetic contract'
        return message, (422, json.dumps({'kind': 'Status', 'status': 'Failure', 'reason': 'Invalid', 'code': 422,
            'message': "ValidatingAdmissionPolicy 'cloudlab-workload-namespace-native' with binding "
                       "'cloudlab-workload-namespace-native' denied request: " + message}))

    def test_initial_unsafe_admission_is_journaled_before_exact_denial(self):
        message, denial = self.initial_denial()
        probe, unchanged, records = Mock(side_effect=[(201, ''), denial]), Mock(), []
        proof.qualify_initial_install(probe, unchanged, records.append, message, clock=lambda: 0, pause=lambda _: None)
        self.assertEqual([row['httpCode'] for row in records], [201, 422])
        self.assertEqual([row['unsafeAdmission'] for row in records], [True, False])
        self.assertFalse(proof.native_denial(records[0]))
        self.assertTrue(proof.native_denial(records[1]))
        self.assertEqual(unchanged.call_count, 4)

    def test_initial_dispatch_has_attempt_bound_and_rejects_unrelated_failures(self):
        message, denial = self.initial_denial()
        probe, records = Mock(return_value=(201, '')), []
        with self.assertRaisesRegex(RuntimeError, '16 attempts'):
            proof.qualify_initial_install(probe, Mock(), records.append, message, clock=lambda: 0, pause=lambda _: None)
        self.assertEqual(len(records), 16)
        for response in ((401, ''), (403, ''), (500, ''), (422, denial[1].replace(message, 'unrelated')),
                         urllib.error.URLError(ssl.SSLCertVerificationError()), urllib.error.URLError(ssl.SSLEOFError())):
            probe = Mock(side_effect=response) if isinstance(response, Exception) else Mock(return_value=response)
            with self.subTest(response=response), self.assertRaises(RuntimeError):
                proof.qualify_initial_install(probe, Mock(), Mock(), message, clock=lambda: 0, pause=lambda _: None)
            self.assertEqual(probe.call_count, 1)
        probe = Mock(return_value=denial)
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            proof.qualify_initial_install(probe, Mock(side_effect=[None, RuntimeError('identity changed')]), Mock(),
                                          message, clock=lambda: 0, pause=lambda _: None)
        self.assertEqual(probe.call_count, 1)

    def test_initial_dispatch_checks_deadline_after_reads_and_successful_probe(self):
        message, denial = self.initial_denial()
        for slow in ('read', 'probe', 'post-read'):
            now, reads, records = [0], [0], []
            def unchanged():
                reads[0] += 1
                if slow == 'read' or slow == 'post-read' and reads[0] == 2: now[0] = 31
            def probe():
                if slow == 'probe': now[0] = 31
                return denial
            with self.subTest(slow=slow), self.assertRaisesRegex(RuntimeError, 'deadline'):
                proof.qualify_initial_install(probe, unchanged, records.append, message,
                                              clock=lambda: now[0], pause=lambda _: None)
            self.assertEqual(len(records), 0 if slow == 'read' else 1)

    def test_prepare_qualifies_before_matrix_and_preserves_initial_journal(self):
        candidate = proof.namespace_guard_desired()
        message = candidate[0]['spec']['validations'][0]['message']
        _, denial = self.initial_denial()
        denial = (denial[0], denial[1].replace('initial synthetic contract', message))
        api = Mock()
        api.apply.side_effect = lambda row: row
        api.probe.side_effect = [(201, ''), denial]
        with tempfile.TemporaryDirectory() as directory, patch.object(proof, 'STATE', Path(directory) / 'state.json'), \
                patch.object(proof, 'project', return_value='namespace-proof-unit'), \
                patch.object(proof, 'render', return_value=candidate), patch.object(proof, 'namespace_guard_validate'), \
                patch.object(proof, 'guard_snapshot', return_value=[]), patch.object(proof, 'identities', return_value={}), \
                patch.object(proof.time, 'sleep'), patch.object(proof, 'allow') as allow, patch.object(proof, 'deny') as deny:
            def allowed(*args):
                self.assertTrue(proof.read(proof.STATE)['initialInstall']['qualified'])
            def denied(*args, **kwargs):
                value = proof.read(proof.STATE)
                value['lastProbe'] = {'case': kwargs['case']}
                proof.save(proof.STATE, value)
            allow.side_effect, deny.side_effect = allowed, denied
            proof.prepare(api)
            receipt = proof.read(proof.STATE)
            self.assertEqual(receipt['phase'], 'prepared')
            self.assertEqual(receipt['initialInstall']['unsafeAdmissionCount'], 1)
            self.assertEqual(receipt['initialInstall']['knownUnavailableCount'], 0)
            self.assertEqual(len(receipt['initialInstall']['attempts']), 2)
            self.assertEqual(receipt['lastProbe']['case'], 'previous-owner-selection')
            self.assertEqual(allow.call_count + deny.call_count, receipt['checks'])
            self.assertEqual(api.probe.call_count, 2)

    def test_armed_monitor_rejects_201_before_later_denial_can_hide_it(self):
        _, denial = self.initial_denial()
        api = Mock()
        api.probe.side_effect = [(201, ''), denial]
        value = {'phase': 'prepared', 'namespaces': [], 'identities': {}, 'unsafe': {}, 'denialMessage': 'initial synthetic contract'}
        with tempfile.TemporaryDirectory() as directory, patch.object(proof, 'STATE', Path(directory) / 'state.json'), \
                patch.object(proof, 'state', return_value=value), patch.object(proof, 'identities', return_value={}):
            (Path(directory) / 'before.json').write_text('{}')
            with self.assertRaisesRegex(RuntimeError, 'Unsafe Namespace'):
                proof.monitor(api)
            self.assertEqual(api.probe.call_count, 1)
            self.assertEqual(proof.read(proof.STATE)['lastProbe']['httpCode'], 201)

    def test_native_default_invalid_denial_requires_422_typed_status_and_exact_attribution(self):
        message = 'declared synthetic validation failure'
        body = {'apiVersion': 'v1', 'kind': 'Status', 'status': 'Failure', 'reason': 'Invalid', 'code': 422,
            'message': 'namespaces "cloudlab-app-native-proof-01234567-unit" is forbidden: ' +
                       "ValidatingAdmissionPolicy 'cloudlab-workload-namespace-native' with binding "
                       "'cloudlab-workload-namespace-native' denied request: " + message}
        api = Mock()
        with tempfile.TemporaryDirectory() as directory, patch.object(proof, 'STATE', Path(directory) / 'state.json'):
            proof.save(proof.STATE, {'phase': 'preparing'})
            api.probe.return_value = (422, json.dumps(body))
            proof.deny(api, {}, message, case='unit-invalid')
            receipt = proof.read(proof.STATE)
            self.assertEqual(receipt['lastProbe'], {'case': 'unit-invalid', 'httpCode': 422,
                'statusMatches': True, 'attributionMatches': True, 'messageMatches': True})
            self.assertNotIn('diagnostic', receipt['lastProbe'])
            for code, changed in ((201, body), (403, body), (401, body), (500, body),
                    (422, dict(body, reason='Forbidden')), (422, dict(body, code=403)),
                    (422, dict(body, message=body['message'].replace("with binding 'cloudlab-workload-namespace-native'", "with binding 'foreign'"))),
                    (422, dict(body, message=body['message'].replace("ValidatingAdmissionPolicy 'cloudlab-workload-namespace-native'", "ValidatingAdmissionPolicy 'foreign'"))),
                    (422, dict(body, message=body['message'].replace(message, 'policy compilation failed')))):
                api.probe.return_value = (code, json.dumps(changed))
                with self.subTest(code=code, changed=changed), self.assertRaises(RuntimeError):
                    proof.deny(api, {}, message, case='unit-rejected')
            self.assertFalse(proof.native_denial(proof.denial_evidence('unit-malformed', 422, 'not-json', message)))

    def test_restart_inspection_requires_exact_owned_pinned_cluster_and_persistent_data(self):
        project = 'namespace-proof-unit'
        image = yaml.safe_load((Path(__file__).parents[2] / 'access/tests/compose.permissions-proof.yaml').read_text())['services']['cluster']['image']
        document = {'Id': 'a' * 64, 'Image': 'sha256:' + 'b' * 64,
            'Config': {'Image': image, 'Cmd': ['server', '--data-dir=/fixture/cluster-data'], 'Labels': {
                'com.docker.compose.project': project, 'com.docker.compose.service': 'cluster',
                'cloudlab.io/purpose': 'namespace-startup-proof'}},
            'State': {'Running': True, 'StartedAt': '2026-11-06T00:00:00.000000001Z'},
            'Mounts': [{'Type': 'volume', 'Name': project + '_credentials', 'Destination': '/fixture', 'RW': True}],
            'NetworkSettings': {'Networks': {project + '_fixture': {'IPAddress': '10.245.240.2'}}}}
        accepted = proof.inspect_cluster([document], project)
        self.assertEqual(accepted['id'], document['Id'])
        self.assertEqual(accepted['volumes'], [[project + '_credentials', '/fixture']])
        for change in ('id', 'project', 'purpose', 'service', 'image', 'data-dir', 'data-volume', 'writable', 'host-mount', 'network', 'stopped', 'time'):
            altered = copy.deepcopy(document)
            if change == 'id': altered['Id'] = 'foreign'
            elif change in ('project', 'service'): altered['Config']['Labels']['com.docker.compose.' + change] = 'foreign'
            elif change == 'purpose': altered['Config']['Labels']['cloudlab.io/purpose'] = 'foreign'
            elif change == 'image': altered['Config']['Image'] = 'rancher/k3s:latest'
            elif change == 'data-dir': altered['Config']['Cmd'] = ['server']
            elif change == 'data-volume': altered['Mounts'][0]['Name'] = 'shared-data'
            elif change == 'writable': altered['Mounts'][0]['RW'] = False
            elif change == 'host-mount': altered['Mounts'].append({'Type': 'bind', 'Destination': '/host', 'Source': '/'})
            elif change == 'network': altered['NetworkSettings']['Networks'] = {'shared': {'IPAddress': '10.245.240.2'}}
            elif change == 'stopped': altered['State']['Running'] = False
            else: altered['State']['StartedAt'] = '2026-11-06T00:00:00'
            with self.subTest(change=change), self.assertRaises((RuntimeError, ValueError)):
                proof.inspect_cluster([altered], project)

    def test_restart_unavailability_never_substitutes_arbitrary_http_or_tls_errors(self):
        status = {'kind': 'Status', 'status': 'Failure', 'reason': 'ServiceUnavailable', 'message': 'starting'}
        self.assertTrue(proof.server_unavailable(503, json.dumps(status)))
        for code, change in ((500, {}), (503, {'reason': 'Invalid'}), (503, {'kind': 'Namespace'}),
                             (401, {}), (403, {}), (503, {'status': 'Success'}),
                             (500, {'reason': 'InternalError', 'message': 'policy evaluation failed; not yet ready to handle request'})):
            with self.subTest(code=code, change=change):
                self.assertFalse(proof.server_unavailable(code, json.dumps(dict(status, **change))))
        self.assertFalse(proof.server_unavailable(503, 'unrelated failure'))
        self.assertTrue(proof.unavailable(urllib.error.URLError(ConnectionRefusedError())))
        self.assertFalse(proof.unavailable(urllib.error.URLError(ssl.SSLCertVerificationError())))
