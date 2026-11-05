"""Offline held-process, log, gate and enrollment boundaries."""
import contextlib
import copy
import io
import json
import os
import time
import unittest
from unittest.mock import Mock, patch

from playbooks.observability.tests import lifecycle_dns as dns
from playbooks.observability.tests.lifecycle_stack_proof import Qualification

POD = '11111111-1111-1111-1111-111111111111'
JOB = '22222222-2222-2222-2222-222222222222'
CM = '33333333-3333-3333-3333-333333333333'
NONCE = 'a' * 64
CONFIG = 'b' * 64
EXECUTION_FIELDS = ('initContainers', 'ephemeralContainers', 'envFrom', 'args', 'workingDir',
                    'lifecycle', 'livenessProbe', 'readinessProbe', 'startupProbe')


def inject_execution(spec, field):
    if field in ('initContainers', 'ephemeralContainers'):
        spec[field] = [{'name': 'injected', 'image': 'fixture/unrequested', 'command': ['unrequested']}]
    else:
        values = {'envFrom': [{'configMapRef': {'name': 'unrequested'}}], 'args': ['unrequested'],
                  'workingDir': '/unrequested', 'lifecycle': {'postStart': {'exec': {'command': ['unrequested']}}}}
        spec['containers'][0][field] = values.get(field, {'exec': {'command': ['unrequested']}})


def matrix(ready=True):
    return [{'control': 'ambient', 'query': name, 'transport': transport, 'expectedAnswer': ready,
             'rcode': ('NOERROR' if ready else 'SERVFAIL') if transport in ('udp', 'tcp') else 'not-applicable',
             'errno': 'none', 'elapsedCMApply': 5}
            for name, transport in [('resolver', 'metadata')] + [(name, transport) for name in ('cluster-a', 'issuer-a')
                for transport in ('udp', 'tcp', 'system')]]


def binding():
    return {'podUID': POD, 'jobUID': JOB, 'nonce': NONCE, 'configHash': CONFIG, 'pid': 1}


def result(ready=True):
    value = {'kind': 'result', 'binding': binding(), 'dns': matrix(ready), 'exitCode': 0 if ready else 1}
    value['resultDigest'] = dns.digest({key: value[key] for key in ('binding', 'dns', 'exitCode')})
    return value


def gate():
    return {'metadata': {'uid': CM, 'resourceVersion': '7'}, 'data': {'gate.json': json.dumps({
        'phase': 'hold', 'nonce': NONCE, 'configHash': CONFIG, 'podUID': '', 'jobUID': '', 'resultDigest': ''})}}


def template():
    return {'serviceAccountName': 'fixture-issuer-probe', 'automountServiceAccountToken': False,
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'seccompProfile': {'type': 'RuntimeDefault'}},
        'volumes': [{'name': 'gate', 'configMap': {'name': 'fixture-issuer-dns-gate', 'defaultMode': 420, 'optional': False}}],
        'containers': [{'name': 'probe', 'image': 'fixture/python@sha256:' + 'a' * 64, 'command': ['python', '-c', 'source'],
            'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '128Mi'}},
            'volumeMounts': [{'name': 'gate', 'mountPath': '/fixture-gate', 'readOnly': True}],
            'env': [{'name': 'FIXTURE_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}},
                    {'name': 'FIXTURE_JOB_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1',
                        'fieldPath': "metadata.labels['batch.kubernetes.io/controller-uid']"}}}]}]}


def pod():
    value = {'metadata': {'name': 'fixture-issuer-dns-test', 'uid': POD,
        'labels': {'cloudlab.io/lifecycle-probe': 'true', 'batch.kubernetes.io/controller-uid': JOB},
        'ownerReferences': [{'kind': 'Job', 'uid': JOB, 'controller': True}],
        'annotations': {'ambient.istio.io/redirection': 'enabled'}}, 'spec': template(),
        'status': {'phase': 'Running', 'containerStatuses': [{'name': 'probe', 'containerID': 'containerd://' + 'c' * 64,
            'restartCount': 0, 'ready': True, 'started': True, 'state': {'running': {'startedAt': '2026-11-05T00:00:00Z'}}}]}}
    value['spec']['dnsPolicy'] = 'ClusterFirst'
    return value


class HeldProtocolTests(unittest.TestCase):
    def namespace(self):
        value = {'__name__': 'unit_fixture'}
        exec(dns.diagnostic_code('ambient', '10.43.0.10', '10.43.0.1', '10.43.0.20',
                               time.monotonic() - 5, nonce=NONCE), value)
        return value

    def test_queries_wait_for_run_negative_result_remains_held_until_matching_finish(self):
        namespace = self.namespace()
        operation = {'phase': 'hold', 'nonce': NONCE, 'configHash': dns.digest(namespace['config']),
                     'podUID': '', 'jobUID': '', 'resultDigest': ''}
        records, phases = [], []
        collect = Mock(return_value=matrix(False))
        namespace['collect'] = collect
        namespace['strict_gate'] = lambda: copy.deepcopy(operation)
        def emit(raw, **kwargs):
            records.append(json.loads(raw))
        def advance(seconds):
            phases.append(operation['phase'])
            if operation['phase'] == 'hold':
                collect.assert_not_called()
                self.assertEqual(records[0]['kind'], 'waiting')
                operation.update(phase='run', podUID=POD, jobUID=JOB)
            else:
                collect.assert_called_once()
                self.assertEqual(records[-1]['kind'], 'result')
                self.assertEqual(records[-1]['exitCode'], 1)
                self.assertEqual(operation['phase'], 'run')
                operation.update(phase='finish', resultDigest=records[-1]['resultDigest'])
        with patch.dict(os.environ, FIXTURE_POD_UID=POD, FIXTURE_JOB_UID=JOB), patch('os.getpid', return_value=1), \
                patch('builtins.print', side_effect=emit), patch('time.sleep', side_effect=advance), self.assertRaises(SystemExit) as failure:
            namespace['held_lifecycle']()
        self.assertEqual(failure.exception.code, 1)
        self.assertEqual(phases, ['hold', 'run'])
        self.assertEqual(records[0]['binding'], records[1]['binding'])
        self.assertNotIn('10.43.', json.dumps(records))

    def test_stale_or_foreign_gate_cannot_start_queries_or_finish_early(self):
        for field, value in [('nonce', 'f' * 64), ('configHash', 'f' * 64), ('podUID', JOB), ('jobUID', POD), ('phase', 'finish')]:
            namespace = self.namespace()
            initial = {'phase': 'hold', 'nonce': NONCE, 'configHash': dns.digest(namespace['config']),
                       'podUID': '', 'jobUID': '', 'resultDigest': ''}
            bad = {**initial, 'phase': 'run', 'podUID': POD, 'jobUID': JOB, field: value}
            sequence = iter([initial, bad])
            namespace['strict_gate'] = lambda: next(sequence)
            namespace['collect'] = Mock()
            with self.subTest(field=field), patch.dict(os.environ, FIXTURE_POD_UID=POD, FIXTURE_JOB_UID=JOB), \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                namespace['held_lifecycle']()
            namespace['collect'].assert_not_called()

    def test_gate_file_rejects_duplicate_trailing_oversized_or_nonstring_fields(self):
        namespace = self.namespace()
        document = {'phase': 'hold', 'nonce': NONCE, 'configHash': CONFIG, 'podUID': '', 'jobUID': '', 'resultDigest': ''}
        raw = json.dumps(document)
        for value in (raw + '{}', raw.replace('"phase": "hold"', '"phase": "hold", "phase": "hold"'),
                      ' ' * 4097, json.dumps({**document, 'podUID': 1}), raw[:-1]):
            with self.subTest(size=len(value)), patch('builtins.open', return_value=io.StringIO(value)), self.assertRaises(ValueError):
                namespace['strict_gate']()

    def test_finish_digest_or_binding_mismatch_cannot_complete_or_repeat_queries(self):
        for field in ('resultDigest', 'nonce', 'configHash', 'podUID', 'jobUID'):
            namespace = self.namespace()
            initial = {'phase': 'hold', 'nonce': NONCE, 'configHash': dns.digest(namespace['config']),
                       'podUID': '', 'jobUID': '', 'resultDigest': ''}
            run = {**initial, 'phase': 'run', 'podUID': POD, 'jobUID': JOB}
            calls = 0
            def document():
                nonlocal calls
                calls += 1
                if calls == 1: return initial
                if calls == 2: return run
                return {**run, 'phase': 'finish', 'resultDigest': 'f' * 64, field: 'wrong'}
            namespace['strict_gate'] = document
            namespace['collect'] = Mock(return_value=matrix(False))
            with self.subTest(field=field), patch.dict(os.environ, FIXTURE_POD_UID=POD, FIXTURE_JOB_UID=JOB), \
                    patch('os.getpid', return_value=1), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                namespace['held_lifecycle']()
            namespace['collect'].assert_called_once()

    def test_held_time_is_included_and_future_or_rollback_clock_is_refused(self):
        namespace = self.namespace()
        namespace['config']['appliedAt'] = 100.0
        namespace['exchange'] = Mock(side_effect=TimeoutError())
        with patch('time.monotonic', return_value=150.0), patch('builtins.open', return_value=io.StringIO('nameserver 10.43.0.10\n')), \
                patch('socket.getaddrinfo', side_effect=TimeoutError()), patch('signal.signal'), patch('signal.alarm'):
            rows = namespace['collect']()
        self.assertTrue(all(row['elapsedCMApply'] == 50 for row in rows))
        for timestamp in (float('nan'), float('inf'), -1, time.monotonic() + 100):
            with self.subTest(timestamp=timestamp), self.assertRaises(RuntimeError):
                dns.diagnostic_config('ambient', '10.43.0.10', '10.43.0.1', '10.43.0.20', timestamp)
        with patch('time.monotonic', side_effect=[150.0, 149.0]), \
                patch('builtins.open', return_value=io.StringIO('nameserver 10.43.0.10\n')), self.assertRaises(SystemExit) as failure:
            namespace['collect']()
        self.assertEqual(failure.exception.code, 2)


class RecordAndGateTests(unittest.TestCase):
    def check(self, raw):
        return dns.log_records(raw, pod_uid=POD, job_uid=JOB, nonce=NONCE, config_hash=CONFIG, control='ambient')

    def test_only_ordered_complete_bound_records_and_exact_digest_are_accepted(self):
        waiting = {'kind': 'waiting', 'binding': binding()}
        good = result(False)
        raw = ('\n'.join(json.dumps(value) for value in (waiting, good)) + '\n').encode()
        self.assertEqual(self.check(raw), [waiting, good])
        bad = [raw[:-1], raw + b'{}\n', b' ' * 8193, json.dumps(good).encode() + b'\n',
               raw.replace(b'"pid": 1', b'"pid": 1, "pid": 1', 1), b'{"kind":\n']
        for field, value in [('pid', 2), ('pid', True), ('nonce', 'f' * 64), ('podUID', JOB), ('jobUID', POD), ('configHash', 'f' * 64)]:
            changed = copy.deepcopy(good)
            changed['binding'][field] = value
            bad.append((json.dumps(waiting) + '\n' + json.dumps(changed) + '\n').encode())
        changed = copy.deepcopy(good)
        changed['resultDigest'] = 'f' * 64
        bad.append((json.dumps(waiting) + '\n' + json.dumps(changed) + '\n').encode())
        for index, value in enumerate(bad):
            with self.subTest(case=index), self.assertRaises(RuntimeError): self.check(value)

    def test_finish_requires_verified_result_and_patch_only_targets_tested_cm_data(self):
        api = Mock()
        def request(path, method, operations, **kwargs):
            self.assertEqual(method, 'PATCH')
            self.assertEqual([op['path'] for op in operations], ['/metadata/uid', '/metadata/resourceVersion', '/data', '/data'])
            self.assertEqual([op['op'] for op in operations], ['test', 'test', 'test', 'replace'])
            self.assertEqual(operations[0]['value'], CM)
            self.assertEqual(kwargs, {'content_type': 'application/json-patch+json'})
            return {'metadata': {'uid': CM, 'resourceVersion': '8'}, 'data': operations[-1]['value']}
        api.request.side_effect = request
        value = dns.update_gate(api, '/fixed/configmaps/gate', gate(), 'run', binding())
        self.assertEqual(json.loads(value['data']['gate.json'])['podUID'], POD)
        for verified, final in ((False, result()), (True, None)):
            before = api.request.call_count
            with self.subTest(verified=verified), self.assertRaises(RuntimeError):
                dns.update_gate(api, '/fixed/configmaps/gate', value, 'finish', binding(), result=final, verified=verified)
            self.assertEqual(api.request.call_count, before)
        finished = dns.update_gate(api, '/fixed/configmaps/gate', value, 'finish', binding(), result=result(), verified=True)
        self.assertEqual(json.loads(finished['data']['gate.json'])['resultDigest'], result()['resultDigest'])

    def test_log_reader_is_exact_scoped_mtls_opener_and_refuses_byte_overflow(self):
        api = Mock()
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=None)
        response.read.return_value = b''
        api.opener.open.return_value = response
        dns.read_logs(api, 'cloudlab-identity', 'fixture-dns-pod', time.monotonic() + 10)
        uri = api.opener.open.call_args.args[0]
        self.assertEqual(uri, 'https://cluster:6443/api/v1/namespaces/cloudlab-identity/pods/fixture-dns-pod/log?limitBytes=8192')
        response.read.assert_called_once_with(8193)
        for namespace, name in (('argocd', 'fixture-dns-pod'), ('cloudlab-identity', '../secrets')):
            count = api.opener.open.call_count
            with self.subTest(namespace=namespace), self.assertRaises(RuntimeError):
                dns.read_logs(api, namespace, name, time.monotonic() + 10)
            self.assertEqual(api.opener.open.call_count, count)
        response.read.return_value = b'x' * 8193
        with self.assertRaises(RuntimeError): dns.read_logs(api, 'cloudlab-identity', 'fixture-dns-pod', time.monotonic() + 10)


class CoordinatorTests(unittest.TestCase):
    def subject(self, fault=None, ready=False):
        value = Qualification.__new__(Qualification)
        value.deadline = time.monotonic() + 3600
        value.dns_enrollment = Mock(side_effect=[{'mesh': 'stable'}, {'mesh': 'changed' if fault == 'mesh' else 'stable'}])
        api = Mock()
        value.api = api
        operation = gate()
        state = {'phase': 'hold', 'jobDeleted': False, 'gateDeleted': False, 'resultRead': False, 'finish': False}
        job = {'metadata': {'uid': JOB}, 'spec': {'template': {'spec': template()}}}
        final = result(ready)
        def current_pod():
            current = pod()
            if fault and fault.startswith('execution:'):
                inject_execution(current['spec'], fault.split(':', 1)[1])
            if state['phase'] == 'run':
                if fault == 'container': current['status']['containerStatuses'][0]['containerID'] = 'containerd://' + 'd' * 64
                elif fault == 'restart': current['status']['containerStatuses'][0]['restartCount'] = 1
                elif fault == 'capture': current['metadata']['annotations'] = {}
                elif fault == 'job-label': current['metadata']['labels']['batch.kubernetes.io/controller-uid'] = POD
                elif fault == 'premature':
                    current['status']['phase'] = 'Failed'
                    current['status']['containerStatuses'][0]['state'] = {'terminated': {'startedAt': '2026-11-05T00:00:00Z', 'exitCode': 2}}
            if state['phase'] == 'finish':
                current['metadata']['annotations'] = {}
                current['status']['phase'] = 'Succeeded' if ready else 'Failed'
                current['status']['containerStatuses'][0]['state'] = {'terminated': {
                    'startedAt': '2026-11-05T00:00:00Z', 'finishedAt': '2026-11-05T00:00:01Z',
                    'exitCode': 0 if ready else 1, 'reason': 'Completed' if ready else 'Error'}}
            return current
        def request(path, method='GET', document=None, **kwargs):
            if method == 'PATCH':
                self.assertEqual(document[0], {'op': 'test', 'path': '/metadata/uid', 'value': CM})
                self.assertEqual(document[1]['value'], operation['metadata']['resourceVersion'])
                self.assertEqual(document[2]['value'], operation['data'])
                changed = json.loads(document[3]['value']['gate.json'])
                if changed['phase'] == 'finish':
                    self.assertTrue(state['resultRead'])
                    self.assertEqual(value.dns_enrollment.call_count, 2)
                    state['finish'] = True
                state['phase'] = changed['phase']
                operation['data'] = document[3]['value']
                operation['metadata']['resourceVersion'] = str(int(operation['metadata']['resourceVersion']) + 1)
                return copy.deepcopy(operation)
            if method == 'DELETE':
                if '/jobs/' in path: state['jobDeleted'] = True
                else: state['gateDeleted'] = True
                return {}
            if '/jobs/' in path:
                current = copy.deepcopy(job)
                if fault == 'job-uid' and state['phase'] == 'run': current['metadata']['uid'] = POD
                if state['phase'] == 'finish': current['status'] = {'conditions': [{'type': 'Complete' if ready else 'Failed', 'status': 'True'}]}
                return current
            if path.endswith('/pods'): return {'items': [current_pod()]}
            raise AssertionError('Unexpected fixture API path')
        api.request.side_effect = request
        api.absent.side_effect = lambda path: state['gateDeleted'] if '/configmaps/' in path else state['jobDeleted']
        def opened(uri, timeout):
            self.assertTrue(uri.endswith('/pods/fixture-issuer-dns-test/log?limitBytes=8192'))
            self.assertTrue(0 < timeout <= 15)
            records = [{'kind': 'waiting', 'binding': binding()}]
            if state['phase'] == 'run':
                changed = copy.deepcopy(final)
                if fault == 'pid': changed['binding']['pid'] = 2
                if fault == 'digest': changed['resultDigest'] = 'f' * 64
                records.append(changed)
                state['resultRead'] = True
            raw = ('\n'.join(json.dumps(record) for record in records) + '\n').encode()
            if fault == 'truncated' and state['phase'] == 'run': raw = raw[:-1]
            response = Mock(status=200)
            response.read.return_value = raw
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=None)
            return response
        api.opener.open.side_effect = opened
        def wait(predicate, label, seconds=300, **kwargs):
            self.assertTrue(kwargs.get('fatal'))
            self.assertTrue(0 <= seconds <= 240)
            observed = predicate()
            self.assertTrue(observed)
            return observed
        value.wait = wait
        return value, job, gate(), state

    def test_negative_result_is_verified_while_running_then_terminal_annotation_is_separate(self):
        value, job, initial, state = self.subject()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rows = value.running_dns('cloudlab-identity', 'fixture-issuer-dns', 'ambient', job, initial,
                '/api/v1/namespaces/cloudlab-identity/configmaps/fixture-issuer-dns-gate', NONCE, CONFIG, time.monotonic() + 240)
        self.assertFalse(dns.matrix_ready(rows))
        self.assertTrue(state['finish'] and state['jobDeleted'] and state['gateDeleted'])
        self.assertIn('"capture": "absent"', output.getvalue())
        self.assertNotIn('10.43.', output.getvalue())

    def test_forged_or_changed_running_identity_result_or_mesh_never_gets_finish(self):
        for fault in ('container', 'restart', 'capture', 'job-label', 'job-uid', 'premature', 'pid', 'digest', 'truncated', 'mesh'):
            value, job, initial, state = self.subject(fault)
            with self.subTest(fault=fault), self.assertRaises(RuntimeError):
                value.running_dns('cloudlab-identity', 'fixture-issuer-dns', 'ambient', job, initial,
                    '/api/v1/namespaces/cloudlab-identity/configmaps/fixture-issuer-dns-gate', NONCE, CONFIG, time.monotonic() + 240)
            self.assertFalse(state['finish'])

    def test_remaining_operation_budget_cannot_be_extended_to_issue_finish(self):
        value, job, initial, state = self.subject()
        clock = [0.0]
        calls = 0
        def enrollment(*args):
            nonlocal calls
            calls += 1
            if calls == 2: clock[0] = 241.0
            return {'mesh': 'stable'}
        value.dns_enrollment = Mock(side_effect=enrollment)
        with patch('time.monotonic', side_effect=lambda: clock[0]), self.assertRaises(RuntimeError):
            value.running_dns('cloudlab-identity', 'fixture-issuer-dns', 'ambient', job, initial,
                '/api/v1/namespaces/cloudlab-identity/configmaps/fixture-issuer-dns-gate', NONCE, CONFIG, 240.0)
        self.assertFalse(state['finish'])

    def test_live_pod_extra_execution_is_rejected_before_any_gate_release(self):
        for field in EXECUTION_FIELDS:
            value, job, initial, state = self.subject('execution:' + field)
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                value.running_dns('cloudlab-identity', 'fixture-issuer-dns', 'ambient', job, initial,
                    '/api/v1/namespaces/cloudlab-identity/configmaps/fixture-issuer-dns-gate', NONCE, CONFIG, time.monotonic() + 240)
            self.assertEqual(state['phase'], 'hold')
            self.assertFalse(state['finish'])
            value.api.opener.open.assert_not_called()
            self.assertFalse(any(len(call.args) > 1 and call.args[1] == 'PATCH' for call in value.api.request.call_args_list))

    def test_admission_extra_execution_never_reaches_coordinator(self):
        for field in EXECUTION_FIELDS:
            value = Qualification.__new__(Qualification)
            value.api, value.running_dns = Mock(), Mock()
            value.api.absent.return_value = True
            value.deadline = time.monotonic() + 3600
            value.python_image = template()['containers'][0]['image']
            created = {}
            def apply(document):
                accepted = copy.deepcopy(document)
                accepted['metadata'].update(uid=JOB if document['kind'] == 'Job' else CM, resourceVersion='7')
                if document['kind'] == 'Job': inject_execution(accepted['spec']['template']['spec'], field)
                created[document['kind']] = accepted
                return accepted
            value.api.apply.side_effect = apply
            config = {'control': 'ambient', 'resolver': '10.43.0.10', 'cluster': '10.43.0.1',
                      'issuer': '10.43.0.20', 'applied_at': time.monotonic() - 5}
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                value.issuer_probe('cloudlab-identity', 'fixture-issuer-dns', dns=config)
            value.running_dns.assert_not_called()
            value.api.request.assert_not_called()
            self.assertEqual(json.loads(created['ConfigMap']['data']['gate.json'])['phase'], 'hold')

    def test_empty_native_execution_defaults_preserve_same_source(self):
        expected = template()
        actual = copy.deepcopy(expected)
        actual.update(initContainers=[], ephemeralContainers=[])
        actual['containers'][0].update(envFrom=[], args=[], workingDir='', lifecycle={},
                                      livenessProbe={}, readinessProbe={}, startupProbe={})
        self.assertTrue(dns.same_execution_source(actual, expected))

    def test_namespace_mesh_generation_config_uid_or_container_changes_alter_snapshot_or_fail(self):
        source = Qualification.__new__(Qualification)
        api = Mock()
        source.api = api
        objects = {'/api/v1/namespaces/cloudlab-identity': {'metadata': {'uid': POD,
            'labels': {'istio.io/dataplane-mode': 'ambient', 'istio-injection': 'disabled'}}}}
        mesh_pods = []
        for index, name in enumerate(('istio-cni-node', 'ztunnel'), 4):
            uid = str(index) * 8 + '-4444-4444-4444-' + str(index) * 12
            objects['/apis/apps/v1/namespaces/istio-system/daemonsets/' + name] = {
                'metadata': {'uid': uid, 'generation': 2}, 'spec': {'template': {'spec': {
                    'volumes': [{'name': 'config', 'configMap': {'name': name}}], 'containers': [{'name': 'mesh'}]}}},
                'status': {'observedGeneration': 2, **{field: 1 for field in ('desiredNumberScheduled', 'currentNumberScheduled',
                    'updatedNumberScheduled', 'numberReady', 'numberAvailable')}}}
            objects['/api/v1/namespaces/istio-system/configmaps/' + name] = {
                'metadata': {'uid': uid, 'resourceVersion': '3'}, 'data': {'mode': 'fixed'}}
            mesh_pods.append({'metadata': {'uid': uid, 'ownerReferences': [{'kind': 'DaemonSet', 'controller': True, 'uid': uid}]},
                'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}],
                    'containerStatuses': [{'name': 'mesh', 'containerID': 'containerd://' + str(index) * 64,
                        'restartCount': 0, 'ready': True, 'state': {'running': {'startedAt': '2026-11-05T00:00:00Z'}}}]}})
        objects['/api/v1/namespaces/istio-system/pods'] = {'items': mesh_pods}
        api.request.side_effect = lambda path: copy.deepcopy(objects[path])
        baseline = source.dns_enrollment('cloudlab-identity', 'ambient')
        for fault in ('namespace-uid', 'generation', 'config-data', 'config-uid', 'restart', 'container', 'ready'):
            changed = copy.deepcopy(objects)
            if fault == 'namespace-uid': changed['/api/v1/namespaces/cloudlab-identity']['metadata']['uid'] = CM
            elif fault == 'generation': changed['/apis/apps/v1/namespaces/istio-system/daemonsets/ztunnel']['metadata']['generation'] = 3
            elif fault == 'config-data': changed['/api/v1/namespaces/istio-system/configmaps/ztunnel']['data']['mode'] = 'changed'
            elif fault == 'config-uid': changed['/api/v1/namespaces/istio-system/configmaps/ztunnel']['metadata']['uid'] = CM
            else:
                status = changed['/api/v1/namespaces/istio-system/pods']['items'][1]['status']['containerStatuses'][0]
                if fault == 'restart': status['restartCount'] = 1
                elif fault == 'container': status['containerID'] = 'containerd://' + 'f' * 64
                else: status['ready'] = False
            api.request.side_effect = lambda path: copy.deepcopy(changed[path])
            with self.subTest(fault=fault):
                try: current = source.dns_enrollment('cloudlab-identity', 'ambient')
                except RuntimeError: continue
                self.assertNotEqual(current, baseline)


if __name__ == '__main__':
    unittest.main()
