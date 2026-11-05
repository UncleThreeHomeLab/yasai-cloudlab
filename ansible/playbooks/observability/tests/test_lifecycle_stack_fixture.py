"""Offline safety boundaries for the actual-chart disposable fixture."""
import copy
import contextlib
import functools
import io
import json
from pathlib import Path
import socket
import ssl
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import yaml

from playbooks.argocd.tests.fixtures import GitServer, GitSource, ReadOnlyGit, command
from playbooks.observability.tests.lifecycle_stack_proof import (
    OWNER, PRIVATE, PUBLIC, ROOT, ObservedGit, denied_github_job, fixture_mesh_values, helm,
    issuer_probe_code, owner_application, pinned_images, repo_values, source_guard)
from playbooks.observability.tests import lifecycle_dns


class DNSDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.namespace = {'__name__': 'fixture_unit'}
        exec(compile(lifecycle_dns.diagnostic_code('ordinary', '10.43.0.10', '10.43.0.1', '10.43.0.20',
                     time.monotonic() - 5, nonce='a' * 64),
                     'fixture-dns.py', 'exec'), self.namespace)
        self.query = self.namespace['question']('kubernetes.default.svc.cluster.local.')

    def response(self, query=None, code=0, owner=b'\xc0\x0c'):
        query = query or self.query
        packet = bytearray(query)
        packet[2:4] = struct.pack('!H', 0x8180 | code)
        if code == 0:
            packet[6:8] = struct.pack('!H', 1)
            packet += owner + struct.pack('!HHIH', 1, 1, 5, 4) + bytes([10, 43, 0, 1])
        return struct.pack('!H', len(packet)) + packet

    def test_strict_projected_validator_refuses_forged_or_unbounded_answers(self):
        response = self.response()
        validate = self.namespace['validated_answer']
        self.assertEqual(validate(response, self.query, '10.43.0.1'), 'success')
        self.assertEqual(validate(self.response(code=2), self.query, '10.43.0.1'), 'candidate')
        _, end = self.namespace['dns_name'](self.query, 12)
        changes = [
            (2, b'\0\0'), (4, struct.pack('!H', 0x8980)), (4, struct.pack('!H', 0x8380)),
            (4, struct.pack('!H', 0x0180)), (15, b'x'),
            (2 + end, struct.pack('!H', 28)), (4 + end, struct.pack('!H', 2)),
            (2 + len(self.query) + 2, struct.pack('!H', 28)),
            (2 + len(self.query) + 4, struct.pack('!H', 2)),
            (len(response) - 1, b'\x02'), (8, struct.pack('!H', 513)),
            (14, b'\xc0\x0c'), (2 + len(self.query) + 10, struct.pack('!H', 5)),
        ]
        bad = [response[:-1], response + b'trailing', b'\0\x0c' + b'\0' * 12]
        foreign = self.namespace['question']('foreign.example.invalid')[12:-4]
        bad.append(self.response(owner=foreign))
        for offset, value in changes:
            packet = bytearray(response)
            packet[offset:offset + len(value)] = value
            bad.append(bytes(packet))
        for index, packet in enumerate(bad):
            with self.subTest(case=index), self.assertRaises((ValueError, struct.error, RecursionError)):
                validate(packet, self.query, '10.43.0.1')

    def test_same_validator_accepts_valid_udp_and_fragmented_tcp_with_bounded_sockets(self):
        from unittest.mock import MagicMock
        response = self.response()
        for tcp in (False, True):
            connection = MagicMock()
            connection.recv.side_effect = [response[:1], response[1:2], response[2:17], response[17:]] if tcp else [response[2:]]
            with self.subTest(tcp=tcp), patch('socket.socket') as factory:
                factory.return_value.__enter__.return_value = connection
                raw = self.namespace['exchange'](self.query, tcp)
                self.assertEqual(self.namespace['validated_answer'](raw, self.query, '10.43.0.1'), 'success')
                connection.connect.assert_called_once_with(('10.43.0.10', 53))
                self.assertTrue(all(0 < call.args[0] <= 3 for call in connection.settimeout.call_args_list))
                if tcp: connection.sendall.assert_called_once_with(struct.pack('!H', len(self.query)) + self.query)
                else: connection.send.assert_called_once_with(self.query)

    def test_servfail_candidate_is_never_ready_and_both_fixed_queries_still_run(self):
        wire_queries = []
        def wire(query, tcp):
            wire_queries.append((self.namespace['dns_name'](query, 12)[0], tcp))
            return self.response(query, code=2)
        self.namespace['exchange'] = wire
        def addresses(name, *args):
            expected = '10.43.0.1' if name == 'kubernetes.default.svc.cluster.local.' else '10.43.0.20'
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (expected, 0))]
        with patch('builtins.open', return_value=io.StringIO('nameserver 10.43.0.10\n')), \
                patch('socket.getaddrinfo', side_effect=addresses) as resolver, patch('signal.signal'), patch('signal.alarm') as alarm:
            rows = self.namespace['collect']()
        self.assertEqual(len(rows), 7)
        self.assertEqual([call.args[0] for call in resolver.call_args_list],
                         ['kubernetes.default.svc.cluster.local.', lifecycle_dns.LOGIN_HOST])
        self.assertEqual(wire_queries, [(name, tcp) for name in
            ('kubernetes.default.svc.cluster.local', lifecycle_dns.LOGIN_HOST) for tcp in (False, True)])
        self.assertEqual([call.args for call in alarm.call_args_list], [(3,), (0,), (3,), (0,)])
        self.assertEqual(sum(row['rcode'] == 'SERVFAIL' and row['expectedAnswer'] is False for row in rows), 4)
        self.assertFalse(lifecycle_dns.matrix_ready(rows))
        self.assertNotIn('10.43.', json.dumps(rows))
        malformed = copy.deepcopy(rows)
        malformed[1]['expectedAnswer'] = 'candidate'
        with self.assertRaises(RuntimeError): lifecycle_dns.matrix_ready(malformed)

    def test_ordinary_and_ambient_results_are_collected_before_failure_blocks_tls(self):
        from unittest.mock import Mock
        from playbooks.observability.tests.lifecycle_stack_proof import Qualification
        subject = Qualification.__new__(Qualification)
        subject.dns_applied = 0
        subject.api = Mock()
        subject.api.request.side_effect = [
            {'metadata': {'labels': {'istio-injection': 'disabled'}}}, {'items': []}]
        subject.dns_identity = Mock(return_value=({}, '10.43.0.10', '10.43.0.1', '10.43.0.20'))
        rows = [{'control': 'ordinary', 'query': name, 'transport': transport,
                 'expectedAnswer': transport != 'udp', 'rcode': 'SERVFAIL' if transport == 'udp' else
                 'NOERROR' if transport == 'tcp' else 'not-applicable', 'errno': 'none', 'elapsedCMApply': 0}
                for name, transport in [('resolver', 'metadata')] + [(name, transport) for name in ('cluster-a', 'issuer-a')
                    for transport in ('udp', 'tcp', 'system')]]
        ambient = copy.deepcopy(rows)
        for row in ambient: row['control'] = 'ambient'
        subject.issuer_probe = Mock(side_effect=[rows, ambient])
        with patch('time.monotonic', return_value=5), contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(RuntimeError, '^ordinary-dns-readiness-failed$'):
            subject.issuer_dns()
        self.assertEqual([call.args[0] for call in subject.issuer_probe.call_args_list], ['external-secrets', 'cloudlab-identity'])
        self.assertTrue(all(call.kwargs.get('dns') for call in subject.issuer_probe.call_args_list))

    def test_resolver_or_known_service_failure_never_claims_issuer_failure_or_runs_tls(self):
        import ast
        import inspect
        import textwrap
        from unittest.mock import Mock
        from playbooks.observability.tests.lifecycle_stack_proof import Qualification
        method = ast.parse(textwrap.dedent(inspect.getsource(Qualification.gateway_issuer))).body[0]
        continuation = ast.FunctionDef(name='continuation', args=ast.arguments(posonlyargs=[],
            args=[ast.arg(arg='self')], kwonlyargs=[], kw_defaults=[], defaults=[]), body=method.body[-2:], decorator_list=[])
        namespace = {}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[continuation], type_ignores=[])),
                     'actual-gateway-continuation.py', 'exec'), namespace)
        for control in ('ordinary', 'ambient'):
            for query, transport in (('resolver', 'metadata'), ('cluster-a', 'udp')):
                subject = Qualification.__new__(Qualification)
                subject.dns_applied = 0
                subject.api = Mock()
                subject.api.request.side_effect = [{'metadata': {'labels': {'istio-injection': 'disabled'}}}, {'items': []}]
                subject.dns_identity = Mock(return_value=({}, '10.43.0.10', '10.43.0.1', '10.43.0.20'))
                matrices = []
                for current in ('ordinary', 'ambient'):
                    rows = [{'control': current, 'query': name, 'transport': protocol, 'expectedAnswer': True,
                        'rcode': 'NOERROR' if protocol in ('udp', 'tcp') else 'not-applicable', 'errno': 'none', 'elapsedCMApply': 0}
                        for name, protocol in [('resolver', 'metadata')] + [(name, protocol) for name in ('cluster-a', 'issuer-a')
                            for protocol in ('udp', 'tcp', 'system')]]
                    if current == control:
                        row = next(row for row in rows if row['query'] == query and row['transport'] == transport)
                        row['expectedAnswer'] = False
                        if transport == 'udp': row['rcode'] = 'SERVFAIL'
                    self.assertTrue(all(row['expectedAnswer'] for row in rows if row['query'] == 'issuer-a'))
                    matrices.append(rows)
                subject.issuer_probe = Mock(side_effect=matrices)
                with self.subTest(control=control, query=query), patch('time.monotonic', return_value=5), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        self.assertRaisesRegex(RuntimeError, '^' + control + '-dns-readiness-failed$'):
                    namespace['continuation'](subject)
                self.assertEqual(subject.issuer_probe.call_count, 2)
                self.assertTrue(all(call.kwargs.get('dns') for call in subject.issuer_probe.call_args_list))

    def test_control_policy_or_namespace_change_stops_before_creating_any_probe(self):
        from unittest.mock import Mock
        from playbooks.observability.tests.lifecycle_stack_proof import Qualification
        for labels, policies in [({'istio.io/dataplane-mode': 'ambient'}, []),
                ({'istio-injection': 'disabled'}, [{'spec': {'policyTypes': ['Egress'], 'egress': []}}])]:
            subject = Qualification.__new__(Qualification)
            subject.api = Mock()
            subject.api.request.side_effect = [{'metadata': {'labels': labels}}, {'items': policies}]
            subject.issuer_probe = Mock()
            with self.subTest(labels=labels), self.assertRaises(RuntimeError): subject.issuer_dns()
            subject.issuer_probe.assert_not_called()
            subject.api.apply.assert_not_called()

    def test_dns_binding_requires_current_custom_declaration_and_ready_original_endpoints(self):
        from unittest.mock import Mock
        from playbooks.observability.tests.lifecycle_stack_proof import Qualification
        base = '/api/v1/namespaces/'
        custom = {'metadata': {'uid': 'custom-uid', 'resourceVersion': '7'}, 'data': {'lifecycle.server': 'synthetic'}}
        pod = {'metadata': {'uid': 'dns-pod', 'labels': {'k8s-app': 'kube-dns'}},
               'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        objects = {
            base + 'kube-system/services/kube-dns': {'metadata': {'uid': 'dns-service'}, 'spec': {
                'clusterIP': '10.43.0.10', 'selector': {'k8s-app': 'kube-dns'},
                'ports': [{'protocol': transport, 'port': 53} for transport in ('UDP', 'TCP')]}},
            base + 'kube-system/endpoints/kube-dns': {'metadata': {'uid': 'dns-endpoint'},
                'subsets': [{'addresses': [{'targetRef': {'uid': 'dns-pod'}}]}]},
            base + 'kube-system/pods': {'items': [pod]},
            base + 'kube-system/configmaps/coredns-custom': custom,
            base + 'cloudlab-gateway-private/services/cloudlab-istio': {'metadata': {'uid': 'gateway'}, 'spec': {'clusterIP': '10.43.0.20'}},
            base + 'default/services/kubernetes': {'metadata': {'uid': 'cluster'}, 'spec': {'clusterIP': '10.43.0.1'}},
        }
        subject = Qualification.__new__(Qualification)
        subject.api = Mock()
        subject.dns_custom = copy.deepcopy(custom)
        subject.api.request.side_effect = lambda path: copy.deepcopy(objects[path])
        before = subject.dns_identity()
        self.assertEqual(before[1:], ('10.43.0.10', '10.43.0.1', '10.43.0.20'))
        self.assertEqual(subject.dns_identity(), before)
        for fault in ('custom-uid', 'custom-rv', 'custom-data', 'pod-ready', 'endpoint-uid', 'not-ready', 'selector'):
            changed = copy.deepcopy(objects)
            if fault.startswith('custom-'):
                target = changed[base + 'kube-system/configmaps/coredns-custom']
                if fault == 'custom-data': target['data']['lifecycle.server'] = 'changed'
                else: target['metadata']['uid' if fault == 'custom-uid' else 'resourceVersion'] = 'changed'
            elif fault == 'pod-ready': changed[base + 'kube-system/pods']['items'][0]['status']['conditions'][0]['status'] = 'False'
            elif fault == 'selector': changed[base + 'kube-system/services/kube-dns']['spec']['selector'] = {'app': 'borrowed'}
            elif fault == 'endpoint-uid': changed[base + 'kube-system/endpoints/kube-dns']['subsets'][0]['addresses'][0]['targetRef']['uid'] = 'other'
            else: changed[base + 'kube-system/endpoints/kube-dns']['subsets'][0]['notReadyAddresses'] = [{'targetRef': {'uid': 'dns-pod'}}]
            subject.api.request.side_effect = lambda path: copy.deepcopy(changed[path])
            with self.subTest(fault=fault), self.assertRaises(RuntimeError): subject.dns_identity()

    def test_dns_job_keeps_own_tokenless_identity_and_refuses_optout_or_foreign_source(self):
        from unittest.mock import Mock
        from playbooks.observability.tests.lifecycle_stack_proof import Qualification
        subject = Qualification.__new__(Qualification)
        subject.api, subject.running_dns = Mock(), Mock(return_value=[])
        subject.deadline = time.monotonic() + 3600
        subject.python_image = 'fixture.invalid/python@sha256:' + 'a' * 64
        created = {}
        job_uid = '22222222-2222-2222-2222-222222222222'
        def apply(obj):
            created[obj['kind']] = copy.deepcopy(obj)
            value = copy.deepcopy(obj)
            value['metadata'].update(uid=job_uid if obj['kind'] == 'Job' else '33333333-3333-3333-3333-333333333333', resourceVersion='7')
            return value
        subject.api.apply.side_effect = apply
        subject.api.absent.return_value = True
        inputs = {'control': 'ambient', 'resolver': '10.43.0.10', 'cluster': '10.43.0.1', 'issuer': '10.43.0.20', 'applied_at': time.monotonic() - 1}
        subject.issuer_probe('cloudlab-identity', 'fixture-dns', dns=inputs)
        self.assertEqual(set(created), {'ServiceAccount', 'ConfigMap', 'Job'})
        self.assertFalse(created['ServiceAccount']['automountServiceAccountToken'])
        template = created['Job']['spec']['template']
        self.assertEqual(template['metadata']['labels'], {'cloudlab.io/lifecycle-probe': 'true'})
        self.assertEqual(created['Job']['spec']['activeDeadlineSeconds'], 240)
        self.assertEqual(created['Job']['spec']['backoffLimit'], 0)
        self.assertNotIn('annotations', template['metadata'])
        self.assertFalse(template['spec']['automountServiceAccountToken'])
        self.assertEqual(template['spec']['volumes'], [{'name': 'gate', 'configMap': {'name': 'fixture-dns-gate', 'defaultMode': 420, 'optional': False}}])
        self.assertEqual(template['spec']['containers'][0]['volumeMounts'], [{'name': 'gate', 'mountPath': '/fixture-gate', 'readOnly': True}])
        for fault in (None, 'account', 'token', 'command', 'image', 'capture', 'optout', 'host-alias'):
            pod = copy.deepcopy(template)
            pod['metadata'].update(name='fixture-dns-pod', uid='11111111-1111-1111-1111-111111111111',
                ownerReferences=[{'kind': 'Job', 'uid': job_uid, 'controller': True}],
                annotations={'ambient.istio.io/redirection': 'enabled'})
            pod['metadata']['labels']['batch.kubernetes.io/controller-uid'] = job_uid
            pod['spec']['dnsPolicy'] = 'ClusterFirst'
            pod['status'] = {'phase': 'Running', 'containerStatuses': [{'name': 'probe', 'containerID': 'containerd://' + 'b' * 64,
                'restartCount': 0, 'ready': True, 'started': True, 'state': {'running': {'startedAt': '2026-11-05T00:00:00Z'}}}]}
            if fault == 'account': pod['spec']['serviceAccountName'] = 'external-secrets'
            elif fault == 'token': pod['spec']['automountServiceAccountToken'] = True
            elif fault == 'command': pod['spec']['containers'][0]['command'] = ['always-pass']
            elif fault == 'image': pod['spec']['containers'][0]['image'] = 'unapproved'
            elif fault == 'capture': pod['metadata']['annotations'] = {}
            elif fault == 'optout': pod['metadata']['annotations']['ambient.istio.io/dns-capture'] = 'false'
            elif fault == 'host-alias': pod['spec']['hostAliases'] = [{'ip': '10.43.0.20', 'hostnames': [lifecycle_dns.LOGIN_HOST]}]
            if fault is None: self.assertTrue(lifecycle_dns.pod_identity(pod, job_uid, template['spec'], 'ambient'))
            else:
                with self.subTest(fault=fault), self.assertRaises(RuntimeError):
                    lifecycle_dns.pod_identity(pod, job_uid, template['spec'], 'ambient')


class KialiFixtureTests(unittest.TestCase):
    def test_actual_six_child_render_qualifies_only_exact_kiali_config_and_route(self):
        from playbooks.observability.tests import lifecycle_stack_proof as stack
        from playbooks.observability.tests.fixtures import native_overrides, native_source_inputs
        inputs = native_source_inputs()
        inputs['observabilityInputs'].update(loginHost=lifecycle_dns.LOGIN_HOST,
            grafanaHost=lifecycle_dns.GRAFANA_HOST, kialiHost=lifecycle_dns.KIALI_HOST)
        overrides = native_overrides(inputs)
        self.assertEqual(set(overrides), set(stack.CHILDREN))
        objects = []
        for name, values in overrides.items():
            path = 'platform/observability' + ('' if name == 'cloudlab-observability' else '/' + name.removeprefix('cloudlab-'))
            objects.extend(stack.helm(path, values, stack.NS, name))
        self.assertGreater(sum(o['kind'] == 'ConfigMap' and 'config.yaml' in o.get('data', {}) for o in objects), 1)
        stack.kiali_configuration(objects)
        for kind, name in (('ConfigMap', 'cloudlab-kiali'), ('HTTPRoute', 'kiali')):
            for mutation in ('namespace', 'missing', 'duplicate'):
                changed = copy.deepcopy(objects)
                target = next(o for o in changed if o['kind'] == kind and o['metadata']['name'] == name)
                if mutation == 'namespace': target['metadata']['namespace'] = 'other'
                elif mutation == 'missing': changed.remove(target)
                else: changed.append(copy.deepcopy(target))
                with self.subTest(kind=kind, mutation=mutation), self.assertRaises(RuntimeError):
                    stack.kiali_configuration(changed)
            foreign = copy.deepcopy(next(o for o in objects if o['kind'] == kind and o['metadata']['name'] == name))
            foreign['metadata']['namespace'] = 'other'
            stack.kiali_configuration(objects + [foreign])
        duplicate = {'kind': 'ConfigMap', 'metadata': {'name': 'cloudlab-kiali', 'namespace': stack.NS}, 'data': {}}
        with self.assertRaisesRegex(RuntimeError, 'configuration is ambiguous'):
            stack.kiali_configuration(objects + [duplicate])
        changed = copy.deepcopy(objects)
        target = next(o for o in changed if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'cloudlab-kiali')
        target['data'] = {}
        with self.assertRaisesRegex(RuntimeError, 'configuration payload is missing'):
            stack.kiali_configuration(changed)
        duplicate['metadata']['namespace'] = 'other'
        stack.kiali_configuration(objects + [duplicate])

    def test_all_tls_probe_jobs_bind_admission_terminal_pod_and_cleanup_identity(self):
        from unittest.mock import Mock
        from playbooks.observability.tests import lifecycle_stack_proof as stack
        job_uid = '11111111-1111-1111-1111-111111111111'
        pod_uid = '22222222-2222-2222-2222-222222222222'
        mutations = (None, 'staged-status', 'admission-command', 'admission-init', 'admission-env', 'job-uid', 'job-source',
                     'pod-owner', 'pod-label', 'pod-namespace', 'pod-name', 'pod-command', 'pod-init',
                     'pod-env', 'pod-probe', 'pod-exit', 'pod-failed', 'job-failed', 'pod-restarts',
                     'pod-running', 'pod-incomplete', 'pod-count', 'cleanup-rv')
        for kiali in (False, True):
            namespace = stack.NS if kiali else 'cloudlab-identity'
            name = 'fixture-kiali-openid' if kiali else 'fixture-platform-issuer'
            for mutation in mutations:
                with self.subTest(kiali=kiali, mutation=mutation):
                    subject = stack.Qualification.__new__(stack.Qualification)
                    subject.api = Mock()
                    subject.ca, subject.python_image = 'public-ca', 'pinned-existing-image'
                    subject.deadline = time.monotonic() + 300
                    state = {}
                    def apply(obj):
                        accepted = copy.deepcopy(obj)
                        if obj['kind'] == 'Job':
                            accepted['metadata'].update(uid=job_uid, resourceVersion='7')
                            containers = accepted['spec']['template']['spec']['containers']
                            if mutation == 'admission-command': containers[0]['command'] = ['python', '-c', 'pass']
                            elif mutation == 'admission-init': accepted['spec']['template']['spec']['initContainers'] = [{'name': 'extra'}]
                            elif mutation == 'admission-env': containers[0]['envFrom'] = [{'configMapRef': {'name': 'extra'}}]
                            state['job'] = accepted
                            spec = copy.deepcopy(obj['spec']['template']['spec'])
                            spec['dnsPolicy'] = 'ClusterFirst'
                            pod = {'metadata': {'name': name + '-abcde', 'namespace': namespace, 'uid': pod_uid,
                                'labels': {'cloudlab.io/lifecycle-probe': 'true',
                                    'batch.kubernetes.io/controller-uid': job_uid, 'batch.kubernetes.io/job-name': name},
                                'ownerReferences': [{'apiVersion': 'batch/v1', 'kind': 'Job', 'name': name,
                                    'uid': job_uid, 'controller': True, 'blockOwnerDeletion': True}]}, 'spec': spec,
                                'status': {'phase': 'Succeeded', 'containerStatuses': [{'name': 'probe', 'restartCount': 0,
                                    'containerID': 'containerd://' + 'a' * 64, 'state': {'terminated': {
                                        'exitCode': 0, 'reason': 'Completed', 'startedAt': '2026-01-01T00:00:00Z',
                                        'finishedAt': '2026-01-01T00:00:01Z'}}}]}}
                            if mutation == 'pod-owner': pod['metadata']['ownerReferences'][0]['uid'] = pod_uid
                            elif mutation == 'pod-label': pod['metadata']['labels']['batch.kubernetes.io/controller-uid'] = pod_uid
                            elif mutation == 'pod-namespace': pod['metadata']['namespace'] = 'other'
                            elif mutation == 'pod-name': pod['metadata']['name'] = 'other-abcde'
                            elif mutation == 'pod-command': spec['containers'][0]['command'] = ['python', '-c', 'pass']
                            elif mutation == 'pod-init': spec['initContainers'] = [{'name': 'extra'}]
                            elif mutation == 'pod-env': spec['containers'][0]['envFrom'] = [{'configMapRef': {'name': 'extra'}}]
                            elif mutation == 'pod-probe': spec['containers'][0]['startupProbe'] = {'exec': {'command': ['extra']}}
                            elif mutation == 'pod-exit': pod['status']['containerStatuses'][0]['state']['terminated']['exitCode'] = 1
                            elif mutation == 'pod-failed': pod['status']['phase'] = 'Failed'
                            elif mutation == 'pod-restarts': pod['status']['containerStatuses'][0]['restartCount'] = 1
                            elif mutation == 'pod-running': pod['status']['phase'] = 'Running'
                            elif mutation == 'pod-incomplete': pod['status']['containerStatuses'][0]['state']['terminated'].pop('finishedAt')
                            state['pods'] = [pod, copy.deepcopy(pod)] if mutation == 'pod-count' else [pod]
                            state['originalPod'] = copy.deepcopy(pod)
                        return accepted
                    def request(path, method='GET', data=None):
                        if method == 'DELETE': return {}
                        if '/pods?' in path: return {'items': state['pods']}
                        state['polls'] = state.get('polls', 0) + 1
                        current = copy.deepcopy(state['job'])
                        current['status'] = {'succeeded': 1, 'conditions': [{'type': 'Complete', 'status': 'True'}]}
                        if mutation == 'staged-status':
                            state['reads'] = state.get('reads', 0) + 1
                            state['pods'] = [copy.deepcopy(state['originalPod'])]
                            if state['reads'] == 1:
                                pod_status = state['pods'][0]['status']
                                pod_status['phase'] = 'Running'
                                terminal = pod_status['containerStatuses'][0]['state']['terminated']
                                terminal.pop('reason')
                                terminal.pop('finishedAt')
                            if state['reads'] < 3: current['status']['conditions'] = []
                        if mutation == 'job-uid': current['metadata']['uid'] = pod_uid
                        elif mutation == 'job-failed': current['status'] = {'conditions': [{'type': 'Failed', 'status': 'True'}]}
                        elif mutation == 'job-source': current['spec']['template']['spec']['containers'][0]['command'] = ['python', '-c', 'pass']
                        elif mutation == 'cleanup-rv': current['metadata'].pop('resourceVersion')
                        return current
                    subject.api.apply.side_effect = apply
                    subject.api.request.side_effect = request
                    observed = []
                    def wait(predicate, *args, **kwargs):
                        for _ in range(3):
                            result = predicate()
                            observed.append(bool(result))
                            if result: return result
                            self.assertFalse(any(len(call.args) > 1 and call.args[1] == 'DELETE'
                                                 for call in subject.api.request.call_args_list))
                        raise RuntimeError('Synthetic readiness budget exhausted')
                    subject.wait = Mock(side_effect=wait)
                    if mutation in (None, 'staged-status'):
                        subject.issuer_probe(namespace, name, kiali=kiali)
                        self.assertEqual(observed, [False, False, True] if mutation == 'staged-status' else [True])
                        deletion = [call for call in subject.api.request.call_args_list if len(call.args) > 1 and call.args[1] == 'DELETE']
                        self.assertEqual(len(deletion), 1)
                        self.assertEqual(deletion[0].args[2]['preconditions'], {'uid': job_uid, 'resourceVersion': '7'})
                        # The exact native-defaulted ConfigMap volume remains accepted.
                        self.assertEqual(state['job']['spec']['template']['spec']['volumes'][0]['configMap'],
                                         {'name': name, 'defaultMode': 420, 'optional': False})
                    else:
                        with self.assertRaises(RuntimeError): subject.issuer_probe(namespace, name, kiali=kiali)
                        self.assertFalse(any(len(call.args) > 1 and call.args[1] == 'DELETE'
                                             for call in subject.api.request.call_args_list))
                        if mutation.startswith('admission-'): subject.wait.assert_not_called()
                        elif mutation not in ('pod-running', 'pod-incomplete'):
                            self.assertEqual(state['polls'], 1)

    def test_kiali_probe_uses_existing_tokenless_job_and_fixed_scope(self):
        from unittest.mock import Mock
        from playbooks.observability.tests import lifecycle_stack_proof as stack
        subject = stack.Qualification.__new__(stack.Qualification)
        subject.api, subject.wait = Mock(), Mock()
        subject.ca, subject.python_image, subject.deadline = 'public-ca', 'pinned-existing-image', time.monotonic() + 300
        def admitted(obj):
            result = copy.deepcopy(obj)
            if result['kind'] == 'Job': result['metadata'].update(uid='11111111-1111-1111-1111-111111111111')
            return result
        subject.api.apply.side_effect = admitted
        subject.wait.return_value = {'metadata': {'resourceVersion': '7'}}
        subject.issuer_probe(stack.NS, 'fixture-kiali-openid', kiali=True)
        job = next(call.args[0] for call in subject.api.apply.call_args_list if call.args[0]['kind'] == 'Job')
        spec = job['spec']['template']['spec']
        self.assertIs(spec['automountServiceAccountToken'], False)
        self.assertEqual(spec['serviceAccountName'], 'fixture-issuer-probe')
        self.assertEqual(job['spec']['template']['metadata']['labels'], {'cloudlab.io/lifecycle-probe': 'true'})
        self.assertEqual(spec['containers'][0]['command'], ['python', '-c', stack.kiali_probe_code()])
        self.assertEqual(job['spec']['activeDeadlineSeconds'], 240)
        self.assertEqual(job['spec']['backoffLimit'], 0)
        self.assertEqual(spec['volumes'], [{'name': 'trust', 'configMap': {
            'name': 'fixture-kiali-openid', 'defaultMode': 420, 'optional': False}}])
        for namespace, name in (('external-secrets', 'fixture-kiali-openid'), (stack.NS, 'other')):
            subject.api.reset_mock()
            with self.assertRaises(RuntimeError): subject.issuer_probe(namespace, name, kiali=True)
            subject.api.apply.assert_not_called()

    def test_existing_argo_owner_supplies_only_exact_reader_and_rejects_extra_authority(self):
        from playbooks.observability.tests import lifecycle_stack_proof as stack
        objects = stack.kiali_observer()
        self.assertIs(repo_values()['kialiBackendObserver'], True)
        self.assertEqual({o['kind'] for o in objects}, {'Role', 'RoleBinding'})
        self.assertTrue(all(o['metadata']['namespace'] == 'argocd' for o in objects))
        for mutation in ('verb', 'subject', 'roleRef', 'namespace', 'extra'):
            changed = copy.deepcopy(objects)
            role = next(o for o in changed if o['kind'] == 'Role')
            binding = next(o for o in changed if o['kind'] == 'RoleBinding')
            if mutation == 'verb': role['rules'][0]['verbs'].append('create')
            elif mutation == 'subject': binding['subjects'][0]['name'] = 'other'
            elif mutation == 'roleRef': binding['roleRef']['kind'] = 'ClusterRole'
            elif mutation == 'namespace': role['metadata']['namespace'] = 'other'
            else: changed.append(copy.deepcopy(role))
            with self.subTest(mutation=mutation), patch.object(stack, 'helm', return_value=changed), self.assertRaises(RuntimeError):
                stack.kiali_observer()

    def test_public_ca_only_git_supplement_preserves_canonical_bytes_and_native_ordering(self):
        import shutil
        from playbooks.observability.tests import lifecycle_stack_proof as stack
        from playbooks.observability.tests.fixtures import native_overrides, native_source_inputs
        subject = stack.Qualification.__new__(stack.Qualification)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            subject.generate_pki(directory)
            files = stack.git_files(subject.ca)
            path = 'platform/observability/kiali/templates/fixture-issuer-ca.yaml'
            self.assertEqual({name for name in files if not (ROOT / name).is_file()}, {path})
            self.assertTrue(all((ROOT / name).read_bytes() == raw for name, raw in files.items() if name != path))
            supplement = yaml.safe_load(files[path])
            self.assertEqual(supplement['kind'], 'ConfigMap')
            self.assertEqual(supplement['metadata'], {'name': 'cloudlab-kiali-cabundle', 'namespace': stack.NS,
                'annotations': {'argocd.argoproj.io/sync-wave': '-1'}})
            self.assertEqual(supplement['data'], {'openid-server-ca.crt': subject.ca})
            self.assertNotIn(b'PRIVATE KEY', files[path])
            chart = directory / 'kiali'
            shutil.copytree(ROOT / 'platform/observability/kiali', chart)
            (chart / 'templates/fixture-issuer-ca.yaml').write_bytes(files[path])
            inputs = native_source_inputs()
            inputs['observabilityInputs'].update(loginHost=lifecycle_dns.LOGIN_HOST,
                grafanaHost=lifecycle_dns.GRAFANA_HOST, kialiHost=lifecycle_dns.KIALI_HOST)
            objects = stack.helm(str(chart), native_overrides(inputs)['cloudlab-kiali'], stack.NS, 'cloudlab-kiali')
            stack.kiali_configuration(objects)
            trust = next(o for o in objects if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'cloudlab-kiali-cabundle')
            deployment = next(o for o in objects if o['kind'] == 'Deployment')
            self.assertLess(int(trust['metadata']['annotations']['argocd.argoproj.io/sync-wave']),
                            int(deployment['metadata'].get('annotations', {}).get('argocd.argoproj.io/sync-wave', '0')))
            self.assertTrue(any(v.get('configMap', {}).get('name') == 'cloudlab-kiali-cabundle'
                                for v in deployment['spec']['template']['spec']['volumes']))
            self.assertFalse(any(o['kind'] in ('Role', 'RoleBinding') and o['metadata']['namespace'] == 'argocd' for o in objects))
            for mutation in ('root', 'host', 'port', 'scopes', 'params', 'route'):
                changed = copy.deepcopy(objects)
                configmap = next(o for o in changed if o['kind'] == 'ConfigMap' and 'config.yaml' in o.get('data', {}))
                config = yaml.safe_load(configmap['data']['config.yaml'])
                if mutation == 'root': config['server']['web_root'] = '/'
                elif mutation == 'host': config['server']['web_fqdn'] = 'wrong.example.test'
                elif mutation == 'port': config['server']['web_port'] = '8443'
                elif mutation == 'scopes': config['auth']['openid']['scopes'] = ['openid']
                elif mutation == 'params': config['auth']['openid']['additional_request_params'] = {'prompt': 'none'}
                else: next(o for o in changed if o['kind'] == 'HTTPRoute')['spec']['rules'][0]['matches'][0]['path']['value'] = '/kiali'
                configmap['data']['config.yaml'] = yaml.safe_dump(config)
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): stack.kiali_configuration(changed)
            for invalid in ((directory / 'ca.key').read_text(), subject.ca + subject.ca, 'not PEM'):
                with self.assertRaises(RuntimeError): stack.git_files(invalid)

    def test_native_redirect_requires_exact_flow_and_never_follows_or_prints_opaque_values(self):
        import email.message
        import urllib.parse
        from playbooks.observability.tests import lifecycle_stack_proof as stack
        secret = 'opaque-canary-never-print'
        query = {'client_id': 'kiali', 'response_type': 'code', 'redirect_uri': 'https://' + lifecycle_dns.KIALI_HOST + '/kiali',
                 'scope': 'openid profile email', 'nonce': secret, 'state': secret,
                 'code_challenge': 'a' * 43, 'code_challenge_method': 'S256'}
        def headers(location):
            value = email.message.Message(); value['Location'] = location
            return value
        source = stack.kiali_probe_code()
        def execute(location, expected, cookie=None):
            output = io.StringIO()
            response_headers = headers(location)
            response_headers['Set-Cookie'] = ('opaque=' + secret + '; Secure; HttpOnly; Path=/kiali; SameSite=Lax'
                                              if cookie is None else cookie)
            error = urllib.error.HTTPError(secret, 302, secret, response_headers, None)
            with patch('ssl.create_default_context') as context, patch('urllib.request.build_opener') as build, \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                build.return_value.open.side_effect = error
                if expected: exec(compile(source, 'actual-kiali-probe.py', 'exec'), {})
                else:
                    with self.assertRaises(SystemExit) as failure: exec(compile(source, 'actual-kiali-probe.py', 'exec'), {})
                    self.assertEqual(failure.exception.code, 1)
                build.return_value.open.assert_called_once_with('https://' + lifecycle_dns.KIALI_HOST + '/kiali/api/auth/openid_redirect', timeout=3)
                context.assert_called_once_with(cafile='/fixture/ca.crt')
                self.assertIsNone(build.call_args.args[0].redirect_request(None, None, None, None, None, None))
            self.assertNotIn(secret, output.getvalue())
            self.assertNotIn('https://', output.getvalue())
        valid = lifecycle_dns.ISSUER + '/auth?' + urllib.parse.urlencode(query)
        execute(valid, True)
        execute(valid, False, cookie='opaque=' + 'a' * 4097)
        execute(valid, False, cookie='not-a-cookie')
        for mutation in ('root', 'host', 'port', 'port-zero', 'callback-slash', 'callback-port', 'duplicate', 'extra', 'pkce', 'state', 'fragment', 'userinfo'):
            target, changed = lifecycle_dns.ISSUER + '/auth', dict(query)
            if mutation == 'root': target = lifecycle_dns.ISSUER + '/wrong'
            elif mutation == 'host': target = target.replace(lifecycle_dns.LOGIN_HOST, 'wrong.example.test')
            elif mutation == 'port': target = target.replace(lifecycle_dns.LOGIN_HOST, lifecycle_dns.LOGIN_HOST + ':8443')
            elif mutation == 'port-zero': target = target.replace(lifecycle_dns.LOGIN_HOST, lifecycle_dns.LOGIN_HOST + ':0')
            elif mutation == 'callback-slash': changed['redirect_uri'] += '/'
            elif mutation == 'callback-port': changed['redirect_uri'] = 'https://' + lifecycle_dns.KIALI_HOST + ':443/kiali'
            elif mutation == 'extra': changed['extra'] = secret
            elif mutation == 'pkce': changed['code_challenge'] = 'a' * 42 + '!'
            elif mutation == 'state': changed['state'] = ''
            elif mutation == 'userinfo': target = target.replace('https://', 'https://user@')
            location = target + '?' + urllib.parse.urlencode(changed)
            if mutation == 'duplicate': location += '&client_id=kiali'
            if mutation == 'fragment': location += '#' + secret
            with self.subTest(mutation=mutation): execute(location, False)


class StackFixtureTests(unittest.TestCase):
    def test_reduced_current_comparison_helpers_require_current_destination(self):
        import ast
        import inspect
        from types import SimpleNamespace
        from unittest.mock import Mock
        from playbooks.observability.tests import lifecycle_controller_proof as reduced
        nodes = [node for node in ast.walk(ast.parse(inspect.getsource(reduced.run)))
                 if isinstance(node, ast.FunctionDef) and node.name in ('complete', 'history')]
        self.assertEqual({node.name for node in nodes}, {'complete', 'history'})
        parent = reduced.application('native-current', 'native-current', 'main', repository='private')
        child = reduced.application('cloudlab-observability', 'platform/observability', 'a' * 40,
                                    namespace='cloudlab-observability')
        marker_path, sentinel_path = '/marker', '/sentinel'
        for phase in ('Succeeded', 'Failed', 'Error'):
            for fault in (None, 'missing', 'namespace', 'server'):
                documents = {}
                for app, revision in ((parent, 'b' * 40), (child, 'a' * 40)):
                    value = copy.deepcopy(app)
                    comparison = {'source': copy.deepcopy(value['spec']['source']),
                                  'destination': copy.deepcopy(value['spec']['destination'])}
                    if fault == 'missing': comparison.pop('destination')
                    elif fault == 'namespace': comparison['destination']['namespace'] = 'stale'
                    elif fault == 'server': comparison['destination']['server'] = 'https://stale.example.invalid'
                    value['status'] = {'sync': {'status': 'Synced', 'revision': revision, 'comparedTo': comparison},
                        'health': {'status': 'Healthy'}, 'operationState': {'phase': phase, 'finishedAt': 'finished',
                            'syncResult': {'source': copy.deepcopy(value['spec']['source']), 'revision': revision}}}
                    documents[reduced.APPS + value['metadata']['name']] = value
                documents[marker_path] = {'metadata': {'uid': 'marker-uid'}}
                documents[sentinel_path] = {'metadata': {'uid': 'sentinel-uid'}}
                api = Mock()
                api.request.side_effect = lambda path: copy.deepcopy(documents[path])
                namespace = {'api': api, 'private': SimpleNamespace(revision='b' * 40),
                    'public': SimpleNamespace(revision='a' * 40), 'APPS': reduced.APPS, 'json': json,
                    'require': reduced.require, 'marker_path': marker_path, 'sentinel_path': sentinel_path,
                    'marker_uid': 'marker-uid', 'sentinel_uid': 'sentinel-uid'}
                exec(compile(ast.fix_missing_locations(ast.Module(body=copy.deepcopy(nodes), type_ignores=[])),
                             'actual-reduced-comparison-functions.py', 'exec'), namespace)
                with self.subTest(phase=phase, destination=fault):
                    self.assertEqual(bool(namespace['complete']('native-current')), fault is None)
                    with contextlib.redirect_stdout(io.StringIO()):
                        if fault is None: namespace['history']('current destination')
                        else:
                            with self.assertRaises(RuntimeError): namespace['history']('stale destination')

    def test_current_comparison_and_health_qualify_parent_and_child_without_fresh_operation_history(self):
        from unittest.mock import Mock
        from playbooks.observability.tests import lifecycle_stack_proof as stack
        from playbooks.observability.tests.fixtures import native_source_inputs
        public, private = 'a' * 40, 'b' * 40
        parent, _ = stack.parent_objects(public, private)
        inputs = native_source_inputs()
        inputs['nativeSource'] = {'repository': stack.PUBLIC, 'revision': public, 'valuesRepository': stack.PRIVATE}
        children = stack.helm('platform/observability/gitops', inputs)
        child = next(o for o in children if o['metadata']['name'] == 'cloudlab-observability')
        for base in (parent, child):
            multiple = base['metadata']['name'] == stack.PARENT
            source_key, revision_key = ('sources', 'revisions') if multiple else ('source', 'revision')
            current = copy.deepcopy(base['spec'][source_key])
            revision = [public, private] if multiple else public
            base['status'] = {'sync': {'status': 'Synced', revision_key: revision,
                'comparedTo': {source_key: copy.deepcopy(current), 'destination': copy.deepcopy(base['spec']['destination'])}},
                'health': {'status': 'Healthy'}}
            subject = stack.Qualification.__new__(stack.Qualification)
            subject.api = Mock()
            def ready(obj):
                subject.api.request.return_value = obj
                return subject.app_ready(base['metadata']['name'], public, private)
            with self.subTest(name=base['metadata']['name'], case='missing-history'): self.assertTrue(ready(base))
            for phase in ('Succeeded', 'Failed', 'Error'):
                old = copy.deepcopy(base)
                old['status']['operationState'] = {'phase': phase, 'finishedAt': '2026-01-01T00:00:00Z',
                    'syncResult': {source_key: copy.deepcopy(current), revision_key: ['c' * 40, private] if multiple else 'c' * 40}}
                previous = old['status']['operationState']['syncResult'][source_key]
                (previous[0] if multiple else previous)['targetRevision'] = 'c' * 40
                with self.subTest(name=base['metadata']['name'], phase=phase): self.assertTrue(ready(old))
            for phase in ('Running', 'Terminating'):
                active = copy.deepcopy(base)
                active['status']['operationState'] = {'phase': phase,
                    'syncResult': {source_key: copy.deepcopy(current), revision_key: revision}}
                with self.subTest(name=base['metadata']['name'], phase=phase): self.assertFalse(ready(active))
            for phase in ('Failed', 'Error'):
                finished = copy.deepcopy(base)
                finished['status']['operationState'] = {'phase': phase, 'finishedAt': '2026-01-01T00:00:00Z',
                    'syncResult': {source_key: copy.deepcopy(current), revision_key: copy.deepcopy(revision)}}
                with self.subTest(name=base['metadata']['name'], phase=phase, sameSource=True):
                    self.assertTrue(ready(finished))
                finished['status']['sync']['status'] = 'OutOfSync'
                with self.subTest(name=base['metadata']['name'], phase=phase, converged=False):
                    self.assertFalse(ready(finished))
            for fault in ('revision', 'comparison', 'destination-missing', 'destination-namespace', 'destination-server',
                          'changed-input', 'out-of-sync', 'unknown', 'unhealthy', 'error', 'request', 'paused'):
                changed = copy.deepcopy(base)
                if fault == 'revision': changed['status']['sync'][revision_key] = ['c' * 40, private] if multiple else 'c' * 40
                elif fault == 'comparison': changed['status']['sync']['comparedTo'][source_key] = [] if multiple else {}
                elif fault == 'destination-missing': changed['status']['sync']['comparedTo'].pop('destination')
                elif fault == 'destination-namespace': changed['status']['sync']['comparedTo']['destination']['namespace'] = 'stale'
                elif fault == 'destination-server': changed['status']['sync']['comparedTo']['destination']['server'] = 'https://stale.example.invalid'
                elif fault == 'changed-input':
                    target = changed['spec'][source_key][0] if multiple else changed['spec'][source_key]
                    target.setdefault('helm', {}).setdefault('valuesObject', {})['newInput'] = True
                elif fault == 'out-of-sync': changed['status']['sync']['status'] = 'OutOfSync'
                elif fault == 'unknown': changed['status']['sync']['status'] = 'Unknown'
                elif fault == 'unhealthy': changed['status']['health']['status'] = 'Unknown'
                elif fault == 'error': changed['status']['conditions'] = [{'type': 'ComparisonError'}]
                elif fault == 'request': changed['operation'] = {}
                elif fault == 'paused': changed['spec']['syncPolicy']['automated']['enabled'] = False
                with self.subTest(name=base['metadata']['name'], fault=fault): self.assertFalse(ready(changed))
            if not multiple:
                changed = copy.deepcopy(base)
                changed['metadata']['annotations']['cloudlab.io/observability-input-digest'] = 'd' * 64
                self.assertFalse(ready(changed))

    def test_actual_fixture_ca_has_critical_usage_and_default_strict_tls_accepts_only_trusted_hostname(self):
        from unittest.mock import Mock
        from playbooks.observability.tests import lifecycle_stack_proof as stack
        class FirstAPI(Exception):
            pass
        subject = stack.Qualification.__new__(stack.Qualification)
        subject.api = Mock()
        subject.api.apply.side_effect = FirstAPI
        arguments = []
        def generate(argv):
            arguments.append(list(argv))
            return command(argv)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(stack, 'command', side_effect=generate), self.assertRaises(FirstAPI):
                subject.generate_pki(directory)
                subject.gateway_issuer(directory)
            subject.api.apply.assert_called_once()
            self.assertEqual(subject.api.apply.call_args.args[0]['kind'], 'Secret')
            self.assertEqual(len(arguments), 3)
            self.assertEqual(arguments[0][arguments[0].index('-addext') + 1], 'keyUsage=critical,keyCertSign,cRLSign')
            self.assertEqual(sum(argv.count('-addext') for argv in arguments), 1)
            self.assertTrue(all('-addext' not in argv for argv in arguments[1:]))
            self.assertTrue(all(argv[argv.index('-newkey') + 1] == 'rsa:2048' for argv in arguments[:2]))
            self.assertEqual(arguments[0][arguments[0].index('-days') + 1], '2')
            self.assertEqual(arguments[2][arguments[2].index('-days') + 1], '2')
            usage = command(['openssl', 'x509', '-in', str(directory / 'ca.crt'), '-noout', '-ext', 'keyUsage'])
            basic = command(['openssl', 'x509', '-in', str(directory / 'ca.crt'), '-noout', '-ext', 'basicConstraints'])
            self.assertIn('X509v3 Key Usage: critical', usage)
            self.assertIn('Certificate Sign, CRL Sign', usage)
            self.assertIn('X509v3 Basic Constraints: critical', basic)
            self.assertIn('CA:TRUE', basic)
            command(['openssl', 'verify', '-x509_strict', '-purpose', 'sslserver', '-verify_hostname', lifecycle_dns.LOGIN_HOST,
                     '-CAfile', str(directory / 'ca.crt'), str(directory / 'server.crt')])
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(str(directory / 'server.crt'), str(directory / 'server.key'))
            def handshake(hostname, trusted):
                client_context = ssl.create_default_context(cafile=str(directory / 'ca.crt')) if trusted else ssl.create_default_context()
                self.assertTrue(client_context.check_hostname)
                self.assertEqual(client_context.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(client_context.verify_flags & ssl.VERIFY_X509_STRICT)
                incoming, outgoing, peer_in, peer_out = [ssl.MemoryBIO() for _ in range(4)]
                client = client_context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=hostname)
                server = server_context.wrap_bio(peer_in, peer_out, server_side=True)
                client_done = server_done = False
                transferred = 0
                for _ in range(20):
                    if not client_done:
                        try: client.do_handshake(); client_done = True
                        except (ssl.SSLWantReadError, ssl.SSLWantWriteError): pass
                    if outgoing.pending:
                        self.assertLessEqual(outgoing.pending, 65536)
                        data = outgoing.read(65536)
                        transferred += len(data)
                        peer_in.write(data)
                    if not server_done:
                        try: server.do_handshake(); server_done = True
                        except (ssl.SSLWantReadError, ssl.SSLWantWriteError): pass
                    if peer_out.pending:
                        self.assertLessEqual(peer_out.pending, 65536)
                        data = peer_out.read(65536)
                        transferred += len(data)
                        incoming.write(data)
                    self.assertLessEqual(transferred, 131072)
                    if client_done and server_done: return
                self.fail('Bounded fixture TLS handshake did not complete')
            handshake(lifecycle_dns.LOGIN_HOST, True)
            for hostname, trusted, expected in [('wrong.' + lifecycle_dns.ZONE, True, 62), (lifecycle_dns.LOGIN_HOST, False, 20)]:
                with self.subTest(trusted=trusted), self.assertRaises(ssl.SSLCertVerificationError) as failure:
                    handshake(hostname, trusted)
                self.assertEqual(failure.exception.verify_code, expected)
            self.assertEqual((directory / 'server.ext').read_text(), 'subjectAltName=DNS:' + lifecycle_dns.LOGIN_HOST
                + ',DNS:*.internal.' + lifecycle_dns.ZONE + '\n')
        self.assertFalse(directory.exists())

    def test_positive_fixture_hosts_routes_dns_tls_and_payload_share_reserved_test_zone(self):
        import ast
        import inspect
        import textwrap
        from unittest.mock import Mock
        from playbooks.observability.tests import lifecycle_stack_proof as stack
        self.assertEqual(lifecycle_dns.ZONE, 'example.test')
        self.assertEqual(lifecycle_dns.LOGIN_HOST, 'login.' + lifecycle_dns.ZONE)
        self.assertEqual(lifecycle_dns.ISSUER, 'https://' + lifecycle_dns.LOGIN_HOST + '/realms/platform')
        source = ast.parse(textwrap.dedent(inspect.getsource(stack.Qualification.run)))
        private = next(node for node in ast.walk(source) if isinstance(node, ast.Dict)
            and {'loginHost', 'grafanaHost', 'kialiHost'} <= {key.value for key in node.keys if isinstance(key, ast.Constant)})
        inputs = eval(compile(ast.Expression(private), 'positive-private-fixture.py', 'eval'), vars(stack))
        self.assertEqual([inputs[key] for key in ('loginHost', 'grafanaHost', 'kialiHost')],
            [lifecycle_dns.LOGIN_HOST, lifecycle_dns.GRAFANA_HOST, lifecycle_dns.KIALI_HOST])
        subject = stack.Qualification.__new__(stack.Qualification)
        subject.api, subject.apply_all, subject.issuer_dns, subject.issuer_probe = Mock(), Mock(), Mock(), Mock()
        raw = (ROOT / 'platform/connectivity/gateways/values.json').read_bytes()
        image = json.loads(raw)['proxyImage']
        applied = []
        def apply(value):
            applied.append(copy.deepcopy(value))
            return {**value, 'metadata': {**value['metadata'], 'uid': 'fixture-uid', 'resourceVersion': '7'}}
        subject.api.apply.side_effect = apply
        def request(path, *args):
            if path.endswith('/deployments'): return {'items': [{'spec': {'template': {'spec': {'containers': [{'image': image}]}}}}]}
            if path.endswith('/configmaps/coredns'): return {'data': {'Corefile': 'import custom/*.server'}}
            return {'metadata': {'labels': {'istio-injection': 'disabled'}}}
        subject.api.request.side_effect = request
        subject.wait = lambda predicate, label, *args: {'spec': {'clusterIP': '10.43.0.20'}} if label == 'private Gateway Service' else True
        with tempfile.TemporaryDirectory() as temporary, patch.object(stack, 'command'), patch.object(stack, 'helm', return_value=[]) as render:
            directory = Path(temporary)
            for name in ('ca.key', 'ca.crt', 'server.key', 'server.crt'): (directory / name).write_text('synthetic')
            subject.generate_pki(directory)
            subject.gateway_issuer(directory)
            self.assertEqual(render.call_args.args[1]['zone'], lifecycle_dns.ZONE)
            self.assertEqual((directory / 'server.ext').read_text(), 'subjectAltName=DNS:' + lifecycle_dns.LOGIN_HOST
                + ',DNS:*.internal.' + lifecycle_dns.ZONE + '\n')
        self.assertEqual((ROOT / 'platform/connectivity/gateways/values.json').read_bytes(), raw)
        route = next(value for value in applied if value['kind'] == 'HTTPRoute')
        self.assertEqual(route['spec']['hostnames'], [lifecycle_dns.LOGIN_HOST])
        core = next(value for value in applied if value['metadata']['name'] == 'coredns-custom')['data']['lifecycle.server']
        self.assertTrue(core.startswith(lifecycle_dns.ZONE + ':53 {'))
        self.assertIn('10.43.0.20 ' + lifecycle_dns.LOGIN_HOST + ' ' + lifecycle_dns.KIALI_HOST + '\n', core)
        self.assertEqual(core.count('10.43.0.20 '), 1)
        server = next(value for value in applied if value['metadata']['name'] == 'fixture-issuer' and value['kind'] == 'ConfigMap')['data']['issuer.py']
        server_assignment = next(node for node in ast.parse(server).body if isinstance(node, ast.Assign))
        self.assertEqual(ast.literal_eval(server_assignment.value), lifecycle_dns.ISSUER)
        self.assertEqual(ast.literal_eval(ast.parse(issuer_probe_code()).body[0].value), lifecycle_dns.ISSUER)
        self.assertNotIn('example.invalid', inspect.getsource(stack.Qualification))

    def test_issuer_probe_reports_only_safe_categories_and_preserves_failure_and_retry_bounds(self):
        secret = 'secret-token:https://sensitive.invalid/private?password=hidden'
        cases = [
            ('dns', urllib.error.URLError(socket.gaierror(-2, secret))),
            ('connect', urllib.error.URLError(ConnectionRefusedError(111, secret))),
            ('timeout', urllib.error.URLError(TimeoutError(secret))),
            ('tls-verify-or-handshake', urllib.error.URLError(ssl.SSLCertVerificationError(1, secret))),
            ('tls-verify-or-handshake', ssl.SSLError(1, secret)),
            ('http-status', urllib.error.HTTPError(secret, 503, secret, {}, None)),
            ('unknown', RuntimeError(secret)),
        ]
        for category, error in cases:
            with self.subTest(category=category), patch('ssl.create_default_context') as context, \
                    patch('urllib.request.urlopen', side_effect=error) as request, patch('time.sleep') as sleep:
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as failure:
                    exec(compile(issuer_probe_code(), 'fixture-issuer-probe.py', 'exec'), {})
                self.assertEqual(failure.exception.code, 1)
                self.assertEqual(output.getvalue(), 'issuer-probe stage=request failure=' + category + '\n')
                self.assertNotIn(secret, output.getvalue())
                self.assertEqual(request.call_count, 45)
                self.assertEqual([call.args for call in sleep.call_args_list], [(2,)] * 44)
                context.assert_called_once_with(cafile='/fixture/ca.crt')
                self.assertTrue(all(call.args == (lifecycle_dns.ISSUER + '/.well-known/openid-configuration',)
                    and call.kwargs == {'context': context.return_value, 'timeout': 3} for call in request.call_args_list))

    def test_issuer_probe_payload_ca_and_success_keep_exact_trust_and_identity(self):
        for payload in ('not-json:secret-token', '{"issuer":"https://secret.invalid/private"}'):
            with self.subTest(payload=payload), patch('ssl.create_default_context'), \
                    patch('urllib.request.urlopen', side_effect=lambda *args, **kwargs: io.StringIO(payload)) as request, \
                    patch('time.sleep'):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as failure:
                    exec(compile(issuer_probe_code(), 'fixture-issuer-probe.py', 'exec'), {})
                self.assertEqual(failure.exception.code, 1)
                self.assertEqual(output.getvalue(), 'issuer-probe stage=payload failure=payload\n')
                self.assertEqual(request.call_count, 45)
        with patch('ssl.create_default_context', side_effect=OSError('secret-ca-path')), patch('urllib.request.urlopen') as request:
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as failure:
                exec(compile(issuer_probe_code(), 'fixture-issuer-probe.py', 'exec'), {})
            self.assertEqual(failure.exception.code, 1)
            self.assertEqual(output.getvalue(), 'issuer-probe stage=local-ca failure=local-ca\n')
            request.assert_not_called()
        with patch('ssl.create_default_context'), patch('urllib.request.urlopen',
                return_value=io.StringIO(json.dumps({'issuer': lifecycle_dns.ISSUER}))) as request, \
                patch('time.sleep') as sleep:
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                exec(compile(issuer_probe_code(), 'fixture-issuer-probe.py', 'exec'), {})
            self.assertEqual(output.getvalue(), '')
            request.assert_called_once()
            sleep.assert_not_called()

    def test_docker_cni_adaptation_changes_only_named_binary_hostpath(self):
        path = 'platform/connectivity/istio/cni'
        source = ROOT / path / 'values.json'
        raw = source.read_bytes()
        canonical_values = json.loads(raw)
        adapted_values = fixture_mesh_values('cni')
        self.assertEqual(adapted_values['cni'].pop('cni'), {'cniBinDir': '/bin'})
        self.assertEqual(adapted_values, canonical_values)
        canonical = helm(path, canonical_values, 'istio-system', 'cni')
        adapted = helm(path, fixture_mesh_values('cni'), 'istio-system', 'cni')
        def binary_volume(objects):
            daemonset = next(o for o in objects if o['kind'] == 'DaemonSet' and o['metadata']['name'] == 'istio-cni-node')
            return next(v for v in daemonset['spec']['template']['spec']['volumes'] if v['name'] == 'cni-bin-dir')
        self.assertEqual(binary_volume(canonical)['hostPath']['path'], '/var/lib/rancher/k3s/data/cni')
        self.assertEqual(binary_volume(adapted)['hostPath']['path'], '/bin')
        binary_volume(adapted)['hostPath']['path'] = binary_volume(canonical)['hostPath']['path']
        self.assertEqual(adapted, canonical)
        self.assertEqual(source.read_bytes(), raw)
        for component in ('base', 'istiod', 'ztunnel'):
            self.assertEqual(fixture_mesh_values(component), json.loads(
                (ROOT / 'platform/connectivity/istio' / component / 'values.json').read_text()))

    def test_image_tags_are_optional_but_repository_and_digest_must_match(self):
        digest = 'sha256:' + 'a' * 64
        allowed = {'docker.io/grafana/loki:3.6.12@' + digest}
        pinned_images([{'image': next(iter(allowed))}], allowed)
        pinned_images([{'image': 'docker.io/grafana/loki@' + digest}], allowed)
        for value in ('other.invalid/grafana/loki@' + digest, 'docker.io/other/loki@' + digest,
                      'docker.io/grafana/loki@sha256:' + 'b' * 64, 'docker.io/grafana/loki:3.6.12'):
            with self.subTest(image=value), self.assertRaises(RuntimeError):
                pinned_images([{'image': value}], allowed)

    def test_sources_keep_https_roles_actual_paths_and_full_shas(self):
        app = {'metadata': {'name': 'cloudlab-loki'}, 'spec': {'source': {
            'repoURL': PUBLIC, 'targetRevision': 'a' * 40, 'path': 'platform/observability/loki'}}}
        source_guard(app, 'a' * 40, 'b' * 40)
        for change in ({'repoURL': PRIVATE, 'targetRevision': 'b' * 40}, {'targetRevision': 'main'},
                       {'repoURL': 'http://fixture/public.git'}, {'path': 'synthetic-chart'}):
            bad = copy.deepcopy(app)
            bad['spec']['source'].update(change)
            with self.assertRaises(RuntimeError):
                source_guard(bad, 'a' * 40, 'b' * 40)
        parent = {'metadata': {'name': 'cloudlab-observability-gitops'}, 'spec': {'sources': [
            {'repoURL': PUBLIC, 'targetRevision': 'a' * 40}, {'repoURL': PRIVATE, 'targetRevision': 'b' * 40}]}}
        source_guard(parent, 'a' * 40, 'b' * 40)
        parent['spec']['sources'][1] = copy.deepcopy(parent['spec']['sources'][0])
        with self.assertRaises(RuntimeError):
            source_guard(parent, 'a' * 40, 'b' * 40)

    def test_git_override_is_repo_server_only_read_only_global_config(self):
        values = repo_values()['argo-cd']
        repo = values['repoServer']
        self.assertIn({'name': 'GIT_CONFIG_GLOBAL', 'value': '/fixture/gitconfig'}, repo['env'])
        self.assertFalse(any(v['name'] == 'GIT_CONFIG_COUNT' for v in repo['env']))
        self.assertTrue(repo['volumeMounts'][0]['readOnly'])
        self.assertEqual(repo['volumes'][0]['configMap']['name'], 'fixture-git')
        for component in ('controller', 'server', 'applicationSet'):
            self.assertFalse(any(v['name'] == 'GIT_CONFIG_GLOBAL' for v in values[component].get('env', [])))

    def test_denial_probe_is_bounded_tokenless_and_disjoint_from_real_services(self):
        job = denied_github_job()
        self.assertNotIn('status', job)
        self.assertEqual(job['spec']['activeDeadlineSeconds'], 150)
        pod = job['spec']['template']
        self.assertEqual(pod['metadata']['labels'], {'cloudlab.io/restricted-git': 'true'})
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        self.assertNotIn('hostNetwork', pod['spec'])
        self.assertIn('@sha256:', pod['spec']['containers'][0]['image'])

    def test_outer_owner_is_only_fixture_application_authority(self):
        project, app = owner_application()
        self.assertEqual(project['spec']['sourceRepos'], [OWNER])
        self.assertEqual(project['spec']['clusterResourceWhitelist'], [])
        self.assertEqual(project['spec']['namespaceResourceWhitelist'], [{'group': 'argoproj.io', 'kind': 'Application'}])
        self.assertEqual(project['spec']['destinations'], [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}])
        self.assertEqual(app['spec']['source'], {'repoURL': OWNER, 'targetRevision': 'main', 'path': 'parent'})

    def test_default_git_denies_owner_and_fixture_extension_only_adds_exact_owner_upload_pack(self):
        self.assertEqual(ReadOnlyGit.repositories, ('public.git', 'private.git'))
        self.assertEqual(ObservedGit.repositories, ('public.git', 'private.git', 'owner.git'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = GitSource(root, 'owner', {'parent/marker': 'synthetic'})
            for handler in (ReadOnlyGit, ObservedGit):
                server = GitServer(('127.0.0.1', 0), functools.partial(handler, directory=str(root)))
                server.observation_lock, server.observations = threading.Lock(), []
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                url = 'http://127.0.0.1:' + str(server.server_port)
                try:
                    if handler is ReadOnlyGit:
                        with self.assertRaises(urllib.error.HTTPError) as failure:
                            urllib.request.urlopen(url + '/owner.git/info/refs?service=git-upload-pack')
                        self.assertEqual(failure.exception.code, 403)
                    else:
                        clone = root / 'clone'
                        command(['git', 'clone', '--branch', 'main', url + '/owner.git', str(clone)])
                        self.assertEqual(command(['git', 'rev-parse', 'HEAD'], clone).strip(), owner.revision)
                    for path in ('/arbitrary.git/info/refs?service=git-upload-pack', '/owner.git/HEAD',
                                 '/owner.git/git-receive-pack', '/owner.git/../private-key',
                                 '/owner.git/info/refs?service=git-receive-pack',
                                 '/owner.git/%2e%2e/private-key'):
                        with self.subTest(handler=handler.__name__, path=path), self.assertRaises(urllib.error.HTTPError) as failure:
                            urllib.request.urlopen(url + path)
                        self.assertEqual(failure.exception.code, 403)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
