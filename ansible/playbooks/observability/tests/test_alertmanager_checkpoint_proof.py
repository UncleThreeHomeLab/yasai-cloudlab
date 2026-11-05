"""Check proof authority and snapshot completeness without VM credentials."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import runpy
import tarfile
import tempfile
import threading
import types
import sys
import unittest
from unittest.mock import patch
from unittest.mock import Mock

import yaml

from playbooks.observability.tests import alertmanager_checkpoint_proof as proof


class CheckpointProofTests(unittest.TestCase):
    def receipt(self, directory):
        return proof.Receipt(directory, 'a' * 16)

    def test_native_nc_request_targets_and_utf8_content_length_are_fixed(self):
        value = [{'labels': {'alertname': 'Fixture'}, 'annotations': {'summary': '測試'}}]
        raw = proof.native_http_request('/api/v2/alerts', value)
        header, body = raw.split(b'\r\n\r\n')
        self.assertEqual(body, proof.canonical(value))
        self.assertIn(b'Content-Length: ' + str(len(body)).encode(), header)
        self.assertTrue(header.startswith(b'POST /api/v2/alerts HTTP/1.1\r\n'))
        self.assertIn(b'Host: 127.0.0.1:9093\r\nConnection: close\r\nAccept-Encoding: identity\r\n', header)
        for path, value in [('http://foreign:9093/api/v2/status', None), ('/api/v2/status?x=1', None),
                            ('/api/v2/status\r\nHost: foreign', None), ('/api/v2/silence/not-a-uuid', None),
                            ('/api/v2/alerts', None), ('/api/v2/status', [{}]), ('/api/v2/alerts', []),
                            ('/api/v2/alerts', [{}] * 17), ('/api/v2/alerts', [{'x': 'a' * 1048576}])]:
            with self.subTest(path=path), self.assertRaises(RuntimeError): proof.native_http_request(path, value)
        self.assertTrue(proof.native_http_request('/api/v2/silence/12345678-abcd-4321-abcd-123456789abc').startswith(b'GET '))

    def test_source_storage_accepts_only_exact_public_bounded_emptydir_shape(self):
        expected = {'emptyDir': {'sizeLimit': '64Mi'}}
        self.assertEqual(proof.approved_source_storage(expected), expected)
        for value in (None, {}, {'emptyDir': {}}, {'emptyDir': {'sizeLimit': '1Gi'}},
                {'emptyDir': {'sizeLimit': 64}}, {'emptyDir': {'sizeLimit': '64Mi', 'medium': 'Memory'}},
                {'emptyDir': {'sizeLimit': '64Mi'}, 'disableMountSubPath': True},
                {'emptyDir': {'sizeLimit': '64Mi'}, 'volumeClaimTemplate': {}}, {'hostPath': {'path': '/data'}}):
            with self.subTest(value=value), self.assertRaises(RuntimeError): proof.approved_source_storage(value)
        with patch.object(proof, 'preflight') as api, tempfile.TemporaryDirectory(dir='/root') as directory, \
                self.assertRaises(RuntimeError):
            proof.run({'sourceStorage': {'volumeClaimTemplate': {}}}, directory, 'a' * 16)
        api.assert_not_called()

    def test_expected_retained_storage_normalizes_only_approved_emptydir_null(self):
        expected = {'volumeClaimTemplate': {'metadata': {'annotations': {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}},
            'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'cloudlab-telemetry',
                     'resources': {'requests': {'storage': '1Gi'}}}}}
        for value in (expected, dict(copy.deepcopy(expected), emptyDir=None)):
            original = copy.deepcopy(value)
            result = proof.approved_retained_storage(value)
            self.assertEqual(result, expected)
            self.assertEqual(value, original)
            self.assertIsNot(result['volumeClaimTemplate'], value['volumeClaimTemplate'])
        for fault in ('empty', 'mode', 'size', 'access', 'class', 'annotations', 'name', 'owner', 'unknown', 'unrelated-null'):
            value = copy.deepcopy(expected)
            template = value['volumeClaimTemplate']
            if fault == 'empty': value = {'volumeClaimTemplate': {}}
            if fault == 'mode': value['emptyDir'] = {}
            if fault == 'size': template['spec']['resources']['requests']['storage'] = '2Gi'
            if fault == 'access': template['spec']['accessModes'] = ['ReadWriteMany']
            if fault == 'class': template['spec']['storageClassName'] = 'foreign'
            if fault == 'annotations': template['metadata']['annotations'] = {}
            if fault == 'name': template['metadata']['name'] = 'foreign'
            if fault == 'owner': template['metadata']['ownerReferences'] = []
            if fault == 'unknown': value['disableMountSubPath'] = False
            if fault == 'unrelated-null': template['spec']['selector'] = None
            with self.subTest(fault=fault), self.assertRaises(RuntimeError): proof.approved_retained_storage(value)
        for storage in (dict(copy.deepcopy(expected), emptyDir=None), {'emptyDir': {}}, expected):
            payload = {'sourceStorage': {'emptyDir': {'sizeLimit': '64Mi'}}, 'storage': storage,
                       'retention': {'whenDeleted': 'Delete', 'whenScaled': 'Retain'} if storage == expected else
                                    {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}}
            with tempfile.TemporaryDirectory(dir='/root') as directory, patch.object(proof, 'Receipt') as receipt, \
                    patch.object(proof, 'preflight') as api, self.assertRaises(RuntimeError):
                proof.run(payload, directory, 'a' * 16)
            receipt.assert_not_called()
            api.assert_not_called()

    def test_native_storage_calibration_is_dryrun_fullspec_and_preserves_source(self):
        target = {'volumeClaimTemplate': {'metadata': {'annotations': {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}},
            'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'cloudlab-telemetry',
                     'resources': {'requests': {'storage': '1Gi'}}}}}
        for fault in ('', 'status-rv-only', 'status-between-candidates', 'initial-replicas', 'initial-retention', 'response-uid', 'response-rv',
                      'replicas', 'retention', 'extra-default', 'keeps-null', 'second-roundtrip', 'api',
                      'source-uid', 'source-spec', 'before-uid', 'before-spec', 'between-uid', 'between-spec', 'claim', 'claim-api'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir='/root') as directory:
                cluster = proof.Cluster(self.receipt(directory))
                source = proof.document('Alertmanager', 'primary', cluster, spec={'replicas': 0,
                    'storage': {'emptyDir': {'sizeLimit': '64Mi'}}, 'image': 'native@sha256:' + 'a' * 64,
                    'additionalArgs': [{'name': 'data.maintenance-interval', 'value': '5s'}],
                    'persistentVolumeClaimRetentionPolicy': {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}})
                row = cluster.receipt.intent(source)
                source['metadata'].update(uid='manager', resourceVersion='7')
                cluster.receipt.created(row, source)
                original = copy.deepcopy(source)
                reads, patches = [], []
                current_rv = '7'
                def read(kind, name=None, namespace=None):
                    reads.append(kind)
                    if kind == 'PersistentVolumeClaim':
                        if fault == 'claim-api': raise RuntimeError('Claim API unavailable')
                        return {'items': [{'metadata': {'uid': 'foreign'}}] if fault == 'claim' else []}
                    current = copy.deepcopy(source)
                    current['metadata']['resourceVersion'] = current_rv
                    if fault == 'initial-replicas': current['spec']['replicas'] = 1
                    if fault == 'initial-retention': current['spec']['persistentVolumeClaimRetentionPolicy']['whenDeleted'] = 'Delete'
                    number = reads.count('Alertmanager')
                    if number == 2 and fault == 'before-uid' or number == 3 and fault == 'between-uid': current['metadata']['uid'] = 'foreign'
                    if number == 2 and fault == 'before-spec' or number == 3 and fault == 'between-spec': current['spec']['additionalArgs'] = []
                    if number == 4:
                        if fault == 'source-uid': current['metadata']['uid'] = 'foreign'
                        if fault == 'source-spec': current['spec']['additionalArgs'] = []
                        if fault == 'status-rv-only': current.update(status={'updated': True}); current['metadata']['resourceVersion'] = '8'
                    return current
                def dryrun(*args):
                    nonlocal current_rv
                    self.assertIn('--dry-run=server', args)
                    self.assertIn('--type=json', args)
                    patch_body = json.loads(args[args.index('-p') + 1])
                    self.assertEqual(patch_body[:2], [{'op': 'test', 'path': '/metadata/uid', 'value': 'manager'},
                        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current_rv}])
                    self.assertEqual(patch_body[2], {'op': 'replace', 'path': '/spec/storage',
                        'value': target if not patches else dict(copy.deepcopy(target), emptyDir=None)})
                    patches.append(patch_body)
                    if fault == 'api': raise RuntimeError('Stale UID/RV or API rejection')
                    returned = copy.deepcopy(source)
                    returned['metadata']['resourceVersion'] = current_rv
                    returned['spec']['storage'] = copy.deepcopy(target)
                    if fault == 'response-uid': returned['metadata']['uid'] = 'foreign'
                    if fault == 'response-rv': returned['metadata']['resourceVersion'] = 'foreign'
                    if fault == 'replicas': returned['spec']['replicas'] = 1
                    if fault == 'retention': returned['spec']['persistentVolumeClaimRetentionPolicy']['whenScaled'] = 'Delete'
                    if fault == 'extra-default': returned['spec']['unexpectedDefault'] = False
                    if fault == 'keeps-null': returned['spec']['storage']['emptyDir'] = None
                    if fault == 'second-roundtrip' and len(patches) == 2: returned['spec']['image'] = 'foreign'
                    if fault == 'status-between-candidates' and len(patches) == 1: current_rv = '8'
                    return proof.canonical(returned)
                with patch.object(proof, 'get', side_effect=read), patch.object(proof, 'kubectl', side_effect=dryrun), \
                        patch.object(cluster, 'patch') as write:
                    if fault in ('', 'status-rv-only', 'status-between-candidates'):
                        proof.calibrate_retained_storage(cluster, target)
                        self.assertEqual(len(patches), 2)
                        self.assertEqual(reads, ['Alertmanager'] * 4 + ['PersistentVolumeClaim'])
                        if fault == 'status-between-candidates':
                            self.assertEqual([patch[1]['value'] for patch in patches], ['7', '8'])
                    else:
                        with self.assertRaises(RuntimeError): proof.calibrate_retained_storage(cluster, target)
                        if fault in ('before-uid', 'before-spec'): self.assertFalse(patches)
                        if fault in ('between-uid', 'between-spec'): self.assertEqual(len(patches), 1)
                    write.assert_not_called()
                self.assertEqual(source, original)

    def test_source_cr_admission_and_readback_reject_changed_storage_before_scale(self):
        source = {'apiVersion': 'monitoring.coreos.com/v1', 'kind': 'Alertmanager', 'metadata': {'name': 'primary'},
                  'spec': {'replicas': 0, 'storage': {'emptyDir': {'sizeLimit': '64Mi'}}}}
        for failure in (None, 'dryrun-pvc', 'dryrun-mount', 'created-mode', 'readback-mode', 'early-scale'):
            cluster = Mock(namespace='fixture')
            dryrun, created, current = (copy.deepcopy(source) for _ in range(3))
            if failure == 'dryrun-pvc': dryrun['spec']['storage'] = {'volumeClaimTemplate': {}}
            if failure == 'dryrun-mount': dryrun['spec']['storage']['disableMountSubPath'] = True
            if failure == 'created-mode': created['spec']['storage'] = {'emptyDir': {}}
            if failure == 'readback-mode': current['spec']['storage'] = {'hostPath': {'path': '/data'}}
            if failure == 'early-scale': dryrun['spec']['replicas'] = 1
            cluster.create.side_effect = [dryrun, created]
            cluster.current.return_value = current
            with self.subTest(failure=failure):
                if failure:
                    with self.assertRaises(RuntimeError): proof.create_source_manager(cluster, source)
                    if failure in ('dryrun-pvc', 'dryrun-mount', 'early-scale'):
                        cluster.create.assert_called_once_with(source, dry_run=True)
                else:
                    proof.create_source_manager(cluster, source)
                    self.assertEqual(cluster.create.call_args_list, [unittest.mock.call(source, dry_run=True), unittest.mock.call(source)])
                    cluster.current.assert_called_once_with('Alertmanager', 'primary', 'fixture')
                cluster.patch.assert_not_called()

    def test_source_volume_requires_native_bounded_emptydir_and_exact_subpath(self):
        spec = {'containers': [{'name': 'alertmanager', 'volumeMounts': [{'name': 'alertmanager-primary-db',
                    'mountPath': '/alertmanager', 'subPath': 'alertmanager-db'}]}],
                'volumes': [{'name': 'alertmanager-primary-db', 'emptyDir': {'sizeLimit': '64Mi'}}]}
        proof.source_volume(spec)
        with self.assertRaises(RuntimeError):
            proof.source_volume(spec, [{'metadata': {'name': 'unexpected-claim'}}])
        for failure in ('missing-subpath', 'expression', 'pvc', 'hostpath', 'ephemeral', 'size', 'unknown-source'):
            changed = copy.deepcopy(spec)
            if failure == 'missing-subpath': changed['containers'][0]['volumeMounts'][0].pop('subPath')
            if failure == 'expression': changed['containers'][0]['volumeMounts'][0]['subPathExpr'] = 'other'
            if failure == 'pvc': changed['volumes'][0] = {'name': 'alertmanager-primary-db', 'persistentVolumeClaim': {'claimName': 'foreign'}}
            if failure == 'hostpath': changed['volumes'].append({'name': 'other', 'hostPath': {'path': '/data'}})
            if failure == 'ephemeral': changed['volumes'].append({'name': 'other', 'ephemeral': {'volumeClaimTemplate': {}}})
            if failure == 'size': changed['volumes'][0]['emptyDir']['sizeLimit'] = '1Gi'
            if failure == 'unknown-source': changed['volumes'][0]['secret'] = {'secretName': 'foreign'}
            with self.subTest(failure=failure), self.assertRaises(RuntimeError): proof.source_volume(changed)

    def test_native_zero_to_one_profile_allows_only_exact_replica_argument_transition(self):
        namespace = proof.PREFIX + 'a' * 16
        zero = proof.pod_profile({'containers': [{'name': 'alertmanager', 'image': 'pinned-native',
            'args': ['--config.file=/config/native', '--cluster.listen-address=[$(POD_IP)]:9094',
                     '--cluster.peer-name=$(POD_NAME)', '--data.maintenance-interval=5s']}],
            'serviceAccountName': 'proof-alertmanager'})
        original = copy.deepcopy(zero)
        current = copy.deepcopy(zero)
        current['containers'][0]['args'][1] = '--cluster.listen-address='
        current['containers'][0]['args'].append('--cluster.peer=alertmanager-primary-0.alertmanager-operated:9094')
        self.assertEqual(proof.singleton_profile(zero, current, namespace), current)
        self.assertEqual(zero, original)
        for change in ('foreign-peer', 'second-peer', 'listen-enabled', 'maintenance', 'unexpected-arg', 'image', 'command'):
            changed = copy.deepcopy(current)
            container = changed['containers'][0]
            if change == 'foreign-peer': container['args'][-1] = '--cluster.peer=other.foreign.svc:9094'
            if change == 'second-peer': container['args'].append('--cluster.peer=alertmanager-primary-1.alertmanager-operated:9094')
            if change == 'listen-enabled': container['args'][1] = '--cluster.listen-address=:9094'
            if change == 'maintenance': container['args'][3] = '--data.maintenance-interval=15m'
            if change == 'unexpected-arg': container['args'].append('--web.listen-address=:1234')
            if change == 'image': container['image'] = 'foreign'
            if change == 'command': container['command'] = ['/bin/sh']
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                proof.singleton_profile(zero, changed, namespace)

    def test_singleton_template_pins_current_owned_lineage_and_preserves_zero_admission(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            image = 'native@sha256:' + 'a' * 64
            zero_spec = {'securityContext': copy.deepcopy(proof.POD_SECURITY), 'serviceAccountName': 'proof-alertmanager',
                'automountServiceAccountToken': False, 'containers': [{'name': 'alertmanager', 'image': image,
                    'args': ['--config.file=/config/native', '--cluster.listen-address=[$(POD_IP)]:9094',
                             '--data.maintenance-interval=5s'], 'securityContext': copy.deepcopy(proof.SECURITY),
                    'resources': copy.deepcopy(proof.RESOURCES)}]}
            one_spec = copy.deepcopy(zero_spec)
            one_spec['containers'][0]['args'][1] = '--cluster.listen-address='
            one_spec['containers'][0]['args'].append('--cluster.peer=alertmanager-primary-0.alertmanager-operated:9094')
            objects = {}
            def record(item, uid):
                row = cluster.receipt.intent(item)
                item['metadata'].update(uid=uid, resourceVersion='1')
                cluster.receipt.created(row, item)
                objects[item['kind']] = item
                return item
            manager = record(proof.document('Alertmanager', 'primary', cluster, spec={'replicas': 1,
                'forceEnableClusterMode': False, 'additionalArgs': [{'name': 'data.maintenance-interval', 'value': '5s'}]}), 'manager')
            sts = record(proof.document('StatefulSet', 'alertmanager-primary', cluster,
                spec={'replicas': 1, 'template': {'metadata': {'labels': proof.labels(cluster.operation)}, 'spec': one_spec}},
                status={'observedGeneration': 2, 'currentReplicas': 1, 'replicas': 1}), 'statefulset')
            sts['metadata'].update(generation=2, ownerReferences=[{'kind': 'Alertmanager', 'name': 'primary',
                                                                  'uid': 'manager', 'controller': True}])
            service = record(proof.document('Service', 'alertmanager-operated', cluster,
                spec={'clusterIP': 'None', 'selector': {'alertmanager': 'primary'}, 'ports': [{'port': 9093}]}), 'service')
            pod = record(proof.document('Pod', 'alertmanager-primary-0', cluster, spec=copy.deepcopy(one_spec),
                status={'containerStatuses': [{'name': 'alertmanager', 'containerID': 'source', 'restartCount': 0,
                        'state': {'running': {'startedAt': '2026-11-05T12:00:00Z'}}}]}), 'pod')
            pod['metadata']['labels']['alertmanager'] = 'primary'
            pod['metadata']['ownerReferences'] = [{'kind': 'StatefulSet', 'name': 'alertmanager-primary',
                                                  'uid': 'statefulset', 'controller': True}]
            lineage = {'uid': 'statefulset', 'generation': 1, 'replicas': 0,
                       'alertmanagerUID': 'manager', 'serviceUID': 'service'}
            cluster.receipt.value['evidence'].update(zeroNativePodProfile=proof.pod_profile(zero_spec), zeroNativeTemplate=lineage)
            with patch.object(proof, 'kubectl', return_value=b'{}'):
                controls = proof.pod_dry_run({'metadata': {'labels': proof.labels(cluster.operation)}, 'spec': zero_spec},
                                             cluster.namespace, 'zero-admission')
            before = copy.deepcopy(objects)
            for change in (None, 'image', 'security', 'foreign-peer', 'unexpected-arg', 'uid', 'owner', 'pod-owner',
                           'service-uid', 'dns', 'observed-generation', 'current-replicas'):
                objects.clear(); objects.update(copy.deepcopy(before))
                source = objects['Pod']
                current = objects['StatefulSet']
                if change == 'image': current['spec']['template']['spec']['containers'][0]['image'] = 'foreign@sha256:' + 'b' * 64
                if change == 'security': current['spec']['template']['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'] = True
                if change == 'foreign-peer': current['spec']['template']['spec']['containers'][0]['args'][-1] = '--cluster.peer=other.namespace:9094'
                if change == 'unexpected-arg': current['spec']['template']['spec']['containers'][0]['args'].append('--web.listen-address=:1234')
                if change == 'uid': current['metadata']['uid'] = 'foreign'
                if change == 'owner': current['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                if change == 'pod-owner': source['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                if change == 'service-uid': objects['Service']['metadata']['uid'] = 'foreign'
                if change == 'dns': source['spec']['dnsConfig'] = {'searches': ['foreign.svc']}
                if change == 'observed-generation': current['status']['observedGeneration'] = 1
                if change == 'current-replicas': current['status']['currentReplicas'] = 0
                with self.subTest(change=change), patch.object(proof, 'get', side_effect=lambda kind, *args: copy.deepcopy(objects[kind])), \
                        patch.object(proof, 'kubectl', return_value=b'{}'):
                    if change in ('observed-generation', 'current-replicas'):
                        self.assertIsNone(proof.qualify_singleton_template(cluster, source, controls))
                    elif change:
                        with self.assertRaises(RuntimeError): proof.qualify_singleton_template(cluster, source, controls)
                    else:
                        self.assertEqual(proof.qualify_singleton_template(cluster, source, controls)['metadata']['uid'], 'statefulset')
                        self.assertEqual(cluster.receipt.value['evidence']['nativePodProfile'], proof.pod_profile(one_spec))
                self.assertEqual(cluster.receipt.value['evidence']['zeroNativeTemplate'], lineage)
                self.assertEqual(cluster.receipt.value['evidence']['zeroNativePodProfile'], proof.pod_profile(zero_spec))

    def test_native_http_framing_rejects_ambiguity_truncation_encoding_and_trailing_bytes(self):
        length = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
        chunked = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n'
        self.assertEqual(proof.parse_native_http(length), (b'{}', 'length'))
        self.assertEqual(proof.parse_native_http(chunked), (b'{}', 'chunked'))
        for raw in (length + b'x', length[:-1], length.replace(b'Content-Length: 2', b'Content-Length: 2\r\nContent-Length: 2'),
                length.replace(b'Content-Length: 2', b'Content-Length: 2\r\ncontent-length: 3'),
                length.replace(b'Content-Length: 2', b'Content-Length: 2\r\nTransfer-Encoding: chunked'),
                length.replace(b'Content-Length: 2', b'Content-Length: 2, 2'),
                length.replace(b'Content-Length: 2', b'Content-Length: 2\r\nContent-Encoding: gzip'),
                length.replace(b'200 OK', b'302 Redirect'), length.replace(b'Content-Length:', b' Content-Length:'),
                b'HTTP/1.1 200 OK\r\nX: ' + b'x' * 32768 + b'\r\n\r\n',
                b'HTTP/1.1 200 OK\r\n' + b'X: y\r\n' * 101 + b'\r\n',
                b'HTTP/1.1 200 OK\r\n\r\n{}', chunked + b'HTTP/1.1 200 OK\r\n\r\n', chunked[:-1],
                chunked.replace(b'chunked', b'gzip, chunked'), chunked.replace(b'2\r\n{}', b'3\r\n{}'),
                chunked.replace(b'0\r\n\r\n', b'0\r\nX-Trailer: no\r\n\r\n'),
                b'x' * (2 * 1024 * 1024 + 1)):
            with self.subTest(length=len(raw), prefix=raw[:60]), self.assertRaises(RuntimeError):
                proof.parse_native_http(raw)

    def test_native_nc_exec_is_single_fixed_stdin_and_rechecks_receipted_actor(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            image = 'native@sha256:' + 'a' * 64
            cluster.receipt.value['evidence']['fixtureImages'] = {'alertmanager': image}
            pod = proof.document('Pod', 'alertmanager-primary-0', cluster,
                spec={'containers': [{'name': 'alertmanager', 'image': image}]},
                status={'containerStatuses': [{'name': 'alertmanager', 'containerID': 'container', 'restartCount': 0,
                        'state': {'running': {'startedAt': '2026-11-05T12:00:00Z'}}}]})
            row = cluster.receipt.intent(pod)
            pod['metadata']['uid'] = 'source'
            cluster.receipt.created(row, pod)
            response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
            with patch.object(proof, 'get', return_value=pod), patch.object(proof, 'exec_pod', return_value=response) as execute:
                self.assertEqual(proof.native_request(cluster, 'alertmanager-primary-0', '/api/v2/status'), '{}')
                execute.assert_called_once()
                self.assertEqual(execute.call_args.args, (cluster.namespace, 'alertmanager-primary-0',
                    '/bin/nc', '-n', '-w', '8', '127.0.0.1', '9093'))
                self.assertEqual(execute.call_args.kwargs, {'container': 'alertmanager',
                    'body': proof.native_http_request('/api/v2/status'), 'limit': 2 * 1024 * 1024,
                    'timeout': 20, 'reject_warnings': True})
            for change in ('uid', 'process', 'image', 'container', 'owner', 'ephemeral'):
                current = copy.deepcopy(pod)
                if change == 'uid': current['metadata']['uid'] = 'foreign'
                if change == 'process': current['status']['containerStatuses'][0]['containerID'] = 'foreign'
                if change == 'image': current['spec']['containers'][0]['image'] = 'foreign'
                if change == 'container': current['spec']['containers'][0]['name'] = 'foreign'
                if change == 'owner': current['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                if change == 'ephemeral': current['spec']['ephemeralContainers'] = [{'name': 'foreign'}]
                with self.subTest(change=change), patch.object(proof, 'get', side_effect=[pod, current]), \
                        patch.object(proof, 'exec_pod', return_value=response) as execute, patch.object(proof, 'parse_native_http') as parse:
                    with self.assertRaises(RuntimeError): proof.native_request(cluster, 'alertmanager-primary-0', '/metrics')
                    execute.assert_called_once()
                    parse.assert_not_called()

    def test_namespace_deny_requires_actual_exclusive_listeners_and_reviewed_profiles(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            images = {key: key + '@sha256:' + 'a' * 64 for key in ('alertmanager', 'reloader', 'operator', 'python')}
            cluster.receipt.value['evidence']['fixtureImages'] = images
            pods, services, expected = {}, {}, {}
            ambient = {15001, 15006, 15008, 15053}
            def record(item):
                row = cluster.receipt.intent(item)
                item['metadata']['uid'] = item['metadata']['name']
                cluster.receipt.created(row, item)
                return item
            for name, role, image in [('alertmanager-primary-0', 'manager', 'alertmanager'),
                    ('proof-operator-fixture', 'operator', 'operator'), ('client', 'client', 'python'),
                    ('unauthorized', 'client', 'python'), ('receiver', 'receiver', 'python'),
                    ('validator', 'validator', 'alertmanager'), ('writer', 'client', 'python')]:
                container = 'alertmanager' if role == 'manager' else 'operator' if role == 'operator' else name
                spec = {'serviceAccountName': 'proof-client', 'containers': [{'name': container, 'image': images[image],
                        'command': ['fixed-reviewed-command'], 'ports': ([{'name': 'web', 'containerPort': 9093}]
                                                                      if role == 'manager' else [])}]}
                pod = proof.document('Pod', name, cluster, spec=spec, status={'phase': 'Running', 'containerStatuses': [{
                    'name': container, 'containerID': name, 'restartCount': 0,
                    'state': {'running': {'startedAt': '2026-11-05T12:00:00Z'}}}]})
                pod['metadata']['labels']['checkpoint-role'] = role
                if role == 'manager':
                    pod['metadata']['labels']['alertmanager'] = 'primary'
                    cluster.receipt.value['evidence']['nativePodProfile'] = proof.pod_profile(spec)
                if role == 'operator':
                    record(proof.document('Deployment', 'proof-operator', cluster, spec={'template': {'spec': spec}}))
                if name == 'writer':
                    pod['status'] = {'phase': 'Succeeded', 'containerStatuses': [{'name': name, 'state': {'terminated': {'exitCode': 0}}}]}
                pods[name] = record(pod)
                expected[name] = ambient | ({8080, 9093} if role == 'manager' else {8080} if role in ('operator', 'receiver')
                                             else {9093} if role == 'validator' else set())
            for name, selector, port, target in [('receiver', {'checkpoint-role': 'receiver'}, 8080, 8080),
                    ('alertmanager-operated', {'alertmanager': 'primary'}, 9093, 'web')]:
                services[name] = record(proof.document('Service', name, cluster, spec={'selector': selector,
                    'ports': [{'name': 'http', 'port': port, 'targetPort': target}]}))
            code = record(proof.document('ConfigMap', 'proof-code', cluster, data={'proof.py': Path(proof.__file__).read_text()}))
            def read(kind, name=None, namespace=None):
                if kind == 'Pod': return pods[name] if name else {'items': list(pods.values())}
                if kind == 'Service': return services[name] if name else {'items': list(services.values())}
                if kind == 'ConfigMap': return code
                raise AssertionError('Unexpected fixture query')
            def execute(namespace, name, *arguments, **kwargs):
                self.assertNotEqual(name, 'writer')
                self.assertEqual(kwargs['timeout'], 20)
                ports = expected[name]
                if arguments[:2] == ('python', '-c'): return json.dumps(sorted(ports)).encode()
                self.assertEqual(arguments[:2], ('/bin/sh', '-ec'))
                if arguments[2].startswith('set -eu'): return b'native-owner\n'
                return ('\n'.join(format(port, '04X') for port in ports) + '\n').encode()
            with patch.object(proof, 'record_generated'), patch.object(proof, 'cleanup_inventory'), \
                    patch.object(proof, 'get', side_effect=read), patch.object(proof, 'exec_pod', side_effect=execute):
                actual = proof.namespace_listener_profile(cluster)
                self.assertNotIn('writer', actual)
                self.assertEqual(set(actual), set(pods) - {'writer'})
                for change in ('extra-listener', 'command', 'foreign-pod', 'service', 'code'):
                    frozen_pods, frozen_services, frozen_code = copy.deepcopy(pods), copy.deepcopy(services), copy.deepcopy(code)
                    if change == 'extra-listener': expected['client'].add(9093)
                    if change == 'command': pods['client']['spec']['containers'][0]['command'] = ['foreign']
                    if change == 'foreign-pod': pods['client']['metadata']['uid'] = 'foreign'
                    if change == 'service': services['receiver']['spec']['ports'][0]['targetPort'] = 9093
                    if change == 'code': code['data']['proof.py'] = 'foreign executable'
                    with self.subTest(change=change), self.assertRaises(RuntimeError): proof.namespace_listener_profile(cluster)
                    pods.clear(); pods.update(frozen_pods)
                    services.clear(); services.update(frozen_services)
                    code.clear(); code.update(frozen_code)
                    expected['client'].discard(9093)

    def test_native_validation_uses_pinned_loopback_actor_for_each_store_behavior(self):
        cluster = Mock(namespace='fixture')
        silence = {'id': '12345678-abcd-4321-abcd-123456789abc', 'matchers': [], 'startsAt': 'start',
                   'endsAt': 'end', 'createdBy': 'fixture', 'comment': 'fixture'}
        records = [proof.alert('FixtureGroup')]
        with patch.object(proof, 'native_request', return_value=json.dumps(silence)) as request, \
                patch.object(proof, 'callbacks', return_value=[]), patch.object(proof.time, 'sleep'), \
                patch.object(proof, 'delivered', return_value=True), \
                patch.object(proof, 'wait', side_effect=lambda label, check, **kwargs: self.assertTrue(check())):
            proof.native_validation(cluster, 'validator', records, [silence], 'FixtureControl')
        self.assertEqual(request.call_count, 3)
        self.assertEqual(request.call_args_list[0].args, (cluster, 'validator', '/api/v2/silence/' + silence['id']))
        self.assertTrue(all(call.args[:2] == (cluster, 'validator') for call in request.call_args_list))
        self.assertEqual([call.args[2] for call in request.call_args_list[1:]], ['/api/v2/alerts', '/api/v2/alerts'])
        self.assertEqual(request.call_args_list[1].args[3][0], records[0])

    def test_fresh_dns_timeout_and_protocol_failures_never_prove_denial(self):
        for reason, outcome in [(proof.socket.gaierror(), 'dns'), (TimeoutError(), 'timeout'),
                                (proof.http.client.BadStatusLine('private-value'), 'protocol'), ('unknown-value', 'error')]:
            output = io.StringIO()
            with self.subTest(outcome=outcome), patch.object(proof.sys, 'stdin', io.StringIO(json.dumps({
                    'url': 'http://receiver:8080/events', 'expectedDenied': True}))), \
                    patch.object(proof.urllib.request, 'build_opener') as opener, redirect_stdout(output):
                opener.return_value.open.side_effect = proof.urllib.error.URLError(reason)
                proof.http_request()
            result = json.loads(output.getvalue())
            self.assertFalse(result['denied'])
            self.assertTrue(result['inconclusive'])
            self.assertEqual(result['outcome'], outcome)
            self.assertNotIn('private-value', output.getvalue())
            with patch.object(proof, 'exec_pod', return_value=proof.canonical(result)), \
                    patch.object(proof, 'record_probe_outcome') as evidence, self.assertRaises(RuntimeError):
                proof.request('fixture', 'http://receiver:8080/events', expected_denied=True)
            evidence.assert_called_once_with('fresh-http', 'request', outcome)

    def test_probe_evidence_records_only_finite_safe_stage_outcome(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory, patch.object(proof, 'DIAGNOSTIC_DIRECTORY', Path(directory)):
            proof.record_probe_outcome('held-http', 'revocation', 'timeout')
            files = list(Path(directory).glob('probe-*.json'))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(files[0].read_bytes()), {'actor': 'held-http', 'stage': 'revocation', 'outcome': 'timeout'})
            self.assertLessEqual(files[0].stat().st_size, 256)
            with self.assertRaises(RuntimeError): proof.record_probe_outcome('held-http', 'private-value', 'timeout')
            self.assertEqual(len(list(Path(directory).glob('probe-*.json'))), 1)

    def test_namespace_mtls_and_pod_enrollment_fail_closed(self):
        values = {'pod-security.kubernetes.io/enforce': 'restricted',
                  'pod-security.kubernetes.io/enforce-version': 'v1.36',
                  'istio.io/dataplane-mode': 'ambient', 'istio-injection': 'disabled'}
        proof.namespace_controls({'metadata': {'labels': values}})
        for key in values:
            changed = dict(values, **{key: 'unsafe'})
            with self.subTest(label=key), self.assertRaises(RuntimeError):
                proof.namespace_controls({'metadata': {'labels': changed}})
        with self.assertRaises(RuntimeError):
            proof.namespace_controls({'metadata': {'labels': dict(values, **{'service-secrets': 'approved'})}})
        with self.assertRaises(RuntimeError):
            proof.namespace_controls({'metadata': {'labels': dict(values, **{'cloudlab.io/service-secrets': 'approved'})}})
        root = {'spec': {'mtls': {'mode': 'STRICT'}}}
        proof.strict_root_policy([root])
        for policies in ([], [root, root], [{'spec': {'mtls': {'mode': 'PERMISSIVE'}}}],
                         [{'spec': {'mtls': {'mode': 'STRICT'}, 'portLevelMtls': {'9093': {'mode': 'PERMISSIVE'}}}}]):
            with self.subTest(policies=policies), self.assertRaises(RuntimeError):
                proof.strict_root_policy(policies)
        proof.pod_enrolled({'metadata': {'annotations': {'ambient.istio.io/redirection': 'enabled'}}})
        for annotations in ({}, {'ambient.istio.io/redirection': 'disabled'}):
            with self.assertRaises(RuntimeError):
                proof.pod_enrolled({'metadata': {'annotations': annotations}})

    def test_http_denial_preserves_authorization_transport_and_positive_distinction(self):
        payload = {'url': 'http://receiver:8080/events', 'expectedDenied': True}
        for error, expected in [(proof.urllib.error.HTTPError(payload['url'], 403, 'Forbidden', {}, None), 'authorization'),
                                (proof.urllib.error.URLError(ConnectionResetError()), 'transport')]:
            output = io.StringIO()
            with patch.object(proof.sys, 'stdin', io.StringIO(json.dumps(payload))), \
                    patch.object(proof.urllib.request, 'build_opener') as opener, redirect_stdout(output):
                opener.return_value.open.side_effect = error
                proof.http_request()
            self.assertEqual(json.loads(output.getvalue())['denial'], expected)
        output = io.StringIO()
        with patch.object(proof.sys, 'stdin', io.StringIO(json.dumps(payload))), \
                patch.object(proof.urllib.request, 'build_opener') as opener, redirect_stdout(output):
            opener.return_value.open.side_effect = proof.urllib.error.HTTPError(payload['url'], 503, 'Unavailable', {}, None)
            proof.http_request()
        self.assertTrue(json.loads(output.getvalue())['inconclusive'])

    def test_principal_proof_requires_both_policy_directions_and_finishes_restricted(self):
        for broken_positive in (False, True):
            cluster = Mock(namespace='fixture')
            policy = {'metadata': {'name': 'fixture-readers'}, 'spec': {'rules': [
                {'from': [{'source': {'principals': ['cluster.local/ns/fixture/sa/proof-client']}}]}]}}
            state = {'current': None, 'expanded_success': False}
            def create(document):
                state['current'] = dict(copy.deepcopy(document), metadata={'uid': 'policy'})
                return copy.deepcopy(state['current'])
            def current(*_):
                return state['current']
            def update(_kind, _name, patches, _namespace):
                self.assertEqual(state['current']['spec'], patches[0]['value'])
                state['current']['spec']['rules'][0]['from'][0]['source']['principals'] = copy.deepcopy(patches[1]['value'])
            def request(_namespace, _url, *, client='client', expected_denied=False):
                allowed = (not state['current'] or (not broken_positive and
                    'cluster.local/ns/fixture/sa/default' in state['current']['spec']['rules'][0]['from'][0]['source']['principals']))
                if client == 'unauthorized' and not allowed:
                    if expected_denied:
                        return {'denied': True, 'denial': 'transport'}
                    raise RuntimeError('Missing positive control')
                if client == 'unauthorized' and state['current']:
                    state['expanded_success'] = True
                return {'text': '{}', 'denied': False}
            def wait(_label, predicate, **_):
                proof.require(predicate(), 'Positive control never succeeded')
            cluster.create.side_effect = create
            cluster.current.side_effect = current
            cluster.patch.side_effect = update
            with self.subTest(broken_positive=broken_positive), \
                    patch.object(proof, 'authorization_context', return_value='fixed-context'), \
                    patch.object(proof, 'request', side_effect=request), patch.object(proof, 'wait', side_effect=wait):
                if broken_positive:
                    with self.assertRaises(RuntimeError):
                        proof.principal_proof(cluster, policy)
                    cluster.receipt.phase.assert_not_called()
                else:
                    proof.principal_proof(cluster, policy)
                    self.assertTrue(state['expanded_success'])
                    cluster.receipt.phase.assert_called_once()
                self.assertEqual(state['current']['spec'], policy['spec'])

    def test_host_preflight_refuses_overrides_unsafe_paths_and_interrupted_runs(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory, patch.object(proof, 'HOST_BASE', Path(directory)):
            target = Path(directory) / ('observability-checkpoint-' + 'a' * 16)
            with self.assertRaises(RuntimeError):
                proof.host_preflight('/opt/cloudlab', 'a' * 16, 'b' * 64, False)
            with self.assertRaises(RuntimeError):
                proof.host_preflight(str(target), 'a' * 16, 'b' * 64, True)
            self.assertFalse(target.exists())
            proof.host_preflight(str(target), 'a' * 16, 'b' * 64, False)
            with self.assertRaises(RuntimeError):
                proof.host_preflight(str(target), 'a' * 16, 'b' * 64, False)
            self.assertFalse((target / 'proof.py').exists())
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            link = Path(directory) / 'link'
            link.symlink_to(Path(directory), target_is_directory=True)
            with patch.object(proof, 'HOST_BASE', link), self.assertRaises(RuntimeError):
                proof.host_preflight(str(link / ('observability-checkpoint-' + 'a' * 16)), 'a' * 16, 'b' * 64, False)

    def test_cleanup_host_preflight_requires_exact_retained_hashes(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory, patch.object(proof, 'HOST_BASE', Path(directory)):
            target = Path(directory) / ('observability-checkpoint-' + 'a' * 16)
            proof.host_preflight(str(target), 'a' * 16, 'b' * 64, False)
            receipt = self.receipt(target / 'state')
            driver, payload = b'original-reviewed-driver', {'synthetic': True}
            proof.write_new(target / 'proof.py', driver)
            proof.write_new(target / 'input.json', proof.canonical(payload))
            receipt.value['provenance'] = {'driver': proof.digest(driver), 'input': proof.digest(proof.canonical(payload))}
            receipt.save()
            proof.host_preflight(str(target), 'a' * 16, proof.digest(driver), True)
            with self.assertRaises(RuntimeError):
                proof.host_preflight(str(target), 'a' * 16, 'b' * 64, True)
            (target / 'input.json').write_text('{"synthetic":false}')
            with self.assertRaises(RuntimeError):
                proof.host_preflight(str(target), 'a' * 16, proof.digest(driver), True)

    def test_receipt_is_durable_before_create_and_existing_resources_are_not_adopted(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            receipt = self.receipt(directory)
            cluster = proof.Cluster(receipt)
            document = proof.document('ConfigMap', 'proof', cluster, data={})
            def create(*args, **kwargs):
                saved = json.loads(receipt.path.read_bytes())
                self.assertEqual(saved['resources'][0]['uid'], None)
                return json.dumps(dict(document, metadata=dict(document['metadata'], uid='new'))).encode()
            with patch.object(proof, 'get', return_value=None), patch.object(proof, 'kubectl', side_effect=create):
                cluster.create(document)
            self.assertEqual(json.loads(receipt.path.read_bytes())['resources'][0]['uid'], 'new')
            with patch.object(proof, 'get', return_value=document), patch.object(proof, 'kubectl') as mutate:
                with self.assertRaises(RuntimeError):
                    cluster.create(document)
                mutate.assert_not_called()
            with self.assertRaises(RuntimeError):
                self.receipt(directory)

    def test_interrupted_receipt_replace_preserves_commit_and_cleanup_can_advance_without_adopting_pending(self):
        for failure in (KeyboardInterrupt(), OSError('Injected replace failure')):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory(dir='/root') as directory:
                receipt = self.receipt(directory)
                cluster = proof.Cluster(receipt)
                current = proof.document('ConfigMap', 'owned', cluster, data={})
                row = receipt.intent(current)
                current['metadata'].update(uid='owned', resourceVersion='1')
                receipt.created(row, current)
                committed = receipt.path.read_bytes()
                legacy = Path(directory) / 'receipt.pending'
                proof.write_new(legacy, b'legacy interrupted bytes must not be adopted')
                interrupted = Path(directory) / ('receipt.pending-' + 'b' * 32)
                identity = proof.object_identity(current)
                with patch.object(proof.secrets, 'token_hex', return_value='b' * 32), \
                        patch.object(Path, 'replace', side_effect=failure), self.assertRaises(type(failure)):
                    receipt.deleting(current, row['specHash'])
                self.assertEqual(receipt.path.read_bytes(), committed)
                pending_bytes = interrupted.read_bytes()
                self.assertEqual(interrupted.stat().st_mode & 0o777, 0o600)
                self.assertEqual(interrupted.stat().st_uid, proof.os.geteuid())
                self.assertEqual(json.loads(pending_bytes)['deletions'][0]['uid'], 'owned')
                recovered = proof.Receipt.load(directory, 'a' * 16)
                self.assertIsNone(recovered.deletion(identity))
                recovered.deleting(current, row['specHash'])
                recovered = proof.Receipt.load(directory, 'a' * 16)
                self.assertFalse(recovered.deletion(identity)['complete'])
                recovered.deleted(identity)
                self.assertTrue(proof.Receipt.load(directory, 'a' * 16).deletion(identity)['complete'])
                self.assertEqual(interrupted.read_bytes(), pending_bytes)
                self.assertEqual(legacy.read_bytes(), b'legacy interrupted bytes must not be adopted')
                self.assertEqual(sorted(Path(directory).glob('receipt.pending*')), sorted([legacy, interrupted]))

    def test_unique_receipt_pending_collision_and_symlink_are_never_overwritten(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory(dir='/root') as directory:
                receipt = self.receipt(directory)
                committed = receipt.path.read_bytes()
                pending = Path(directory) / ('receipt.pending-' + 'c' * 32)
                protected = Path(directory) / 'unrelated'
                proof.write_new(protected, b'protected unrelated bytes')
                if symlink: pending.symlink_to(protected)
                else: proof.write_new(pending, b'existing pending bytes')
                with patch.object(proof.secrets, 'token_hex', return_value='c' * 32), self.assertRaises(OSError):
                    receipt.save()
                self.assertEqual(receipt.path.read_bytes(), committed)
                self.assertEqual(protected.read_bytes(), b'protected unrelated bytes')
                if symlink: self.assertEqual(pending.readlink(), protected)
                else: self.assertEqual(pending.read_bytes(), b'existing pending bytes')

    def test_prerequisite_accounts_are_exact_and_admitted_before_any_persistence(self):
        cluster = Mock(namespace='fixture', operation='a' * 16)
        accounts = [proof.document('ServiceAccount', name, cluster, automountServiceAccountToken=mount)
                    for name, mount in [('proof-operator', True), ('proof-client', False), ('proof-alertmanager', False)]]
        calls = []
        def create(item, dry_run=False):
            calls.append((item['metadata']['name'], dry_run))
            return copy.deepcopy(item)
        cluster.create.side_effect = create
        proof.create_service_accounts(cluster, accounts)
        self.assertEqual(calls, [(item['metadata']['name'], dry_run) for dry_run in (True, False) for item in accounts])
        for change in ('missing', 'mount', 'namespace', 'secret', 'pull', 'metadata'):
            bad = copy.deepcopy(accounts)
            if change == 'missing': bad.pop()
            if change == 'mount': bad[0]['automountServiceAccountToken'] = False
            if change == 'namespace': bad[0]['metadata']['namespace'] = 'foreign'
            if change == 'secret': bad[0]['secrets'] = [{'name': 'credential'}]
            if change == 'pull': bad[0]['imagePullSecrets'] = [{'name': 'credential'}]
            if change == 'metadata': bad[0]['metadata']['finalizers'] = ['foreign']
            cluster.create.reset_mock()
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                proof.create_service_accounts(cluster, bad)
            cluster.create.assert_not_called()
        for key in ('secrets', 'imagePullSecrets'):
            calls.clear()
            def inject(item, dry_run=False):
                calls.append(dry_run)
                return dict(copy.deepcopy(item), **{key: [{'name': 'injected'}]})
            cluster.create.side_effect = inject
            with self.subTest(injected=key), self.assertRaises(RuntimeError):
                proof.create_service_accounts(cluster, accounts)
            self.assertEqual(calls, [True])

    def test_operator_pod_admission_failure_leaves_only_namespace_and_reviewed_accounts(self):
        documents = list(yaml.safe_load_all(Path(proof.__file__).with_name('alertmanager-checkpoint-fixture.yaml').read_text()))
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            objects, calls = {}, []
            def read(kind, name, namespace=None):
                return objects.get((kind, name, namespace))
            def mutate(*arguments, body=None, **kwargs):
                item = json.loads(body)
                dry_run = '--dry-run=server' in arguments
                calls.append((item['kind'], item['metadata']['name'], dry_run))
                item['metadata'].update(uid=item['metadata']['name'], resourceVersion='1',
                                        creationTimestamp='2026-11-05T12:00:00Z')
                if not dry_run:
                    objects[item['kind'], item['metadata']['name'], item['metadata'].get('namespace')] = item
                return proof.canonical(item)
            payload = {'images': {'operator': 'operator', 'reloader': 'reloader'}, 'manifests': documents,
                       'sourceStorage': {'emptyDir': {'sizeLimit': '64Mi'}},
                       'retention': {'whenDeleted': 'Retain', 'whenScaled': 'Retain'},
                       'storage': {'volumeClaimTemplate': {'metadata': {'annotations': {
                           'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}},
                           'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'cloudlab-telemetry',
                                    'resources': {'requests': {'storage': '1Gi'}}}}}}
            with patch.object(proof, 'preflight', return_value={'API_CIDR': '192.0.2.1/32',
                    'API_SERVICE_CIDR': '192.0.2.2/32', 'API_PORT': 6443}), patch.object(proof, 'record_housekeeping'), \
                    patch.object(proof, 'get', side_effect=read), patch.object(proof, 'kubectl', side_effect=mutate), \
                    patch.object(proof, 'pod_dry_run', side_effect=RuntimeError('Rejected operator template')):
                with self.assertRaisesRegex(RuntimeError, 'Rejected operator template'):
                    proof.run(payload, directory, 'a' * 16)
            self.assertEqual(sorted(kind for kind, name, namespace in objects),
                             ['Namespace', 'ServiceAccount', 'ServiceAccount', 'ServiceAccount'])
            accounts = [(name, dry_run) for kind, name, dry_run in calls if kind == 'ServiceAccount']
            self.assertEqual([dry_run for name, dry_run in accounts], [True, True, True, False, False, False])
            self.assertEqual(len({name for name, dry_run in accounts}), 3)

    def test_foreign_scope_is_rejected_even_with_matching_labels(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            for kind, name, namespace in [('Namespace', 'production', None), ('ClusterRole', 'cluster-admin', None),
                                          ('AuthorizationPolicy', 'foreign', cluster.namespace),
                                          ('ConfigMap', 'proof', 'cloudlab-observability')]:
                document = {'apiVersion': 'v1', 'kind': kind, 'metadata': {'name': name, 'labels': proof.labels(cluster.operation)}}
                if namespace:
                    document['metadata']['namespace'] = namespace
                with self.subTest(kind=kind), patch.object(proof, 'get') as read, patch.object(proof, 'kubectl') as mutate:
                    with self.assertRaises(RuntimeError):
                        cluster.create(document)
                    read.assert_not_called()
                    mutate.assert_not_called()

    def test_patch_and_delete_keep_uid_resource_version_preconditions(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            document = proof.document('ConfigMap', 'proof', cluster, data={})
            row = cluster.receipt.intent(document)
            current = copy.deepcopy(document)
            current['metadata'].update(uid='owned', resourceVersion='9')
            cluster.receipt.created(row, current)
            with patch.object(proof, 'get', return_value=current), patch.object(proof, 'kubectl', return_value=b'{}') as mutate:
                cluster.patch('ConfigMap', 'proof', [], cluster.namespace)
                patches = json.loads(mutate.call_args.args[5])
                self.assertEqual(patches[:2], [{'op': 'test', 'path': '/metadata/uid', 'value': 'owned'},
                    {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '9'}])
                cluster.delete('ConfigMap', 'proof', cluster.namespace)
                self.assertEqual(json.loads(mutate.call_args.kwargs['body'])['preconditions'],
                                 {'uid': 'owned', 'resourceVersion': '9'})
                current['metadata']['uid'] = 'replacement'
                mutate.reset_mock()
                with self.assertRaises(RuntimeError):
                    cluster.delete('ConfigMap', 'proof', cluster.namespace)
                mutate.assert_not_called()

    def test_api_error_is_not_absence(self):
        with patch.object(proof, 'kubectl', side_effect=RuntimeError('API unavailable')):
            with self.assertRaises(RuntimeError):
                proof.get('ConfigMap', 'proof', 'fixture')

    def test_fresh_storage_rejects_preexisting_and_restore_sources_before_writer_authority(self):
        desired = {'metadata': {'name': 'cloudlab-telemetry', 'uid': 'sc',
                   'labels': {'cloudlab.io/owner': 'observability-platform'}},
                   'provisioner': 'driver.longhorn.io', 'reclaimPolicy': 'Retain',
                   'volumeBindingMode': 'Immediate', 'parameters': {'numberOfReplicas': '2'}}
        claim = {'metadata': {'uid': 'claim', 'name': 'checkpoint', 'namespace': 'fixture',
                 'creationTimestamp': '2026-11-05T12:00:01Z',
                 'annotations': {'volume.kubernetes.io/storage-provisioner': 'driver.longhorn.io'}},
                 'spec': {'storageClassName': 'cloudlab-telemetry', 'volumeName': 'pvc-claim'},
                 'status': {'phase': 'Bound'}}
        pv = {'metadata': {'uid': 'pv', 'name': 'pvc-claim', 'creationTimestamp': '2026-11-05T12:00:02Z',
              'annotations': {'pv.kubernetes.io/provisioned-by': 'driver.longhorn.io'}},
              'spec': {'claimRef': {'uid': 'claim', 'name': 'checkpoint', 'namespace': 'fixture'},
                       'storageClassName': 'cloudlab-telemetry', 'persistentVolumeReclaimPolicy': 'Retain',
                       'csi': {'driver': 'driver.longhorn.io', 'volumeHandle': 'pvc-claim'}}}
        volume = {'metadata': {'uid': 'volume', 'name': 'pvc-claim', 'creationTimestamp': '2026-11-05T12:00:02Z'},
                  'spec': {'numberOfReplicas': 2}, 'status': {'kubernetesStatus': {
                      'pvcName': 'checkpoint', 'namespace': 'fixture', 'pvName': 'pvc-claim'}}}
        baseline = {'boundary': '2026-11-05T12:00:00+00:00', 'storageClassUID': 'sc',
                    'pvs': {'names': [], 'uids': []}, 'volumes': {'names': [], 'uids': []}}
        for failure in (None, 'old-pv', 'old-volume', 'backup', 'clone', 'claim-restore', 'class-restore', 'foreign-link'):
            current_claim, current_pv, current_volume, current_class, before = map(copy.deepcopy,
                (claim, pv, volume, desired, baseline))
            if failure == 'old-pv': before['pvs']['names'] = [proof.digest(b'pvc-claim')]
            if failure == 'old-volume': before['volumes']['uids'] = [proof.digest(b'volume')]
            if failure == 'backup': current_volume['spec']['fromBackup'] = 'foreign-backup'
            if failure == 'clone': current_volume['spec']['dataSource'] = 'foreign-volume'
            if failure == 'claim-restore': current_claim['spec']['dataSource'] = {'name': 'snapshot'}
            if failure == 'class-restore': current_class['parameters']['fromBackup'] = 'foreign-backup'
            if failure == 'foreign-link': current_volume['status']['kubernetesStatus']['namespace'] = 'foreign'
            replies = {'storageclass': current_class, 'pv': current_pv, 'volumes.longhorn.io': current_volume}
            with self.subTest(failure=failure), patch.object(proof, 'get', side_effect=lambda kind, *a: replies[kind]):
                if failure:
                    with self.assertRaises(RuntimeError):
                        proof.fresh_storage(current_claim, before, desired)
                else:
                    self.assertEqual(proof.fresh_storage(current_claim, before, desired)['claim'], 'claim')

    def test_explicit_cleanup_resumes_exact_deletions_and_unenrolled_owned_pod(self):
        # Interrupt after the API commits each delete, before the coordinator observes completion.
        for interrupted_kind, cascade in [('PersistentVolumeClaim', False), ('Volume', False), ('Volume', True), ('Namespace', False)]:
            with self.subTest(interrupted_kind=interrupted_kind, cascade=cascade), tempfile.TemporaryDirectory(dir='/root') as directory:
                cluster = proof.Cluster(self.receipt(directory))
                objects, deleted = {}, []
                controls = {'pod-security.kubernetes.io/enforce': 'restricted',
                    'pod-security.kubernetes.io/enforce-version': 'v1.36',
                    'istio.io/dataplane-mode': 'ambient', 'istio-injection': 'disabled'}
                for kind, name, namespace in [('Namespace', cluster.namespace, None),
                        ('Pod', 'failed-unenrolled', cluster.namespace),
                        ('PersistentVolumeClaim', 'checkpoint', cluster.namespace)]:
                    item = proof.document(kind, name, cluster)
                    if namespace is None: item['metadata'].pop('namespace')
                    if kind == 'Namespace': item['metadata']['labels'].update(controls)
                    row = cluster.receipt.intent(item)
                    item['metadata'].update(uid=kind, resourceVersion='1')
                    cluster.receipt.created(row, item)
                    objects[kind, name, namespace] = item
                identity = {'claim': 'PersistentVolumeClaim', 'pv': 'pv-uid', 'pvName': 'pvc-claim',
                            'volume': 'pvc-claim', 'volumeUID': 'volume-uid', 'handle': 'pvc-claim'}
                pv = {'apiVersion': 'v1', 'kind': 'PersistentVolume',
                      'metadata': {'name': 'pvc-claim', 'uid': 'pv-uid', 'resourceVersion': '2'},
                      'spec': {'claimRef': {'uid': identity['claim'], 'namespace': cluster.namespace, 'name': 'checkpoint'},
                               'csi': {'driver': 'driver.longhorn.io', 'volumeHandle': 'pvc-claim'},
                               'storageClassName': 'cloudlab-telemetry', 'persistentVolumeReclaimPolicy': 'Retain'},
                      'status': {'phase': 'Released'}}
                volume = {'apiVersion': 'longhorn.io/v1beta2', 'kind': 'Volume',
                          'metadata': {'name': 'pvc-claim', 'namespace': 'longhorn-system',
                                       'uid': 'volume-uid', 'resourceVersion': '3'}, 'spec': {'numberOfReplicas': 2},
                          'status': {'kubernetesStatus': {'pvName': 'pvc-claim', 'pvStatus': 'Released', 'pvcName': 'checkpoint',
                              'namespace': cluster.namespace, 'lastPVCRefAt': '2026-11-05T12:00:00Z'}}}
                objects['PersistentVolume', 'pvc-claim', None] = pv
                objects['Volume', 'pvc-claim', 'longhorn-system'] = volume
                cluster.receipt.phase('persistent-validated', storage=identity, storageFresh=True, storageBaseline={'recorded': True})
                aliases = {'pv': 'PersistentVolume', 'volumes.longhorn.io': 'Volume', 'pods': 'Pod'}
                def read(kind, name=None, namespace=None, **kwargs):
                    kind = aliases.get(kind, kind)
                    if name is None:
                        return {'items': [v for (k, n, ns), v in objects.items() if k == kind and ns == namespace]}
                    return objects.get((kind, name, namespace))
                interrupted = False
                def mutate(*arguments, body=None, **kwargs):
                    nonlocal interrupted
                    self.assertEqual(arguments[:2], ('delete', '--raw'))
                    options = json.loads(body)
                    target = next((key for key, value in objects.items()
                        if value['metadata']['uid'] == options['preconditions']['uid']), None)
                    self.assertIsNotNone(target)
                    row = objects.pop(target)
                    saved = json.loads(cluster.receipt.path.read_bytes())
                    self.assertTrue(any(d['uid'] == row['metadata']['uid'] for d in saved['deletions']))
                    if row['kind'] == 'Volume':
                        self.assertTrue(any(d['uid'] == 'pv-uid' and d['resourceVersion'] == '2' for d in saved['deletions']))
                        self.assertTrue(any(d['uid'] == 'volume-uid' and d['resourceVersion'] == '3'
                            and d['scopeHash'] == proof.digest(proof.canonical(identity)) for d in saved['deletions']))
                        if cascade: objects.pop(('PersistentVolume', 'pvc-claim', None))
                    deleted.append(row['kind'])
                    if row['kind'] == interrupted_kind and not interrupted:
                        interrupted = True
                        raise RuntimeError('Injected interruption after API deletion')
                    return b'{}'
                def observe(c, qualification=True):
                    self.assertFalse(qualification)
                    # Qualification rejects this Pod; exact owned cleanup must still proceed.
                    pod = read('Pod', 'failed-unenrolled', cluster.namespace)
                    if pod:
                        with self.assertRaises(RuntimeError): proof.pod_enrolled(pod)
                def wait(_label, predicate, **kwargs):
                    self.assertTrue(predicate())
                replica_rows = [{'node': name, 'manager': name, 'managerUID': name, 'replicaUID': name,
                    'disk': '/var/lib/longhorn', 'parent': '/var/lib/longhorn/replicas',
                    'path': '/var/lib/longhorn/replicas/' + name, 'context': {'disk': '1:2', 'parent': '1:3', 'present': True},
                    'inspector': {'uid': name, 'node': name, 'containerID': name, 'startedAt': '2026-11-05T12:00:00Z', 'restarts': 0}}
                    for name in ('one', 'two')]
                with patch.object(proof, 'get', side_effect=read), patch.object(proof, 'kubectl', side_effect=mutate), \
                        patch.object(proof, 'record_generated', side_effect=observe), \
                        patch.object(proof, 'record_housekeeping'), patch.object(proof, 'record_events'), \
                        patch.object(proof, 'namespace_inventory', return_value=[]), \
                        patch.object(proof, 'namespace_delete_gate'), patch.object(proof, 'wait', side_effect=wait), \
                        patch.object(proof, 'storage_identity', return_value=identity), \
                        patch.object(proof, 'replica_directories', return_value=replica_rows) as directories, \
                        patch.object(proof, 'backing_absent', return_value=True):
                    with self.assertRaisesRegex(RuntimeError, 'Injected interruption'):
                        proof.cleanup(cluster)
                    cluster = proof.Cluster(proof.Receipt.load(directory, 'a' * 16))
                    proof.cleanup(cluster)
                    proof.cleanup(cluster)
                    self.assertEqual(cluster.receipt.value['phase'], 'cleaned')
                    self.assertEqual(deleted.count(interrupted_kind), 1)
                    self.assertEqual(directories.call_count, 1)
                    self.assertTrue(cluster.receipt.value['evidence']['backingFilesVerified'])
                    self.assertEqual(deleted.count('PersistentVolume'), 0 if cascade else 1)

    def test_cleanup_absence_requires_intent_and_replacements_or_api_errors_block(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            item = proof.document('Pod', 'failed', cluster)
            row = cluster.receipt.intent(item)
            item['metadata'].update(uid='owned', resourceVersion='1')
            cluster.receipt.created(row, item)
            identity = proof.object_identity(item)
            with patch.object(proof, 'get', return_value=None), self.assertRaises(RuntimeError):
                cluster.delete('Pod', 'failed', cluster.namespace)
            cluster.receipt.deleting(item, row['specHash'])
            replaced = copy.deepcopy(item)
            replaced['metadata']['uid'] = 'replacement'
            for outcome in (replaced, RuntimeError('API unavailable')):
                with self.subTest(outcome=outcome), patch.object(proof, 'get') as read:
                    if isinstance(outcome, Exception): read.side_effect = outcome
                    else: read.return_value = outcome
                    with self.assertRaises(RuntimeError): proof.deletion_finished(cluster.receipt, identity)
            self.assertFalse(cluster.receipt.deletion(identity)['complete'])

    def test_storage_pair_intent_failure_or_foreign_references_never_delete(self):
        for fault in ('save', 'stale-uid', 'wrong-claim', 'wrong-link', 'restored', 'live-claim', 'absent-pv', 'absent-volume',
                      'zero-replicas', 'one-replica', 'same-node', 'missing-context', 'unpaired-intent', 'already-deleting'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir='/root') as directory:
                cluster = proof.Cluster(self.receipt(directory))
                claim = proof.document('PersistentVolumeClaim', 'checkpoint', cluster)
                row = cluster.receipt.intent(claim)
                claim['metadata'].update(uid='claim', resourceVersion='1')
                cluster.receipt.created(row, claim)
                identity = {'claim': 'claim', 'pv': 'pv', 'pvName': 'pvc-claim', 'volume': 'pvc-claim',
                            'volumeUID': 'volume', 'handle': 'pvc-claim'}
                pv = {'apiVersion': 'v1', 'kind': 'PersistentVolume',
                    'metadata': {'name': 'pvc-claim', 'uid': 'pv', 'resourceVersion': '2'},
                    'spec': {'claimRef': {'uid': 'claim', 'name': 'checkpoint', 'namespace': cluster.namespace},
                        'csi': {'driver': 'driver.longhorn.io', 'volumeHandle': 'pvc-claim'},
                        'storageClassName': 'cloudlab-telemetry', 'persistentVolumeReclaimPolicy': 'Retain'},
                    'status': {'phase': 'Released'}}
                volume = {'apiVersion': 'longhorn.io/v1beta2', 'kind': 'Volume',
                    'metadata': {'name': 'pvc-claim', 'namespace': 'longhorn-system', 'uid': 'volume', 'resourceVersion': '3'},
                    'spec': {'numberOfReplicas': 2}, 'status': {'kubernetesStatus': {'pvName': 'pvc-claim', 'pvStatus': 'Released',
                        'pvcName': 'checkpoint', 'namespace': cluster.namespace, 'lastPVCRefAt': '2026-11-05T12:00:00Z'}}}
                if fault == 'stale-uid': pv['metadata']['uid'] = 'replacement'
                if fault == 'wrong-claim': pv['spec']['claimRef']['name'] = 'foreign'
                if fault == 'wrong-link': volume['status']['kubernetesStatus']['pvName'] = 'foreign'
                if fault == 'restored': volume['spec']['fromBackup'] = 'foreign'
                if fault == 'already-deleting': volume['metadata']['deletionTimestamp'] = '2026-11-05T12:00:00Z'
                cluster.receipt.phase('retention-verified', storageFresh=True, storageBaseline={'recorded': True}, storage=identity)
                if fault == 'unpaired-intent': cluster.receipt.deleting(volume, proof.digest(proof.canonical(identity)))
                before = cluster.receipt.path.read_bytes()
                replicas = [{'node': name, 'manager': name, 'managerUID': name, 'replicaUID': name,
                    'disk': '/var/lib/longhorn', 'parent': '/var/lib/longhorn/replicas',
                    'path': '/var/lib/longhorn/replicas/' + name, 'context': {'disk': '1:2', 'parent': '1:3', 'present': True},
                    'inspector': {'uid': name, 'node': name, 'containerID': name, 'startedAt': '2026-11-05T12:00:00Z', 'restarts': 0}}
                    for name in ('one', 'two')]
                if fault == 'zero-replicas': replicas = []
                if fault == 'one-replica': replicas.pop()
                if fault == 'same-node': replicas[1]['node'] = replicas[0]['node']
                if fault == 'missing-context': replicas[0].pop('context')
                def read(kind, *args, **kwargs):
                    if kind == 'pv': return None if fault == 'absent-pv' else pv
                    if kind == 'volumes.longhorn.io': return None if fault == 'absent-volume' else volume
                    if kind == 'PersistentVolumeClaim': return claim if fault == 'live-claim' else None
                    raise AssertionError(kind)
                original_save = cluster.receipt.save
                def save():
                    if fault == 'save' and len(cluster.receipt.value.get('deletions', [])) == 2:
                        raise OSError('Injected durable paired-intent failure')
                    original_save()
                with patch.object(proof, 'get', side_effect=read), patch.object(proof, 'kubectl') as mutate, \
                        patch.object(proof, 'cleanup_inventory'), patch.object(proof, 'replica_directories', return_value=replicas), \
                        patch.object(cluster.receipt, 'save', side_effect=save):
                    with self.assertRaises((RuntimeError, OSError)): proof.cleanup_storage(cluster, identity)
                    mutate.assert_not_called()
                saved = json.loads(cluster.receipt.path.read_bytes())
                if fault != 'unpaired-intent': self.assertFalse(saved.get('deletions'))
                if fault in ('stale-uid', 'wrong-claim', 'absent-pv', 'absent-volume', 'unpaired-intent'):
                    self.assertEqual(cluster.receipt.path.read_bytes(), before)

    def test_stateless_recovery_is_separate_bounded_and_never_deletes_storage(self):
        for fault in ('', 'receipt-hash', 'driver-hash', 'foreign', 'foreign-owner', 'data', 'api', 'inspector', 'alias', 'pvc-alias',
                      'rbac', 'namespace-rbac', 'role-rules', 'unknown-rbac-token',
                      'unknown', 'unexpected-absence', 'duplicate-json', 'unknown-field', 'one-replica',
                      'interrupt-deployment', 'interrupt-namespace', 'receipt-buffer-race', 'input-buffer-race',
                      'changed-nflog', 'changed-silences', 'missing-snapshot-hashes', 'invalid-snapshot-hash', 'extra-snapshot-hash',
                      'wrong-native-prefix', 'nonstring-native-prefix', 'unobserved-prefix', 'driver-prefix',
                      'native-foreign-owner', 'unknown-metadata', 'wrong-slice-prefix', 'unsupported-pod-profile'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir='/root') as temporary:
                root = Path(temporary)
                state = root / 'old' / 'state'
                receipt = self.receipt(state)
                old = proof.Cluster(receipt)
                objects = {}
                def record(item, uid, owners=None):
                    row = receipt.intent(item)
                    item['metadata'].update(uid=uid, resourceVersion='1')
                    if owners:
                        item['metadata']['ownerReferences'] = [{'uid': owner, 'kind': kind, 'name': name, 'controller': True}
                            for owner, kind, name in owners]
                        row.update(observed=True, owners=[value[0] for value in owners])
                    receipt.created(row, item)
                    objects[item['kind'], item['metadata']['name'], item['metadata'].get('namespace')] = item
                    return item
                namespace = proof.document('Namespace', old.namespace, old)
                namespace['metadata'].pop('namespace')
                namespace['metadata']['creationTimestamp'] = '2026-11-05T12:00:00Z'
                namespace['metadata']['labels'].update({'pod-security.kubernetes.io/enforce': 'restricted',
                    'pod-security.kubernetes.io/enforce-version': 'v1.36', 'istio.io/dataplane-mode': 'ambient', 'istio-injection': 'disabled'})
                record(namespace, 'namespace')
                # prepare() carries this complete native fixture unchanged, including non-RBAC placeholders.
                manifests = list(yaml.safe_load_all(Path(proof.__file__).with_name('alertmanager-checkpoint-fixture.yaml').read_text()))
                self.assertTrue(all('${' + token + '}' in json.dumps(manifests)
                    for token in ('API_CIDR', 'API_SERVICE_CIDR', 'API_PORT', 'OPERATOR_IMAGE', 'RELOADER_IMAGE')))
                rbac = [item for item in manifests if item['kind'] in ('Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding')]
                for declaration in rbac:
                    item = proof.substitute(declaration, {'NAMESPACE': old.namespace, 'OPERATION': old.operation})
                    item['metadata'].setdefault('labels', {}).update(proof.labels(old.operation))
                    record(item, item['kind'])
                if fault == 'unknown-rbac-token':
                    next(item for item in manifests if item['kind'] == 'Role')['rules'][0]['verbs'].append('${UNKNOWN_RBAC}')
                images = {'operator': 'operator@sha256:' + 'a' * 64, 'reloader': 'reloader@sha256:' + 'b' * 64}
                deployment = proof.substitute(next(item for item in manifests if item['kind'] == 'Deployment'),
                    {'NAMESPACE': old.namespace, 'OPERATION': old.operation, 'OPERATOR_IMAGE': images['operator'], 'RELOADER_IMAGE': images['reloader']})
                deployment['metadata'].setdefault('labels', {}).update(proof.labels(old.operation))
                record(deployment, 'deployment')
                pod_spec = copy.deepcopy(deployment['spec']['template']['spec'])
                pod_spec['nodeName'] = 'fixture-node'
                record(proof.document('ReplicaSet', 'operator-rs', old, apiVersion='apps/v1',
                    spec={'template': copy.deepcopy(deployment['spec']['template'])}), 'rs', [('deployment', 'Deployment', 'proof-operator')])
                pod = proof.document('Pod', 'operator-rs-abc12', old, spec=copy.deepcopy(pod_spec))
                pod['metadata']['labels'].update(deployment['spec']['template']['metadata']['labels'])
                pod['metadata']['generateName'] = 'operator-rs-'
                record(pod, 'pod', [('rs', 'ReplicaSet', 'operator-rs')])
                record(proof.document('Service', 'receiver', old, spec={'selector': {'checkpoint-role': 'receiver'},
                    'ports': [{'name': 'http', 'port': 8080, 'targetPort': 8080}]}), 'service')
                endpoint_slice = proof.document('EndpointSlice', 'receiver-abc12', old, apiVersion='discovery.k8s.io/v1',
                    addressType='IPv4', ports=[{'name': 'http', 'port': 8080, 'protocol': 'TCP'}], endpoints=[])
                endpoint_slice['metadata']['generateName'] = 'receiver-'
                record(endpoint_slice, 'slice', [('service', 'Service', 'receiver')])
                record(proof.document('ConfigMap', 'proof-code', old, data={'proof.py': 'retained driver'}), 'code')
                claim = record(proof.document('PersistentVolumeClaim', 'checkpoint', old), 'claim')
                objects.pop(('PersistentVolumeClaim', 'checkpoint', old.namespace))
                identity = {'claim': 'claim', 'pv': 'pv', 'pvName': 'pvc-claim', 'volume': 'pvc-claim', 'volumeUID': 'volume', 'handle': 'pvc-claim'}
                replicas = [{'node': name, 'manager': name, 'managerUID': name, 'replicaUID': name,
                    'disk': '/var/lib/longhorn', 'parent': '/var/lib/longhorn/replicas',
                    'path': '/var/lib/longhorn/replicas/' + name, 'context': {'disk': '1:2', 'parent': '1:3', 'present': True},
                    'inspector': {'uid': name, 'node': name, 'containerID': name, 'startedAt': '2026-11-05T12:00:00Z', 'restarts': 0}}
                    for name in ('one', 'two')]
                if fault == 'one-replica': replicas.pop()
                if fault == 'unobserved-prefix': next(row for row in receipt.value['resources'] if row.get('uid') == 'pod')['observed'] = False
                driver = b'retained driver'
                payload = {'manifests': manifests, 'images': images}
                input_raw = json.dumps(payload, indent=2).encode()
                proof.write_new(state.parent / 'proof.py', driver)
                proof.write_new(state.parent / 'input.json', input_raw)
                for name in proof.FILES: proof.write_new(state / name, b'immutable snapshot')
                if fault.startswith('changed-'):
                    (state / fault.removeprefix('changed-')).write_bytes(b'previously changed snapshot')
                receipt.value['provenance'] = {'driver': proof.digest(driver), 'input': proof.digest(proof.canonical(payload))}
                receipt.value['cleanup'] = {'started': True}
                snapshot_evidence = {'hashes': {name: proof.digest(b'immutable snapshot') for name in proof.FILES}}
                if fault == 'missing-snapshot-hashes': snapshot_evidence = {}
                if fault == 'invalid-snapshot-hash': snapshot_evidence['hashes']['nflog'] = 'not-a-digest'
                if fault == 'extra-snapshot-hash': snapshot_evidence['hashes']['foreign'] = '0' * 64
                receipt.phase('retention-verified', storage=identity, storageFresh=True, replicaDirectories=replicas,
                              housekeepingRoots={}, **snapshot_evidence)
                if fault == 'foreign': objects['Pod', 'operator-rs-abc12', old.namespace]['metadata']['uid'] = 'foreign'
                if fault == 'foreign-owner': objects['ConfigMap', 'proof-code', old.namespace]['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                if fault == 'data': objects['Pod', 'operator-rs-abc12', old.namespace]['spec']['volumes'] = [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'foreign'}}]
                if fault == 'wrong-native-prefix': pod['metadata']['generateName'] = 'foreign-'
                if fault == 'nonstring-native-prefix': pod['metadata']['generateName'] = 123
                if fault == 'driver-prefix': objects['ConfigMap', 'proof-code', old.namespace]['metadata']['generateName'] = 'proof-'
                if fault == 'native-foreign-owner': pod['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                if fault == 'unknown-metadata': pod['metadata']['unapprovedMetadata'] = 'unapproved'
                if fault == 'wrong-slice-prefix': endpoint_slice['metadata']['generateName'] = 'foreign-'
                if fault == 'unsupported-pod-profile': pod['spec']['containers'][0]['image'] = 'foreign@sha256:' + 'c' * 64
                if fault == 'rbac': objects['ClusterRoleBinding', 'checkpoint-' + old.operation, None]['subjects'][0]['namespace'] = 'foreign'
                if fault == 'namespace-rbac': objects['RoleBinding', 'proof-operator', old.namespace]['subjects'][0]['namespace'] = 'foreign'
                if fault == 'role-rules': objects['Role', 'proof-operator', old.namespace]['rules'][0]['verbs'].append('*')
                if fault == 'unknown': objects['ConfigMap', 'unknown', old.namespace] = proof.document('ConfigMap', 'unknown', old) | {'metadata': {
                    'name': 'unknown', 'namespace': old.namespace, 'uid': 'unknown', 'resourceVersion': '1'}}
                plan = {'predecessor': {'receiptSHA256': proof.digest(receipt.path.read_bytes()), 'driverSHA256': proof.digest(driver),
                    'inputSHA256': proof.digest(input_raw), 'inputCanonicalSHA256': proof.digest(proof.canonical(payload))},
                    'recoveryDriverSHA256': proof.digest(Path(proof.__file__).read_bytes()), 'targets': copy.deepcopy(list(objects.values()))}
                if fault == 'receipt-hash': plan['predecessor']['receiptSHA256'] = '0' * 64
                if fault == 'driver-hash': plan['recoveryDriverSHA256'] = '0' * 64
                if fault == 'unknown-field': plan['extra'] = True
                if fault == 'unexpected-absence': objects.pop(('ConfigMap', 'proof-code', old.namespace))
                plan_raw = proof.canonical(plan)
                if fault == 'duplicate-json': plan_raw = b'{"targets":[],"targets":[]}'
                plan_path = root / 'recovery-input.json'
                proof.write_new(plan_path, plan_raw)
                artifacts = {path: proof.protected_bytes(path)[1] for path in (receipt.path, state.parent / 'proof.py', state.parent / 'input.json', *(state / name for name in proof.FILES))}
                aliases = {'pv': 'PersistentVolume', 'volumes.longhorn.io': 'Volume'}
                for item in objects.values():
                    if item['apiVersion'] != 'v1':
                        aliases[proof.api_path(item).rsplit('/', 2)[1] + '.' + '.'.join(reversed(item['apiVersion'].split('/')))] = item['kind']
                deleted = []
                interrupted = False
                def read(kind, name=None, namespace=None, **kwargs):
                    if fault == 'api' and kind == 'pv': raise RuntimeError('API unavailable')
                    if fault == 'alias' and kind == 'pv' and name is None:
                        return {'items': [{'metadata': {'name': 'alias', 'uid': 'alias'}, 'spec': {'csi': {'volumeHandle': 'pvc-claim'}}}]}
                    kind = aliases.get(kind, kind)
                    if name is None: return {'items': [item for (k, n, ns), item in objects.items() if k == kind and ns == namespace]}
                    return copy.deepcopy(objects.get((kind, name, namespace)))
                def mutate(*args, body=None, **kwargs):
                    nonlocal interrupted
                    if args == ('get', '--raw', '/apis'): return b'{"groups":[]}'
                    if args == ('get', '--raw', '/api/v1/persistentvolumeclaims?limit=100'):
                        return proof.canonical({'items': [{'metadata': {'uid': 'foreign', 'name': 'foreign', 'namespace': 'foreign'},
                            'spec': {'volumeName': 'pvc-claim'}}] if fault == 'pvc-alias' else []})
                    self.assertEqual(args[:2], ('delete', '--raw'))
                    options = json.loads(body)
                    key = next(key for key, item in objects.items() if item['metadata']['uid'] == options['preconditions']['uid'])
                    item = objects.pop(key)
                    self.assertEqual(options['preconditions']['resourceVersion'], item['metadata']['resourceVersion'])
                    self.assertNotIn(item['kind'], ('PersistentVolume', 'Volume', 'PersistentVolumeClaim'))
                    deleted.append(item['kind'])
                    removed = {item['metadata']['uid']}
                    while True:
                        children = [key for key, value in objects.items() if any(owner['uid'] in removed for owner in value['metadata'].get('ownerReferences', []))]
                        if not children: break
                        for child in children: removed.add(objects.pop(child)['metadata']['uid'])
                    if item['kind'] == 'Namespace':
                        for child in [key for key in objects if key[2] == old.namespace]: objects.pop(child)
                    if not fault and item['kind'] == 'Deployment':
                        objects['Event', pod['metadata']['name'] + '.123abc', old.namespace] = {
                            'apiVersion': 'v1', 'kind': 'Event', 'metadata': {'name': pod['metadata']['name'] + '.123abc',
                                'namespace': old.namespace, 'uid': 'killing-event', 'resourceVersion': '1', 'creationTimestamp': '2026-11-05T12:01:00Z'},
                            'involvedObject': {'apiVersion': 'v1', 'kind': 'Pod', 'name': pod['metadata']['name'], 'namespace': old.namespace,
                                'uid': 'pod', 'fieldPath': 'spec.containers{operator}', 'resourceVersion': '200'},
                            'type': 'Normal', 'reason': 'Killing', 'message': 'Stopping container operator',
                            'source': {'component': 'kubelet', 'host': 'fixture-node'}, 'reportingComponent': 'kubelet',
                            'reportingInstance': 'fixture-node', 'eventTime': None, 'count': 1,
                            'firstTimestamp': '2026-11-05T12:01:00Z', 'lastTimestamp': '2026-11-05T12:01:00Z'}
                    if fault == 'interrupt-' + item['kind'].lower() and not interrupted:
                        interrupted = True
                        raise RuntimeError('Injected interruption after API deletion')
                    return b'{}'
                def inventory(_): return [copy.deepcopy(item) for (k, n, ns), item in objects.items() if ns == old.namespace]
                def wait(_, predicate, **kwargs): self.assertTrue(predicate())
                protected_read = proof.protected_bytes
                reads = {}
                def captured(path):
                    raw, metadata = protected_read(path)
                    path = Path(path)
                    reads[path] = reads.get(path, 0) + 1
                    if fault == 'receipt-buffer-race' and path == receipt.path and reads[path] == 1:
                        altered = json.loads(raw)
                        altered['evidence']['storage']['pvName'] = 'unapproved'
                        raw = proof.canonical(altered)
                    if fault == 'input-buffer-race' and path == state.parent / 'input.json' and reads[path] == 3:
                        altered = json.loads(raw)
                        altered['manifests'].append({'kind': 'RoleBinding', 'metadata': {'name': 'unapproved'},
                            'subjects': [{'kind': 'ServiceAccount', 'name': 'unapproved', 'namespace': 'unapproved'}]})
                        raw = proof.canonical(altered)
                    return raw, metadata
                with patch.object(proof, 'get', side_effect=read) as get_calls, patch.object(proof, 'kubectl', side_effect=mutate) as api_calls, \
                        patch.object(proof, 'namespace_inventory', side_effect=inventory), patch.object(proof, 'wait', side_effect=wait), \
                        patch.object(proof, 'DIAGNOSTIC_DIRECTORY', None), \
                        patch.object(proof, 'protected_bytes', side_effect=captured), \
                        patch.object(proof, 'substitute', wraps=proof.substitute) as substitution, \
                        patch.object(proof, 'backing_absent', side_effect=RuntimeError('Inspector changed') if fault == 'inspector' else None,
                                     return_value=True):
                    if fault and not fault.startswith('interrupt-'):
                        with self.assertRaises((RuntimeError, OSError)): proof.recover_stateless(state, root / 'recovery', old.operation, plan_path)
                        self.assertFalse(deleted)
                    else:
                        if not fault:
                            with patch.object(receipt, 'save') as forbidden:
                                proof.recovery_inventory(old, plan['targets'], payload, initial=True)
                                forbidden.assert_not_called()
                            self.assertFalse(deleted)
                        if fault:
                            with self.assertRaisesRegex(RuntimeError, 'Injected interruption'):
                                proof.recover_stateless(state, root / 'recovery', old.operation, plan_path)
                        result = proof.recover_stateless(state, root / 'recovery', old.operation, plan_path)
                        self.assertEqual(result, {'statelessRemnantsCleaned': True, 'predecessorQualification': 'incomplete'})
                        count = len(deleted)
                        self.assertEqual(proof.recover_stateless(state, root / 'recovery', old.operation, plan_path), result)
                        self.assertEqual(len(deleted), count)
                        self.assertEqual(deleted[0], 'Deployment')
                        self.assertEqual(deleted[-1], 'Namespace')
                        self.assertNotIn('Event', deleted)
                    if fault == 'receipt-buffer-race': substitution.assert_not_called()
                    if fault == 'input-buffer-race':
                        calls = [call.args[0] for call in substitution.call_args_list if isinstance(call.args[0], list)
                                 and call.args[0] and all(isinstance(row, dict) and row.get('kind') in ('Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding')
                                                       for row in call.args[0])]
                        self.assertEqual(calls[0], rbac)
                    if fault in ('changed-nflog', 'changed-silences', 'missing-snapshot-hashes', 'invalid-snapshot-hash', 'extra-snapshot-hash'):
                        get_calls.assert_not_called()
                        api_calls.assert_not_called()
                self.assertEqual({path: proof.protected_bytes(path)[1] for path in artifacts}, artifacts)

    def test_recovery_event_observations_require_durable_delete_and_fixed_native_provenance(self):
        for fault in ('', 'missing-intent', 'unaccepted', 'not-durable', 'reference', 'node', 'container', 'reason', 'reporter',
                      'namespace', 'schema', 'owner', 'time', 'lineage', 'zero-pods', 'saved-provenance', 'saved-series-time', 'count-regression', 'series-overflow'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir='/root') as directory:
                receipt = self.receipt(directory)
                cluster = proof.Cluster(receipt)
                deployment = proof.document('Deployment', 'proof-operator', cluster, apiVersion='apps/v1', spec={'replicas': 1})
                deployment['metadata'].update(uid='deployment', resourceVersion='7')
                profile = {'podUID': 'pod', 'podName': 'operator-rs-abc12', 'namespace': cluster.namespace, 'node': 'fixture-node',
                    'container': 'operator', 'namespaceUID': 'namespace', 'namespaceCreatedAt': '2026-11-05T12:00:00Z',
                    'deployment': proof.object_identity(deployment), 'deploymentScopeHash': proof.digest(proof.canonical(proof.recovery_shape(deployment)))}
                if fault != 'missing-intent':
                    intent = receipt.deleting(deployment, profile['deploymentScopeHash'])
                    if fault != 'unaccepted':
                        intent['accepted'] = True
                        if fault != 'not-durable': receipt.save()
                event = {'apiVersion': 'v1', 'kind': 'Event',
                    'metadata': {'name': profile['podName'] + '.123abc', 'namespace': cluster.namespace, 'uid': 'event-uid',
                        'resourceVersion': '1', 'creationTimestamp': '2026-11-05T12:01:00Z'},
                    'involvedObject': {'apiVersion': 'v1', 'kind': 'Pod', 'name': profile['podName'], 'namespace': cluster.namespace,
                        'uid': 'pod', 'fieldPath': 'spec.containers{operator}', 'resourceVersion': '99'},
                    'type': 'Normal', 'reason': 'Killing', 'message': 'Stopping container operator',
                    'source': {'component': 'kubelet', 'host': 'fixture-node'}, 'reportingComponent': 'kubelet',
                    'reportingInstance': 'fixture-node', 'eventTime': None, 'count': 1,
                    'firstTimestamp': '2026-11-05T12:01:00Z', 'lastTimestamp': '2026-11-05T12:01:00Z'}
                predecessor = types.SimpleNamespace(receipt=types.SimpleNamespace(value={'events': []}))
                profiles = {'pod': profile}
                if fault == 'reference': event['involvedObject']['uid'] = 'foreign'
                if fault == 'node': event['source']['host'] = 'foreign'
                if fault == 'container': event['involvedObject']['fieldPath'] = 'spec.containers{foreign}'
                if fault == 'reason': event['reason'] = 'Unhealthy'
                if fault == 'reporter': event['reportingComponent'] = 'foreign'
                if fault == 'namespace': event['metadata']['namespace'] = 'foreign'
                if fault == 'schema': event['data'] = {'extra': 'unapproved'}
                if fault == 'owner': event['metadata']['ownerReferences'] = []
                if fault == 'time': event['firstTimestamp'] = '2000-01-01T00:00:00Z'
                if fault == 'lineage': profile['deployment']['uid'] = 'foreign'
                if fault == 'zero-pods': profiles = {}
                if fault == 'count-regression': event['count'] = 2
                if fault == 'series-overflow': event['series'] = {'count': 1025, 'lastObservedTime': event['lastTimestamp']}
                immutable = proof.canonical([deployment])
                with patch.object(proof, 'recovery_operator_pods', return_value=profiles), patch.object(proof, 'kubectl') as mutate:
                    if fault in ('saved-provenance', 'saved-series-time', 'count-regression'):
                        proof.recovery_events(predecessor, [deployment], {}, [event], receipt)
                        if fault in ('saved-provenance', 'saved-series-time'):
                            if fault == 'saved-provenance': receipt.value['recoveryEvents'][0]['identity']['node'] = 'foreign'
                            else: receipt.value['recoveryEvents'][0].update(seriesCount=1, seriesLastAt='')
                            receipt.save()
                            event_list = []  # TTL disappearance must not hide a changed saved record.
                        else:
                            event['count'] = 1
                            event_list = [event]
                        with self.assertRaises((RuntimeError, ValueError)): proof.recovery_events(predecessor, [deployment], {}, event_list, receipt)
                    elif fault:
                        with self.assertRaises((RuntimeError, ValueError)): proof.recovery_events(predecessor, [deployment], {}, [event], receipt)
                    else:
                        self.assertEqual(proof.recovery_events(predecessor, [deployment], {}, [event], receipt), [])
                        converted = copy.deepcopy(event)
                        converted['apiVersion'] = 'events.k8s.io/v1'
                        for before, after in [('involvedObject', 'regarding'), ('source', 'deprecatedSource'), ('message', 'note'),
                                ('reportingComponent', 'reportingController'), ('count', 'deprecatedCount'),
                                ('firstTimestamp', 'deprecatedFirstTimestamp'), ('lastTimestamp', 'deprecatedLastTimestamp')]:
                            converted[after] = converted.pop(before)
                        converted['deprecatedCount'] = 2
                        converted['deprecatedLastTimestamp'] = '2026-11-05T12:01:01Z'
                        converted['series'] = {'count': 2, 'lastObservedTime': converted['deprecatedLastTimestamp']}
                        self.assertEqual(proof.recovery_events(predecessor, [deployment], {}, [converted], receipt), [])
                        self.assertEqual(receipt.value['recoveryEvents'][0]['count'], 2)
                        loaded = proof.Receipt.load(directory, 'a' * 16)
                        self.assertEqual(proof.recovery_events(predecessor, [deployment], {}, [], loaded), [])
                        self.assertEqual(len(loaded.value['recoveryEvents']), 1)
                    self.assertEqual(proof.canonical([deployment]), immutable)
                    self.assertEqual(predecessor.receipt.value, {'events': []})
                    mutate.assert_not_called()
        self.assertEqual(proof.recovery_operator_pods(None, [], {}), {})

    def test_recovery_delete_reads_the_frozen_served_api_version(self):
        for fault in ('', 'version', 'uid', 'spec', 'api'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir='/root') as directory:
                cluster = proof.Cluster(self.receipt(directory))
                target = proof.document('AuthorizationPolicy', 'source-quiescence', cluster,
                    apiVersion='security.istio.io/v1beta1', spec={'action': 'DENY'})
                row = cluster.receipt.intent(target)
                target['metadata'].update(uid='policy', resourceVersion='7')
                cluster.receipt.created(row, target)
                current = copy.deepcopy(target)
                if fault == 'version': current['apiVersion'] = 'security.istio.io/v1'
                if fault == 'uid': current['metadata']['uid'] = 'foreign'
                if fault == 'spec': current['spec']['action'] = 'ALLOW'
                with patch.object(proof, 'get', return_value=current,
                        side_effect=RuntimeError('API unavailable') if fault == 'api' else None) as read, \
                        patch.object(proof, 'kubectl', return_value=b'{}') as mutate:
                    if fault:
                        with self.assertRaises(RuntimeError): proof.delete_recovery_target(cluster, target)
                        mutate.assert_not_called()
                    else:
                        proof.delete_recovery_target(cluster, target)
                        self.assertEqual(mutate.call_args.args[:3], ('delete', '--raw', proof.api_path(target)))
                        self.assertEqual(json.loads(mutate.call_args.kwargs['body'])['preconditions'], {'uid': 'policy', 'resourceVersion': '7'})
                    read.assert_called_once_with('authorizationpolicies.v1beta1.security.istio.io', 'source-quiescence', cluster.namespace)
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            target = proof.document('ConfigMap', 'proof-code', cluster, data={'proof.py': 'synthetic'})
            row = cluster.receipt.intent(target)
            target['metadata'].update(uid='code', resourceVersion='8')
            cluster.receipt.created(row, target)
            with patch.object(proof, 'get', return_value=target) as read, patch.object(proof, 'kubectl', return_value=b'{}') as mutate:
                proof.delete_recovery_target(cluster, target)
                read.assert_called_once_with('ConfigMap', 'proof-code', cluster.namespace)
                self.assertEqual(mutate.call_args.args[:3], ('delete', '--raw', proof.api_path(target)))

    def test_cleanup_observation_does_not_require_owned_failed_pod_enrollment(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            pod = proof.document('Pod', 'failed', cluster)
            row = cluster.receipt.intent(pod)
            pod['metadata']['uid'] = 'owned-unenrolled'
            cluster.receipt.created(row, pod)
            def read(kind, **kwargs):
                return {'items': [pod] if kind == 'Pod' else []}
            with patch.object(proof, 'get', side_effect=read):
                with self.assertRaises(RuntimeError): proof.record_generated(cluster)
                proof.record_generated(cluster, qualification=False)
            with patch.object(cluster, 'current'):
                proof.namespace_delete_gate(cluster, [pod], allow_owned=True, retiring=True)
                foreign = copy.deepcopy(pod)
                foreign['metadata']['uid'] = 'replacement'
                with self.assertRaises(RuntimeError):
                    proof.namespace_delete_gate(cluster, [foreign], allow_owned=True, retiring=True)

    def test_command_output_is_bounded_before_reading_it(self):
        with self.assertRaises(RuntimeError):
            proof.command([sys.executable, '-c', 'import os; os.write(1,b"x"*4096)'], limit=64)

    def test_cleanup_discovery_covers_all_versions_and_failure_is_not_empty(self):
        replies = {
            '/apis': {'groups': [{'versions': [{'groupVersion': 'monitoring.coreos.com/v1'},
                                             {'groupVersion': 'monitoring.coreos.com/v1alpha1'}]}]},
            '/api/v1': {'groupVersion': 'v1', 'resources': []},
            '/apis/monitoring.coreos.com/v1': {'groupVersion': 'monitoring.coreos.com/v1', 'resources': []},
            '/apis/monitoring.coreos.com/v1alpha1': {'groupVersion': 'monitoring.coreos.com/v1alpha1',
                'resources': [{'name': 'alertmanagerconfigs', 'kind': 'AlertmanagerConfig', 'namespaced': True,
                               'verbs': ['list', 'delete']}]},
            '/apis/monitoring.coreos.com/v1alpha1/namespaces/fixture/alertmanagerconfigs?limit=100':
                {'items': [{'metadata': {'uid': 'unknown'}}], 'metadata': {}}}
        def read(*arguments, **_):
            return json.dumps(replies[arguments[2]]).encode()
        with patch.object(proof, 'kubectl', side_effect=read):
            rows = proof.namespace_inventory('fixture')
            self.assertEqual(rows[0]['kind'], 'AlertmanagerConfig')
        with patch.object(proof, 'kubectl', side_effect=RuntimeError('discovery unavailable')):
            with self.assertRaises(RuntimeError):
                proof.namespace_inventory('fixture')

    def test_backing_absence_requires_same_inspector_and_accessible_parent_filesystem(self):
        manager = {'metadata': {'uid': 'manager'}, 'spec': {'nodeName': 'node'},
                   'status': {'containerStatuses': [{'name': 'longhorn-manager', 'containerID': 'process',
                       'restartCount': 2, 'state': {'running': {'startedAt': 'started'}}}]}}
        row = {'manager': 'manager', 'disk': '/var/lib/longhorn', 'parent': '/var/lib/longhorn/replicas',
               'path': '/var/lib/longhorn/replicas/synthetic', 'inspector': proof.inspector_identity(manager),
               'context': {'disk': '12:1', 'parent': '12:2', 'present': True}}
        with patch.object(proof, 'get', return_value=manager), patch.object(proof, 'command') as command:
            command.return_value = (0, b'12:1\n12:2\n-\nabsent\n', b'')
            self.assertTrue(proof.backing_absent(row))
            command.return_value = (0, b'12:1\n12:2\n12\npresent\n', b'')
            self.assertFalse(proof.backing_absent(row))
            for result in [(1, b'', b'inaccessible'), (0, b'99:1\n99:2\n-\nabsent\n', b'')]:
                command.return_value = result
                with self.assertRaises(RuntimeError):
                    proof.backing_absent(row)
            manager['status']['containerStatuses'][0]['containerID'] = 'replacement'
            command.reset_mock()
            with self.assertRaises(RuntimeError):
                proof.backing_absent(row)
            command.assert_not_called()

    def archive(self, members):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            for name, value, kind in members:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value) if kind == tarfile.REGTYPE else None)
        return stream.getvalue()

    def test_archive_requires_exact_complete_native_bytes(self):
        values = {'nflog': b'notification-state', 'silences': b'silence-state'}
        hashes = {k: proof.digest(v) for k, v in values.items()}
        normal = [(k, v, tarfile.REGTYPE) for k, v in values.items()]
        self.assertEqual(proof.parse_archive(self.archive(normal), hashes), values)
        cases = [normal[:1], normal + normal[:1], [('../nflog', b'x', tarfile.REGTYPE)] + normal,
                 [('nflog', b'', tarfile.SYMTYPE), normal[1]],
                 [('nflog', b'changed', tarfile.REGTYPE), normal[1]]]
        for members in cases:
            with self.subTest(members=[x[0] for x in members]), self.assertRaises(RuntimeError):
                proof.parse_archive(self.archive(members), hashes)
        with self.assertRaises(RuntimeError):
            proof.parse_archive(b'x' * (proof.LIMIT + 1), hashes)
        with self.assertRaises(RuntimeError):
            proof.parse_archive(self.archive(normal)[:1000], hashes)

    def test_generations_exclude_stale_and_inflight_snapshot(self):
        def metadata(inode, modified):
            return {name: {'inode': inode, 'mtime': modified, 'ctime': modified,
                           'size': 10, 'regular': True} for name in proof.FILES}
        tracker = proof.Generations(100, metadata(1, 90))
        self.assertFalse(tracker.observe(metadata(2, 99)))
        self.assertFalse(tracker.observe(metadata(3, 101)))
        self.assertFalse(tracker.observe(metadata(3, 101)))
        self.assertTrue(tracker.observe(metadata(4, 106)))
        for bad in ('regular', 'size'):
            row = metadata(5, 111)
            row['nflog'][bad] = False if bad == 'regular' else proof.LIMIT
            with self.assertRaises(RuntimeError):
                tracker.observe(row)

    def test_empty_inflight_generation_does_not_qualify_or_abort_final_full_snapshot(self):
        def metadata(inode, modified, size, present=True):
            return {name: {'inode': inode, 'mtime': modified, 'ctime': modified, 'size': size,
                           'present': present, 'regular': present} for name in proof.FILES}
        for baseline in (metadata(1, 90, 0), metadata(0, 0, 0, present=False)):
            tracker = proof.Generations(100, baseline)
            self.assertFalse(tracker.observe(baseline))
            self.assertFalse(tracker.observe(metadata(2, 101, 0)))
            self.assertFalse(tracker.observe(metadata(3, 106, 0)))
            self.assertTrue(tracker.observe(metadata(4, 111, 12)))

    def test_native_endpoints_require_service_pod_and_controller_identity(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            service = proof.document('Service', 'receiver', cluster, spec={'clusterIP': 'None',
                'selector': {'checkpoint-role': 'receiver'},
                'ports': [{'name': 'http', 'port': 8080, 'targetPort': 'http'}]})
            service['metadata'].update(uid='service', resourceVersion='1')
            row = cluster.receipt.intent(service)
            cluster.receipt.created(row, service)
            pods = {}
            for index in range(2):
                pod = proof.document('Pod', 'receiver' + str(index), cluster,
                    spec={'containers': [{'ports': [{'name': 'http', 'containerPort': 8080}]}]},
                    status={'podIPs': [{'ip': '192.0.2.' + str(index + 10)}]})
                pod['metadata']['labels']['checkpoint-role'] = 'receiver'
                pod['metadata']['uid'] = 'pod' + str(index)
                pod_row = cluster.receipt.intent(pod)
                cluster.receipt.created(pod_row, pod)
                pods[pod['metadata']['name']] = pod
            endpoint = proof.document('Endpoints', 'receiver', cluster, subsets=[{
                'addresses': [{'ip': '192.0.2.10', 'targetRef': {'kind': 'Pod', 'namespace': cluster.namespace,
                    'name': 'receiver0', 'uid': 'pod0'}}],
                'notReadyAddresses': [{'ip': '192.0.2.11', 'targetRef': {'kind': 'Pod', 'namespace': cluster.namespace,
                    'name': 'receiver1', 'uid': 'pod1'}}],
                'ports': [{'name': 'http', 'port': 8080, 'protocol': 'TCP'}]}])
            endpoint['metadata'].update(uid='endpoint', managedFields=[{'manager': 'kube-controller-manager'}])
            endpoint['metadata']['labels'].update({'endpoints.kubernetes.io/managed-by': 'endpoint-controller',
                                                   'service.kubernetes.io/headless': ''})
            endpoint['metadata']['annotations'] = {'endpoints.kubernetes.io/last-change-trigger-time': '2026-01-01T00:00:00Z'}
            def read(kind, name, namespace=None, **_):
                return service if kind == 'Service' else pods[name]
            with patch.object(proof, 'get', side_effect=read), patch.object(proof, 'kubectl') as mutate:
                derived = proof.endpoint_binding(cluster, endpoint)
                self.assertEqual(derived['serviceUID'], 'service')
                self.assertEqual(derived['targets'], ['pod0', 'pod1'])
                self.assertEqual(derived['owners'], [])
                for native in ('kube-controller-manager', 'k3s'):
                    current = copy.deepcopy(endpoint)
                    current['metadata']['managedFields'] = [{'manager': native}]
                    observed = proof.endpoint_binding(cluster, current)
                    self.assertEqual(observed['writers'], [native])
                    self.assertEqual(proof.endpoint_binding(cluster, current, observed), observed)
                    other = 'k3s' if native == 'kube-controller-manager' else 'kube-controller-manager'
                    current['metadata']['managedFields'] = [{'manager': other}]
                    with self.subTest(replaced_writer=native), self.assertRaises(RuntimeError):
                        proof.endpoint_binding(cluster, current, observed)
                for writers in ([], ['foreign'], ['k3s', 'kube-controller-manager'], ['k3s', 'foreign']):
                    current = copy.deepcopy(endpoint)
                    current['metadata']['managedFields'] = [{'manager': name} for name in writers]
                    with self.subTest(writers=writers), self.assertRaises(RuntimeError):
                        proof.endpoint_binding(cluster, current)
                for change in ('uid', 'controller', 'pod', 'ip', 'not-ready-ip', 'port', 'selector', 'service', 'named-port'):
                    current, old_service, old_pods = copy.deepcopy(endpoint), copy.deepcopy(service), copy.deepcopy(pods)
                    if change == 'uid': current['metadata']['uid'] = 'replacement'
                    if change == 'controller': current['metadata']['managedFields'][0]['manager'] = 'foreign'
                    if change == 'pod': current['subsets'][0]['addresses'][0]['targetRef']['uid'] = 'foreign'
                    if change == 'ip': current['subsets'][0]['addresses'][0]['ip'] = '192.0.2.99'
                    if change == 'not-ready-ip': current['subsets'][0]['notReadyAddresses'][0]['ip'] = '192.0.2.99'
                    if change == 'port': current['subsets'][0]['ports'][0]['port'] = 8081
                    if change == 'selector': service['spec']['selector'] = {'checkpoint-role': 'foreign'}
                    if change == 'service': service['metadata']['uid'] = 'replacement'
                    if change == 'named-port': pods['receiver1']['spec']['containers'][0]['ports'][0]['containerPort'] = 8081
                    with self.subTest(change=change), self.assertRaises(RuntimeError):
                        proof.endpoint_binding(cluster, current, derived)
                    service.clear(); service.update(old_service)
                    pods.clear(); pods.update(old_pods)
                mutate.assert_not_called()

    def test_source_restart_and_replacement_block_checkpoint(self):
        pod = {'metadata': {'uid': 'source'}, 'status': {'containerStatuses': [{'name': 'alertmanager',
            'restartCount': 0, 'containerID': 'process', 'state': {'running': {'startedAt': 'time'}}}]}}
        identity = proof.source_identity(pod)
        for change in ('uid', 'process', 'restart'):
            current = copy.deepcopy(pod)
            if change == 'uid': current['metadata']['uid'] = 'other'
            if change == 'process': current['status']['containerStatuses'][0]['containerID'] = 'other'
            if change == 'restart': current['status']['containerStatuses'][0]['restartCount'] = 1
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                proof.source_unchanged(current, identity)

    def test_maintenance_removes_only_integrations(self):
        config = {'route': {'receiver': 'root', 'routes': [{'receiver': 'child', 'matchers': ['service="test"']}]},
                  'receivers': [{'name': 'root', 'webhook_configs': [{'url': 'http://fixture'}]},
                                {'name': 'child', 'email_configs': [{'to': 'fixture@invalid'}]}]}
        frozen = proof.maintenance_config(config)
        self.assertEqual(frozen['route'], config['route'])
        self.assertEqual(frozen['receivers'], [{'name': 'root'}, {'name': 'child'}])
        self.assertIn('webhook_configs', config['receivers'][0])

    def test_native_redacted_fixture_requires_exact_route_receiver_and_integrations(self):
        # Captured from the pinned AM0.34.1 native status serializer, including native receiver labels.
        prefix = ('global:\n  resolve_timeout: 5m\n  http_config:\n    follow_redirects: true\n'
            '    enable_http2: true\n  smtp_hello: localhost\n  smtp_require_tls: true\n'
            '  smtp_tls_config:\n    insecure_skip_verify: false\n'
            '  slack_app_url: https://slack.com/api/chat.postMessage\n'
            '  pagerduty_url: https://events.pagerduty.com/v2/enqueue\n'
            '  opsgenie_api_url: https://api.opsgenie.com/\n  wechat_api_url: https://qyapi.weixin.qq.com/cgi-bin/\n'
            '  victorops_api_url: https://alert.victorops.com/integrations/generic/20131114/alert/\n'
            '  telegram_api_url: https://api.telegram.org\n  webex_api_url: https://webexapis.com/v1/messages\n'
            '  rocketchat_api_url: https://open.rocket.chat/\n'
            'route:\n  receiver: proof\n  group_by:\n  - alertname\n  continue: false\n'
            '  group_wait: 0s\n  group_interval: 1s\n  repeat_interval: 1h\nreceivers:\n')
        receiver = '- name: proof\n  labels:\n    name: proof\n'
        integration = ('  - send_resolved: true\n    http_config:\n      follow_redirects: true\n'
            '      enable_http2: true\n    url: <secret>\n    url_file: ""\n    max_alerts: 0\n    timeout: 0s\n')
        baseline = prefix + receiver + '  webhook_configs:\n' + integration * 2 + 'templates: []\n'
        maintenance = prefix + receiver + 'templates: []\n'
        self.assertNotIn('receiver:8080', baseline)
        self.assertEqual(proof.native_maintenance_text(baseline), maintenance)
        for changed in (maintenance, baseline.replace(integration * 2, integration),
                baseline.replace(integration * 2, integration * 3), baseline.replace('- name: proof', '- name: foreign'),
                baseline.replace('    name: proof', '    name: foreign'), baseline.replace('receiver: proof', 'receiver: foreign'),
                baseline.replace('url: <secret>', 'url: http://receiver:8080'),
                baseline.replace('webhook_configs:', 'email_configs:'), baseline + 'receivers:\n- name: extra\n',
                baseline.replace('templates: []', 'templates: [foreign]')):
            with self.subTest(changed=changed[-120:]), self.assertRaises(RuntimeError):
                proof.native_maintenance_text(changed)

    def test_native_reload_requires_exact_config_success_fresh_timestamp_and_same_process(self):
        cluster = Mock(namespace='fixture')
        pod = {'metadata': {'uid': 'source'}, 'status': {'containerStatuses': [{
            'name': 'alertmanager', 'containerID': 'native-process', 'restartCount': 0,
            'state': {'running': {'startedAt': '2026-11-05T12:00:00Z'}}}]}}
        identity = proof.source_identity(pod)
        for text, successful, timestamp, expected in [('expected', 1, 101, True), ('expected', 1, 100, False),
                ('expected', 0, 101, False), ('old-with-no-url', 1, 101, False), ('expected\n', 1, 101, False)]:
            metrics = ('alertmanager_config_last_reload_successful ' + str(successful) + '\n'
                'alertmanager_config_last_reload_success_timestamp_seconds ' + str(timestamp) + '\n')
            replies = {'/api/v2/status': json.dumps({'config': {'original': text}}), '/metrics': metrics}
            with self.subTest(text=text, successful=successful, timestamp=timestamp), \
                    patch.object(proof, 'source_get', side_effect=lambda ns, path: replies[path]), \
                    patch.object(proof, 'get', return_value=pod):
                self.assertEqual(proof.native_reloaded(cluster, 'expected', 100, identity), expected)
        with patch.object(proof, 'get', return_value=pod), patch.object(proof, 'native_reload_state') as read:
            pod['status']['containerStatuses'][0]['restartCount'] = 1
            with self.assertRaises(RuntimeError): proof.native_reloaded(cluster, 'expected', 100, identity)
            read.assert_not_called()
        for metrics in ('', 'alertmanager_config_last_reload_successful 1\n',
                'alertmanager_config_last_reload_successful 1\n'
                'alertmanager_config_last_reload_success_timestamp_seconds NaN\n',
                'alertmanager_config_last_reload_successful 1\nalertmanager_config_last_reload_successful 0\n'
                'alertmanager_config_last_reload_success_timestamp_seconds 101\n'):
            with self.subTest(metrics=metrics), patch.object(proof, 'source_get', side_effect=[
                    json.dumps({'config': {'original': 'expected'}}), metrics]), self.assertRaises(RuntimeError):
                proof.native_reload_state(cluster)

    def test_failure_record_is_bounded_private_and_cannot_replace_primary_exception(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            receipt = self.receipt(directory)
            try:
                proof.source_unchanged({}, {})
            except RuntimeError as error:
                error.args = ('private diagnostic value must never be written',)
                with patch.object(proof, 'DIAGNOSTIC_DIRECTORY', Path(directory)):
                    self.assertTrue(proof.record_failure(error))
                    with patch.object(proof, 'write_new', side_effect=OSError('unwritable')):
                        self.assertFalse(proof.record_failure(error))
                    receipt.value['phase'] = 'private invalid phase value'
                    receipt.save()
                    self.assertFalse(proof.record_failure(error))
                    receipt.phase('prepared')
                self.assertEqual(str(error), 'private diagnostic value must never be written')
            files = list(Path(directory).glob('failure-*.json'))
            self.assertEqual(len(files), 1)
            raw = files[0].read_bytes()
            self.assertLessEqual(len(raw), 1024)
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
            self.assertNotIn(b'private diagnostic', raw)
            value = json.loads(raw)
            self.assertEqual(set(value), {'exception', 'frames', 'phase'})
            self.assertEqual(value['exception'], 'RuntimeError')
            self.assertEqual(value['frames'][-1]['function'], 'source_identity')
            self.assertEqual(value['frames'][-2]['function'], 'source_unchanged')
            self.assertLessEqual(len(value['frames']), 4)
            self.assertEqual(value['phase'], 'prepared')
            self.assertGreater(value['frames'][-1]['line'], 0)
            self.assertEqual(json.loads(receipt.path.read_bytes()), receipt.value)

    def test_failure_record_handles_actual_main_entrypoint_traceback(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            receipt = self.receipt(directory)
            original = receipt.path.read_bytes()
            arguments = [proof.__file__, '--cleanup', '--operation', 'a' * 16, '--directory', directory]
            with patch.object(sys, 'argv', arguments), \
                    patch.object(proof.subprocess, 'run', side_effect=AssertionError('No external commands allowed')) as api:
                with self.assertRaises(SystemExit):
                    runpy.run_path(proof.__file__, run_name='__main__')
                api.assert_not_called()
            files = list(Path(directory).glob('failure-*.json'))
            self.assertEqual(len(files), 1)
            value = json.loads(files[0].read_bytes())
            self.assertEqual([frame['function'] for frame in value['frames']], ['module', 'main', 'cleanup', 'row'])
            self.assertEqual(value['exception'], 'RuntimeError')
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
            self.assertLessEqual(files[0].stat().st_size, 1024)
            self.assertEqual(receipt.path.read_bytes(), original)

    def test_failure_record_maps_only_known_same_file_anonymous_frames_without_values(self):
        for expression, anonymous in [('(lambda: source_identity({}))()', 'lambda'),
                                      ('next(source_identity({}) for unused in (0,))', 'genexpr')]:
            with self.subTest(anonymous=anonymous), tempfile.TemporaryDirectory(dir='/root') as directory:
                self.receipt(directory)
                try:
                    exec(compile(expression, proof.__file__, 'exec'), dict(vars(proof), __name__='__main__'))
                except RuntimeError as error:
                    error.args = ('synthetic-secret-message-never-record',)
                    with patch.object(proof, 'DIAGNOSTIC_DIRECTORY', Path(directory)):
                        self.assertTrue(proof.record_failure(error))
                files = list(Path(directory).glob('failure-*.json'))
                self.assertEqual(len(files), 1)
                raw = files[0].read_bytes()
                self.assertNotIn(b'synthetic-secret', raw)
                value = json.loads(raw)
                self.assertEqual([frame['function'] for frame in value['frames']], ['module', anonymous, 'source_identity'])
                self.assertTrue(all(set(frame) == {'function', 'line'} and frame['line'] > 0 for frame in value['frames']))
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            self.receipt(directory)
            code = compile('source_identity({})', proof.__file__, 'exec').replace(co_name='<not-approved>')
            try:
                types.FunctionType(code, vars(proof))()
            except RuntimeError as error:
                with patch.object(proof, 'DIAGNOSTIC_DIRECTORY', Path(directory)):
                    self.assertFalse(proof.record_failure(error))
            self.assertFalse(list(Path(directory).glob('failure-*.json')))

    def test_held_socket_proves_two_requests_and_eof_without_reconnect_timeout_is_inconclusive(self):
        for outcome in ('revoked', 'timeout', 'late-eof', 'late-control'):
            client, server = proof.socket.socketpair()
            requests = []
            clock = [0]
            def serve():
                with server, server.makefile('rb') as reader:
                    for _ in range(3):
                        header = b''
                        while not header.endswith(b'\r\n\r\n'):
                            line = reader.readline(1024)
                            if not line: return
                            header += line
                        requests.append(header)
                        server.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
            worker = threading.Thread(target=serve)
            worker.start()
            native_select = proof.select.select
            control = io.StringIO('check\n')
            def select(readers, writers, errors, seconds):
                if readers == [control]:
                    if outcome == 'late-control': clock[0] = 26
                    return readers, [], []
                if outcome == 'timeout': return [], [], []
                result = native_select(readers, writers, errors, seconds)
                if outcome == 'late-eof': clock[0] = 41
                return result
            output = io.StringIO()
            try:
                with self.subTest(outcome=outcome), patch.object(proof.socket, 'create_connection', return_value=client) as connect, \
                        patch.object(proof.sys, 'stdin', control), patch.object(proof.select, 'select', side_effect=select), \
                        patch.object(proof.time, 'sleep') as idle, patch.object(proof.time, 'monotonic', side_effect=lambda: clock[0]), \
                        redirect_stdout(output):
                    if outcome != 'revoked':
                        with self.assertRaisesRegex(RuntimeError, 'inconclusive'): proof.held_http_probe()
                    else:
                        proof.held_http_probe()
                    connect.assert_called_once_with(('alertmanager-primary-0.alertmanager-operated', 9093), timeout=5)
                    idle.assert_called_once_with(45)
                messages = [json.loads(line) for line in output.getvalue().splitlines()]
                self.assertEqual(messages[0], {'ready': True, 'requests': 3, 'idleSeconds': 45, 'connections': 1})
                self.assertEqual(len(messages), 2)
                if outcome != 'revoked': self.assertEqual(messages[1], {'error': {
                    'stage': 'control' if outcome == 'late-control' else 'revocation', 'outcome': 'timeout'}})
                else: self.assertEqual(messages[1], {'revoked': True, 'connections': 1})
            finally:
                client.close()
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(requests), 3)
            self.assertTrue(all(b'Connection: keep-alive\r\n' in value for value in requests))

    def test_held_exec_error_closes_control_and_terminates_only_its_child(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [proof.subprocess.TimeoutExpired('fixture', 5), 0]
        with patch.object(proof.subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(proof, 'probe_message', side_effect=RuntimeError('Child failed')):
            with self.assertRaisesRegex(RuntimeError, 'Child failed'):
                with proof.held_source_connection(proof.PREFIX + 'a' * 16):
                    self.fail('Failed child cannot authorize policy mutation')
        self.assertEqual(spawn.call_args.args[0][4:9], ['-n', proof.PREFIX + 'a' * 16, 'client', '--', 'python'])
        process.stdin.close.assert_called_once()
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        process.stdout.close.assert_called_once()

    def test_parent_held_budget_rejects_late_inspection_eof_or_child_exit_and_records_clock(self):
        for outcome in ('success', 'late-start', 'late-eof', 'late-exit', 'exit-timeout', 'old-ready'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory(dir='/root') as directory:
                clock = [100]
                process = Mock()
                process.poll.return_value = 0
                def message(child, timeout, stage='control'):
                    self.assertIs(child, process)
                    if stage == 'baseline':
                        self.assertEqual(timeout, 80)
                        return {'ready': True, 'requests': 2} if outcome == 'old-ready' else {
                            'ready': True, 'requests': 3, 'idleSeconds': 45, 'connections': 1}
                    self.assertGreater(timeout, 0)
                    self.assertLessEqual(timeout, 40)
                    clock[0] = 141 if outcome == 'late-eof' else 130
                    return {'revoked': True, 'connections': 1}
                def finish(timeout):
                    if outcome == 'exit-timeout': raise proof.subprocess.TimeoutExpired('fixture', timeout)
                    if outcome == 'late-exit': clock[0] = 141
                    return 0
                process.wait.side_effect = finish
                def exercise():
                    with proof.held_source_connection(proof.PREFIX + 'a' * 16) as (inspect, baseline):
                        self.assertEqual(baseline, 100)
                        clock[0] = 125 if outcome == 'late-start' else 124
                        inspect()
                with patch.object(proof, 'DIAGNOSTIC_DIRECTORY', Path(directory)), \
                        patch.object(proof.time, 'monotonic', side_effect=lambda: clock[0]), \
                        patch.object(proof.subprocess, 'Popen', return_value=process), \
                        patch.object(proof, 'probe_message', side_effect=message):
                    if outcome == 'success': exercise()
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'inconclusive'): exercise()
                records = [json.loads(path.read_bytes()) for path in Path(directory).glob('probe-*.json')]
                if outcome == 'old-ready':
                    self.assertEqual(records, [{'actor': 'held-http', 'stage': 'baseline', 'outcome': 'protocol'}])
                else:
                    self.assertIn({'actor': 'held-http', 'stage': 'baseline', 'outcome': 'success', 'baselineMonotonic': 100}, records)
                    if outcome == 'success':
                        self.assertIn({'actor': 'held-http', 'stage': 'revocation', 'outcome': 'closed'}, records)
                    else:
                        self.assertTrue(any(row['outcome'] == 'timeout' for row in records))
                        self.assertFalse(any(row['outcome'] == 'closed' for row in records))
                if outcome in ('late-start', 'old-ready'): process.stdin.write.assert_not_called()
                else: process.stdin.write.assert_called_once_with(b'check\n')
                process.stdin.close.assert_called_once()
                process.stdout.close.assert_called_once()

    def test_held_child_protocol_is_bounded_and_timeout_or_extra_output_blocks_proof(self):
        for raw, valid in [(b'{"ready":true,"requests":2}\n', True), (b'', False),
                           (b'x' * 1025 + b'\n', False), (b'{}\n{}\n', False)]:
            descriptor, writer = proof.os.pipe()
            proof.os.write(writer, raw)
            proof.os.close(writer)
            with proof.os.fdopen(descriptor, 'rb', buffering=0) as output:
                process = Mock(stdout=output)
                with self.subTest(size=len(raw)), patch.object(proof, 'record_probe_outcome'):
                    if valid:
                        self.assertEqual(proof.probe_message(process, 1), {'ready': True, 'requests': 2})
                    else:
                        with self.assertRaises(RuntimeError): proof.probe_message(process, 1)
                with patch.object(proof.select, 'select', return_value=([], [], [])), patch.object(proof, 'record_probe_outcome'), \
                        self.assertRaisesRegex(RuntimeError, 'inconclusive'):
                    proof.probe_message(process, 1)

    def test_native_deny_is_causal_health_stable_and_precedes_network_closure(self):
        for failure in (None, 'socket-timeout', 'policy-replaced', 'context-changed', 'unready', 'late-create', 'late-fresh', 'late-ready'):
            events = []
            clock = [0]
            cluster = Mock(namespace=proof.PREFIX + 'a' * 16, operation='a' * 16)
            pod = {'spec': {'containers': [{'name': 'alertmanager', 'readinessProbe': {
                'httpGet': {'path': '/-/ready'}, 'failureThreshold': 1, 'periodSeconds': 1, 'timeoutSeconds': 1}}]}}
            policy = None
            def create(item, dry_run=False):
                nonlocal policy
                events.append('dryrun' if dry_run else 'deny')
                if not dry_run and failure == 'late-create': clock[0] = 26
                policy = dict(copy.deepcopy(item), metadata={'uid': 'deny'})
                return policy
            def current(kind, name, namespace=None):
                if kind == 'Pod': return pod
                if kind == 'NetworkPolicy': return {'spec': {'ingress': [{'ports': [{'port': 9093}]}]}}
                if failure == 'policy-replaced': return dict(policy, metadata={'uid': 'foreign'})
                return policy
            @proof.contextmanager
            def held(namespace):
                events.append('two-positive-gets')
                baseline = clock[0]
                if failure == 'late-ready': clock[0] = 26
                def revoked():
                    events.append('revoked')
                    if failure == 'socket-timeout': raise RuntimeError('Inconclusive socket timeout')
                try: yield revoked, baseline
                finally: events.append('child-closed')
            def request(*args, **kwargs):
                events.append('fresh-denied')
                if failure == 'late-fresh': clock[0] = 26
                return {'denied': True}
            def ready(*args):
                events.append('ready')
                return None if failure == 'unready' else pod
            cluster.current.side_effect = current
            cluster.create.side_effect = create
            cluster.patch.side_effect = lambda *args: events.append('np-close')
            contexts = ['fixed', 'changed' if failure == 'context-changed' else 'fixed']
            with self.subTest(failure=failure), patch.object(proof, 'held_source_connection', side_effect=held), \
                    patch.object(proof, 'namespace_listener_profile'), \
                    patch.object(proof, 'authorization_context', side_effect=contexts), \
                    patch.object(proof, 'source_unchanged'), patch.object(proof, 'pod_ready', side_effect=ready), \
                    patch.object(proof, 'source_get', return_value=json.dumps({'config': {'original': 'maintenance'}})), \
                    patch.object(proof, 'get'), patch.object(proof, 'request', side_effect=request), \
                    patch.object(proof, 'record_probe_outcome'), \
                    patch.object(proof, 'wait', side_effect=lambda label, check, **kwargs: self.assertTrue(check())), \
                    patch.object(proof.time, 'monotonic', side_effect=lambda: clock[0]), \
                    patch.object(proof.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
                if failure:
                    with self.assertRaises(RuntimeError): proof.quiesce_source(cluster, {}, 'maintenance')
                    cluster.patch.assert_not_called()
                    cluster.delete.assert_not_called()
                    cluster.receipt.phase.assert_not_called()
                    if failure == 'late-ready': self.assertNotIn('deny', events)
                else:
                    access = proof.quiesce_source(cluster, {}, 'maintenance')
                    self.assertTrue(access)
                    self.assertLess(events.index('two-positive-gets'), events.index('deny'))
                    self.assertLess(events.index('deny'), events.index('revoked'))
                    self.assertLess(events.index('revoked'), events.index('ready'))
                    self.assertLess(events.index('ready'), events.index('np-close'))
                    self.assertEqual(policy['spec']['action'], 'DENY')
                    self.assertNotIn('selector', policy['spec'])
                    self.assertNotIn('targetRefs', policy['spec'])
                    self.assertEqual(policy['spec']['rules'], [{'to': [{'operation': {'ports': ['9093']}}]}])
                    self.assertEqual(cluster.receipt.phase.call_args.kwargs['readinessWindowSeconds'], 4)
                    cluster.delete.assert_not_called()

    def test_held_deny_requires_exact_receipted_policy_and_blocks_unsafe_cutover(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            namespace = proof.document('Namespace', cluster.namespace, cluster)
            namespace['metadata'].pop('namespace')
            namespace['metadata']['labels'].update({'pod-security.kubernetes.io/enforce': 'restricted',
                'pod-security.kubernetes.io/enforce-version': 'v1.36', 'istio.io/dataplane-mode': 'ambient',
                'istio-injection': 'disabled'})
            ns_row = cluster.receipt.intent(namespace)
            namespace['metadata']['uid'] = 'namespace'
            cluster.receipt.created(ns_row, namespace)
            policy = proof.source_deny_policy(cluster)
            row = cluster.receipt.intent(policy)
            policy['metadata'].update(uid='deny', resourceVersion='1')
            cluster.receipt.created(row, policy)
            source = proof.document('Pod', 'alertmanager-primary-0', cluster)
            source['metadata']['labels']['checkpoint-role'] = 'manager'
            with patch.object(proof, 'get', side_effect=lambda kind, *args: source if kind == 'Pod'
                    else namespace if kind == 'Namespace' else policy):
                proof.require_source_denied(cluster)
            for change in ('absent', 'uid', 'owner', 'port', 'selector'):
                current = copy.deepcopy(policy)
                if change == 'absent': current = None
                if change == 'uid': current['metadata']['uid'] = 'foreign'
                if change == 'owner': current['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
                if change == 'port': current['spec']['rules'][0]['to'][0]['operation']['ports'] = ['8080']
                if change == 'selector': current['spec']['selector'] = {'matchLabels': {proof.LABEL: 'foreign'}}
                with self.subTest(change=change), patch.object(proof, 'get', side_effect=lambda kind, *args:
                        namespace if kind == 'Namespace' else source if kind == 'Pod' else current), self.assertRaises(RuntimeError):
                    proof.require_source_denied(cluster)
            source['metadata']['labels']['checkpoint-role'] = 'foreign'
            with patch.object(proof, 'get', side_effect=lambda kind, *args: source if kind == 'Pod'
                    else namespace if kind == 'Namespace' else policy), \
                    self.assertRaises(RuntimeError):
                proof.require_source_denied(cluster)
            cluster.receipt.phase('persistent-validated')
            with patch.object(proof, 'source_unchanged'), patch.object(proof, 'get', return_value=None), \
                    patch.object(cluster, 'patch') as mutate, self.assertRaises(RuntimeError):
                proof.promote_storage(cluster, {}, 'alertmanager-primary-0', {})
            mutate.assert_not_called()

    def test_maintenance_error_or_early_promotion_preserves_source(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            with patch.object(proof, 'get') as read, patch.object(cluster, 'patch') as mutate:
                with self.assertRaises(RuntimeError):
                    proof.promote_storage(cluster, {}, 'source', {})
                read.assert_not_called()
                mutate.assert_not_called()
            baseline = {name: {'inode': 1, 'mtime': 90, 'ctime': 90, 'size': 10, 'regular': True}
                        for name in proof.FILES}
            with patch.object(proof, 'snapshot_metadata', return_value=(100, baseline, {})), \
                    patch.object(proof, 'require_source_denied'), \
                    patch.object(proof, 'maintenance_errors', side_effect=[{'nflog': 0, 'silences': 0},
                                                                          {'nflog': 1, 'silences': 0}]), \
                    patch.object(proof, 'source_unchanged'), patch.object(proof, 'get'), \
                    patch.object(proof, 'wait', side_effect=lambda _label, check, **_: check()), \
                    patch.object(proof, 'exec_pod') as capture, patch.object(proof, 'write_new') as persist:
                with self.assertRaises(RuntimeError):
                    proof.verify_snapshots(cluster, 'source', {})
                capture.assert_not_called()
                persist.assert_not_called()

    def test_final_claim_uses_actual_native_names_and_subpath(self):
        storage = {'volumeClaimTemplate': {'metadata': {'annotations': {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}},
            'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'cloudlab-telemetry',
                     'resources': {'requests': {'storage': '1Gi'}}}}}
        statefulset = {'metadata': {'name': 'alertmanager-primary', 'labels': {'alertmanager': 'primary'}},
                       'spec': {'selector': {'matchLabels': {'alertmanager': 'primary'}}}}
        pod = {'spec': {'containers': [{'name': 'alertmanager', 'volumeMounts': [{'name': 'alertmanager-primary-db',
                       'mountPath': '/alertmanager', 'subPath': 'alertmanager-db'}]}],
                       'volumes': [{'name': 'alertmanager-primary-db', 'emptyDir': {}}]}}
        claim = proof.final_claim(statefulset, pod, storage, 'fixture', 'a' * 16)
        self.assertEqual(claim['metadata']['name'], 'alertmanager-primary-db-alertmanager-primary-0')
        self.assertNotIn('ownerReferences', claim['metadata'])
        pod['spec']['containers'][0]['volumeMounts'][0].pop('subPath')
        with self.assertRaises(RuntimeError):
            proof.final_claim(statefulset, pod, storage, 'fixture', 'a' * 16)

    def test_retained_replacement_wait_ignores_only_known_old_uid_and_verifies_new_native_mount(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            objects = {}
            def record(item, uid):
                row = cluster.receipt.intent(item)
                item['metadata'].update(uid=uid, resourceVersion='1')
                cluster.receipt.created(row, item)
                objects[item['kind']] = item
                return row
            namespace = proof.document('Namespace', cluster.namespace, cluster)
            namespace['metadata'].pop('namespace')
            namespace['metadata']['labels'].update({'pod-security.kubernetes.io/enforce': 'restricted',
                'pod-security.kubernetes.io/enforce-version': 'v1.36', 'istio.io/dataplane-mode': 'ambient', 'istio-injection': 'disabled'})
            record(namespace, 'namespace')
            target = {'volumeClaimTemplate': {'metadata': {'annotations': {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}},
                                               'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'cloudlab-telemetry',
                                                       'resources': {'requests': {'storage': '1Gi'}}}}}
            record(proof.document('Alertmanager', 'primary', cluster, spec={'replicas': 1, 'storage': target,
                   'persistentVolumeClaimRetentionPolicy': {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}}), 'manager')
            record(proof.source_deny_policy(cluster), 'deny')
            claim_name = 'alertmanager-primary-db-alertmanager-primary-0'
            record(proof.document('PersistentVolumeClaim', claim_name, cluster,
                   spec=copy.deepcopy(target['volumeClaimTemplate']['spec']) | {'volumeName': 'pvc-claim'},
                   status={'phase': 'Bound'}), 'claim')
            objects['pv'] = {'metadata': {'uid': 'pv', 'name': 'pvc-claim'}, 'spec': {
                'persistentVolumeReclaimPolicy': 'Retain', 'claimRef': {'uid': 'claim'},
                'csi': {'driver': 'driver.longhorn.io', 'volumeHandle': 'volume'}}}
            objects['volumes.longhorn.io'] = {'metadata': {'uid': 'volume-uid', 'name': 'volume'},
                                           'spec': {'numberOfReplicas': 2}, 'status': {'robustness': 'healthy'}}
            spec = {'serviceAccountName': 'proof-alertmanager', 'automountServiceAccountToken': False,
                'containers': [{'name': 'alertmanager', 'image': 'native@sha256:' + 'a' * 64,
                    'args': ['--cluster.listen-address=', '--data.maintenance-interval=5s'],
                    'volumeMounts': [{'name': 'alertmanager-primary-db', 'mountPath': '/alertmanager', 'subPath': 'alertmanager-db'}]}],
                'volumes': [{'name': 'alertmanager-primary-db', 'emptyDir': {'sizeLimit': '64Mi'}}]}
            old_sts = proof.document('StatefulSet', 'alertmanager-primary', cluster, spec={'template': {'spec': copy.deepcopy(spec)}})
            old_sts['metadata'].update(generation=1, ownerReferences=[{'kind': 'Alertmanager', 'name': 'primary',
                                                                     'uid': 'manager', 'controller': True}])
            sts_row = record(old_sts, 'old-sts')
            sts_row.update(observed=True, owners=['manager'])
            old = proof.document('Pod', 'alertmanager-primary-0', cluster, spec=copy.deepcopy(spec), status={'phase': 'Running',
                'conditions': [{'type': 'Ready', 'status': 'True'}], 'containerStatuses': [{'name': 'alertmanager',
                    'containerID': 'old-container', 'restartCount': 0, 'state': {'running': {'startedAt': '2026-11-05T12:00:00Z'}}}]})
            old['metadata']['labels']['checkpoint-role'] = 'manager'
            old['metadata'].update(annotations={'ambient.istio.io/redirection': 'enabled'}, ownerReferences=[{
                'kind': 'StatefulSet', 'name': 'alertmanager-primary', 'uid': 'old-sts', 'controller': True}])
            old_row = record(old, 'old-pod')
            old_row.update(observed=True, owners=['old-sts'])
            original = proof.source_identity(old)
            new = copy.deepcopy(old)
            new['metadata']['uid'] = 'new-pod'
            new['metadata']['ownerReferences'][0]['uid'] = 'new-sts'
            new['status']['containerStatuses'][0]['containerID'] = 'new-container'
            new['spec']['volumes'] = [{'name': 'alertmanager-primary-db', 'persistentVolumeClaim': {'claimName': claim_name}}]
            new_sts = copy.deepcopy(old_sts)
            new_sts['metadata']['uid'] = 'new-sts'
            new_sts['spec'].update(replicas=1, persistentVolumeClaimRetentionPolicy={'whenDeleted': 'Retain', 'whenScaled': 'Retain'},
                template={'spec': copy.deepcopy(spec)}, volumeClaimTemplates=[{'metadata': {'name': 'alertmanager-primary-db'},
                    'spec': copy.deepcopy(target['volumeClaimTemplate']['spec']) | {'volumeMode': 'Filesystem'}}])
            new_sts['status'] = {'observedGeneration': 1}
            new_sts['spec']['template']['spec']['volumes'] = []
            storage = {'claim': 'claim', 'pv': 'pv', 'pvName': 'pvc-claim', 'volume': 'volume',
                       'volumeUID': 'volume-uid', 'handle': 'volume'}
            cluster.receipt.phase('persistent-validated', storageFresh=True, storage=storage, nativePodProfile=proof.pod_profile(spec))
            baseline = copy.deepcopy(objects)
            known = [row.get('uid') for row in cluster.receipt.value['resources']]
            for case in ('old-healthy', 'old-terminal', 'new-ready', 'new-pending', 'old-scope', 'old-owner', 'wrong-phase',
                         'new-terminal', 'new-deleting', 'foreign-label', 'foreign-owner', 'restarted', 'wrong-claim', 'wrong-subpath',
                         'wrong-csi', 'wrong-image', 'wrong-template', 'wrong-target', 'wrong-deny'):
                objects.clear(); objects.update(copy.deepcopy(baseline))
                objects['Pod'] = copy.deepcopy(old if case.startswith('old-') or case == 'wrong-phase' else new)
                objects['StatefulSet'] = copy.deepcopy(old_sts if case.startswith('old-') or case == 'wrong-phase' else new_sts)
                cluster.receipt.value['phase'] = 'snapshot-captured' if case == 'wrong-phase' else 'persistent-validated'
                candidate = objects['Pod']
                if case == 'old-terminal':
                    candidate['metadata']['deletionTimestamp'] = '2026-11-05T12:01:00Z'
                    candidate['status']['phase'] = 'Failed'
                if case == 'old-scope': candidate['metadata']['namespace'] = 'foreign'
                if case == 'old-owner': candidate['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                if case == 'new-pending': candidate['status']['conditions'] = []
                if case == 'new-terminal': candidate['status']['phase'] = 'Failed'
                if case == 'new-deleting': candidate['metadata']['deletionTimestamp'] = '2026-11-05T12:01:00Z'
                if case == 'foreign-label': candidate['metadata']['labels'][proof.LABEL] = 'foreign'
                if case == 'foreign-owner': objects['StatefulSet']['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                if case == 'restarted': candidate['status']['containerStatuses'][0]['restartCount'] = 1
                if case == 'wrong-claim': candidate['spec']['volumes'][0]['persistentVolumeClaim']['claimName'] = 'foreign'
                if case == 'wrong-subpath': candidate['spec']['containers'][0]['volumeMounts'][0]['subPath'] = 'foreign'
                if case == 'wrong-csi': objects['pv']['spec']['csi']['volumeHandle'] = 'foreign'
                if case == 'wrong-image': candidate['spec']['containers'][0]['image'] = 'foreign'
                if case == 'wrong-template': objects['StatefulSet']['spec']['volumeClaimTemplates'][0]['metadata']['name'] = 'foreign'
                if case == 'wrong-target': objects['Alertmanager']['spec']['storage'] = {'emptyDir': {}}
                if case == 'wrong-deny': objects['AuthorizationPolicy']['spec']['rules'] = []
                def read(kind, name=None, namespace=None):
                    return copy.deepcopy(objects[{'pvc': 'PersistentVolumeClaim', 'pod': 'Pod'}.get(kind, kind)])
                with self.subTest(case=case), patch.object(proof, 'get', side_effect=read), \
                        patch.object(proof, 'pod_ready', wraps=proof.pod_ready) as readiness, patch.object(proof, 'kubectl') as mutate:
                    if case in ('old-healthy', 'old-terminal', 'new-pending'):
                        self.assertIsNone(proof.retained_replacement(cluster, 'alertmanager-primary-0', original, target, claim_name, storage))
                        if case.startswith('old-'): readiness.assert_not_called()
                    elif case == 'new-ready':
                        self.assertEqual(proof.retained_replacement(cluster, 'alertmanager-primary-0', original,
                            target, claim_name, storage)['metadata']['uid'], 'new-pod')
                        readiness.assert_called_once()
                    else:
                        with self.assertRaises(RuntimeError): proof.retained_replacement(cluster, 'alertmanager-primary-0', original,
                            target, claim_name, storage)
                    mutate.assert_not_called()
                self.assertEqual([row.get('uid') for row in cluster.receipt.value['resources']], known)

    def test_unknown_or_replaced_housekeeping_blocks_namespace_delete(self):
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            cluster = proof.Cluster(self.receipt(directory))
            namespace = proof.document('Namespace', cluster.namespace, cluster)
            namespace['metadata'].pop('namespace')
            namespace['metadata'].update(uid='namespace', resourceVersion='1', creationTimestamp='2026-11-05T12:00:00Z')
            row = cluster.receipt.intent(namespace)
            cluster.receipt.created(row, namespace)
            certificate = proof.ssl.DER_cert_to_PEM_cert(proof.ssl.create_default_context().get_ca_certs(binary_form=True)[0])
            metadata = {'namespace': cluster.namespace, 'resourceVersion': '2', 'creationTimestamp': '2026-11-05T12:00:01Z'}
            objects = {}
            for kind, name, manager, data in [('ServiceAccount', 'default', None, None),
                    ('ConfigMap', 'kube-root-ca.crt', 'k3s', {'ca.crt': certificate}),
                    ('ConfigMap', 'istio-ca-root-cert', 'pilot-discovery', {'root-cert.pem': certificate}),
                    ('ConfigMap', 'istio-ca-crl', 'pilot-discovery', {'ca-crl.pem': ''})]:
                current = {'apiVersion': 'v1', 'kind': kind, 'metadata': dict(metadata, name=name, uid=name)}
                if manager: current['metadata']['managedFields'] = [{'manager': manager}]
                if name.startswith('istio-'): current['metadata']['labels'] = {'istio.io/config': 'true'}
                if name == 'kube-root-ca.crt': current['metadata']['annotations'] = {'kubernetes.io/description': 'native description'}
                if data is not None: current['data'] = data
                objects[kind, name] = current
            roots = {'kube-root-ca.crt': proof.certificate_hash(certificate),
                     'istio-ca-root-cert': proof.certificate_hash(certificate), 'istio-ca-crl': proof.revocation_hash('')}
            with patch.object(cluster, 'current', return_value=namespace), \
                    patch.object(proof, 'housekeeping_roots', return_value=roots), \
                    patch.object(proof, 'get', side_effect=lambda kind, name, *args, **kwargs: objects.get((kind, name))):
                proof.record_housekeeping(cluster)
                proof.namespace_delete_gate(cluster, list(objects.values()))
                for name, change in [('default', 'tokens'), ('default', 'pull'), ('default', 'override'),
                        ('default', 'custom-label'), ('default', 'before-namespace'), ('default', 'owner'),
                        ('kube-root-ca.crt', 'empty-writers'), ('kube-root-ca.crt', 'extra-data'),
                        ('kube-root-ca.crt', 'foreign-ca'), ('istio-ca-crl', 'foreign-crl'),
                        ('istio-ca-root-cert', 'custom-label'), ('istio-ca-root-cert', 'manager'),
                        ('default', 'uid'), ('kube-root-ca.crt', 'unknown')]:
                    kind = 'ServiceAccount' if name == 'default' else 'ConfigMap'
                    current = copy.deepcopy(objects[kind, name])
                    if change == 'tokens': current['secrets'] = [{'name': 'token'}]
                    if change == 'pull': current['imagePullSecrets'] = [{'name': 'credential'}]
                    if change == 'override': current['automountServiceAccountToken'] = False
                    if change == 'custom-label': current['metadata']['labels'] = {'foreign': 'true'}
                    if change == 'before-namespace': current['metadata']['creationTimestamp'] = '2026-11-05T11:59:59Z'
                    if change == 'owner': current['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                    if change == 'empty-writers': current['metadata'].pop('managedFields')
                    if change == 'extra-data': current['data']['foreign'] = 'bytes'
                    if change == 'foreign-ca': current['data']['ca.crt'] = 'forged'
                    if change == 'foreign-crl': current['data']['ca-crl.pem'] = 'forged'
                    if change == 'manager': current['metadata']['managedFields'] = [{'manager': 'foreign'}]
                    if change == 'uid': current['metadata']['uid'] = 'replacement'
                    if change == 'unknown': current['kind'] = 'Secret'
                    with self.subTest(name=name, change=change), self.assertRaises((RuntimeError, proof.ssl.SSLError)):
                        proof.namespace_delete_gate(cluster, [current])

    def test_housekeeping_trust_reads_only_public_selected_cluster_ca(self):
        certificate = proof.ssl.DER_cert_to_PEM_cert(proof.ssl.create_default_context().get_ca_certs(binary_form=True)[0])
        public = {'istio-ca-root-cert': {'data': {'root-cert.pem': certificate}},
                  'istio-ca-crl': {'data': {'ca-crl.pem': ''}}}
        with patch.object(proof, 'kubectl', return_value=proof.base64.b64encode(certificate.encode())) as read, \
                patch.object(proof, 'get', side_effect=lambda kind, name, namespace: public[name]):
            result = proof.housekeeping_roots()
            self.assertEqual(result['kube-root-ca.crt'], proof.certificate_hash(certificate))
            self.assertEqual(read.call_args.args, ('config', 'view', '--raw', '--minify', '-o',
                'jsonpath={.clusters[0].cluster.certificate-authority-data}'))
        for response in (b'', b'not-base64', proof.base64.b64encode(b'forged-certificate')):
            with self.subTest(response=response), patch.object(proof, 'kubectl', return_value=response), \
                    self.assertRaises((RuntimeError, ValueError)):
                proof.housekeeping_roots()

    def test_fixture_has_no_gossip_privilege_or_production_scope(self):
        path = Path(proof.__file__).with_name('alertmanager-checkpoint-fixture.yaml')
        documents = list(yaml.safe_load_all(path.read_text()))
        text = path.read_text()
        self.assertNotIn('9094', text)
        self.assertNotIn('service-secrets', text)
        self.assertIn('restricted', text)
        self.assertIn('--controller-id=${OPERATION}', text)
        for row in documents:
            if row['kind'] in ('Role', 'ClusterRole'):
                for rule in row['rules']:
                    self.assertNotIn('*', rule['resources'])
                    self.assertNotIn('*', rule['verbs'])
        api = next(r for r in documents if r['metadata']['name'] == 'operator-api')
        self.assertEqual(api['spec']['podSelector']['matchLabels'], {'checkpoint-role': 'operator'})
        health = next(r for r in documents if r['metadata']['name'] == 'native-health')
        self.assertEqual(health['spec']['podSelector']['matchExpressions'],
                         [{'key': 'checkpoint-role', 'operator': 'In', 'values': ['manager', 'validator']}])
        self.assertEqual(health['spec']['ingress'][0]['ports'], [{'port': 9093, 'protocol': 'TCP'}])
        self.assertEqual(health['spec']['ingress'][0]['from'], [
            {'ipBlock': {'cidr': '169.254.7.127/32'}},
            {'ipBlock': {'cidr': 'fd16:9254:7127:1337:ffff:ffff:ffff:ffff/128'}}])

    def test_prepare_uses_current_native_retained_template_and_pinned_images(self):
        from playbooks.observability.files import chart
        original_render = chart.render
        rendered = []
        def render(*args, **kwargs):
            result = original_render(*args, **kwargs)
            for item in result:
                if item['kind'] == 'Alertmanager': rendered.append((item, copy.deepcopy(item)))
            return result
        with patch.object(chart, 'render', side_effect=render):
            value = proof.prepare()
        self.assertTrue(all(current == before for current, before in rendered))
        self.assertIn('emptyDir', rendered[0][0]['spec']['storage'])
        self.assertIsNone(rendered[0][0]['spec']['storage']['emptyDir'])
        self.assertEqual(set(value['storage']), {'volumeClaimTemplate'})
        self.assertEqual(value['sourceStorage'], {'emptyDir': {'sizeLimit': '64Mi'}})
        self.assertEqual(value['retention'], {'whenDeleted': 'Retain', 'whenScaled': 'Retain'})
        self.assertEqual(value['storage']['volumeClaimTemplate']['spec']['resources']['requests']['storage'], '1Gi')
        self.assertTrue(all('@sha256:' in image for image in value['images'].values()))


if __name__ == '__main__':
    unittest.main()
