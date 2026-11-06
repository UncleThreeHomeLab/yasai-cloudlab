"""Runtime checkpoint boundaries without Kubernetes, credentials or fixture imports."""
import copy
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.observability.files import checkpoint as check, handoff_backend as backend

PINS = {key: value for key, value in json.loads((Path(__file__).resolve().parents[4] /
    'platform/observability/images.lock.json').read_text()).items() if key in ('operator', 'alertmanager')}


def uid(number):
    return '%08x-0000-0000-0000-000000000000' % number


def object_value(kind, name, number, namespace=check.NAMESPACE):
    return {'kind': kind, 'apiVersion': {'Application': 'argoproj.io/v1alpha1', 'Alertmanager': 'monitoring.coreos.com/v1',
            'StatefulSet': 'apps/v1', 'Deployment': 'apps/v1', 'StorageClass': 'storage.k8s.io/v1', 'Volume': 'longhorn.io/v1beta2'}.get(kind, 'v1'),
        'metadata': {'name': name, 'namespace': namespace, 'uid': uid(number)}, 'spec': {}}


def source_objects():
    app = object_value('Application', check.APPLICATION, 1, 'argocd')
    app['metadata']['labels'] = {'cloudlab.io/owner': 'observability-platform'}
    app['spec'] = {'project': 'cloudlab-observability', 'source': {'targetRevision': 'a' * 40}}
    manager = object_value('Alertmanager', 'cloudlab', 2)
    manager['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
        'cloudlab-prometheus:monitoring.coreos.com/Alertmanager:cloudlab-observability/cloudlab'}
    manager['spec'] = {'replicas': 1, 'storage': {'emptyDir': {'sizeLimit': '64Mi'}}, 'image': PINS['alertmanager']}
    statefulset = object_value('StatefulSet', 'alertmanager-cloudlab', 3)
    statefulset['spec'] = {'replicas': 1, 'selector': {'matchLabels': {'alertmanager': 'cloudlab'}}}
    statefulset['metadata']['labels'] = {'alertmanager': 'cloudlab'}
    pod = object_value('Pod', 'alertmanager-cloudlab-0', 4)
    for child, parent in [(statefulset, manager), (pod, statefulset)]:
        child['metadata']['ownerReferences'] = [{'apiVersion': parent['apiVersion'], 'kind': parent['kind'],
            'name': parent['metadata']['name'], 'uid': parent['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}]
    pod['spec'] = {'securityContext': {'runAsUser': 1000, 'runAsGroup': 2000, 'fsGroup': 2000},
        'containers': [{'name': 'alertmanager', 'image': PINS['alertmanager'],
            'args': ['--cluster.listen-address='],
            'volumeMounts': [{'name': 'alertmanager-cloudlab-db', 'mountPath': '/alertmanager', 'subPath': 'alertmanager-db'}]}],
        'volumes': [{'name': 'alertmanager-cloudlab-db', 'emptyDir': {'sizeLimit': '64Mi'}}]}
    pod['status'] = {'containerStatuses': [{'name': 'alertmanager', 'containerID': 'containerd://' + 'a' * 64,
        'restartCount': 0, 'state': {'running': {'startedAt': '2026-11-05T00:00:00Z'}}}]}
    operator = object_value('Deployment', 'cloudlab-prometheus-operator', 5)
    operator['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
        'cloudlab-prometheus:apps/Deployment:cloudlab-observability/cloudlab-prometheus-operator'}
    operator['spec'] = {'template': {'spec': {'containers': [{'image': PINS['operator']}]}}}
    return app, manager, statefulset, pod, operator


def archive(values, extra=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as stream:
        for name, raw in values.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            stream.addfile(member, io.BytesIO(raw))
        if extra:
            stream.addfile(extra, io.BytesIO(b''))
    return output.getvalue()


def metadata(number, sizes=None):
    return {name: {'present': True, 'inode': number, 'mtime': number, 'ctime': number,
        'size': (sizes or {}).get(name, 0), 'regular': True, 'links': 1} for name in check.FILES}


class CheckpointTests(unittest.TestCase):
    def test_source_profile_binds_existing_native_lineage_and_production_interval(self):
        app, manager, sts, pod, operator = source_objects()
        binding = check.bind_source(app, manager, sts, pod, operator, copy.deepcopy(app['spec']), PINS)
        self.assertEqual(binding['source'], check.source_identity(pod))
        for case in ('parent', 'operator', 'clustering', 'interval', 'subpath', 'source-storage'):
            objects = copy.deepcopy([app, manager, sts, pod, operator])
            if case == 'parent': objects[2]['metadata']['ownerReferences'][0]['uid'] = uid(9)
            if case == 'operator': objects[4]['spec']['template']['spec']['containers'][0]['image'] = 'other'
            if case == 'clustering': objects[3]['spec']['containers'][0]['args'] = ['--cluster.listen-address=:9094']
            if case == 'interval': objects[1]['spec']['additionalArgs'] = [{'name': 'data.maintenance-interval', 'value': '5s'}]
            if case == 'subpath': objects[3]['spec']['containers'][0]['volumeMounts'][0]['subPath'] = 'other'
            if case == 'source-storage': objects[1]['spec']['storage'] = {'emptyDir': {}}
            with self.subTest(case=case), self.assertRaises(RuntimeError): check.bind_source(*objects, app['spec'], PINS)

    def test_source_process_restart_replacement_and_validation_failure(self):
        pod = source_objects()[3]
        original = copy.deepcopy(pod)
        expected = check.source_identity(pod)
        reads = Mock(return_value=pod)
        validate = Mock(side_effect=RuntimeError('native load failed'))
        with self.assertRaisesRegex(RuntimeError, 'native load failed'):
            check.with_preserved_source(validate, reads, expected)
        self.assertEqual(reads.call_count, 2)
        self.assertEqual(pod, original)
        for change in ('uid', 'restart', 'container', 'start'):
            changed = copy.deepcopy(pod)
            if change == 'uid': changed['metadata']['uid'] = uid(99)
            if change == 'restart': changed['status']['containerStatuses'][0]['restartCount'] = 1
            if change == 'container': changed['status']['containerStatuses'][0]['containerID'] = 'containerd://' + 'b' * 64
            if change == 'start': changed['status']['containerStatuses'][0]['state']['running']['startedAt'] = 'later'
            with self.subTest(change=change), self.assertRaises(RuntimeError): check.source_unchanged(changed, expected)

    def test_each_store_requires_two_completed_post_boundary_generations_even_when_empty(self):
        generations = check.Generations(100, metadata(90))
        self.assertFalse(generations.observe(metadata(99)))
        self.assertFalse(generations.observe(metadata(101)))
        self.assertFalse(generations.observe(metadata(101)))
        partial = metadata(102)
        partial['silences'] = metadata(101)['silences']
        self.assertFalse(generations.observe(partial))
        self.assertTrue(generations.observe(metadata(102)))
        missing = metadata(103)
        missing['silences'] = {'present': False, 'inode': 0, 'mtime': 0, 'ctime': 0, 'size': 0, 'regular': False, 'links': 0}
        self.assertFalse(generations.observe(missing))
        for bad in ('links', 'regular', 'size'):
            altered = metadata(104)
            altered['nflog'][bad] = {'links': 2, 'regular': False, 'size': check.LIMIT}[bad]
            with self.subTest(bad=bad), self.assertRaises(RuntimeError): generations.observe(altered)

    def test_zero_mixed_and_nonempty_archives_have_exact_names_hashes_and_regular_files(self):
        for values in ({'nflog': b'', 'silences': b''}, {'nflog': b'native', 'silences': b''}):
            hashes = {name: check.digest(raw) for name, raw in values.items()}
            raw = archive(values)
            self.assertEqual(check.parse_archive(raw, hashes), values)
            bad = hashes | {'nflog': 'a' * 64}
            with self.assertRaises(RuntimeError): check.parse_archive(raw, bad)
            with self.assertRaises(RuntimeError): check.parse_archive(raw + b'x' * 512, hashes)
            for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.REGTYPE):
                extra = tarfile.TarInfo('other')
                extra.type, extra.linkname = kind, 'nflog'
                with self.subTest(kind=kind), self.assertRaises(RuntimeError): check.parse_archive(archive(values, extra), hashes)
        with self.assertRaises(RuntimeError): check.parse_archive(b'x' * (check.LIMIT + 512), hashes)

    def test_metadata_parser_and_capture_bind_stable_bytes_without_requiring_nonempty_stores(self):
        values = {'nflog': b'', 'silences': b'silences'}
        lines = ['103']
        for name in check.FILES:
            lines.extend(['102:102:102:%d:8180:1' % len(values[name]), check.digest(values[name]) + '  /alertmanager/' + name])
        before = check.snapshot_metadata(('\n'.join(lines) + '\n').encode())
        generations = check.Generations(100, metadata(90))
        generations.observe(metadata(101))
        after = (104, before[1], before[2])
        self.assertEqual(check.captured(before, after, archive(values), generations), values)
        changed = copy.deepcopy(after)
        changed[1]['silences']['inode'] = 105
        with self.assertRaises(RuntimeError): check.captured(before, changed, archive(values), generations)
        for wrong in (b'103\n102:102:102:0:a1ff:1\n' + b'a' * 64 + b'  /alertmanager/nflog\nmissing\nmissing\n',
                      ('\n'.join(lines).replace(':8180:1', ':8180:2') + '\n').encode()):
            with self.assertRaises(RuntimeError): check.snapshot_metadata(wrong)

    def test_capture_rechecks_source_and_both_quiescence_controls_around_reads(self):
        pod = source_objects()[3]
        expected = check.source_identity(pod)
        values = {'nflog': b'', 'silences': b''}
        sample = (103, metadata(102), {name: check.digest(raw) for name, raw in values.items()})
        def tracker():
            result = check.Generations(100, metadata(90))
            result.observe(metadata(101))
            return result
        state = copy.deepcopy(pod)
        reads = Mock(return_value=state)
        quiescent = Mock(return_value=True)
        self.assertEqual(check.capture(reads, lambda: sample, lambda: archive(values), quiescent, expected, tracker()), values)
        self.assertEqual(reads.call_count, 4)
        self.assertEqual(quiescent.call_count, 4)
        with self.assertRaises(RuntimeError):
            check.capture(reads, lambda: sample, lambda: archive(values), lambda: False, expected, tracker())
        def changed_archive():
            state['metadata']['uid'] = uid(99)
            return archive(values)
        with self.assertRaises(RuntimeError):
            check.capture(reads, lambda: sample, changed_archive, lambda: True, expected, tracker())

    def test_final_claim_and_validator_keep_native_name_ids_binary_and_subpath(self):
        _, _, sts, pod, _ = source_objects()
        profile = json.loads((Path(__file__).resolve().parents[4] /
            'platform/observability/gitops/handoff-profiles.json').read_text())['storageProfiles']['alertmanager-retained-1gi-v1']
        storage = {'volumeClaimTemplate': {'metadata': {'annotations': check.CLAIM_ANNOTATIONS}, 'spec': {
            'accessModes': profile['accessModes'], 'storageClassName': profile['storageClassName'],
            'volumeMode': profile['volumeMode'], 'resources': {'requests': {'storage': profile['storage']}}}}}
        claim = check.final_claim(sts, pod, storage, 'a' * 16, PINS)
        self.assertEqual(claim['metadata']['name'], 'alertmanager-cloudlab-db-alertmanager-cloudlab-0')
        self.assertEqual(claim['spec']['volumeMode'], 'Filesystem')
        self.assertNotIn('ownerReferences', claim['metadata'])
        claim['metadata']['uid'] = uid(6)
        plan = check.validation_plan(pod, claim, 'cloudlab-checkpoint-' + 'a' * 16, PINS)
        self.assertEqual(plan['configuration']['receivers'], [{'name': 'checkpoint-validation'}])
        self.assertEqual(plan['pod']['spec']['securityContext']['runAsUser'], 1000)
        self.assertEqual(plan['pod']['spec']['securityContext']['runAsGroup'], 2000)
        self.assertEqual(plan['pod']['spec']['containers'][0]['image'], PINS['alertmanager'])
        self.assertFalse(plan['pod']['spec']['automountServiceAccountToken'])
        foreign = copy.deepcopy(claim)
        foreign['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
        with self.assertRaises(RuntimeError): check.validation_plan(pod, foreign, 'cloudlab-checkpoint-' + 'a' * 16, PINS)
        block_storage = copy.deepcopy(storage)
        block_storage['volumeClaimTemplate']['spec']['volumeMode'] = 'Block'
        with self.assertRaisesRegex(RuntimeError, 'Noncanonical retained storage template'):
            check.final_claim(sts, pod, block_storage, 'a' * 16, PINS)
        block_claim = copy.deepcopy(claim)
        block_claim['spec']['volumeMode'] = 'Block'
        with self.assertRaisesRegex(RuntimeError, 'Validator claim differs'):
            check.validation_plan(pod, block_claim, 'cloudlab-checkpoint-' + 'a' * 16, PINS)
        wrong = copy.deepcopy(pod)
        wrong['spec']['containers'][0]['volumeMounts'][0]['subPath'] = 'other'
        with self.assertRaises(RuntimeError): check.final_claim(sts, wrong, storage, 'a' * 16, PINS)

    def test_payload_writes_preserve_zero_bytes_and_never_overwrite(self):
        # /root is private in the offline runner; /tmp ancestry is intentionally rejected.
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            values = {'nflog': b'', 'silences': b'native'}
            hashes = check.write_payloads(directory, values)
            self.assertEqual(hashes, {name: check.digest(raw) for name, raw in values.items()})
            self.assertEqual((Path(directory) / 'nflog').read_bytes(), b'')
            with self.assertRaises(FileExistsError): check.write_payloads(directory, values)
            self.assertEqual(os.stat(Path(directory) / 'silences').st_mode & 0o777, 0o600)

    def test_fresh_storage_refuses_foreign_restored_old_or_changed_class(self):
        _, _, sts, pod, _ = source_objects()
        expected = check.final_claim(sts, pod, {'volumeClaimTemplate': {
            'metadata': {'annotations': check.CLAIM_ANNOTATIONS}, 'spec': check.CLAIM_SPEC}}, 'a' * 16, PINS)
        claim = copy.deepcopy(expected)
        claim['metadata'].update(uid=uid(6), creationTimestamp='2026-11-05T00:00:02Z')
        claim['metadata']['annotations']['volume.kubernetes.io/storage-provisioner'] = 'driver.longhorn.io'
        handle = 'pvc-' + uid(6)
        claim['spec']['volumeName'], claim['status'] = handle, {'phase': 'Bound', 'capacity': {'storage': '1Gi'}}
        pv = object_value('PersistentVolume', handle, 7, None)
        pv['metadata'].update(creationTimestamp='2026-11-05T00:00:03Z', annotations={'pv.kubernetes.io/provisioned-by': 'driver.longhorn.io'})
        pv['spec'] = {'claimRef': {'name': claim['metadata']['name'], 'namespace': check.NAMESPACE, 'uid': uid(6)},
            'storageClassName': 'cloudlab-telemetry', 'persistentVolumeReclaimPolicy': 'Retain', 'capacity': {'storage': '1Gi'},
            'csi': {'driver': 'driver.longhorn.io', 'volumeHandle': handle}}
        volume = object_value('Volume', handle, 8, 'longhorn-system')
        volume['metadata']['creationTimestamp'] = '2026-11-05T00:00:04Z'
        volume['spec'] = {'numberOfReplicas': 2, 'size': '1073741824'}
        volume['status'] = {'robustness': 'healthy', 'kubernetesStatus': {
            'pvcName': claim['metadata']['name'], 'pvName': handle, 'namespace': check.NAMESPACE}}
        storage_class = object_value('StorageClass', 'cloudlab-telemetry', 9, None)
        storage_class['metadata']['labels'] = {'cloudlab.io/owner': 'observability-platform'}
        storage_class.update(provisioner='driver.longhorn.io', reclaimPolicy='Retain', parameters={'numberOfReplicas': '2'})
        baseline = {'complete': True, 'boundary': '2026-11-05T00:00:01Z', 'storageClassUID': uid(9),
            'pvs': {'uids': [], 'names': []}, 'volumes': {'uids': [], 'names': []}}
        check.fresh_storage(claim, pv, volume, storage_class, baseline, expected, storage_class)
        pv['spec']['volumeMode'] = 'Filesystem'
        check.fresh_storage(claim, pv, volume, storage_class, baseline, expected, storage_class)
        for case in ('foreign', 'restored', 'old', 'class', 'incomplete', 'link', 'labels', 'claim-mode', 'pv-mode'):
            values = copy.deepcopy([claim, pv, volume, storage_class, baseline])
            if case == 'foreign': values[1]['spec']['claimRef']['uid'] = uid(99)
            if case == 'restored': values[2]['spec']['fromBackup'] = 'backup'
            if case == 'old': values[4]['pvs']['uids'] = [check.digest(uid(7).encode())]
            if case == 'class': values[3]['parameters']['numberOfReplicas'] = '1'
            if case == 'incomplete': values[4]['complete'] = False
            if case == 'labels': values[0]['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            if case == 'link': values[2]['status']['kubernetesStatus']['pvcName'] = 'foreign'
            if case == 'claim-mode': values[0]['spec']['volumeMode'] = 'Block'
            if case == 'pv-mode': values[1]['spec']['volumeMode'] = 'Block'
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                check.fresh_storage(*values, expected, storage_class)

        # A fresh detached Longhorn volume cannot become healthy before its
        # first consumer. Identity must pass before mounting; health gates stdin.
        volume['spec']['nodeID'] = ''
        volume['status'].update(state='detached', robustness='unknown', currentNodeID='')
        binding = check.fresh_storage_identity(claim, pv, volume, storage_class, baseline, expected, storage_class)
        with self.assertRaises(RuntimeError):
            check.fresh_storage(claim, pv, volume, storage_class, baseline, expected, storage_class)
        check.storage_usage(volume, 'unmounted')
        with self.assertRaises(check.StorageUsageNotReady): check.storage_usage(volume, 'mounted')
        value = backend.Backend.__new__(backend.Backend)
        payloads = {'nflog': b'', 'silences': b'native'}
        hashes = {name: check.digest(raw) for name, raw in payloads.items()}
        value.state = {'storageBaseline': baseline, 'claimDocument': expected, 'storage': binding,
            'mutations': {}, 'checkpoint': hashes}
        value.storage_objects = lambda: (claim, pv, volume)
        value.resource = lambda *_args: storage_class
        value.get = lambda _path: storage_class
        consumers, events = [], []
        value.list = lambda *_args: copy.deepcopy(consumers)
        value.save, value.quiescent = lambda: None, lambda: True
        read_identity = value.storage_identity_binding
        def identity_checked():
            result = read_identity()
            events.append('identity')
            return result
        value.storage_identity_binding = identity_checked
        writer = {'metadata': {'name': 'cloudlab-checkpoint-writer-' + 'a' * 16}, 'spec': {}}
        def create(key, _path, document):
            self.assertEqual(key, 'writer')
            self.assertEqual(volume['status']['state'], 'detached')
            self.assertEqual(volume['status']['robustness'], 'unknown')
            self.assertFalse(consumers)
            events.append('idle-consumer-created')
            consumer = {'metadata': {'name': document['metadata']['name'], 'namespace': check.NAMESPACE, 'uid': uid(10)},
                'spec': {'nodeName': 'worker', 'volumes': [{'name': 'data', 'persistentVolumeClaim': {
                    'claimName': claim['metadata']['name']}}]}}
            consumers.append(consumer)
            value.state['mutations'][key] = {'uid': uid(10), 'deleted': False}
            volume['spec']['nodeID'] = 'worker'
            volume['status'].update(state='attaching', currentNodeID='worker')
            return consumer
        def running(_key, _container):
            events.append('idle-consumer-running')
            volume['status'].update(state='attached', robustness='degraded')
            return consumers[0]
        def advance(_seconds):
            if volume['status']['state'] == 'attached':
                events.append('healthy')
                volume['status']['robustness'] = 'healthy'
            else:
                self.assertEqual(volume['status']['state'], 'detaching')
                events.append('detached')
                volume['status'].update(state='detached', robustness='unknown', currentNodeID='')
        def stdin(_key, _container, _arguments, *, body, limit):
            value.storage_binding('mounted', 'writer')
            self.assertEqual(volume['status']['robustness'], 'healthy')
            self.assertEqual(json.loads(body)['hashes'], hashes)
            events.append('stdin-write')
            return check.canonical(hashes)
        def remove(key):
            self.assertTrue(value.state['checkpointWritten'])
            events.append('consumer-deleted')
            value.state['mutations'][key]['deleted'] = True
            consumers.clear()
            volume['spec']['nodeID'] = ''
            volume['status']['state'] = 'detaching'
        value.create, value.wait_owned, value.exec_owned, value.remove = create, running, stdin, remove
        with patch.object(backend.time, 'sleep', side_effect=advance):
            value.write_checkpoint(payloads, writer)
        ordered = [event for event in events if event != 'identity']
        self.assertEqual(ordered, ['idle-consumer-created', 'idle-consumer-running', 'healthy', 'stdin-write',
            'consumer-deleted', 'detached'])
        self.assertLess(events.index('identity'), events.index('idle-consumer-created'))
        self.assertEqual(value.storage_binding('unmounted'), binding)
        before = list(events)
        for wrong in ('uid', 'link'):
            value.state['mutations'] = {}
            if wrong == 'uid': pv['spec']['claimRef']['uid'] = uid(99)
            else: volume['status']['kubernetesStatus']['pvcName'] = 'foreign'
            with self.subTest(before_mount=wrong), self.assertRaises(RuntimeError):
                value.write_checkpoint(payloads, writer)
            pv['spec']['claimRef']['uid'] = uid(6)
            volume['status']['kubernetesStatus']['pvcName'] = claim['metadata']['name']
            self.assertEqual(events, before)


if __name__ == '__main__':
    unittest.main()
