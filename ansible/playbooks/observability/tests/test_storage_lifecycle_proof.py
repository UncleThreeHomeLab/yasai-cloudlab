"""Offline boundaries for the fixed three-claim CSI proof."""
import copy
import base64
import io
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from playbooks.observability.tests import storage_lifecycle_proof as proof


OPERATION = '0123456789abcdef'


def uid(number):
    return '00000000-0000-0000-0000-' + str(number).zfill(12)


class MemoryReceipt:
    def __init__(self):
        self.operation = OPERATION
        self.namespace = proof.namespace(OPERATION)
        self.value = {'context': {}, 'objects': {}, 'roots': {}, 'intents': {}, 'markers': {}, 'evidence': {},
                      'baseline': {'nodes': ['node-a', 'node-b']}, 'appPhase': 'scaled-down',
                      'storage': {name: {'identity': {'claim': {'uid': uid(index), 'kind': 'PersistentVolumeClaim',
                          'apiVersion': 'v1', 'name': proof.claim_names(OPERATION)[name], 'namespace': self.namespace},
                          'handle': 'pvc-' + uid(index)}} for index, name in enumerate(('loki', 'tempo', 'grafana'), 1)}}
        self.saves = []

    def save(self):
        self.saves.append(copy.deepcopy(self.value))

    def intention(self, name, identity, scope):
        return proof.Receipt.intention(self, name, identity, scope)

    def record(self, name, obj):
        return proof.Receipt.record(self, name, obj)

    def phase(self, phase):
        self.value['phase'] = phase
        self.save()


def storage_chain(receipt, component='loki', index=1):
    def obj(kind, name, number, namespace=None, api='v1'):
        return {'kind': kind, 'apiVersion': api, 'metadata': {'name': name, 'namespace': namespace,
            'uid': uid(number), 'resourceVersion': '12', 'creationTimestamp': '2026-11-05T12:00:01Z'}, 'spec': {}}
    claim = obj('PersistentVolumeClaim', proof.claim_names(receipt.operation)[component], index, receipt.namespace)
    handle = 'pvc-' + claim['metadata']['uid']
    claim['metadata'].update(labels={'cloudlab.io/owner': proof.OWNER, proof.LABEL: receipt.operation},
        annotations={'volume.kubernetes.io/storage-provisioner': 'driver.longhorn.io'})
    claim['spec'] = {'storageClassName': 'cloudlab-telemetry', 'accessModes': ['ReadWriteOnce'],
                     'resources': {'requests': {'storage': '1Gi'}}, 'volumeName': handle}
    claim['status'] = {'phase': 'Bound'}
    pv = obj('PersistentVolume', handle, index + 10)
    pv['metadata']['annotations'] = {'pv.kubernetes.io/provisioned-by': 'driver.longhorn.io'}
    pv['spec'] = {'claimRef': {'uid': claim['metadata']['uid'], 'name': claim['metadata']['name'], 'namespace': receipt.namespace},
        'storageClassName': 'cloudlab-telemetry', 'capacity': {'storage': '1Gi'}, 'persistentVolumeReclaimPolicy': 'Retain',
        'csi': {'driver': 'driver.longhorn.io', 'volumeHandle': handle}}
    pv['status'] = {'phase': 'Released'}
    volume = obj('Volume', handle, index + 20, 'longhorn-system', 'longhorn.io/v1beta2')
    volume['spec'] = {'size': '1073741824', 'numberOfReplicas': 2}
    volume['status'] = {'robustness': 'healthy', 'kubernetesStatus': {'pvName': handle, 'pvStatus': 'Released',
        'pvcName': claim['metadata']['name'], 'namespace': receipt.namespace, 'lastPVCRefAt': '2026-11-05T12:10:00Z'}}
    return claim, pv, volume


def replica_rows():
    return [{'node': 'node-' + slot, 'replicaUID': uid(index + 30), 'manager': 'longhorn-manager-' + slot,
        'inspector': {'uid': uid(index + 40), 'node': 'node-' + slot}, 'disk': '/var/lib/longhorn',
        'parent': '/var/lib/longhorn/replicas', 'path': '/var/lib/longhorn/replicas/pvc-' + uid(1) + '-' + str(index).zfill(8),
        'context': {'present': True, 'disk': '1:2', 'parent': '1:3', 'replica': '1:4'}} for index, slot in enumerate(('a', 'b'))]


def native_marker_spec(spec):
    native = copy.deepcopy(spec)
    native.update(priority=0, tolerations=[{'key': 'node.kubernetes.io/' + key, 'operator': 'Exists',
        'effect': 'NoExecute', 'tolerationSeconds': 300} for key in ('not-ready', 'unreachable')],
        dnsPolicy='ClusterFirst', schedulerName='default-scheduler', terminationGracePeriodSeconds=30,
        preemptionPolicy='PreemptLowerPriority', serviceAccount='default')
    native['containers'][0].update(terminationMessagePath='/dev/termination-log', terminationMessagePolicy='File',
                                    imagePullPolicy='IfNotPresent')
    return native


def native_secret(document):
    result = copy.deepcopy(document)
    data = result.setdefault('data', {})
    data.update({key: base64.b64encode(value.encode('utf-8')).decode('ascii')
                 for key, value in result.pop('stringData', {}).items()})
    result.setdefault('type', 'Opaque')
    return result


def housekeeping_fixture(operation=OPERATION):
    certificate = re.search(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',
                            Path('/etc/ssl/certs/ca-certificates.crt').read_text()).group(0)
    namespace = proof.root_documents(operation)[0]
    namespace['metadata'].update(uid=uid(201), resourceVersion='10', creationTimestamp='2026-11-05T12:00:00Z')
    namespace['metadata']['labels']['kubernetes.io/metadata.name'] = proof.namespace(operation)
    namespace['spec'] = {'finalizers': ['kubernetes']}
    namespace['status'] = {'phase': 'Active'}
    objects = []
    for index, (kind, name, manager, data) in enumerate([
            ('ServiceAccount', 'default', 'kube-controller-manager', None),
            ('ConfigMap', 'kube-root-ca.crt', 'k3s', {'ca.crt': certificate}),
            ('ConfigMap', 'istio-ca-root-cert', 'pilot-discovery', {'root-cert.pem': certificate}),
            ('ConfigMap', 'istio-ca-crl', 'pilot-discovery', {'ca-crl.pem': ''})], 202):
        obj = {'apiVersion': 'v1', 'kind': kind, 'metadata': {'name': name, 'namespace': proof.namespace(operation),
            'uid': uid(index), 'resourceVersion': '11', 'creationTimestamp': '2026-11-05T12:00:01Z',
            'managedFields': [{'manager': manager, 'operation': 'Update', 'apiVersion': 'v1', 'fieldsType': 'FieldsV1', 'fieldsV1': {}}]}}
        if data is not None: obj['data'] = data
        if name.startswith('istio-'): obj['metadata']['labels'] = {'istio.io/config': 'true'}
        objects.append(obj)
    roots = {'kube-root-ca.crt': proof.certificate_hash(certificate), 'istio-ca-root-cert': proof.certificate_hash(certificate),
             'istio-ca-crl': proof.revocation_hash('')}
    return namespace, objects, roots


def discovery_fixture(collections, namespace):
    responses = {'/apis': {'groups': []}, '/api/v1': {'groupVersion': 'v1', 'resources': []}}
    groups = {}
    for version, plural, kind, items in collections:
        root = '/api/v1' if version == 'v1' else '/apis/' + version
        if version != 'v1':
            group = version.split('/')[0]
            if group not in groups:
                groups[group] = {'name': group, 'preferredVersion': {'groupVersion': version}, 'versions': [{'groupVersion': version}]}
        responses.setdefault(root, {'groupVersion': version, 'resources': []})['resources'].append(
            {'name': plural, 'kind': kind, 'namespaced': True, 'verbs': ['get', 'list', 'delete']})
        responses[root + '/namespaces/' + namespace + '/' + plural + '?limit=100'] = {
            'apiVersion': version, 'kind': kind + 'List', 'metadata': {'resourceVersion': '42'}, 'items': items}
    responses['/apis']['groups'] = list(groups.values())
    return responses


def stage_empty_recovery(root, payload):
    operation = 'fedcba9876543210'
    old = root / ('observability-storage-' + OPERATION)
    old.mkdir(mode=0o700)
    (old / 'state').mkdir(mode=0o700)
    namespace, objects, roots = housekeeping_fixture()
    receipt = {'context': {'version': 1, 'profile': proof.PROFILE, 'operation': OPERATION,
        'driver': proof.PREDECESSOR_DRIVER, 'input': proof.digest(proof.canonical(payload))},
        'phase': 'namespace-created', 'steps': ['namespace-created'], 'pendingStep': 'baseline-qualified',
        'roots': {'namespace': {'documentHash': proof.digest(proof.canonical(proof.root_documents(OPERATION)[0])), 'accepted': True}},
        'objects': {'namespace': proof.object_id(namespace)}, 'intents': {}, 'storage': {}, 'markers': {}, 'evidence': {}}
    buffers = {'proof.py': b'# synthetic predecessor artifact\n', 'input.json': proof.canonical(payload),
               'state/receipt.json': proof.canonical(receipt), 'operation.lock': b''}
    for name, raw in buffers.items():
        (old / name).write_bytes(raw)
        (old / name).chmod(0o600)
    envelope = {'version': 1, 'profile': proof.RECOVERY_PROFILE, 'operation': operation, 'predecessor': {
        'operation': OPERATION, 'driverSHA256': proof.PREDECESSOR_DRIVER, 'inputSHA256': proof.digest(buffers['input.json']),
        'receiptSHA256': proof.digest(buffers['state/receipt.json']), 'namespaceUID': namespace['metadata']['uid']}}
    new = root / ('observability-storage-recovery-' + operation)
    new.mkdir(mode=0o700)
    for name, raw in {'proof.py': Path(proof.__file__).read_bytes(), 'input.json': proof.canonical(envelope)}.items():
        (new / name).write_bytes(raw)
        (new / name).chmod(0o600)
    return envelope, old, new / 'state', buffers, namespace, objects, roots


def stage_storage_recovery(root, payload):
    operation = 'fedcba9876543210'
    old = root / ('observability-storage-' + OPERATION)
    old.mkdir(mode=0o700)
    receipt = proof.Receipt(old / 'state', OPERATION, payload)
    value = receipt.value
    value.update(context={'version': 1, 'profile': proof.PROFILE, 'operation': OPERATION,
        'driver': proof.STORAGE_PREDECESSOR_DRIVER, 'input': proof.STORAGE_PREDECESSOR_INPUT},
        phase='drift-repaired', pendingStep='scaled-down-qualified', cleanupStarted=True,
        admission={'running': {}}, baseline={'boundary': '2026-11-05T12:00:00+00:00',
        'class': {'uid': uid(400), 'spec': 'a' * 64}, 'nodes': ['node-a','node-b'],
        'pvs': {'uid': [], 'name': []}, 'volumes': {'uid': [], 'name': []}})
    value['evidence']['cascadeRetainedClaims'] = True
    docs = {}
    for number, (key, document) in enumerate(zip(('namespace','project','app'), proof.root_documents(OPERATION)), 200):
        value['roots'][key] = {'accepted': True, 'documentHash': proof.digest(proof.canonical(document))}
        document['metadata'].update(uid=uid(number), resourceVersion='8')
        value['objects'][key] = proof.object_id(document)
        docs[key] = document
    def intent(key, identity, scope, accepted=True, complete=True, cascade=False):
        value['intents'][key] = {'identity': identity, 'scope': proof.digest(proof.canonical(scope)),
            'accepted': accepted, 'complete': complete}
        if cascade: value['intents'][key]['cascade'] = True
    intent('delete-app', value['objects']['app'], {'source':payload['source'],'app':value['objects']['app']})
    value['intents']['replica-drift'] = {'accepted': True, 'complete': True}
    chains = {}
    for index, component in enumerate(('loki','tempo','grafana'), 1):
        claim,pv,volume = storage_chain(receipt,component,index)
        identity = {'claim':proof.object_id(claim),'pv':proof.object_id(pv),'volume':proof.object_id(volume),'handle':pv['metadata']['name']}
        replicas = replica_rows()
        for row in replicas: row['path'] = row['path'].replace('pvc-'+uid(1),identity['handle'])
        value['storage'][component] = {'identity':identity,'replicas':replicas}
        value['objects']['claim-'+component] = identity['claim']
        intent('delete-claim-'+component, identity['claim'],identity)
        if component != 'grafana':
            scope={'profile':proof.PROFILE,'operation':OPERATION,'component':component,'identity':identity,'replicas':replicas}
            intent('delete-volume-'+component,identity['volume'],scope)
            intent('delete-pv-'+component,identity['pv'],scope,accepted=False,cascade=True)
        chains[component]=(claim,pv,volume)
    deployment={'apiVersion':'apps/v1','kind':'Deployment','name':receipt.namespace+'-grafana','namespace':receipt.namespace,'uid':uid(500)}
    rs={'apiVersion':'apps/v1','kind':'ReplicaSet','name':deployment['name']+'-abcd123','namespace':receipt.namespace,'uid':uid(501)}
    value['objects'].update({'workload-grafana':deployment,'rs-'+rs['name']:rs})
    chains['grafana'][2]['status'].update(state='detached')
    chains['grafana'][2]['status']['kubernetesStatus'].update(lastPodRefAt='2026-11-05T12:10:00Z',
        workloadsStatus=[{'workloadType':'ReplicaSet','workloadName':rs['name']}])
    buffers={'proof.py':b'# synthetic storage predecessor\n','input.json':proof.canonical(payload),
        'state/receipt.json':proof.canonical(value),'operation.lock':b''}
    for name,raw in buffers.items():
        (old/name).write_bytes(raw);(old/name).chmod(0o600)
    envelope={'version':1,'profile':proof.STORAGE_RECOVERY_PROFILE,'operation':operation,'predecessor':{
        'operation':OPERATION,'driverSHA256':proof.STORAGE_PREDECESSOR_DRIVER,'inputSHA256':proof.STORAGE_PREDECESSOR_INPUT,
        'receiptSHA256':proof.digest(buffers['state/receipt.json']),'namespaceUID':docs['namespace']['metadata']['uid']},
        'dataScope':{c:{'identity':r['identity'],'replicasSHA256':proof.digest(proof.canonical(r['replicas']))} for c,r in value['storage'].items()}}
    new=root/('observability-storage-recovery-'+operation)
    new.mkdir(mode=0o700)
    return envelope,old,new/'state',buffers,value,chains,docs


class StorageProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = proof.prepare(OPERATION)

    def test_cleanup_only_accepts_proven_recorded_grafana_replicaset(self):
        receipt=MemoryReceipt()
        deployment={'apiVersion':'apps/v1','kind':'Deployment','name':receipt.namespace+'-grafana','namespace':receipt.namespace,'uid':uid(500)}
        rs={'apiVersion':'apps/v1','kind':'ReplicaSet','name':deployment['name']+'-abcd','namespace':receipt.namespace,'uid':uid(501)}
        receipt.value['objects']={'workload-grafana':deployment,'rs-'+rs['name']:rs}
        claim,pv,volume=storage_chain(receipt)
        identity={'claim':proof.object_id(claim),'pv':proof.object_id(pv),'volume':proof.object_id(volume),'handle':pv['metadata']['name']}
        receipt.value['storage']['loki']={'identity':identity,'replicas':replica_rows()}
        link=volume['status']['kubernetesStatus'];link.update(lastPodRefAt='now',workloadsStatus=[{'workloadType':'ReplicaSet','workloadName':rs['name']}])
        with patch.object(proof,'current',return_value=None), patch.object(proof,'backing_deletion_gate'), \
             patch.object(proof,'capture_replicas',return_value=replica_rows()):
            proof.paired_intents(receipt,'loki',pv,volume)
            link['workloadsStatus'][0]['workloadName']='unrecorded'
            with self.assertRaisesRegex(RuntimeError,'unknown workload'):proof.paired_intents(receipt,'loki',pv,volume)
        for field,value in [('namespace','other'),('apiVersion','custom/v1'),('uid','bad')]:
            bad=copy.deepcopy(rs);bad[field]=value
            receipt.value['objects']['rs-'+rs['name']]=bad
            with self.assertRaisesRegex(RuntimeError,'Unqualified'):proof.recorded_grafana_replicasets(receipt)
        receipt.value['objects']['rs-'+rs['name']]=rs
        del receipt.value['objects']['workload-grafana']
        with self.assertRaisesRegex(RuntimeError,'Unqualified'):proof.recorded_grafana_replicasets(receipt)

    def test_standalone_history_requires_component_bound_marker_provenance_and_no_consumers(self):
        for mutation in ('none', 'pod-name', 'other-component', 'claim', 'uid', 'source', 'delete', 'typed-marker', 'consumer', 'payload'):
            with self.subTest(mutation=mutation):
                receipt = MemoryReceipt()
                claim, pv, volume = storage_chain(receipt)
                identity = {'claim': proof.object_id(claim), 'pv': proof.object_id(pv),
                            'volume': proof.object_id(volume), 'handle': pv['metadata']['name']}
                receipt.value['storage']['loki'] = {'identity': identity, 'replicas': replica_rows()}
                component = 'tempo' if mutation == 'other-component' else 'loki'
                content = proof.marker_content(receipt, component)
                receipt.value['markers'][component] = {'content': content, 'sha256': proof.digest(content.encode()),
                    'claimUID': receipt.value['storage'][component]['identity']['claim']['uid']}
                document = proof.marker_document(receipt, self.payload, component, 'write')
                marker = proof.object_id(document | {'metadata': document['metadata'] | {'uid': uid(81), 'resourceVersion': '8'}})
                receipt.value['objects']['marker-0'] = marker
                record = {'component': component, 'mode': 'write', 'accepted': True, 'complete': True,
                    'document': proof.digest(proof.canonical(document)), 'admittedSpec': native_marker_spec(document['spec'])}
                record['verifiedIO'] = {'identity': copy.deepcopy(marker), 'document': record['document'], 'mode': 'write',
                    'claimUID': receipt.value['markers'][component]['claimUID'],
                    'sha256': receipt.value['markers'][component]['sha256'], 'finishedAt': '2026-11-05T12:01:00Z'}
                receipt.value['markerRuns'] = [record]
                scope = {'profile': proof.PROFILE, 'marker': marker, 'document': record['document']}
                receipt.value['intents']['delete-marker-0'] = {'identity': marker, 'scope': proof.digest(proof.canonical(scope)),
                    'accepted': True, 'complete': True}
                history = {'podName': receipt.namespace + '-marker', 'podStatus': 'Succeeded', 'workloadName': '', 'workloadType': ''}
                if mutation == 'pod-name': history['podName'] = receipt.namespace + '-unknown'
                if mutation == 'claim': record['verifiedIO']['claimUID'] = uid(99)
                if mutation == 'uid': record['verifiedIO']['identity']['uid'] = uid(99)
                if mutation == 'source': record['admittedSpec']['containers'][0]['command'] = ['python', '-c', 'pass']
                if mutation == 'delete': receipt.value['intents']['delete-marker-0']['accepted'] = False
                if mutation == 'typed-marker': history.update(workloadType='Pod', workloadName=receipt.namespace + '-marker')
                volume['status']['kubernetesStatus'].update(lastPodRefAt='now', workloadsStatus=[history])
                with patch.object(proof, 'current', return_value=None), patch.object(proof, 'backing_deletion_gate'), \
                     patch.object(proof, 'capture_replicas', return_value=replica_rows()), \
                     patch.object(proof, 'root_current'), patch.object(proof, 'listed', return_value=
                         [{'kind': 'Pod'}] if mutation == 'consumer' else []):
                    if mutation == 'none':
                        proof.paired_intents(receipt, 'loki', pv, volume, payload=self.payload)
                        self.assertTrue(all('delete-' + kind + '-loki' in receipt.value['intents'] for kind in ('pv', 'volume')))
                    else:
                        with self.assertRaises(RuntimeError):
                            proof.paired_intents(receipt, 'loki', pv, volume,
                                payload=None if mutation == 'payload' else self.payload)
                        self.assertNotIn('delete-pv-loki', receipt.value['intents'])
                        self.assertNotIn('delete-volume-loki', receipt.value['intents'])

    def test_cleanup_cleaned_flag_survives_paired_intent_value_replacement(self):
        receipt=MemoryReceipt();claim,pv,volume=storage_chain(receipt)
        identity={'claim':proof.object_id(claim),'pv':proof.object_id(pv),'volume':proof.object_id(volume),'handle':pv['metadata']['name']}
        receipt.value['storage']['loki']={'identity':identity,'replicas':replica_rows()}
        receipt.value['intents']['delete-claim-loki']={'identity':identity['claim'],'accepted':True,'complete':True}
        state={'pv':pv,'volume':volume}
        def current(obj):return state.get('pv' if obj==identity['pv'] else 'volume' if obj==identity['volume'] else 'claim')
        def delete(record,key,obj,scope):
            self.assertEqual(set(record.saves[-1]['intents']) & {'delete-pv-loki','delete-volume-loki'}, {'delete-pv-loki','delete-volume-loki'})
            record.value['intents'][key]['accepted']=True
            state['pv']=state['volume']=None
        def finish(record,key,deadline):record.value['intents'][key]['complete']=True
        with patch.object(proof,'current',side_effect=current), patch.object(proof,'backing_deletion_gate'), \
             patch.object(proof,'capture_replicas',return_value=replica_rows()), \
             patch.object(proof,'directory_state',side_effect=lambda r:r['context']), patch.object(proof,'request_delete',side_effect=delete), \
             patch.object(proof,'finish_delete',side_effect=finish), patch.object(proof,'backing_absent',return_value=True), \
             patch.object(proof,'verify_no_storage_dependents'):
            proof.cleanup_storage(receipt,'loki',proof.time.monotonic()+1)
        restored=json.loads(proof.canonical(receipt.saves[-1]))
        self.assertTrue(restored['storage']['loki']['cleaned'])
        self.assertTrue(restored['intents']['delete-pv-loki']['cascade'])

    def test_verified_marker_recovery_adopts_exact_state_and_resumes_only_acknowledged_progress(self):
        producer = proof.digest(b'# synthetic storage predecessor\n')
        with tempfile.TemporaryDirectory(dir='/root') as temporary, \
             patch.object(proof, 'MARKER_PREDECESSOR_DRIVER', producer):
            envelope, old, new, buffers, value, chains, docs = stage_storage_recovery(Path(temporary), self.payload)
            value.update(context={'version': 1, 'profile': proof.PROFILE, 'operation': OPERATION,
                'driver': producer, 'input': proof.digest(proof.canonical(self.payload))}, appPhase='scaled-down',
                phase='marker-written-tempo', pendingStep='marker-written-grafana')
            value['intents'] = {k: v for k, v in value['intents'].items()
                               if not k.startswith(('delete-pv-', 'delete-volume-', 'delete-claim-tempo', 'delete-claim-grafana'))}
            value['intents']['phase-0'] = {'accepted': True, 'complete': True}
            view = MemoryReceipt()
            view.value = value
            value['markerRuns'] = []
            for index, component in enumerate(('loki', 'tempo', 'grafana')):
                content = proof.marker_content(view, component)
                value['markers'][component] = {'content': content, 'sha256': proof.digest(content.encode()),
                    'claimUID': value['storage'][component]['identity']['claim']['uid']}
                document = proof.marker_document(view, self.payload, component, 'write')
                identity = proof.object_id(document | {'metadata': document['metadata'] | {'uid': uid(600 + index), 'resourceVersion': '8'}})
                value['objects']['marker-' + str(index)] = identity
                record = {'component': component, 'mode': 'write', 'accepted': True, 'complete': True,
                    'document': proof.digest(proof.canonical(document)), 'admittedSpec': native_marker_spec(document['spec'])}
                record['verifiedIO'] = {'identity': identity, 'document': record['document'], 'mode': 'write',
                    'claimUID': value['markers'][component]['claimUID'], 'sha256': value['markers'][component]['sha256'],
                    'finishedAt': '2026-11-05T12:01:00Z'}
                value['markerRuns'].append(record)
                scope = {'profile': proof.PROFILE, 'marker': identity, 'document': record['document']}
                value['intents']['delete-marker-' + str(index)] = {'identity': identity,
                    'scope': proof.digest(proof.canonical(scope)), 'accepted': True, 'complete': True}
            buffers['state/receipt.json'] = proof.canonical(value)
            (old / 'state/receipt.json').write_bytes(buffers['state/receipt.json'])
            tree = proof.original_tree(old)[0]
            envelope.update(case=proof.MARKER_RECOVERY_CASE, scopeWitnessSHA256='9' * 64)
            envelope['predecessor'].update(driverSHA256=producer,
                inputSHA256=proof.digest(buffers['input.json']), receiptSHA256=proof.digest(buffers['state/receipt.json']),
                treeSHA256=proof.digest(proof.canonical(tree)))
            proof.storage_recovery_input(envelope, envelope['operation'])
            proof.storage_predecessor(envelope, buffers)
            bad = copy.deepcopy(value)
            bad['intents']['delete-claim-tempo'] = {'accepted': False, 'complete': False}
            with self.assertRaisesRegex(RuntimeError, 'remaining-claim'):
                proof.marker_storage_predecessor(envelope, self.payload, bad)
            def unchanged():
                self.assertEqual(proof.original_tree(old)[0], tree)
            journal = proof.StorageRecoveryReceipt(new, envelope, proof.canonical(envelope), tree, value, unchanged)
            self.assertEqual(journal.value['context']['predecessor']['driverSHA256'], producer)
            self.assertEqual(journal.value['context']['driver'], proof.digest(Path(proof.__file__).read_bytes()))
            for component, row in journal.value['storage'].items():
                identity = row['identity']
                scope = {'profile': proof.PROFILE, 'operation': OPERATION, 'component': component,
                         'identity': identity, 'replicas': row['replicas']}
                for kind, target in (('claim', identity['claim']), ('pv', identity['pv']), ('volume', identity['volume'])):
                    journal.intention('delete-' + kind + '-' + component, target, identity if kind == 'claim' else scope)
                    journal.value['intents']['delete-' + kind + '-' + component].update(accepted=True, complete=True)
                row['cleaned'] = True
            namespace_id = journal.value['objects']['namespace']
            journal.intention('delete-namespace', namespace_id, {'namespace': namespace_id, 'storageCleaned': True})
            journal.value['intents']['delete-namespace'].update(accepted=True, complete=True)
            journal.save()
            absent = lambda row: row['context'] | {'present': False, 'replica': None}
            with patch.object(proof, 'storage_recovery_alias_gate'), patch.object(proof, 'current', return_value=None), \
                 patch.object(proof, 'storage_class', return_value=value['baseline']['class']), \
                 patch.object(proof, 'listed', return_value=[]), patch.object(proof, 'directory_state', side_effect=absent):
                proof.storage_recovery_preflight(journal, deadline=proof.time.monotonic() + 1, payload=self.payload)
                journal.value['intents']['delete-volume-loki']['accepted'] = False
                with self.assertRaisesRegex(RuntimeError, 'acknowledged'):
                    proof.storage_recovery_preflight(journal, deadline=proof.time.monotonic() + 1, payload=self.payload)
            unchanged()

    def test_storage_recovery_scope_and_original_provenance_reject_tampering(self):
        with tempfile.TemporaryDirectory(dir='/root') as temporary, patch.object(proof,'STORAGE_PREDECESSOR_OPERATION',OPERATION), \
             patch.object(proof,'STORAGE_PREDECESSOR_DRIVER',proof.digest(b'# synthetic storage predecessor\n')), \
             patch.object(proof,'STORAGE_PREDECESSOR_INPUT',proof.digest(proof.canonical(self.payload))):
            envelope,old,new,buffers,value,chains,docs=stage_storage_recovery(Path(temporary),self.payload)
            self.assertNotIn('appPhase',value)
            proof.storage_recovery_input(envelope,envelope['operation'])
            proof.storage_predecessor(envelope,buffers)
            for phase in ('running','scaled-down','removed',None):
                explicit=copy.deepcopy(value);explicit['appPhase']=phase
                copies=dict(buffers);copies['state/receipt.json']=proof.canonical(explicit)
                bound=copy.deepcopy(envelope);bound['predecessor']['receiptSHA256']=proof.digest(copies['state/receipt.json'])
                with self.subTest(appPhase=phase):
                    if phase=='running':proof.storage_predecessor(bound,copies)
                    else:
                        with self.assertRaisesRegex(RuntimeError,'Unsupported failed storage predecessor state'):
                            proof.storage_predecessor(bound,copies)
            for mutation in ('driver','namespace','replica','alias','claim-intent','cascade','grafana-intent'):
                bad=copy.deepcopy(envelope);copies=dict(buffers);v=copy.deepcopy(value)
                if mutation=='driver':bad['predecessor']['driverSHA256']='f'*64
                if mutation=='namespace':bad['predecessor']['namespaceUID']=uid(999)
                if mutation=='replica':bad['dataScope']['grafana']['replicasSHA256']='f'*64
                if mutation=='alias':bad['dataScope']['grafana']['identity']['handle']='other'
                if mutation=='claim-intent':v['intents']['delete-claim-grafana']['accepted']=False
                if mutation=='cascade':v['intents']['delete-pv-loki']['cascade']=False
                if mutation=='grafana-intent':v['intents']['delete-volume-grafana']={}
                if v!=value:
                    copies['state/receipt.json']=proof.canonical(v);bad['predecessor']['receiptSHA256']=proof.digest(copies['state/receipt.json'])
                with self.subTest(mutation=mutation), self.assertRaises((RuntimeError,KeyError)):
                    proof.storage_recovery_input(bad,bad['operation']);proof.storage_predecessor(bad,copies)

    def test_storage_recovery_new_journal_resume_preserves_original_and_denies_scope_changes(self):
        with tempfile.TemporaryDirectory(dir='/root') as temporary, patch.object(proof,'ROOT',Path(temporary)), \
             patch.object(proof,'STORAGE_PREDECESSOR_OPERATION',OPERATION), \
             patch.object(proof,'STORAGE_PREDECESSOR_DRIVER',proof.digest(b'# synthetic storage predecessor\n')), \
             patch.object(proof,'STORAGE_PREDECESSOR_INPUT',proof.digest(proof.canonical(self.payload))):
            envelope,old,new,buffers,value,chains,docs=stage_storage_recovery(Path(temporary),self.payload)
            before=proof.original_tree(old)[0]
            def unchanged():self.assertEqual(proof.original_tree(old)[0],before)
            raw=proof.canonical(envelope)
            journal=proof.StorageRecoveryReceipt(new,envelope,raw,before,value,unchanged)
            scope={'profile':proof.PROFILE,'operation':OPERATION,'component':'grafana',
                'identity':value['storage']['grafana']['identity'],'replicas':value['storage']['grafana']['replicas']}
            for key in ('pv','volume'):
                journal.intention('delete-'+key+'-grafana',scope['identity'][key],scope)
            resumed=proof.StorageRecoveryReceipt(new,envelope,raw,before,value,unchanged)
            self.assertTrue(all('delete-'+key+'-grafana' in resumed.value['intents'] for key in ('pv','volume')))
            self.assertFalse(resumed.value['evidence']['qualified'])
            resumed.value['storage']['grafana']['identity']['handle']='other'
            with self.assertRaisesRegex(RuntimeError,'scope changed'):resumed.save()
            self.assertEqual(proof.original_tree(old)[0],before)

    def test_storage_recovery_uses_normal_cleanup_only_and_checks_original_on_interrupt(self):
        with tempfile.TemporaryDirectory(dir='/root') as temporary, patch.object(proof,'ROOT',Path(temporary)), \
             patch.object(proof,'STORAGE_PREDECESSOR_OPERATION',OPERATION), \
             patch.object(proof,'STORAGE_PREDECESSOR_DRIVER',proof.digest(b'# synthetic storage predecessor\n')), \
             patch.object(proof,'STORAGE_PREDECESSOR_INPUT',proof.digest(proof.canonical(self.payload))):
            envelope,old,new,buffers,value,chains,docs=stage_storage_recovery(Path(temporary),self.payload)
            before=proof.original_tree(old)[0]
            def clean(receipt,payload,deadline):
                self.assertEqual(receipt.operation,OPERATION);self.assertEqual(receipt.directory,new)
                for row in receipt.value['storage'].values():row['cleaned']=True
                receipt.value['cleanupComplete']=True;receipt.save()
            with patch.object(proof,'storage_recovery_preflight'), patch.object(proof,'storage_recovery_alias_gate'), \
                 patch.object(proof,'backing_absent',return_value=True), patch.object(proof,'cleanup',side_effect=RuntimeError('interrupted')):
                with self.assertRaisesRegex(RuntimeError,'interrupted'):
                    proof.storage_cleanup_recovery(envelope,new,proof.canonical(envelope),proof.time.monotonic()+1)
            self.assertEqual(proof.original_tree(old)[0],before)
            with patch.object(proof,'storage_recovery_preflight'), patch.object(proof,'storage_recovery_alias_gate'), \
                 patch.object(proof,'backing_absent',return_value=True) as paths, patch.object(proof,'cleanup',side_effect=clean):
                result=proof.storage_cleanup_recovery(envelope,new,proof.canonical(envelope),proof.time.monotonic()+1)
                self.assertEqual(paths.call_count,3)
            self.assertEqual(result,{'cleanup':True,'recoveryOnly':True,'qualified':False,'originalQualified':False})
            self.assertEqual(proof.original_tree(old)[0],before)

    def test_storage_recovery_rechecks_native_profile_and_refuses_unsafe_data(self):
        with tempfile.TemporaryDirectory(dir='/root') as temporary:
            envelope,old,new,buffers,value,chains,docs=stage_storage_recovery(Path(temporary),self.payload)
            original=copy.deepcopy(value)
            for mutation in ('none','restore','class','baseline','claim','attachment','inspector'):
                receipt=MemoryReceipt();receipt.value=copy.deepcopy(original)
                chain=copy.deepcopy(chains['grafana']);identity=receipt.value['storage']['grafana']['identity']
                claim,pv,volume=chain
                fresh=copy.deepcopy(receipt.value['storage']['grafana']['replicas'])
                if mutation=='restore':volume['spec']['fromBackup']='unapproved'
                if mutation=='baseline':receipt.value['baseline']['pvs']['uid']=[proof.digest(pv['metadata']['uid'].encode())]
                if mutation=='inspector':fresh[0]['inspector']['uid']=uid(999)
                class_value=copy.deepcopy(receipt.value['baseline']['class'])
                if mutation=='class':class_value['spec']='f'*64
                def current(obj):
                    if obj==identity['claim']:return claim if mutation=='claim' else None
                    return next((o for o in (pv,volume) if proof.object_id(o)==obj),None)
                def listed(kind,ns=None):
                    if mutation=='attachment' and kind=='volumeattachments.storage.k8s.io':
                        return [{'spec':{'source':{'persistentVolumeName':identity['pv']['name']}}}]
                    return []
                with self.subTest(mutation=mutation), patch.object(proof,'storage_recovery_alias_gate'), \
                     patch.object(proof,'current',side_effect=current), patch.object(proof,'storage_class',return_value=class_value), \
                     patch.object(proof,'capture_replicas',return_value=fresh), patch.object(proof,'listed',side_effect=listed), \
                     patch.object(proof,'kubectl',return_value=b'{"groups":[]}'), patch.object(proof,'request_delete') as delete:
                    if mutation=='none':proof.storage_recovery_preflight(receipt,deadline=proof.time.monotonic()+1)
                    else:
                        with self.assertRaises(RuntimeError):proof.storage_recovery_preflight(receipt,deadline=proof.time.monotonic()+1)
                    delete.assert_not_called()

    def test_storage_recovery_alias_gate_allows_only_exact_old_project_and_backing(self):
        with tempfile.TemporaryDirectory(dir='/root') as temporary:
            envelope,old,new,buffers,value,chains,docs=stage_storage_recovery(Path(temporary),self.payload)
            receipt=MemoryReceipt();receipt.value=value
            for mutation in ('none','app','project','claim','backing'):
                project=copy.deepcopy(docs['project'])
                if mutation=='project':project['metadata']['uid']=uid(999)
                app=copy.deepcopy(docs['app'])
                foreign=copy.deepcopy(chains['grafana'][1]);foreign['metadata']['name']='foreign';foreign['metadata']['uid']=uid(999)
                def namespaced(kind,**kw):
                    if kind=='applications.argoproj.io':return [app] if mutation=='app' else []
                    if kind=='appprojects.argoproj.io':return [project]
                    return [chains['grafana'][0]] if mutation=='claim' else []
                with self.subTest(mutation=mutation), patch.object(proof,'all_namespaced',side_effect=namespaced), \
                     patch.object(proof,'root_current',return_value=docs['project']), \
                     patch.object(proof,'listed',return_value=[foreign] if mutation=='backing' else []):
                    if mutation=='none':proof.storage_recovery_alias_gate(receipt,deadline=proof.time.monotonic()+1)
                    else:
                        with self.assertRaises(RuntimeError):proof.storage_recovery_alias_gate(receipt,deadline=proof.time.monotonic()+1)

    def test_real_producer_binds_published_derivation_and_operation_without_git_metadata(self):
        self.assertEqual(set(self.payload['phases']), set(proof.PHASES))
        self.assertEqual([len(self.payload['phases'][phase]) for phase in proof.PHASES], [21, 21, 1])
        second = proof.prepare('fedcba9876543210')
        for phase in proof.PHASES:
            self.assertEqual(proof.normalized_objects(self.payload['phases'][phase], OPERATION, phase),
                             proof.normalized_objects(second['phases'][phase], second['operation'], phase))
        self.assertEqual(self.payload['source']['revision'], proof.REVISION)
        self.assertEqual(proof.validate_input(copy.deepcopy(self.payload), OPERATION), self.payload)

    def test_profile_hashes_reject_exec_mount_kind_namespace_and_owner_injection(self):
        for mutation in ('command', 'image', 'mount', 'owner', 'namespace', 'extra', 'foreign-reference', 'checksum'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(self.payload)
                objects = bad['phases']['running']
                workload = next(o for o in objects if o['kind'] == 'StatefulSet')
                pod = workload['spec']['template']['spec']
                if mutation == 'command': pod['containers'][0]['command'] = ['/bin/false']
                if mutation == 'image': pod['containers'][0]['image'] = 'untrusted:latest'
                if mutation == 'mount': pod.setdefault('volumes', []).append({'name': 'escape', 'hostPath': {'path': '/'}})
                if mutation == 'owner': workload['metadata']['labels'][proof.LABEL] = '0000000000000000'
                if mutation == 'namespace': workload['metadata']['namespace'] = 'default'
                if mutation == 'extra': objects.append({'kind': 'RoleBinding', 'metadata': {'name': 'x', 'namespace': proof.namespace(OPERATION)}})
                if mutation == 'foreign-reference': pod['serviceAccountName'] = 'obs-storage-1111111111111111-loki'
                if mutation == 'checksum': workload['spec']['template']['metadata']['annotations']['checksum/config'] = '0' * 64
                with self.assertRaises((RuntimeError, KeyError)):
                    proof.validate_input(bad, OPERATION)

    def test_closed_source_image_fields_and_duplicate_json_reject(self):
        for field, value in [('pythonImage', 'python:latest'), ('version', 2), ('operation', '1' * 16),
                             ('profile', 'unrestricted')]:
            bad = copy.deepcopy(self.payload)
            bad[field] = value
            with self.assertRaises(RuntimeError): proof.validate_input(bad, OPERATION)
        bad = copy.deepcopy(self.payload)
        bad['source']['revision'] = 'main'
        with self.assertRaises(RuntimeError): proof.validate_input(bad, OPERATION)
        with self.assertRaises(RuntimeError): proof.parsed(b'{"a":1,"a":2}')
        with self.assertRaises(RuntimeError): proof.parsed(b'{"a":NaN}')

    def test_marker_data_is_distinct_per_claim_operation_and_uid(self):
        receipt = MemoryReceipt()
        values = {component: proof.marker_content(receipt, component) for component in receipt.value['storage']}
        self.assertEqual(len(set(values.values())), 3)
        original = values['loki']
        receipt.value['storage']['loki']['identity']['claim']['uid'] = uid(99)
        self.assertNotEqual(proof.marker_content(receipt, 'loki'), original)
        receipt.operation = '1' * 16
        self.assertNotEqual(proof.marker_content(receipt, 'tempo'), values['tempo'])

    def test_marker_profile_has_only_one_claim_and_no_backend_selector_or_token(self):
        receipt = MemoryReceipt()
        for component in ('loki', 'tempo', 'grafana'):
            content = proof.marker_content(receipt, component)
            receipt.value['markers'][component] = {'content': content, 'sha256': proof.digest(content.encode()),
                'claimUID': receipt.value['storage'][component]['identity']['claim']['uid']}
            for mode in ('write', 'read'):
                document = proof.marker_document(receipt, self.payload, component, mode)
                spec = document['spec']
                self.assertFalse(spec['automountServiceAccountToken'])
                self.assertFalse(spec['enableServiceLinks'])
                self.assertEqual(spec['containers'][0]['command'][:3], ['python', '-c', proof.MARKER_PROGRAM])
                self.assertEqual(len(spec['volumes']), 1)
                self.assertEqual(spec['volumes'][0]['persistentVolumeClaim']['claimName'], proof.claim_names(OPERATION)[component])
                self.assertNotIn('app.kubernetes.io/name', document['metadata']['labels'])
                self.assertEqual(spec['securityContext']['runAsUser'], 472 if component == 'grafana' else 10001)
                self.assertEqual(bool(spec['containers'][0]['volumeMounts'][0].get('readOnly')), mode == 'read')
        receipt.value['markers']['loki']['content'] = '0' * 64
        with self.assertRaises(RuntimeError): proof.marker_document(receipt, self.payload, 'loki', 'write')

    def test_fixed_marker_program_exclusive_write_and_wrong_data_rejection(self):
        # Execute actual fixed source with only its fixed mount path redirected into an owned temp directory.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            code = proof.MARKER_PROGRAM.replace("'/state'", repr(str(directory)))
            leaf = '.cloudlab-storage-' + OPERATION
            def invoke(mode, data, filename=leaf):
                return subprocess.run([sys.executable, '-c', code, mode, filename, data], capture_output=True)
            result = invoke('write', 'a' * 64)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout), {'markerVerified': True, 'sha256': proof.digest(b'a' * 64)})
            self.assertNotEqual(invoke('write', 'b' * 64).returncode, 0)
            self.assertEqual(invoke('read', 'a' * 64).returncode, 0)
            self.assertNotEqual(invoke('read', 'b' * 64).returncode, 0)
            self.assertNotEqual(invoke('read', 'a' * 64, '../escape').returncode, 0)
            self.assertEqual((directory / leaf).read_bytes(), b'a' * 64)

    def test_native_defaults_do_not_grant_admission_added_execution_or_mounts(self):
        receipt = MemoryReceipt()
        content = proof.marker_content(receipt, 'loki')
        receipt.value['markers']['loki'] = {'content': content, 'sha256': proof.digest(content.encode()), 'claimUID': uid(1)}
        spec = proof.marker_document(receipt, self.payload, 'loki', 'write')['spec']
        native = native_marker_spec(spec)
        self.assertTrue(proof.admission_source(native, spec))
        for field, value in [('hostNetwork', True), ('initContainers', [{'name': 'extra'}]),
                             ('serviceAccountName', 'privileged'), ('nodeName', 'forced'), ('priority', 1),
                             ('priority', False), ('priorityClassName', 'system-cluster-critical'),
                             ('tolerations', native['tolerations'] + [{'operator': 'Exists'}]),
                             ('tolerations', [native['tolerations'][0] | {'tolerationSeconds': 301}, native['tolerations'][1]])]:
            bad = copy.deepcopy(native)
            bad[field] = value
            self.assertFalse(proof.admission_source(bad, spec))
        bad = copy.deepcopy(native)
        bad['containers'][0]['command'] = ['python', '-c', 'pass']
        self.assertFalse(proof.admission_source(bad, spec))

    def test_deletion_scope_never_crosses_claim_or_root_authority(self):
        receipt = MemoryReceipt()
        valid = receipt.value['storage']['loki']['identity']['claim']
        proof.deletion_scope(receipt, valid)
        for field, value in [('namespace', 'default'), ('name', 'real-data'), ('uid', uid(99))]:
            bad = copy.deepcopy(valid)
            bad[field] = value
            with self.assertRaises(RuntimeError): proof.deletion_scope(receipt, bad)
        with self.assertRaises(RuntimeError): proof.deletion_scope(receipt, valid | {'kind': 'Secret'})
        calls = []
        native = valid | {'metadata': {}}
        with patch.object(proof, 'kubectl', side_effect=lambda *a, **kw: calls.append(a)):
            obj = {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {
                'name': 'real-data', 'namespace': 'default', 'uid': uid(1), 'resourceVersion': '8'}}
            with self.assertRaises(RuntimeError): proof.request_delete(receipt, 'bad', obj, {})
        self.assertEqual(calls, [])

    def test_standalone_host_import_has_no_runner_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'proof.py'
            target.write_bytes(Path(proof.__file__).read_bytes())
            result = subprocess.run([sys.executable, '-I', str(target), '--help'], capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn(b'--cleanup', result.stdout)

    def test_fresh_storage_chain_rejects_old_foreign_restore_and_alias_data(self):
        receipt = MemoryReceipt()
        receipt.value['baseline'].update(boundary='2026-11-05T12:00:00+00:00', **{'class': {'uid': uid(91)},
            'pvs': {'uid': [], 'name': []}, 'volumes': {'uid': [], 'name': []}})
        chain = storage_chain(receipt)
        def inspect(items):
            claim, pv, volume = items
            with patch.object(proof, 'storage_class', return_value=receipt.value['baseline']['class']), \
                 patch.object(proof, 'get', side_effect=lambda kind, *a: pv if kind == 'pv' else volume):
                return proof.fresh_identity(receipt, claim)
        self.assertEqual(inspect(chain)['handle'], chain[1]['metadata']['name'])
        for mutation in ('old', 'foreign', 'owner', 'deleting', 'restore', 'clone', 'backing-image', 'alias', 'retain', 'uid'):
            with self.subTest(mutation=mutation):
                claim, pv, volume = copy.deepcopy(chain)
                if mutation == 'old': claim['metadata']['creationTimestamp'] = '2026-11-05T11:00:00Z'
                if mutation == 'foreign': claim['metadata']['labels'][proof.LABEL] = 'f' * 16
                if mutation == 'owner': claim['metadata']['ownerReferences'] = [{'uid': uid(99)}]
                if mutation == 'deleting': claim['metadata']['deletionTimestamp'] = '2026-11-05T12:01:00Z'
                if mutation == 'restore': volume['spec']['fromBackup'] = 'backup-url'
                if mutation == 'clone': claim['spec']['dataSource'] = {'name': 'old'}
                if mutation == 'backing-image': volume['spec']['backingImage'] = 'old'
                if mutation == 'alias': pv['spec']['csi']['volumeHandle'] = 'other-volume'
                if mutation == 'retain': pv['spec']['persistentVolumeReclaimPolicy'] = 'Delete'
                if mutation == 'uid': pv['spec']['claimRef']['uid'] = uid(88)
                with self.assertRaises(RuntimeError): inspect((claim, pv, volume))
        receipt.value['baseline']['volumes']['name'] = [proof.digest(chain[2]['metadata']['name'].encode())]
        with self.assertRaises(RuntimeError): inspect(chain)

    def test_capacity_and_incomplete_inventory_stop_before_writes(self):
        with patch.object(proof, 'listed', return_value=[]), patch.object(proof, 'kubectl') as native:
            with self.assertRaises(RuntimeError): proof.storage_baseline()
            native.assert_not_called()
        with patch.object(proof, 'get', return_value={'items': [], 'metadata': {'continue': 'more'}}):
            with self.assertRaises(RuntimeError): proof.listed('pv')

    def test_extra_claim_blocks_all_binding_authority(self):
        receipt = MemoryReceipt()
        claims = [storage_chain(receipt, component, index)[0] for index, component in enumerate(('loki', 'tempo', 'grafana'), 1)]
        claims.append(copy.deepcopy(claims[0]))
        claims[-1]['metadata']['name'] = 'unexpected-data'
        with patch.object(proof, 'listed', return_value=claims), patch.object(proof, 'fresh_identity') as identity:
            with self.assertRaises(RuntimeError): proof.bind_storage(receipt, fresh=True)
            identity.assert_not_called()

    def test_paired_backing_intents_durable_before_either_native_delete(self):
        receipt = MemoryReceipt()
        claim, pv, volume = storage_chain(receipt)
        identity = {'claim': proof.object_id(claim), 'pv': proof.object_id(pv), 'volume': proof.object_id(volume),
                    'handle': pv['metadata']['name']}
        receipt.value['storage']['loki'] = {'identity': identity, 'replicas': replica_rows()}
        with patch.object(proof, 'current', return_value=None), patch.object(proof, 'capture_replicas', return_value=replica_rows()), \
             patch.object(proof, 'backing_deletion_gate'), \
             patch.object(proof, 'kubectl') as native:
            proof.paired_intents(receipt, 'loki', pv, volume)
            native.assert_not_called()
        saved = receipt.saves[-1]['intents']
        self.assertEqual(set(saved), {'delete-pv-loki', 'delete-volume-loki'})
        self.assertTrue(all(not i['accepted'] and not i['complete'] for i in saved.values()))
        receipt.value['intents'].pop('delete-volume-loki')
        with patch.object(proof, 'current', return_value=None), patch.object(proof, 'capture_replicas', return_value=replica_rows()), \
             patch.object(proof, 'backing_deletion_gate'):
            with self.assertRaises(RuntimeError): proof.paired_intents(receipt, 'loki', pv, volume)

    def test_blocked_claim_does_not_authorize_other_volume_or_peer_delete(self):
        receipt = MemoryReceipt()
        claim, pv, volume = storage_chain(receipt)
        identity = {'claim': proof.object_id(claim), 'pv': proof.object_id(pv), 'volume': proof.object_id(volume),
                    'handle': pv['metadata']['name']}
        receipt.value['storage']['loki'] = {'identity': identity, 'replicas': replica_rows()}
        with patch.object(proof, 'current', return_value=claim), patch.object(proof, 'kubectl') as native:
            with self.assertRaises(RuntimeError): proof.paired_intents(receipt, 'loki', pv, volume)
            native.assert_not_called()
        self.assertFalse(receipt.value['intents'])
        for mutation in ('claimRef', 'handle', 'policy'):
            bad = copy.deepcopy(pv)
            if mutation == 'claimRef': bad['spec']['claimRef']['uid'] = uid(99)
            if mutation == 'handle': bad['spec']['csi']['volumeHandle'] = 'foreign'
            if mutation == 'policy': bad['spec']['persistentVolumeReclaimPolicy'] = 'Delete'
            with self.assertRaises(RuntimeError): proof.released_pv(receipt, identity, bad)

    def test_unsafe_replica_paths_and_changed_inspector_never_execute(self):
        for path in ('/var/lib/longhorn/replicas/../other', '/var/lib/longhorn/replicas/a;rm', '/etc'):
            row = copy.deepcopy(replica_rows()[0])
            row['path'] = path
            with patch.object(proof, 'kubectl') as native:
                with self.assertRaises(RuntimeError): proof.directory_state(row)
                native.assert_not_called()
        row = replica_rows()[0]
        with patch.object(proof, 'get', return_value={}), patch.object(proof, 'inspector_identity', return_value={'uid': uid(90)}), \
             patch.object(proof, 'kubectl') as native:
            with self.assertRaises(RuntimeError): proof.directory_state(row)
            native.assert_not_called()

    def test_recreated_resource_stops_exact_deletion(self):
        receipt = MemoryReceipt()
        claim = storage_chain(receipt)[0]
        identity = proof.object_id(claim)
        replacement = copy.deepcopy(claim)
        replacement['metadata']['uid'] = uid(90)
        with patch.object(proof, 'get', return_value=replacement):
            with self.assertRaises(RuntimeError): proof.current(identity)

    def test_backing_alias_attachment_and_external_snapshot_block_native_deletion(self):
        receipt = MemoryReceipt()
        claim, pv, volume = storage_chain(receipt)
        volume['status']['state'] = 'detached'
        identity = {'claim': proof.object_id(claim), 'pv': proof.object_id(pv), 'volume': proof.object_id(volume),
                    'handle': pv['metadata']['name']}
        for case in ('valid', 'pv-alias', 'csi-attachment', 'native-ticket', 'external-snapshot'):
            alias = copy.deepcopy(pv)
            alias['metadata']['uid'] = uid(99)
            def inventory(kind, *unused):
                if kind == 'pv': return [pv, alias] if case == 'pv-alias' else [pv]
                if kind == 'volumeattachments.storage.k8s.io' and case == 'csi-attachment':
                    return [{'spec': {'source': {'persistentVolumeName': pv['metadata']['name']}}}]
                if kind == 'volumeattachments.longhorn.io' and case == 'native-ticket':
                    return [{'spec': {'volume': identity['handle'], 'attachmentTickets': {'foreign': {}}}}]
                if kind == 'volumesnapshotcontents.snapshot.storage.k8s.io' and case == 'external-snapshot':
                    return [{'spec': {'source': {'volumeHandle': identity['handle']}}}]
                return []
            with self.subTest(case=case), patch.object(proof, 'listed', side_effect=inventory), \
                 patch.object(proof, 'kubectl', return_value=b'{"groups":[{"name":"snapshot.storage.k8s.io"}]}'):
                if case == 'valid': proof.backing_deletion_gate(identity, volume)
                else:
                    with self.assertRaises(RuntimeError): proof.backing_deletion_gate(identity, volume)

    def test_interrupted_phase_accepts_only_recorded_exact_input_at_recorded_uid(self):
        receipt = MemoryReceipt()
        receipt.value['appPhase'] = 'running'
        app = proof.root_documents(receipt.operation)[2]
        app['metadata'].update(uid=uid(77), resourceVersion='8')
        receipt.value['objects']['app'] = proof.object_id(app)
        receipt.value['pendingAdvance'] = {'key': 'phase-0', 'identity': proof.object_id(app), 'from': 'running',
            'to': 'scaled-down', 'previous': copy.deepcopy(app['spec']), 'desired': copy.deepcopy(app['spec'])}
        receipt.value['pendingAdvance']['desired']['source']['helm']['valuesObject']['phase'] = 'scaled-down'
        app['spec'] = copy.deepcopy(receipt.value['pendingAdvance']['desired'])
        with patch.object(proof, 'root_current', return_value=app), patch.object(proof, 'kubectl') as native:
            proof.advance(receipt, 'scaled-down')
            native.assert_not_called()
        self.assertEqual(receipt.value['appPhase'], 'scaled-down')
        self.assertTrue(receipt.value['intents']['phase-0']['accepted'])
        self.assertNotIn('pendingAdvance', receipt.value)
        app['spec']['source']['targetRevision'] = 'main'
        with patch.object(proof, 'root_current', return_value=app):
            with self.assertRaises(RuntimeError): proof.advance(receipt, 'removed')

    def test_current_readiness_does_not_require_historical_sync_operation(self):
        receipt = MemoryReceipt()
        app = proof.root_documents(receipt.operation)[2]
        app['metadata'].update(uid=uid(77), resourceVersion='8')
        app['status'] = {'sync': {'status': 'Synced', 'revision': proof.REVISION,
            'comparedTo': {'source': copy.deepcopy(app['spec']['source']), 'destination': app['spec']['destination']}},
            'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded', 'syncResult': {'source': {'old': True}}}}
        with patch.object(proof, 'app_current', return_value=app):
            self.assertTrue(proof.converged(receipt, 'running'))
            app['status']['sync']['comparedTo']['source']['helm']['valuesObject']['phase'] = 'removed'
            self.assertFalse(proof.converged(receipt, 'running'))

    def test_known_marker_resume_finishes_recorded_deletion_without_recreating_or_overwriting(self):
        receipt = MemoryReceipt()
        content = proof.marker_content(receipt, 'loki')
        receipt.value['markers']['loki'] = {'content': content, 'sha256': proof.digest(content.encode()), 'claimUID': uid(1)}
        doc = proof.marker_document(receipt, self.payload, 'loki', 'write')
        marker = copy.deepcopy(doc)
        marker['metadata'].update(uid=uid(81), resourceVersion='8')
        identity = proof.object_id(marker)
        receipt.value['objects']['marker-0'] = identity
        receipt.value['markerRuns'] = [{'component': 'loki', 'mode': 'write', 'document': proof.digest(proof.canonical(doc)),
            'admittedSpec': native_marker_spec(doc['spec']), 'accepted': True, 'complete': False,
            'verifiedIO': {'identity': identity, 'document': proof.digest(proof.canonical(doc)), 'mode': 'write',
                'claimUID': uid(1), 'sha256': receipt.value['markers']['loki']['sha256'], 'finishedAt': '2026-11-05T12:01:00Z'}}]
        receipt.value['intents']['delete-marker-0'] = {'identity': identity, 'accepted': True, 'complete': False}
        with patch.object(proof, 'marker_claim'), patch.object(proof, 'app_current'), patch.object(proof, 'project_guard'), \
             patch.object(proof, 'workload_pods', return_value=[]), patch.object(proof, 'detached', return_value=True), \
             patch.object(proof, 'get', return_value={'secrets': []}), patch.object(proof, 'finish_delete') as finish, \
             patch.object(proof, 'kubectl') as native:
            proof.marker_io(receipt, self.payload, 'loki', 'write', proof.time.monotonic() + 1)
            finish.assert_called_once()
            native.assert_not_called()
        self.assertTrue(receipt.value['markerRuns'][0]['complete'])

    def test_unaccepted_marker_identity_is_never_adopted_on_resume(self):
        receipt = MemoryReceipt()
        content = proof.marker_content(receipt, 'loki')
        receipt.value['markers']['loki'] = {'content': content, 'sha256': proof.digest(content.encode()), 'claimUID': uid(1)}
        doc = proof.marker_document(receipt, self.payload, 'loki', 'write')
        receipt.value['markerRuns'] = [{'component': 'loki', 'mode': 'write', 'document': proof.digest(proof.canonical(doc)),
            'admittedSpec': doc['spec'], 'accepted': False, 'complete': False}]
        with patch.object(proof, 'marker_claim'), patch.object(proof, 'app_current'), patch.object(proof, 'project_guard'), \
             patch.object(proof, 'workload_pods', return_value=[]), patch.object(proof, 'get', return_value={'secrets': []}), \
             patch.object(proof, 'kubectl') as native:
            with self.assertRaises(RuntimeError): proof.marker_io(receipt, self.payload, 'loki', 'write', proof.time.monotonic() + 1)
            native.assert_not_called()

    def test_published_tempo_native_tcp_defaults_preserve_explicit_protocols_and_port_authority(self):
        document = next(obj for obj in self.payload['phases']['running']
                        if obj['kind'] == 'StatefulSet' and obj['metadata']['name'] == proof.namespace(OPERATION) + '-tempo')
        expected = document['spec']['template']['spec']
        source_ports = expected['containers'][0]['ports']
        omitted = next(index for index, port in enumerate(source_ports) if 'protocol' not in port)
        udp = next(index for index, port in enumerate(source_ports) if port.get('protocol') == 'UDP')
        native = copy.deepcopy(document)
        actual = native['spec']['template']['spec']
        for port in actual['containers'][0]['ports']: port.setdefault('protocol', 'TCP')
        self.assertTrue(proof.admitted_document(native, document))
        self.assertEqual(actual['containers'][0]['ports'][udp]['protocol'], 'UDP')
        explicit = copy.deepcopy(document)
        explicit['spec']['template']['spec']['containers'][0]['ports'][omitted]['protocol'] = 'TCP'
        self.assertTrue(proof.admitted_document(native, explicit))
        for mutation in ('non-tcp-default', 'explicit-udp', 'number', 'name', 'extra-field', 'extra-port', 'missing-port'):
            changed = copy.deepcopy(native)
            ports = changed['spec']['template']['spec']['containers'][0]['ports']
            if mutation == 'non-tcp-default': ports[omitted]['protocol'] = 'UDP'
            if mutation == 'explicit-udp': ports[udp]['protocol'] = 'TCP'
            if mutation == 'number': ports[omitted]['containerPort'] += 1
            if mutation == 'name': ports[omitted]['name'] = 'changed'
            if mutation == 'extra-field': ports[omitted]['hostPort'] = 8080
            if mutation == 'extra-port': ports.append({'name': 'extra', 'containerPort': 12345, 'protocol': 'TCP'})
            if mutation == 'missing-port': ports.pop()
            with self.subTest(mutation=mutation):
                self.assertFalse(proof.admitted_document(changed, document))
        changed = copy.deepcopy(native)
        changed['spec']['template']['spec']['containers'][0]['ports'][omitted]['protocol'] = 'UDP'
        self.assertFalse(proof.admitted_document(changed, explicit))

    def test_all_phase_admission_rejects_data_retention_config_and_service_mutation(self):
        for document in self.payload['phases']['running']:
            native = native_secret(document) if document['kind'] == 'Secret' else copy.deepcopy(document)
            self.assertTrue(proof.admitted_document(native, document), document['kind'])
        examples = {kind: next(o for o in self.payload['phases']['running'] if o['kind'] == kind)
                    for kind in ('PersistentVolumeClaim', 'StatefulSet', 'ConfigMap', 'Service')}
        for mutation in ('restore', 'prebound', 'retention', 'config', 'service', 'owner'):
            kind = {'restore': 'PersistentVolumeClaim', 'retention': 'StatefulSet', 'config': 'ConfigMap',
                    'service': 'Service', 'owner': 'PersistentVolumeClaim', 'prebound': 'PersistentVolumeClaim'}[mutation]
            document = examples[kind]
            bad = copy.deepcopy(document)
            if mutation == 'restore': bad['spec']['dataSource'] = {'name': 'private-data'}
            if mutation == 'prebound': bad['spec']['volumeName'] = 'foreign-volume'
            if mutation == 'retention': bad['spec']['persistentVolumeClaimRetentionPolicy'] = {'whenDeleted': 'Delete', 'whenScaled': 'Delete'}
            if mutation == 'config': bad['data']['injected'] = 'changed'
            if mutation == 'service': bad['spec']['type'] = 'LoadBalancer'
            if mutation == 'owner': bad['metadata']['ownerReferences'] = [{'uid': uid(99)}]
            self.assertFalse(proof.admitted_document(bad, document), mutation)
        service = examples['Service']
        native = copy.deepcopy(service)
        native['spec'].update(sessionAffinity='None', internalTrafficPolicy='Cluster', ipFamilyPolicy='SingleStack', ipFamilies=['IPv4'])
        if native['spec'].get('clusterIP') == 'None': native['spec']['clusterIPs'] = ['None']
        self.assertTrue(proof.admitted_document(native, service))

    def test_runtime_pod_authority_allows_only_native_scheduler_defaults(self):
        receipt = MemoryReceipt()
        content = proof.marker_content(receipt, 'loki')
        receipt.value['markers']['loki'] = {'content': content, 'sha256': proof.digest(content.encode()), 'claimUID': uid(1)}
        spec = proof.marker_document(receipt, self.payload, 'loki', 'write')['spec']
        actual = copy.deepcopy(spec)
        actual.update(nodeName='node-a', priority=0, tolerations=[{
            'key': 'node.kubernetes.io/' + key, 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300}
            for key in ('not-ready', 'unreachable')])
        self.assertTrue(proof.source_spec(actual, spec))
        for field, value in [('imagePullSecrets', [{'name': 'private'}]), ('dnsConfig', {'nameservers': ['1.1.1.1']}),
                             ('hostAliases', [{'ip': '1.1.1.1', 'hostnames': ['private']}]), ('priorityClassName', 'system-cluster-critical')]:
            bad = copy.deepcopy(actual)
            bad[field] = value
            self.assertFalse(proof.source_spec(bad, spec), field)

    def test_current_archive_provenance_cannot_use_arbitrary_difference(self):
        from playbooks.observability.tests import storage_fixture
        lock = json.loads((storage_fixture.FIXTURE / 'derivation.lock.json').read_bytes())
        lock['sources']['prometheus']['sha256'] = 'f' * 64
        with patch.object(storage_fixture, 'build', return_value={'derivation.lock.json': json.dumps(lock).encode()}):
            with self.assertRaises(RuntimeError): proof.prepare(OPERATION)

    def test_cleanup_resume_uses_retention_evidence_then_only_recorded_remaining_claims(self):
        for foreign in (False, True):
            receipt = MemoryReceipt()
            roots = {}
            for index, (key, doc) in enumerate(zip(('namespace', 'project', 'app'), proof.root_documents(receipt.operation)), 80):
                doc['metadata'].update(uid=uid(index), resourceVersion='8')
                roots[key] = doc
                receipt.value['objects'][key] = proof.object_id(doc)
            receipt.value['intents']['delete-app'] = {'accepted': True, 'complete': True}
            receipt.value['evidence']['cascadeRetainedClaims'] = True
            remaining = []
            for index, component in enumerate(('loki', 'tempo', 'grafana'), 1):
                claim, pv, volume = storage_chain(receipt, component, index)
                receipt.value['storage'][component] = {'identity': {'claim': proof.object_id(claim), 'pv': proof.object_id(pv),
                    'volume': proof.object_id(volume), 'handle': pv['metadata']['name']}, 'replicas': replica_rows()}
                if component != 'loki': remaining.append(claim)
            if foreign: remaining[0]['metadata']['uid'] = uid(99)
            def native_current(identity):
                return next((obj for key, obj in roots.items() if key != 'app' and proof.object_id(obj) == identity), None)
            def delete_intent(record, key, obj, scope):
                record.value['intents'][key] = {'accepted': True, 'complete': False, 'identity': proof.object_id(obj)}
            def cleaned(record, component, deadline, *, payload):
                if component == 'grafana': remaining.clear()
            with self.subTest(foreign=foreign), patch.object(proof, 'current', side_effect=native_current), \
                 patch.object(proof, 'root_current', side_effect=lambda r, k: roots[k]), patch.object(proof, 'cleanup_markers'), \
                 patch.object(proof, 'housekeeping'), \
                 patch.object(proof, 'workload_pods', return_value=[]), patch.object(proof, 'listed', side_effect=lambda *a: list(remaining)), \
                 patch.object(proof, 'inventory_gate'), patch.object(proof, 'project_guard'), \
                 patch.object(proof, 'request_delete', side_effect=delete_intent), patch.object(proof, 'finish_delete'), \
                 patch.object(proof, 'cleanup_storage', side_effect=cleaned) as storage:
                if foreign:
                    with self.assertRaises(RuntimeError): proof.cleanup(receipt, self.payload, proof.time.monotonic() + 1)
                    storage.assert_not_called()
                else:
                    proof.cleanup(receipt, self.payload, proof.time.monotonic() + 1)
                    self.assertEqual([call.args[1] for call in storage.call_args_list], ['loki', 'tempo', 'grafana'])
                    self.assertTrue(receipt.value['cleanupComplete'])

    def test_surviving_pv_after_native_cascade_is_revalidated_before_delete(self):
        receipt = MemoryReceipt()
        claim, pv, volume = storage_chain(receipt)
        identity = {'claim': proof.object_id(claim), 'pv': proof.object_id(pv), 'volume': proof.object_id(volume),
                    'handle': pv['metadata']['name']}
        receipt.value['storage']['loki'] = {'identity': identity, 'replicas': replica_rows()}
        for key, obj, accepted in [('delete-claim-loki', claim, True), ('delete-pv-loki', pv, False), ('delete-volume-loki', volume, True)]:
            receipt.value['intents'][key] = {'identity': proof.object_id(obj), 'accepted': accepted, 'complete': accepted}
        pv['status']['phase'] = 'Bound'
        with patch.object(proof, 'current', side_effect=lambda obj: pv if obj == identity['pv'] else None), \
             patch.object(proof, 'request_delete') as delete:
            with self.assertRaises(RuntimeError): proof.cleanup_storage(receipt, 'loki', proof.time.monotonic() + 1)
            delete.assert_not_called()

    def test_running_attachments_bind_all_three_claims_to_exact_native_and_csi_objects(self):
        receipt = MemoryReceipt()
        receipt.value['appPhase'] = 'running'
        csi, native = [], []
        for index, component in enumerate(('loki', 'tempo', 'grafana'), 1):
            claim, pv, volume = storage_chain(receipt, component, index)
            receipt.value['storage'][component] = {'identity': {'claim': proof.object_id(claim), 'pv': proof.object_id(pv),
                'volume': proof.object_id(volume), 'handle': pv['metadata']['name']}}
            csi.append({'apiVersion': 'storage.k8s.io/v1', 'kind': 'VolumeAttachment', 'metadata': {
                'name': 'csi-' + component, 'uid': uid(100 + index), 'resourceVersion': '8'},
                'spec': {'source': {'persistentVolumeName': pv['metadata']['name']}, 'attacher': 'driver.longhorn.io',
                         'nodeName': 'node-a'}, 'status': {'attached': True}})
            native.append({'apiVersion': 'longhorn.io/v1beta2', 'kind': 'VolumeAttachment', 'metadata': {
                'name': pv['metadata']['name'], 'namespace': 'longhorn-system', 'uid': uid(110 + index), 'resourceVersion': '8'},
                'spec': {'volume': pv['metadata']['name']}})
        with patch.object(proof, 'listed', side_effect=lambda kind, *a: csi if kind.startswith('volumeattachments.storage') else native):
            proof.record_attachments(receipt, healthy=True)
            self.assertTrue(all(len(row['attachments'][0]['objects']) == 2 for row in receipt.value['storage'].values()))
            csi[1]['status']['attached'] = False
            with self.assertRaises(RuntimeError): proof.record_attachments(receipt, healthy=True)

    def test_receipt_atomicity_context_and_protected_file_boundaries(self):
        with tempfile.TemporaryDirectory(dir='/root', prefix='obs-csi-receipt-') as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            receipt = proof.Receipt(parent / 'state', OPERATION, self.payload)
            original = receipt.path.read_bytes()
            receipt.value['phase'] = 'changed'
            with patch.object(proof.os, 'replace', side_effect=OSError('synthetic interrupted rename')):
                with self.assertRaises(OSError): receipt.save()
            self.assertEqual(receipt.path.read_bytes(), original)
            self.assertEqual([p.name for p in (parent / 'state').iterdir()], ['receipt.json'])
            changed = copy.deepcopy(self.payload)
            changed['operation'] = 'f' * 16
            with self.assertRaises(RuntimeError): proof.Receipt(parent / 'state', OPERATION, changed, resume=True)
            link = parent / 'link'
            link.symlink_to(receipt.path)
            with self.assertRaises(OSError): proof.protected_bytes(link)
            hardlink = parent / 'hardlink'
            os.link(receipt.path, hardlink)
            with self.assertRaises(RuntimeError): proof.protected_bytes(receipt.path)

    def test_delete_refreshes_idle_application_status_without_changing_authority(self):
        for mutation in ('status', 'uid', 'spec', 'metadata', 'scope', 'running', 'unknown-phase', 'storage-status', 'missing'):
            with self.subTest(mutation=mutation):
                receipt = MemoryReceipt()
                obj = proof.root_documents(receipt.operation)[2]
                obj['metadata'].update(uid=uid(81), resourceVersion='8')
                obj['status'] = {'reconciledAt': 'old', 'operationState': {'phase': 'Succeeded'}}
                key = 'delete-app'
                identity = proof.object_id(obj)
                receipt.value['objects']['app'] = identity
                scope = {'source': self.payload['source'], 'app': identity}
                if mutation == 'storage-status':
                    claim, pv, obj = storage_chain(receipt)
                    obj['status']['state'] = 'detached'
                    row = {'claim': proof.object_id(claim), 'pv': proof.object_id(pv),
                           'volume': proof.object_id(obj), 'handle': pv['metadata']['name']}
                    receipt.value['storage']['loki']['identity'] = row
                    key, identity = 'delete-volume-loki', proof.object_id(obj)
                    scope = {'profile': proof.PROFILE, 'operation': receipt.operation, 'component': 'loki',
                             'identity': row, 'replicas': replica_rows()}
                fresh = copy.deepcopy(obj)
                fresh['metadata']['resourceVersion'] = '9'
                if mutation != 'storage-status': fresh['status']['reconciledAt'] = 'new'
                if mutation == 'uid': fresh['metadata']['uid'] = uid(99)
                if mutation == 'spec': fresh['spec']['project'] = 'unapproved-project'
                if mutation == 'metadata': fresh['metadata']['labels']['cloudlab.io/owner'] = 'unapproved-owner'
                if mutation == 'running': fresh['status']['operationState']['phase'] = 'Running'
                if mutation == 'unknown-phase': fresh['status']['operationState']['phase'] = 'Unknown'
                if mutation == 'storage-status': fresh['status']['state'] = 'attached'
                if mutation == 'scope':
                    receipt.intention(key, identity, scope)
                    scope = scope | {'source': scope['source'] | {'revision': 'f' * 40}}
                if mutation == 'missing': fresh = None

                with patch.object(proof, 'get', return_value=fresh) as read, patch.object(proof, 'kubectl', return_value=b'') as native:
                    if mutation == 'status':
                        proof.request_delete(receipt, key, obj, scope)
                        options = proof.parsed(native.call_args.kwargs['body'])
                        self.assertEqual(options['preconditions'], {'uid': identity['uid'], 'resourceVersion': '9'})
                        self.assertEqual(receipt.value['intents'][key]['resourceVersion'], '9')
                        self.assertTrue(receipt.value['intents'][key]['accepted'])
                        proof.request_delete(receipt, key, obj, scope)
                        self.assertEqual(read.call_count, 1)
                        native.assert_called_once()
                        receipt.value['intents'][key]['complete'] = True
                        with self.assertRaisesRegex(RuntimeError, 'Completed deletion target reappeared'):
                            proof.request_delete(receipt, key, obj, scope)
                        native.assert_called_once()
                    else:
                        message = {'uid': 'Recorded resource replaced', 'scope': 'Mutation scope changed',
                                   'running': 'Application is not idle', 'unknown-phase': 'Application is not idle',
                                   'missing': 'Deletion target absent'}.get(mutation, 'Deletion target authority changed')
                        with self.assertRaisesRegex(RuntimeError, message):
                            proof.request_delete(receipt, key, obj, scope)
                        native.assert_not_called()
                        if mutation != 'scope': self.assertNotIn(key, receipt.value['intents'])

    def test_private_first_failure_capture_preserves_original_error_and_protected_tree(self):
        with tempfile.TemporaryDirectory(dir='/root', prefix='obs-csi-failure-') as temporary:
            root = Path(temporary)
            parent = root / ('observability-storage-' + OPERATION)
            parent.mkdir(mode=0o700)
            receipt = proof.Receipt(parent / 'state', OPERATION, self.payload)
            original = receipt.path.read_bytes()
            driver = Path(proof.__file__).read_bytes()
            for name, raw in {'proof.py': driver, 'input.json': proof.canonical(self.payload), 'operation.lock': b''}.items():
                (parent / name).write_bytes(raw)
                (parent / name).chmod(0o600)
            self.assertEqual(len(proof.original_tree(parent)[0]), 6)
            arguments = ['proof.py', '--run', '--directory', str(receipt.directory), '--input', str(parent / 'input.json'),
                         '--operation', OPERATION, '--driver-hash', proof.digest(driver)]
            private_local = 'local-value-not-for-diagnostics'

            def fail(*unused):
                local_value = private_local
                return proof.command(['fixture-native-command'])

            result = subprocess.CompletedProcess(['fixture-native-command'], 23,
                b'private-stdout-not-for-diagnostics', b'fixture-native-error')
            failure = receipt.directory / 'failure.json'
            with patch.object(proof, 'ROOT', root), patch.object(sys, 'argv', arguments), \
                 patch.object(proof, 'run', side_effect=fail) as run, \
                 patch.object(proof.subprocess, 'run', return_value=result), \
                 patch.object(sys, 'stdout', new_callable=io.StringIO) as output:
                with self.assertRaisesRegex(RuntimeError, 'Native command failed'):
                    proof.main()
                first = proof.protected_bytes(failure)
                recorded = proof.parsed(first)
                self.assertEqual(recorded['context'], receipt.value['context'])
                self.assertEqual(recorded['errorType'], 'RuntimeError')
                self.assertEqual(recorded['nativeCommand'],
                    {'exitCode': 23, 'stderr': 'fixture-native-error', 'stderrTruncated': False})
                self.assertIn('command', recorded['traceback'])
                self.assertNotIn(private_local.encode(), first)
                self.assertNotIn(result.stdout, first)
                self.assertEqual(failure.stat().st_mode & 0o777, 0o600)
                self.assertEqual(proof.original_tree(parent)[1]['state/failure.json'], first)
                self.assertEqual(receipt.path.read_bytes(), original)

                run.side_effect = ValueError('later fixture failure')
                with self.assertRaisesRegex(ValueError, 'later fixture failure'):
                    proof.main()
                self.assertEqual(proof.protected_bytes(failure), first)

                failure.unlink()
                with self.assertRaisesRegex(ValueError, 'later fixture failure'):
                    proof.main()
                self.assertNotIn('nativeCommand', proof.parsed(proof.protected_bytes(failure)))

                failure.unlink()
                sentinel = root / 'sentinel'
                sentinel.write_bytes(b'untouched')
                failure.symlink_to(sentinel)
                with self.assertRaisesRegex(ValueError, 'later fixture failure'):
                    proof.main()
                self.assertTrue(failure.is_symlink())
                self.assertEqual(sentinel.read_bytes(), b'untouched')

                failure.unlink()
                with patch.object(proof, 'atomic_json', side_effect=OSError('fixture diagnostic write failure')):
                    with self.assertRaisesRegex(ValueError, 'later fixture failure'):
                        proof.main()
                self.assertFalse(failure.exists())
                self.assertEqual(output.getvalue(), '')
                self.assertEqual(receipt.path.read_bytes(), original)

    def test_unknown_project_blocks_root_only_cleanup_before_any_deletion(self):
        receipt = MemoryReceipt()
        receipt.value['storage'] = {}
        ns = proof.root_documents(receipt.operation)[0]
        ns['metadata'].update(uid=uid(81), resourceVersion='8')
        receipt.value['objects']['namespace'] = proof.object_id(ns)
        with patch.object(proof, 'get', side_effect=lambda kind, *a: {'unknown': True} if kind == 'AppProject' else None), \
             patch.object(proof, 'request_delete') as deletion:
            with self.assertRaises(RuntimeError): proof.cleanup(receipt, self.payload, proof.time.monotonic() + 1)
            deletion.assert_not_called()

    def test_readonly_inspection_records_replica_inode_and_rejects_device_change(self):
        row = replica_rows()[0]
        with patch.object(proof, 'get', return_value={}), patch.object(proof, 'inspector_identity', return_value=row['inspector']), \
             patch.object(proof, 'kubectl', return_value=b'1:2\n1:3\n1:4\npresent\n') as native:
            self.assertEqual(proof.directory_state(row), row['context'])
            self.assertNotIn('rm', native.call_args.args)
        with patch.object(proof, 'get', return_value={}), patch.object(proof, 'inspector_identity', return_value=row['inspector']), \
             patch.object(proof, 'kubectl', return_value=b'1:2\n1:3\n2:4\npresent\n'):
            with self.assertRaises(RuntimeError): proof.directory_state(row)

    def test_replaced_marker_claim_stops_before_pod_or_io_actions(self):
        receipt = MemoryReceipt()
        replacement = storage_chain(receipt)[0]
        replacement['metadata']['uid'] = uid(99)
        with patch.object(proof, 'get', return_value=replacement), patch.object(proof, 'kubectl') as native:
            with self.assertRaises(RuntimeError):
                proof.marker_io(receipt, self.payload, 'loki', 'write', proof.time.monotonic() + 1)
            native.assert_not_called()

    def test_marker_dry_run_defaults_reach_verified_io_before_deletion(self):
        for mutation in ('resource-version', 'uid', 'spec'):
            with self.subTest(mutation=mutation):
                receipt = MemoryReceipt()
                content = proof.marker_content(receipt, 'loki')
                receipt.value['markers']['loki'] = {'content': content, 'sha256': proof.digest(content.encode()), 'claimUID': uid(1)}
                document = proof.marker_document(receipt, self.payload, 'loki', 'write')
                admitted = copy.deepcopy(document)
                admitted['spec'] = native_marker_spec(document['spec'])
                pod = copy.deepcopy(admitted)
                pod['metadata'].update(uid=uid(81), resourceVersion='8')
                pod['spec']['nodeName'] = 'node-a'
                pod['status'] = {'phase': 'Succeeded', 'containerStatuses': [{'name': 'marker', 'restartCount': 0,
                    'state': {'terminated': {'exitCode': 0, 'finishedAt': '2026-11-05T12:01:00Z'}}}]}
                fresh = copy.deepcopy(pod)
                fresh['metadata']['resourceVersion'] = '9'
                if mutation == 'uid': fresh['metadata']['uid'] = uid(99)
                if mutation == 'spec': fresh['spec']['containers'][0]['command'] = ['python', '-c', 'pass']
                state = {'reads': 0, 'deleted': False}

                def get(kind, *unused):
                    if kind == 'pod': return None
                    if kind == 'serviceaccount': return {'kind': 'ServiceAccount'}
                    self.assertEqual(kind, 'pods')
                    if state['deleted']: return None
                    state['reads'] += 1
                    return copy.deepcopy(pod if state['reads'] == 1 else fresh)

                def native(*arguments, **options):
                    if arguments[0] == 'create':
                        return proof.canonical(admitted if '--dry-run=server' in arguments else pod)
                    if arguments[0] == 'logs':
                        return proof.canonical({'markerVerified': True, 'sha256': receipt.value['markers']['loki']['sha256']})
                    self.assertEqual(arguments[0], 'delete')
                    evidence = receipt.value['markerRuns'][0]['verifiedIO']
                    self.assertEqual(evidence, receipt.saves[-1]['markerRuns'][0]['verifiedIO'])
                    self.assertEqual(evidence['identity'], proof.object_id(pod))
                    self.assertEqual(evidence['sha256'], receipt.value['markers']['loki']['sha256'])
                    self.assertEqual(proof.parsed(options['body'])['preconditions'], {'uid': uid(81), 'resourceVersion': '9'})
                    state['deleted'] = True
                    return b''

                with patch.object(proof, 'marker_claim'), patch.object(proof, 'app_current'), patch.object(proof, 'project_guard'), \
                     patch.object(proof, 'workload_pods', return_value=[]), patch.object(proof, 'detached', return_value=True), \
                     patch.object(proof, 'get', side_effect=get), patch.object(proof, 'kubectl', side_effect=native):
                    if mutation == 'resource-version':
                        proof.marker_io(receipt, self.payload, 'loki', 'write', proof.time.monotonic() + 1)
                        self.assertTrue(receipt.value['markerRuns'][0]['complete'])
                    else:
                        message = 'Recorded resource replaced' if mutation == 'uid' else 'Marker source or ownership changed'
                        with self.assertRaisesRegex(RuntimeError, message):
                            proof.marker_io(receipt, self.payload, 'loki', 'write', proof.time.monotonic() + 1)
                    self.assertEqual(state['deleted'], mutation == 'resource-version')

    def test_unverified_marker_deletion_cannot_resume_as_successful_io(self):
        receipt = MemoryReceipt()
        content = proof.marker_content(receipt, 'loki')
        receipt.value['markers']['loki'] = {'content': content, 'sha256': proof.digest(content.encode()), 'claimUID': uid(1)}
        document = proof.marker_document(receipt, self.payload, 'loki', 'read')
        pod = copy.deepcopy(document)
        pod['metadata'].update(uid=uid(81), resourceVersion='8')
        identity = proof.object_id(pod)
        receipt.value['objects']['marker-0'] = identity
        receipt.value['markerRuns'] = [{'component': 'loki', 'mode': 'read', 'document': proof.digest(proof.canonical(document)),
            'admittedSpec': native_marker_spec(document['spec']), 'accepted': True, 'complete': True}]
        receipt.value['intents']['delete-marker-0'] = {'identity': identity, 'accepted': True, 'complete': True}
        with patch.object(proof, 'marker_claim'), patch.object(proof, 'app_current'), patch.object(proof, 'project_guard'), \
             patch.object(proof, 'workload_pods', return_value=[]), patch.object(proof, 'get', return_value={'kind': 'ServiceAccount'}), \
             patch.object(proof, 'finish_delete') as finish, patch.object(proof, 'kubectl') as native:
            with self.assertRaisesRegex(RuntimeError, 'verified I/O'):
                proof.marker_io(receipt, self.payload, 'loki', 'read', proof.time.monotonic() + 1)
            finish.assert_not_called()
            native.assert_not_called()

    def test_failed_read_cleanup_is_safe_but_terminal_even_if_interrupted_before_app_delete(self):
        receipt = MemoryReceipt()
        receipt.value['appPhase'] = 'removed'
        content = proof.marker_content(receipt, 'loki')
        receipt.value['markers']['loki'] = {'content': content, 'sha256': proof.digest(content.encode()), 'claimUID': uid(1)}
        document = proof.marker_document(receipt, self.payload, 'loki', 'read')
        pod = copy.deepcopy(document)
        pod['spec'] = native_marker_spec(document['spec'])
        pod['spec']['nodeName'] = 'node-a'
        pod['metadata'].update(uid=uid(81), resourceVersion='8')
        pod['status'] = {'phase': 'Failed', 'containerStatuses': [{'name': 'marker', 'restartCount': 0,
            'state': {'terminated': {'exitCode': 1, 'finishedAt': '2026-11-05T12:01:00Z'}}}]}
        identity = proof.object_id(pod)
        receipt.value['objects']['marker-0'] = identity
        receipt.value['markerRuns'] = [{'component': 'loki', 'mode': 'read', 'document': proof.digest(proof.canonical(document)),
            'admittedSpec': native_marker_spec(document['spec']), 'accepted': True, 'complete': False}]
        roots = {}
        for index, (key, doc) in enumerate(zip(('namespace', 'project', 'app'), proof.root_documents(receipt.operation)), 90):
            doc['metadata'].update(uid=uid(index), resourceVersion='8')
            roots[key] = doc
            receipt.value['objects'][key] = proof.object_id(doc)
        for row in receipt.value['storage'].values(): row['replicas'] = replica_rows()
        state = {'pod': pod}
        def current(identity):
            if identity == proof.object_id(pod): return state['pod']
            return next((obj for obj in roots.values() if proof.object_id(obj) == identity), None)
        def native(*arguments, **unused):
            self.assertEqual(arguments[0], 'delete')
            self.assertTrue(receipt.value['cleanupStarted'])
            state['pod'] = None
            return b''
        original_delete = proof.request_delete
        def delete(record, key, obj, scope):
            if key == 'delete-app': raise RuntimeError('synthetic interruption before App deletion')
            return original_delete(record, key, obj, scope)
        with patch.object(proof, 'marker_claim'), patch.object(proof, 'app_current'), patch.object(proof, 'project_guard'), \
             patch.object(proof, 'workload_pods', return_value=[]), patch.object(proof, 'detached', return_value=True), \
             patch.object(proof, 'get', side_effect=lambda kind, *a: state['pod'] if kind == 'pod' else {'kind': 'ServiceAccount'}), \
             patch.object(proof, 'current', side_effect=current), patch.object(proof, 'kubectl', side_effect=native) as client, \
             patch.object(proof, 'root_current', side_effect=lambda r, key: roots[key]), \
             patch.object(proof, 'observe_declared'), patch.object(proof, 'record_native_children'), patch.object(proof, 'housekeeping'), \
             patch.object(proof, 'inventory_gate'), patch.object(proof, 'bind_storage', return_value=True), \
             patch.object(proof, 'request_delete', side_effect=delete):
            with self.assertRaisesRegex(RuntimeError, 'Marker Pod failed'):
                proof.marker_io(receipt, self.payload, 'loki', 'read', proof.time.monotonic() + 1)
            client.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, 'synthetic interruption'):
                proof.cleanup(receipt, self.payload, proof.time.monotonic() + 1)
        self.assertIsNone(state['pod'])
        self.assertTrue(receipt.value['markerRuns'][0]['complete'])
        self.assertNotIn('verifiedIO', receipt.value['markerRuns'][0])
        self.assertTrue(receipt.value['cleanupStarted'])
        self.assertNotIn('qualified', receipt.value['evidence'])
        with patch.object(proof, 'step') as step, patch.object(proof, 'kubectl') as native:
            with self.assertRaisesRegex(RuntimeError, 'terminal for qualification'):
                proof.run(receipt, self.payload, proof.time.monotonic() + 1)
            step.assert_not_called()
            native.assert_not_called()

    def test_removed_retention_accepts_detached_unknown_only_with_exact_storage_identity(self):
        class RemovalVerified(Exception):
            pass

        for state in ('detached', 'attached-degraded', 'changed-pv'):
            with self.subTest(state=state):
                receipt = MemoryReceipt()
                receipt.value['appPhase'] = 'removed'
                receipt.value['baseline'].update(boundary='2026-11-05T12:00:00+00:00',
                    **{'class': {'uid': uid(91)}, 'pvs': {'uid': [], 'name': []},
                       'volumes': {'uid': [], 'name': []}})
                chains = [storage_chain(receipt, component, index)
                          for index, component in enumerate(('loki', 'tempo', 'grafana'), 1)]
                for component, (claim, pv, volume) in zip(('loki', 'tempo', 'grafana'), chains):
                    volume['status'].update(state='detached', robustness='unknown', currentNodeID='')
                    receipt.value['storage'][component]['identity'] = {
                        'claim': proof.object_id(claim), 'pv': proof.object_id(pv),
                        'volume': proof.object_id(volume), 'handle': pv['metadata']['name']}
                if state == 'attached-degraded':
                    chains[0][2]['status'].update(state='attached', robustness='degraded', currentNodeID='node-a')
                    chains[0][2]['spec']['nodeID'] = 'node-a'
                if state == 'changed-pv':
                    chains[0][1]['metadata']['uid'] = uid(99)

                def get(kind, name, namespace=None):
                    slot = 1 if kind in ('pv', 'persistentvolumes') else 2
                    return next(chain[slot] for chain in chains if chain[slot]['metadata']['name'] == name)

                def wait(label, predicate, *unused):
                    if not predicate():
                        raise RuntimeError('Timed out: ' + label)

                def step(record, name, action):
                    if name == 'removal-qualified':
                        action()
                        raise RemovalVerified()

                with patch.object(proof, 'step', side_effect=step), patch.object(proof, 'inventory_gate'), \
                     patch.object(proof, 'advance'), patch.object(proof, 'converged', return_value=True), \
                     patch.object(proof, 'require_removed', return_value=True), \
                     patch.object(proof, 'wait', side_effect=wait), patch.object(proof, 'get', side_effect=get), \
                     patch.object(proof, 'listed', side_effect=lambda kind, *a:
                                  [chain[0] for chain in chains] if kind == 'pvc' else []), \
                     patch.object(proof, 'storage_class', return_value=receipt.value['baseline']['class']), \
                     patch.object(proof, 'record_attachments'), patch.object(proof, 'cleanup') as cleanup:
                    error = RemovalVerified if state == 'detached' else RuntimeError
                    with self.assertRaises(error):
                        proof.run(receipt, self.payload, proof.time.monotonic() + 1)
                    cleanup.assert_not_called()

    def test_run_rejects_cleanup_flags_before_steps_or_api_even_with_completed_journal(self):
        for flag in ('cleanupStarted', 'cleanupComplete'):
            receipt = MemoryReceipt()
            receipt.value[flag] = True
            receipt.value['steps'] = ['removal-qualified', 'marker-read-loki']
            with self.subTest(flag=flag), patch.object(proof, 'step') as step, patch.object(proof, 'kubectl') as native:
                with self.assertRaisesRegex(RuntimeError, 'terminal for qualification'):
                    proof.run(receipt, self.payload, proof.time.monotonic() + 1)
                step.assert_not_called()
                native.assert_not_called()

    def test_verified_marker_evidence_is_bound_to_pod_claim_document_mode_and_hash(self):
        receipt = MemoryReceipt()
        content = proof.marker_content(receipt, 'loki')
        receipt.value['markers']['loki'] = {'content': content, 'sha256': proof.digest(content.encode()), 'claimUID': uid(1)}
        doc = proof.marker_document(receipt, self.payload, 'loki', 'read')
        doc['metadata'].update(uid=uid(81), resourceVersion='8')
        identity = proof.object_id(doc)
        record = {'component': 'loki', 'mode': 'read', 'document': proof.digest(proof.canonical(doc))}
        evidence = {'identity': identity, 'document': record['document'], 'mode': 'read', 'claimUID': uid(1),
                    'sha256': receipt.value['markers']['loki']['sha256'], 'finishedAt': '2026-11-05T12:01:00Z'}
        proof.require_marker_verification(receipt, record | {'verifiedIO': evidence}, identity)
        for field, value in [('identity', identity | {'uid': uid(99)}), ('document', 'f' * 64), ('mode', 'write'),
                             ('claimUID', uid(99)), ('sha256', 'f' * 64), ('finishedAt', '')]:
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                proof.require_marker_verification(receipt, record | {'verifiedIO': evidence | {field: value}}, identity)

    def test_published_grafana_secret_accepts_only_native_exact_data_keys_bytes_and_type(self):
        document = next(obj for obj in self.payload['phases']['running']
                        if obj['kind'] == 'Secret' and obj['metadata']['name'] == proof.namespace(OPERATION) + '-grafana-emergency')
        self.assertTrue(document['stringData'])
        native = native_secret(document)
        self.assertNotIn('stringData', native)
        self.assertTrue(proof.admitted_document(native, document))
        key = next(iter(document['stringData']))
        for mutation in ('bytes', 'extra', 'omission', 'stringData', 'type'):
            actual = copy.deepcopy(native)
            if mutation == 'bytes': actual['data'][key] = base64.b64encode(b'wrong-bytes').decode('ascii')
            if mutation == 'extra': actual['data']['unexpected-credential'] = base64.b64encode(b'injected').decode('ascii')
            if mutation == 'omission': actual['data'].pop(key)
            if mutation == 'stringData': actual['stringData'] = {}
            if mutation == 'type': actual['type'] = 'kubernetes.io/tls'
            with self.subTest(mutation=mutation): self.assertFalse(proof.admitted_document(actual, document))
        for field in ('data', 'stringData'):
            source = copy.deepcopy(document)
            source[field] = {key: None}
            with self.subTest(source=field): self.assertFalse(proof.admitted_document(native, source))
        source = copy.deepcopy(document)
        source['data'] = {key: base64.b64encode(b'overridden').decode('ascii'),
                          'preserved': base64.b64encode(b'existing-data').decode('ascii')}
        self.assertTrue(proof.admitted_document(native_secret(source), source))

    def test_observe_declared_compares_recorded_native_secret_data_without_accepting_drift(self):
        document = next(obj for obj in self.payload['phases']['running']
                        if obj['kind'] == 'Secret' and obj['metadata']['name'] == proof.namespace(OPERATION) + '-grafana-emergency')
        admitted = native_secret(document)
        actual = copy.deepcopy(admitted)
        actual['metadata'].update(uid=uid(95), resourceVersion='8')
        receipt = MemoryReceipt()
        name = actual['metadata']['name']
        actual['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = (
            receipt.namespace + ':/Secret:' + receipt.namespace + '/' + name)
        receipt.value['admission'] = {phase: {'Secret/' + name: admitted} for phase in ('running', 'scaled-down')}
        with patch.object(proof, 'get', return_value=actual):
            proof.observe_declared(receipt, {'phases': {'running': [document]}})
            actual['data'][next(iter(actual['data']))] = base64.b64encode(b'drift').decode('ascii')
            with self.assertRaisesRegex(RuntimeError, 'body changed'):
                proof.observe_declared(receipt, {'phases': {'running': [document]}})

    def test_discovery_supplies_only_missing_typemeta_and_rejects_contradictions_or_incomplete_pages(self):
        ns, objects, unused = housekeeping_fixture()
        raw = copy.deepcopy(objects[1])
        raw.pop('apiVersion'); raw.pop('kind')
        responses = discovery_fixture([('v1', 'configmaps', 'ConfigMap', [raw])], proof.namespace(OPERATION))
        def read(*arguments, **kw): return proof.canonical(responses[arguments[-1]])
        with patch.object(proof, 'kubectl', side_effect=read):
            observed = proof.namespace_inventory(proof.namespace(OPERATION))
            self.assertEqual(observed, [objects[1]])
            raw['kind'] = 'Secret'
            with self.assertRaises(RuntimeError): proof.namespace_inventory(proof.namespace(OPERATION))
            raw.pop('kind'); raw['apiVersion'] = 'other.example/v1'
            with self.assertRaises(RuntimeError): proof.namespace_inventory(proof.namespace(OPERATION))
            raw.pop('apiVersion')
            page = responses['/api/v1/namespaces/' + proof.namespace(OPERATION) + '/configmaps?limit=100']
            page['metadata']['continue'] = 'next'
            next_page = copy.deepcopy(page)
            next_page['metadata'] = {'resourceVersion': '43'}
            responses['/api/v1/namespaces/' + proof.namespace(OPERATION) + '/configmaps?limit=100&continue=next'] = next_page
            with self.assertRaises(RuntimeError): proof.namespace_inventory(proof.namespace(OPERATION))

    def test_event_alias_is_core_canonical_and_rejects_foreign_reference_or_custom_group(self):
        ns = proof.namespace(OPERATION)
        core = {'apiVersion': 'v1', 'kind': 'Event', 'metadata': {'name': 'native.1', 'namespace': ns,
            'uid': uid(220), 'resourceVersion': '5'}, 'involvedObject': {'apiVersion': 'v1', 'kind': 'Namespace',
            'name': ns, 'uid': uid(201)}, 'reason': 'core-view'}
        modern = copy.deepcopy(core)
        modern['apiVersion'] = 'events.k8s.io/v1'; modern['regarding'] = modern.pop('involvedObject'); modern['reason'] = 'modern-view'
        responses = discovery_fixture([('v1', 'events', 'Event', [core]), ('events.k8s.io/v1', 'events', 'Event', [modern])], ns)
        with patch.object(proof, 'kubectl', side_effect=lambda *args, **kw: proof.canonical(responses[args[-1]])):
            self.assertEqual(proof.namespace_inventory(ns), [core])
            modern['regarding']['uid'] = uid(999)
            with self.assertRaises(RuntimeError): proof.namespace_inventory(ns)
        modern['regarding']['uid'] = uid(201); modern['apiVersion'] = 'custom.example/v1'
        responses = discovery_fixture([('v1', 'events', 'Event', [core]), ('custom.example/v1', 'events', 'Event', [modern])], ns)
        with patch.object(proof, 'kubectl', side_effect=lambda *args, **kw: proof.canonical(responses[args[-1]])):
            with self.assertRaises(RuntimeError): proof.namespace_inventory(ns)

    def test_ordinary_inventory_allows_native_event_but_blocks_distinct_custom_event_before_mutation(self):
        receipt = MemoryReceipt()
        account = {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'name': 'default', 'namespace': receipt.namespace, 'uid': uid(202)}
        receipt.value['objects']['default-account'] = account
        event = {'apiVersion': 'v1', 'kind': 'Event', 'metadata': {'name': 'native.1', 'namespace': receipt.namespace,
            'uid': uid(301), 'resourceVersion': '5'}, 'involvedObject': copy.deepcopy(account)}
        with patch.object(proof, 'root_current'), patch.object(proof, 'namespace_inventory', return_value=[event]), \
             patch.object(proof, 'request_delete') as mutation, patch.object(proof, 'kubectl') as native:
            proof.inventory_gate(receipt)
            event['apiVersion'] = 'custom.example/v1'
            event['metadata']['uid'] = uid(302)
            with self.assertRaisesRegex(RuntimeError, 'Foreign namespace Event'):
                proof.inventory_gate(receipt)
                proof.request_delete(receipt, 'delete-namespace', {}, {})
            mutation.assert_not_called()
            native.assert_not_called()

    def test_native_default_sa_may_omit_managed_fields_but_foreign_or_missing_cm_writers_fail(self):
        namespace, objects, roots = housekeeping_fixture()
        account, configmap = copy.deepcopy(objects[0]), copy.deepcopy(objects[1])
        account['metadata'].pop('managedFields')
        created_at = namespace['metadata']['creationTimestamp']
        row = proof.housekeeping_identity(account, proof.namespace(OPERATION), created_at, roots)
        self.assertEqual(row['writers'], [])
        account['metadata']['managedFields'] = [{'manager': 'foreign-controller'}]
        with self.assertRaisesRegex(RuntimeError, 'ServiceAccount shape or writer'):
            proof.housekeeping_identity(account, proof.namespace(OPERATION), created_at, roots)
        account['metadata']['managedFields'] = None
        with self.assertRaisesRegex(RuntimeError, 'housekeeping metadata'):
            proof.housekeeping_identity(account, proof.namespace(OPERATION), created_at, roots)
        configmap['metadata'].pop('managedFields')
        with self.assertRaisesRegex(RuntimeError, 'ConfigMap provenance'):
            proof.housekeeping_identity(configmap, proof.namespace(OPERATION), created_at, roots)

    def test_exact_native_housekeeping_records_and_freshly_rejects_foreign_data_writer_or_identity(self):
        namespace, objects, roots = housekeeping_fixture()
        receipt = MemoryReceipt(); receipt.value['storage'] = {}
        receipt.value['objects']['namespace'] = proof.object_id(namespace)
        def get(kind, name=None, ns=None, **kw):
            return next((obj for obj in objects if obj['kind'] == kind and obj['metadata']['name'] == name), None)
        with patch.object(proof, 'root_current', return_value=namespace), patch.object(proof, 'housekeeping_roots', return_value=roots), \
             patch.object(proof, 'get', side_effect=get), patch.object(proof, 'namespace_inventory', return_value=objects):
            proof.housekeeping(receipt, proof.time.monotonic() + 1)
            proof.inventory_gate(receipt)
            self.assertEqual(set(receipt.value['housekeeping']), {'default', 'kube-root-ca.crt', 'istio-ca-root-cert', 'istio-ca-crl'})
            objects[-1]['data']['ca-crl.pem'] = 'foreign'
            with self.assertRaises(RuntimeError): proof.inventory_gate(receipt)
            objects[-1]['data']['ca-crl.pem'] = ''
            objects[-1]['metadata']['managedFields'][0]['manager'] = 'foreign-controller'
            with self.assertRaises(RuntimeError): proof.housekeeping(receipt, proof.time.monotonic() + 1)
            objects[-1]['metadata']['managedFields'][0]['manager'] = 'pilot-discovery'
            objects[-1]['metadata']['uid'] = uid(999)
            with self.assertRaises(RuntimeError): proof.housekeeping(receipt, proof.time.monotonic() + 1)
            objects[-1]['metadata']['uid'] = uid(205)
            foreign = copy.deepcopy(objects[1]); foreign['metadata'].update(name='foreign', uid=uid(999))
            objects.append(foreign)
            with self.assertRaises(RuntimeError): proof.inventory_gate(receipt)

    def test_empty_recovery_predecessor_rejects_app_storage_hash_or_namespace_uid(self):
        self.assertEqual(proof.PREDECESSOR_DRIVER, '238e7bffe09658382b12e7d463a22c9aa81bed1b72c4c51ef3bce218a70d1b47')
        legacy_hash = proof.digest(b'# synthetic predecessor artifact\n')
        with tempfile.TemporaryDirectory(dir='/root', prefix='obs-csi-empty-abi-') as temporary, \
             patch.object(proof, 'PREDECESSOR_DRIVER', legacy_hash):
            envelope, old, new, buffers, namespace, objects, roots = stage_empty_recovery(Path(temporary), self.payload)
            self.assertEqual(proof.predecessor_identity(envelope, buffers), proof.object_id(namespace))
            for mutation in ('app', 'storage', 'malformed', 'hash', 'uid'):
                value, data = copy.deepcopy(envelope), copy.deepcopy(buffers)
                if mutation in ('app', 'storage', 'malformed'):
                    receipt = proof.parsed(data['state/receipt.json'])
                    if mutation == 'app': receipt['roots']['app'] = {'accepted': True}
                    elif mutation == 'storage': receipt['storage']['loki'] = {'unrecorded': True}
                    else: receipt['admission'] = []
                    data['state/receipt.json'] = proof.canonical(receipt)
                    value['predecessor']['receiptSHA256'] = proof.digest(data['state/receipt.json'])
                if mutation == 'hash': value['predecessor']['inputSHA256'] = 'f' * 64
                if mutation == 'uid': value['predecessor']['namespaceUID'] = uid(999)
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): proof.predecessor_identity(value, data)

    def test_empty_recovery_rejects_sibling_escape_and_external_app_or_storage_alias(self):
        legacy_hash = proof.digest(b'# synthetic predecessor artifact\n')
        with tempfile.TemporaryDirectory(dir='/root', prefix='obs-csi-empty-scope-') as temporary, \
             patch.object(proof, 'ROOT', Path(temporary)), patch.object(proof, 'PREDECESSOR_DRIVER', legacy_hash):
            envelope, old, new, buffers, namespace, objects, roots = stage_empty_recovery(Path(temporary), self.payload)
            with patch.object(proof, 'kubectl') as native:
                with self.assertRaises(RuntimeError): proof.empty_recovery(envelope, old / 'state', proof.canonical(envelope), proof.time.monotonic() + 1)
                native.assert_not_called()
            journal = MemoryReceipt()
            journal.value['objects']['namespace'] = proof.object_id(namespace)
            stripped = copy.deepcopy(namespace); stripped['spec']['finalizers'] = []
            with patch.object(proof, 'get', return_value=stripped):
                with self.assertRaisesRegex(RuntimeError, 'native cascade protection'): proof.recovery_namespace(journal)
            for kind in ('applications.argoproj.io', 'pvc', 'pv', 'volumes.longhorn.io'):
                alias = {'metadata': {'name': 'foreign-resource', 'namespace': 'other'}, 'spec': {}, 'status': {}}
                if kind == 'applications.argoproj.io': alias['spec'] = {'destination': {'namespace': journal.namespace}}
                if kind == 'pvc': alias['metadata']['namespace'] = journal.namespace
                if kind == 'pv': alias['spec'] = {'claimRef': {'namespace': journal.namespace}}
                if kind == 'volumes.longhorn.io': alias['status'] = {'kubernetesStatus': {'namespace': journal.namespace}}
                with self.subTest(kind=kind), patch.object(proof, 'all_namespaced', side_effect=lambda requested, **kw: [alias] if requested == kind else []), \
                     patch.object(proof, 'listed', side_effect=lambda requested, *a: [alias] if requested == kind else []):
                    with self.assertRaises(RuntimeError): proof.recovery_alias_gate(journal, deadline=proof.time.monotonic() + 1)

    def test_empty_recovery_interruptions_preserve_original_tree_and_never_qualify(self):
        legacy_hash = proof.digest(b'# synthetic predecessor artifact\n')
        for interruption in ('before-intent', 'before-request', 'after-request'):
            with self.subTest(interruption=interruption), tempfile.TemporaryDirectory(dir='/root', prefix='obs-csi-empty-resume-') as temporary, \
                 patch.object(proof, 'ROOT', Path(temporary)), patch.object(proof, 'PREDECESSOR_DRIVER', legacy_hash):
                envelope, old, new, buffers, namespace, objects, roots = stage_empty_recovery(Path(temporary), self.payload)
                before = proof.original_tree(old)[0]
                state = {'namespace': namespace, 'interrupt': True, 'requests': 0}
                def get(kind, name=None, ns=None, **kw):
                    if kind in ('namespaces', 'Namespace'): return state['namespace']
                    return next((obj for obj in objects if obj['kind'] == kind and obj['metadata']['name'] == name), None)
                original_inventory = proof.recovery_inventory
                def inventory(journal, *, freeze=False):
                    original_inventory(journal, freeze=freeze)
                    if state['interrupt'] and interruption == 'before-intent' and freeze:
                        state['interrupt'] = False
                        raise RuntimeError('synthetic interruption before intent')
                def native(*arguments, body=None):
                    self.assertEqual(arguments[:2], ('delete', '--raw'))
                    self.assertEqual(arguments[2], '/api/v1/namespaces/' + proof.namespace(OPERATION))
                    journal = proof.parsed((new / 'recovery.json').read_bytes())
                    self.assertEqual(journal['namespaceDelete']['identity'], proof.object_id(namespace))
                    self.assertFalse(journal['namespaceDelete']['accepted'])
                    self.assertEqual(proof.parsed(body)['preconditions'], {'uid': uid(201), 'resourceVersion': '10'})
                    if state['interrupt'] and interruption == 'before-request':
                        state['interrupt'] = False
                        raise RuntimeError('synthetic interruption before request')
                    state['requests'] += 1
                    state['namespace'] = None
                    if state['interrupt'] and interruption == 'after-request':
                        state['interrupt'] = False
                        raise RuntimeError('synthetic interrupted acknowledgment')
                    return b''
                with patch.object(proof, 'get', side_effect=get), patch.object(proof, 'housekeeping_roots', return_value=roots), \
                     patch.object(proof, 'namespace_inventory', side_effect=lambda ns: objects if state['namespace'] else []), \
                     patch.object(proof, 'all_namespaced', return_value=[]), patch.object(proof, 'listed', return_value=[]), \
                     patch.object(proof, 'recovery_inventory', side_effect=inventory), patch.object(proof, 'kubectl', side_effect=native):
                    with self.assertRaisesRegex(RuntimeError, 'synthetic interrupt'):
                        proof.empty_recovery(envelope, new, proof.canonical(envelope), proof.time.monotonic() + 3)
                    self.assertEqual(proof.original_tree(old)[0], before)
                    result = proof.empty_recovery(envelope, new, proof.canonical(envelope), proof.time.monotonic() + 3)
                    self.assertEqual(result, {'cleanup': True, 'recoveryOnly': True, 'qualified': False, 'originalQualified': False})
                    self.assertEqual(state['requests'], 1)
                    self.assertEqual(proof.original_tree(old)[0], before)
                    journal = proof.parsed((new / 'recovery.json').read_bytes())
                    self.assertFalse(journal['qualified'])
                    self.assertEqual(journal['phase'], 'completed')

    def test_empty_recovery_absence_without_intent_and_unsafe_old_link_never_delete(self):
        legacy_hash = proof.digest(b'# synthetic predecessor artifact\n')
        with tempfile.TemporaryDirectory(dir='/root', prefix='obs-csi-empty-absent-') as temporary, \
             patch.object(proof, 'ROOT', Path(temporary)), patch.object(proof, 'PREDECESSOR_DRIVER', legacy_hash):
            envelope, old, new, buffers, namespace, objects, roots = stage_empty_recovery(Path(temporary), self.payload)
            before = proof.original_tree(old)[0]
            with patch.object(proof, 'recovery_alias_gate'), patch.object(proof, 'get', return_value=None), \
                 patch.object(proof, 'kubectl') as native:
                with self.assertRaisesRegex(RuntimeError, 'absent without matching durable'):
                    proof.empty_recovery(envelope, new, proof.canonical(envelope), proof.time.monotonic() + 1)
                native.assert_not_called()
            self.assertEqual(proof.original_tree(old)[0], before)
            journal = proof.parsed((new / 'recovery.json').read_bytes())
            self.assertFalse(journal['qualified'])
            self.assertIsNone(journal['namespaceDelete'])
            os.link(old / 'proof.py', Path(temporary) / 'unapproved-link')
            with self.assertRaisesRegex(RuntimeError, 'Unsafe original artifact'): proof.original_tree(old)

    def test_recovery_staging_binds_reviewed_code_envelope_and_exact_sibling_before_execution(self):
        envelope = {'version': 1, 'profile': proof.RECOVERY_PROFILE, 'operation': OPERATION, 'predecessor': {
            'operation': 'fedcba9876543210', 'driverSHA256': proof.PREDECESSOR_DRIVER, 'inputSHA256': '1' * 64,
            'receiptSHA256': '2' * 64, 'namespaceUID': uid(201)}}
        driver = Path(proof.__file__).read_bytes(); driver_hash = proof.digest(driver)
        with tempfile.TemporaryDirectory(dir='/root', prefix='obs-csi-recovery-stage-') as temporary, \
             patch.object(proof, 'ROOT', Path(temporary)), patch.object(proof, 'kubectl') as native:
            target = Path(temporary) / ('observability-storage-recovery-' + OPERATION)
            with self.assertRaises(RuntimeError):
                proof.host_preflight(Path(temporary) / ('observability-storage-' + OPERATION), OPERATION, driver_hash,
                                     'recovery-fresh', proof.canonical(envelope))
            proof.host_preflight(target, OPERATION, driver_hash, 'recovery-fresh', proof.canonical(envelope))
            for name, raw in {'proof.py': driver, 'input.json': proof.canonical(envelope)}.items():
                (target / name).write_bytes(raw); (target / name).chmod(0o600)
            proof.host_preflight(target, OPERATION, driver_hash, 'recovery-installed', proof.canonical(envelope))
            with self.assertRaises(RuntimeError):
                proof.host_preflight(target, OPERATION, 'f' * 64, 'recovery-installed', proof.canonical(envelope))
            changed = copy.deepcopy(envelope); changed['predecessor']['receiptSHA256'] = 'f' * 64
            with self.assertRaisesRegex(RuntimeError, 'envelope differs'):
                proof.host_preflight(target, OPERATION, driver_hash, 'recovery-installed', proof.canonical(changed))
            native.assert_not_called()

    def test_drift_repair_records_owned_replacement_before_inventory_and_rejects_foreign_pods(self):
        receipt = MemoryReceipt()
        receipt.value['admission'] = {'running': {}}
        pods, workloads = [], {}
        for index, component in enumerate(('loki', 'tempo', 'grafana'), 1):
            kind = 'Deployment' if component == 'grafana' else 'StatefulSet'
            workload = copy.deepcopy(next(obj for obj in self.payload['phases']['running']
                if obj['kind'] == kind and obj['metadata']['name'] == receipt.namespace + '-' + component))
            workload['metadata'].update(uid=uid(800 + index), resourceVersion='8')
            for container in workload['spec']['template']['spec']['containers']:
                if container.get('env', False) is None: container.pop('env')
            receipt.value['admission']['running'][kind + '/' + workload['metadata']['name']] = workload
            receipt.record('workload-' + component, workload)
            workloads[component] = workload
            spec = copy.deepcopy(workload['spec']['template']['spec'])
            name = workload['metadata']['name'] + ('-pod' if component == 'grafana' else '-0')
            parent_uid, parent_kind = workload['metadata']['uid'], kind
            if component == 'grafana': parent_uid, parent_kind = uid(820), 'ReplicaSet'
            else:
                spec.setdefault('volumes', []).append({'name': 'storage', 'persistentVolumeClaim': {
                    'claimName': proof.claim_names(OPERATION)[component]}})
                spec.update(hostname=name, subdomain=workload['spec']['serviceName'])
            spec['nodeName'] = 'node-a'
            pods.append({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': receipt.namespace,
                'uid': uid(810 + index), 'resourceVersion': '9', 'ownerReferences': [{'uid': parent_uid,
                    'kind': parent_kind, 'controller': True}]}, 'spec': spec, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}],
                    'containerStatuses': [{'name': spec['containers'][0]['name'], 'restartCount': 0, 'state': {'running': {}}}]}})
            pods[-1]['status']['containerStatuses'][0]['state']['running'] = {'startedAt': '2026-11-05T12:00:00Z'}
        replica = {'apiVersion': 'apps/v1', 'kind': 'ReplicaSet', 'metadata': {'name': receipt.namespace + '-grafana-rs',
            'namespace': receipt.namespace, 'uid': uid(820), 'resourceVersion': '8', 'ownerReferences': [{
                'uid': workloads['grafana']['metadata']['uid'], 'kind': 'Deployment', 'controller': True}]}}
        def listed(kind, *unused): return [replica] if kind == 'replicasets.apps' else pods
        returned = copy.deepcopy(workloads['loki']); returned['spec']['replicas'] = 0
        with patch.object(proof, 'listed', side_effect=listed), patch.object(proof, 'root_current'), \
             patch.object(proof, 'namespace_inventory', side_effect=lambda unused: pods + [replica]), \
             patch.object(proof, 'workload', return_value=workloads['loki']), \
             patch.object(proof, 'kubectl', return_value=proof.canonical(returned)):
            self.assertTrue(proof.record_native_children(receipt))
            old_uid = pods[0]['metadata']['uid']
            pods[0]['metadata']['uid'] = uid(830)
            with self.assertRaisesRegex(RuntimeError, 'Unknown namespace resource'): proof.inventory_gate(receipt)
            proof.drift_and_repair(receipt, proof.time.monotonic() + 2)
            self.assertIn('pod-' + old_uid, receipt.value['objects'])
            self.assertEqual(receipt.value['objects']['pod-' + uid(830)], proof.object_id(pods[0]))
            self.assertTrue(receipt.value['intents']['replica-drift']['complete'])
            proof.inventory_gate(receipt)
            original = copy.deepcopy(pods[0])
            for mutation in ('owner', 'image', 'pvc'):
                pods[0] = copy.deepcopy(original); pods[0]['metadata']['uid'] = uid(831)
                if mutation == 'owner': pods[0]['metadata']['ownerReferences'][0]['uid'] = uid(999)
                if mutation == 'image': pods[0]['spec']['containers'][0]['image'] = 'foreign:latest'
                if mutation == 'pvc':
                    next(volume for volume in pods[0]['spec']['volumes'] if volume['name'] == 'storage')['persistentVolumeClaim']['claimName'] = 'foreign-data'
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): proof.record_native_children(receipt)
                with self.assertRaisesRegex(RuntimeError, 'Unknown namespace resource'): proof.inventory_gate(receipt)

    def test_paginated_global_apps_stream_aggregate_over_limit_without_collecting_all_rows(self):
        calls, total = [], [0]
        deadline = proof.time.monotonic() + 20
        def native(*arguments, **kwargs):
            self.assertEqual(arguments[:2], ('get', '--raw'))
            self.assertEqual(kwargs, {'deadline': deadline})
            url = urlsplit(arguments[2]); query = parse_qs(url.query)
            self.assertEqual(url.path, '/apis/argoproj.io/v1alpha1/applications')
            self.assertEqual(query['limit'], ['1'])
            index = int(query.get('continue', ['0'])[0]); calls.append(index)
            row = {'metadata': {'name': 'app-' + str(index), 'namespace': 'argocd', 'uid': uid(500 + index), 'resourceVersion': '8'},
                   'spec': {'padding': 'x' * (proof.LIMIT // 2)}}
            metadata = {'resourceVersion': '42', 'remainingItemCount': 2 - index}
            if index < 2: metadata['continue'] = str(index + 1)
            raw = proof.canonical({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationList', 'metadata': metadata, 'items': [row]})
            self.assertLess(len(raw), proof.LIMIT); total[0] += len(raw)
            return raw
        with patch.object(proof, 'kubectl', side_effect=native):
            stream = proof.all_namespaced('applications.argoproj.io', deadline=deadline)
            first = next(stream)
            self.assertEqual(calls, [0])
            self.assertEqual(first['kind'], 'Application')
            self.assertEqual(first['apiVersion'], 'argoproj.io/v1alpha1')
            del first
            self.assertEqual(sum(1 for unused in stream), 2)
        self.assertGreater(total[0], proof.LIMIT)
        self.assertEqual(calls, [0, 1, 2])

    def test_paginated_fixed_project_and_pvc_paths_reject_unsupported_scope(self):
        profiles = [('appprojects.argoproj.io', 'argoproj.io/v1alpha1', 'AppProject', '/apis/argoproj.io/v1alpha1/appprojects'),
                    ('pvc', 'v1', 'PersistentVolumeClaim', '/api/v1/persistentvolumeclaims')]
        for kind, version, native_kind, path in profiles:
            response = {'apiVersion': version, 'kind': native_kind + 'List', 'metadata': {'resourceVersion': '42'}, 'items': []}
            with self.subTest(kind=kind), patch.object(proof, 'kubectl', return_value=proof.canonical(response)) as native:
                self.assertEqual(list(proof.all_namespaced(kind, deadline=proof.time.monotonic() + 1)), [])
                self.assertEqual(native.call_args.args, ('get', '--raw', path + '?limit=1'))
        with patch.object(proof, 'kubectl') as native:
            with self.assertRaises(RuntimeError): list(proof.paginated_namespaced('namespaces', deadline=proof.time.monotonic() + 1))
            with self.assertRaises(RuntimeError): list(proof.paginated_namespaced('pvc', '../escape', deadline=proof.time.monotonic() + 1))
            native.assert_not_called()

    def test_paginated_later_page_contradictions_block_recovery_before_mutation(self):
        for mutation in ('type', 'rv', 'uid', 'remaining', 'token'):
            requests = []
            def native(*arguments, **kwargs):
                index = len(requests); requests.append(arguments)
                row = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {
                    'name': 'unrelated-' + str(index), 'namespace': 'argocd', 'uid': uid(600 + index), 'resourceVersion': '8'}, 'spec': {}}
                page = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationList',
                        'metadata': {'resourceVersion': '42', 'continue': 'next'} if index == 0 else {'resourceVersion': '42'}, 'items': [row]}
                if index:
                    if mutation == 'type': row['apiVersion'] = 'custom.example/v1'
                    if mutation == 'rv': page['metadata']['resourceVersion'] = '43'
                    if mutation == 'uid': row['metadata']['uid'] = uid(600)
                    if mutation == 'remaining': page['metadata']['remainingItemCount'] = 1
                    if mutation == 'token': page['metadata']['continue'] = 'next'
                return proof.canonical(page)
            with self.subTest(mutation=mutation), patch.object(proof, 'kubectl', side_effect=native), \
                 patch.object(proof, 'request_delete') as delete:
                with self.assertRaises(RuntimeError):
                    proof.recovery_alias_gate(MemoryReceipt(), deadline=proof.time.monotonic() + 2)
                    proof.request_delete(None, None, None, None)
                delete.assert_not_called()
                self.assertEqual(len(requests), 2)

    def test_inventory_deadline_bounds_native_timeout_and_stops_before_next_page(self):
        result = subprocess.CompletedProcess(['synthetic'], 0, stdout=b'{}', stderr=b'')
        with patch.object(proof.time, 'monotonic', return_value=100), patch.object(proof.subprocess, 'run', return_value=result) as native:
            proof.command(['synthetic'], deadline=100.25)
            self.assertEqual(native.call_args.kwargs['timeout'], 0.25)
            proof.command(['synthetic'])
            self.assertEqual(native.call_args.kwargs['timeout'], 60)
            native.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'deadline expired'): proof.command(['synthetic'], deadline=100)
            native.assert_not_called()
        row = {'metadata': {'name': 'app', 'namespace': 'argocd', 'uid': uid(700), 'resourceVersion': '8'}}
        page = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationList',
                'metadata': {'resourceVersion': '42', 'continue': 'next'}, 'items': [row]}
        with patch.object(proof.time, 'monotonic', return_value=100) as clock, \
             patch.object(proof, 'kubectl', return_value=proof.canonical(page)) as native:
            stream = proof.all_namespaced('applications.argoproj.io', deadline=101)
            next(stream)
            clock.return_value = 102
            with self.assertRaisesRegex(RuntimeError, 'deadline expired'): next(stream)
            self.assertEqual(native.call_count, 1)

    def test_project_guard_streams_only_argocd_apps_and_keeps_exact_consumer_check(self):
        receipt = MemoryReceipt()
        own = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {
            'name': receipt.namespace, 'namespace': 'argocd', 'uid': uid(701), 'resourceVersion': '8'}, 'spec': {'project': receipt.namespace}}
        foreign = copy.deepcopy(own); foreign['metadata'].update(name='foreign-app', uid=uid(702)); foreign['spec']['project'] = 'another-project'
        receipt.value['objects']['app'] = proof.object_id(own)
        def native(*arguments, **kwargs):
            url = urlsplit(arguments[2]); query = parse_qs(url.query)
            self.assertEqual(url.path, '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications')
            index = int(query.get('continue', ['0'])[0])
            metadata = {'resourceVersion': '42'} | ({'continue': '1'} if index == 0 else {})
            return proof.canonical({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationList',
                                    'metadata': metadata, 'items': [own if index == 0 else foreign]})
        with patch.object(proof, 'root_current'), patch.object(proof, 'kubectl', side_effect=native), patch.object(proof, 'listed') as old_list:
            proof.project_guard(receipt, deadline=proof.time.monotonic() + 1)
            with self.assertRaisesRegex(RuntimeError, 'still has a consumer'):
                proof.project_guard(receipt, deadline=proof.time.monotonic() + 1, app_absent=True)
            foreign['spec']['project'] = receipt.namespace
            with self.assertRaisesRegex(RuntimeError, 'Unexpected project consumer'):
                proof.project_guard(receipt, deadline=proof.time.monotonic() + 1)
            old_list.assert_not_called()


if __name__ == '__main__':
    unittest.main()
