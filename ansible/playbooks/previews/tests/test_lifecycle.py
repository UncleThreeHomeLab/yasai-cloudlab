import copy
import unittest
from fixtures import approval, pull, native_inventory_graph, discovered_inventory
from playbooks.previews.files.lifecycle import enroll, retirement, owned, namespace_disposable
from playbooks.previews.files.contract import canonical, digest, names, OWNER


class LifecycleTests(unittest.TestCase):
    def test_outage_is_not_close_and_expiry_is_git_independent(self):
        row = approval()
        self.assertIsNone(retirement(row, row, None, 1500))
        self.assertEqual(retirement(row, row, None, 2000), 'expired')
        self.assertEqual(retirement(row, None, None, 1500), 'orphan')
        changed = pull()
        changed['head']['sha'] = 'e' * 40
        self.assertEqual(retirement(row, row, changed, 1500), 'revision-unapproved')
        closed = pull() | {'state': 'closed'}
        self.assertEqual(retirement(row, row, closed, 1500), 'closed')
        with self.assertRaises(ValueError): retirement(row, row, {}, 1500)

    def test_capacity_counts_retirement_and_tombstone_prevents_replay(self):
        state = {'format': 1, 'entries': {}}
        state = enroll(state, approval(), 1500)
        state = enroll(state, approval('b' * 32), 1500)
        state['entries']['a' * 32]['phase'] = 'retiring'
        with self.assertRaises(ValueError): enroll(state, approval('d' * 32), 1500)
        state['entries']['a' * 32]['phase'] = 'retired'
        row = approval()
        row['sourceSha'] = 'f' * 40
        with self.assertRaises(ValueError): enroll(state, row, 1500)

    def test_prefix_label_is_not_deletion_authority(self):
        row = approval()
        meta = {'name': names(row)['namespace'], 'uid': 'namespace-uid', 'resourceVersion': '4',
                'labels': {'cloudlab.io/owner': OWNER, 'cloudlab.io/preview-instance': row['instance']},
                'annotations': {'cloudlab.io/approval-digest': digest(canonical(row)), 'cloudlab.io/runtime-state-uid': 'state-uid'}}
        obj = {'kind': 'Namespace', 'metadata': meta}
        owned(obj, row, 'state-uid', 'namespace-uid')
        for uid, state in (('replaced-uid', 'state-uid'), ('namespace-uid', 'foreign-state')):
            with self.assertRaises(ValueError): owned(obj, row, state, uid)

    def test_retained_or_foreign_data_blocks_namespace_deletion(self):
        objects = [{'kind': 'Pod', 'metadata': {'name': 'child', 'uid': 'pod', 'ownerReferences': [{'uid': 'replicaset'}]}},
                   {'kind': 'ReplicaSet', 'metadata': {'name': 'replicaset', 'uid': 'replicaset', 'ownerReferences': [{'uid': 'deployment'}]}}]
        self.assertTrue(namespace_disposable(objects, {'deployment'}, 'namespace'))
        for bad in ({'kind': 'PersistentVolumeClaim', 'metadata': {'name': 'data', 'uid': 'data'}},
                    {'kind': 'ConfigMap', 'metadata': {'name': 'foreign', 'uid': 'foreign'}},
                    {'kind': 'ConfigMap', 'metadata': {'name': 'root', 'uid': 'deployment', 'annotations': {'cloudlab.io/retention': 'retain'}}}):
            with self.subTest(kind=bad['kind']), self.assertRaises(ValueError):
                namespace_disposable(objects + [bad], {'deployment'}, 'namespace')

    def test_native_generated_crl_is_disposable_but_retention_still_blocks(self):
        crl = {'kind': 'ConfigMap', 'metadata': {'name': 'istio-ca-crl', 'uid': 'native-crl'}}
        self.assertTrue(namespace_disposable([crl], set(), 'namespace'))
        retained = copy.deepcopy(crl)
        retained['metadata']['annotations'] = {'helm.sh/resource-policy': 'keep'}
        with self.assertRaises(ValueError): namespace_disposable([retained], set(), 'namespace')
        foreign = copy.deepcopy(crl)
        foreign['metadata']['name'] = 'application-data'
        with self.assertRaises(ValueError): namespace_disposable([foreign], set(), 'namespace')

    def test_native_leaves_follow_verified_graph_without_requiring_metrics_uid(self):
        for field, version, address in (('addresses', None, '10.42.1.2'), ('notReadyAddresses', '', 'fd00::2'), ('addresses', 'v1', '10.42.1.2')):
            with self.subTest(field=field, version=version):
                graph = native_inventory_graph(); item = graph[1]['subsets'][0].pop('addresses')[0]
                item['ip'] = address
                if version is not None: item['targetRef']['apiVersion'] = version
                graph[1]['subsets'][0][field] = [item]
                inventory = discovered_inventory(graph, graph[0]['metadata']['namespace']); before = copy.deepcopy(list(inventory))
                self.assertTrue(namespace_disposable(inventory, {'native-root'}, 'namespace'))
                self.assertEqual(list(inventory), before)
        graph = native_inventory_graph(); graph[1]['subsets'] = []
        self.assertTrue(namespace_disposable(discovered_inventory(graph, graph[0]['metadata']['namespace']), {'native-root'}, 'namespace'))

    def test_native_leaf_uids_never_authorize_unknown_descendants(self):
        for leaf in ('Endpoints', 'PodMetrics'):
            with self.subTest(leaf=leaf):
                graph = native_inventory_graph(); obj = next(obj for obj in graph if obj['kind'] == leaf)
                obj['metadata']['uid'] = 'leaf-uid'
                graph.append({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
                    'name': 'foreign-child', 'namespace': obj['metadata']['namespace'], 'uid': 'foreign-child',
                    'ownerReferences': [{'kind': leaf, 'uid': 'leaf-uid'}]}})
                with self.assertRaises(ValueError):
                    namespace_disposable(discovered_inventory(graph, graph[0]['metadata']['namespace']), {'native-root'}, 'namespace')
                with self.assertRaises(ValueError):
                    namespace_disposable(discovered_inventory(graph, graph[0]['metadata']['namespace']), {'native-root', 'leaf-uid'}, 'namespace')
                obj['metadata']['ownerReferences'] = [{'uid': 'native-root'}]
                with self.assertRaises(ValueError):
                    namespace_disposable(discovered_inventory(graph[:-1], graph[0]['metadata']['namespace']), {'native-root', 'leaf-uid'}, 'namespace')

    def test_native_endpoints_refuse_spoofed_missing_or_changed_backing_graph(self):
        cases = ('missing-service', 'foreign-service', 'duplicate-service', 'selectorless', 'selector-type', 'external',
                 'marker', 'refs', 'uid', 'namespace', 'kind', 'name', 'target-uid', 'target-namespace', 'version',
                 'ip', 'selector-mismatch', 'missing-pod', 'foreign-pod', 'subsets', 'addresses', 'target', 'pod-ips')
        for change in cases:
            with self.subTest(change=change):
                graph = native_inventory_graph(); endpoints, pod, service = graph[1:4]
                address = endpoints['subsets'][0]['addresses'][0]; target = address['targetRef']
                if change == 'missing-service': graph.remove(service)
                elif change == 'foreign-service': service['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                elif change == 'duplicate-service': graph.append(copy.deepcopy(service))
                elif change == 'selectorless': service['spec']['selector'] = {}
                elif change == 'selector-type': service['spec']['selector'] = []
                elif change == 'external': service['spec']['type'] = 'ExternalName'
                elif change == 'marker': endpoints['metadata']['labels']['endpoints.kubernetes.io/managed-by'] = 'forged'
                elif change == 'refs': endpoints['metadata']['ownerReferences'] = [{'uid': 'native-root'}]
                elif change == 'uid': endpoints['metadata'].pop('uid')
                elif change == 'namespace': endpoints['metadata']['namespace'] = 'foreign'
                elif change in ('kind', 'name', 'version', 'target-uid', 'target-namespace'):
                    target[{'version': 'apiVersion', 'target-uid': 'uid', 'target-namespace': 'namespace'}.get(change, change)] = 'foreign'
                elif change == 'ip': address['ip'] = '10.42.9.9'
                elif change == 'selector-mismatch': pod['metadata']['labels']['app'] = 'foreign'
                elif change == 'missing-pod': graph.remove(pod)
                elif change == 'foreign-pod': pod['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                elif change == 'subsets': endpoints['subsets'] = {}
                elif change == 'addresses': endpoints['subsets'][0]['addresses'] = {}
                elif change == 'target': address['targetRef'] = None
                elif change == 'pod-ips': pod['status']['podIPs'] = None
                with self.assertRaises(ValueError):
                    namespace_disposable(discovered_inventory(graph, 'cloudlab-preview-synthetic'), {'native-root'}, 'namespace')

    def test_leaf_retention_and_finalizers_veto_even_when_uid_and_refs_look_known(self):
        for kind in ('Endpoints', 'PodMetrics'):
            for change in ('retention', 'keep', 'finalizer'):
                with self.subTest(kind=kind, change=change):
                    graph = native_inventory_graph(); meta = next(obj['metadata'] for obj in graph if obj['kind'] == kind)
                    meta['uid'] = 'native-root'
                    if change == 'finalizer': meta['finalizers'] = ['foreign']
                    else: meta['annotations'] = {'cloudlab.io/retention': 'retain'} if change == 'retention' else {'helm.sh/resource-policy': 'keep'}
                    with self.assertRaises(ValueError):
                        namespace_disposable(discovered_inventory(graph, graph[0]['metadata']['namespace']), {'native-root'}, 'namespace')

    def test_metrics_payload_cannot_self_authorize_without_discovery(self):
        graph = native_inventory_graph(); graph[0]['pod_metrics'] = True; graph[0]['metadata']['uid'] = 'native-root'
        with self.assertRaises(ValueError): namespace_disposable(graph, {'native-root'}, 'namespace')
