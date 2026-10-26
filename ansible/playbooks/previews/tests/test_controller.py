import copy
import json
import unittest
from unittest.mock import patch

from fixtures import approval, catalog, pull, source_responses, generated_application, native_inventory_graph, discovered_inventory
from playbooks.previews.files.contract import OWNER, IDENTITY_STATE, canonical, digest, names
from playbooks.previews.files.controller import Controller
from playbooks.previews.files.kube import identity, Kubernetes, APIError
from playbooks.previews.files.resources import metadata, private_route
from playbooks.previews.files.github import GitHub
from playbooks.previews.files import controller as runtime


class Cluster:
    def __init__(self):
        self.objects, self.deleted, self.counter = {}, [], 0

    def get(self, key):
        return copy.deepcopy(self.objects.get(tuple(key)))

    def create(self, obj):
        key = identity(obj)
        if key in self.objects:
            raise APIError(409)
        self.counter += 1
        obj = copy.deepcopy(obj)
        obj['metadata'].update(uid='uid-' + str(self.counter), resourceVersion=str(self.counter))
        self.objects[key] = obj
        return copy.deepcopy(obj)

    def replace(self, obj):
        key = identity(obj)
        if self.objects[key]['metadata']['resourceVersion'] != obj['metadata']['resourceVersion']:
            raise APIError(409)
        self.counter += 1
        obj = copy.deepcopy(obj)
        obj['metadata']['resourceVersion'] = str(self.counter)
        self.objects[key] = obj
        return copy.deepcopy(obj)

    def delete(self, key, uid, version, *, orphan=False):
        obj = self.objects[tuple(key)]
        if obj['metadata']['uid'] != uid or obj['metadata']['resourceVersion'] != version:
            raise APIError(409)
        self.deleted.append((tuple(key), orphan))
        del self.objects[tuple(key)]
        if orphan:
            for child in self.objects.values():
                refs = child['metadata'].get('ownerReferences', [])
                if any(ref.get('uid') == uid for ref in refs):
                    child['metadata']['ownerReferences'] = [ref for ref in refs if ref.get('uid') != uid]

    def namespace_inventory(self, namespace):
        return [copy.deepcopy(obj) for key, obj in self.objects.items() if key[2] == namespace]

    def identity_phase(self, row, phase):
        key = ('v1', 'ConfigMap', 'cloudlab-identity', IDENTITY_STATE)
        value = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': IDENTITY_STATE, 'namespace': 'cloudlab-identity', 'labels': {'cloudlab.io/owner': 'cloudlab-preview-identity'}},
            'data': {'state.json': json.dumps({'format': 1, 'entries': {row['instance']: {
                'phase': phase, 'originVersion': 2, 'verifiedAt': 1500, 'approvalDigest': digest(canonical(row))}}})}}
        if key in self.objects:
            value['metadata'].update(self.objects[key]['metadata'])
            self.replace(value)
        else:
            self.create(value)


class Git:
    def __init__(self):
        self.value, self.offline = pull(), False

    def pull(self, row):
        if self.offline:
            raise RuntimeError('Provider unavailable')
        return copy.deepcopy(self.value)

    def allows(self, row, now):
        return True

    def verified(self, row):
        from playbooks.previews.files.contract import validate_pull
        result = self.pull(row)
        validate_pull(row, result)
        return result


class ControllerTests(unittest.TestCase):
    def test_legacy_origin_retires_before_discovery_with_any_input(self):
        for mode in ('valid', 'missing', 'invalid'):
            controller, row, settings, cluster, git = self.active()
            del controller.state['entries'][row['instance']]['originVersion']
            cluster.identity_phase(row, 'retired')
            with patch.object(git, 'pull', side_effect=AssertionError('legacy discovery forbidden')):
                for _ in range(30):
                    if mode == 'missing':
                        controller.unavailable_input()
                    else:
                        controller.run(settings if mode == 'valid' else {'malformed': True}, 'https://github.com/example/platform.git')
            self.assertEqual(controller.state['entries'][row['instance']]['phase'], 'retired')
            self.assertFalse(any(key[1] == 'Namespace' and key[3] == names(row)['namespace'] for key in cluster.objects))


    def test_image_update_retires_stored_preview_with_valid_missing_or_malformed_catalog(self):
        from playbooks.previews.files import contract
        for available in ('valid', 'missing', 'malformed'):
            controller, row, settings, cluster, git = self.active()
            cluster.identity_phase(row, 'retired')
            git.offline = True
            with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64), \
                    patch.object(git, 'pull', side_effect=AssertionError('obsolete preview must retire before discovery')):
                for _ in range(30):
                    if available == 'valid':
                        controller.run(settings, 'https://github.com/example/platform.git')
                    elif available == 'missing':
                        controller.unavailable_input()
                    else:
                        controller.run({'malformed': True}, 'https://github.com/example/platform.git')
            self.assertEqual(controller.state['entries'][row['instance']]['phase'], 'retired')
            self.assertFalse(any(key[1] == 'Namespace' and key[3] == names(row)['namespace']
                                 for key in cluster.objects))

    def test_changed_stored_digest_or_instance_blocks_cleanup_after_image_update(self):
        from playbooks.previews.files import contract
        for change in ('digest', 'instance'):
            controller, row, settings, cluster, git = self.active()
            cluster.identity_phase(row, 'retired')
            before = copy.deepcopy(cluster.objects)
            record = controller.state['entries'][row['instance']]
            if change == 'digest':
                record['approvalDigest'] = 'e' * 64
            else:
                record['approval']['instance'] = 'e' * 32
            with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64):
                result = controller.unavailable_input()
            self.assertGreater(result['failures'], 0)
            self.assertFalse(cluster.deleted)
            self.assertEqual({key: value for key, value in cluster.objects.items() if key[3] != 'cloudlab-preview-state'},
                             {key: value for key, value in before.items() if key[3] != 'cloudlab-preview-state'})

    def test_obsolete_new_row_cannot_create_any_execution_authority(self):
        from playbooks.previews.files import contract
        from playbooks.previews.files.resources import resources, workload
        row, settings, cluster, git = approval(), catalog(), Cluster(), Git()
        controller = Controller(cluster, git, 1500)
        with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64), \
                patch.object(git, 'pull', side_effect=AssertionError('obsolete row must not request discovery')):
            controller.run(settings, 'https://github.com/example/platform.git')
            for create in (lambda: resources(row, settings, 'https://github.com/example/platform.git', 'state'),
                           lambda: workload(row, settings), lambda: private_route(row, settings, 'state')):
                with self.assertRaises(ValueError):
                    create()
        self.assertEqual(controller.state['entries'], {})
        self.assertFalse(any(key[1] in ('Namespace', 'ApplicationSet', 'Deployment') for key in cluster.objects))

    def test_image_change_does_not_authorize_deleting_a_replaced_namespace_uid(self):
        from playbooks.previews.files import contract
        controller, row, settings, cluster, git = self.active()
        cluster.identity_phase(row, 'retired')
        key = next(key for key in cluster.objects if key[1] == 'Namespace' and key[3] == names(row)['namespace'])
        cluster.objects[key]['metadata']['uid'] = 'replacement-namespace'
        with patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64):
            result = controller.unavailable_input()
        self.assertGreater(result['failures'], 0)
        self.assertEqual(cluster.objects[key]['metadata']['uid'], 'replacement-namespace')
        self.assertFalse(any(deleted == key for deleted, _ in cluster.deleted))
        self.assertEqual(controller.state['entries'][row['instance']]['phase'], 'retiring')

    def active(self):
        row, settings, cluster, git = approval(), catalog(), Cluster(), Git()
        settings['privateDiscovery'] = True
        cluster.identity_phase(row, 'active')
        controller = Controller(cluster, git, 1500)
        controller.waypoint_ready = lambda row: True
        controller.publication_ready = lambda row, settings: True
        controller.run(settings, 'https://github.com/example/platform.git')
        controller.materialize(controller.state['entries'][row['instance']], private_route(row, settings, controller.object['metadata']['uid']))
        controller.now = 1561
        return controller, row, settings, cluster, git

    def test_new_commit_cannot_change_execution_and_cleanup_preserves_persistent_app(self):
        controller, row, settings, cluster, git = self.active()
        n = names(row)
        appset_key = ('argoproj.io/v1alpha1', 'ApplicationSet', 'argocd', n['name'])
        self.assertEqual(cluster.objects[appset_key]['spec']['template']['spec']['source']['targetRevision'], row['platformRevision'])
        persistent = cluster.create({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
            'metadata': {'name': 'persistent-private', 'namespace': 'argocd'}, 'spec': {'prune': False}})
        before = copy.deepcopy(persistent)
        git.value['head']['sha'] = 'f' * 40
        cluster.identity_phase(row, 'retired')
        for _ in range(30):
            controller.run(settings, 'https://github.com/example/platform.git')
        self.assertEqual(controller.state['entries'][row['instance']]['phase'], 'retired')
        self.assertNotIn(appset_key, cluster.objects)
        self.assertEqual(cluster.get(identity(persistent)), before)
        self.assertTrue(next(orphan for key, orphan in cluster.deleted if key == appset_key))
        self.assertTrue(next(orphan for key, orphan in cluster.deleted if key[1] == 'Namespace'))

    def test_native_inventory_leaves_retire_only_through_namespace_gc_and_fresh_checks(self):
        for changed in (False, True):
            with self.subTest(changed=changed):
                controller, row, settings, cluster, _ = self.active()
                namespace = names(row)['namespace']
                gateway = next(obj for key, obj in cluster.objects.items() if key[1] == 'Gateway' and key[2] == namespace)
                graph = native_inventory_graph(namespace, gateway['metadata']['uid'])
                for obj in graph: cluster.objects[identity(obj)] = copy.deepcopy(obj)
                native_inventory, native_delete = cluster.namespace_inventory, cluster.delete
                calls = []
                def inventory(ns):
                    result = discovered_inventory(native_inventory(ns), ns); calls.append(ns)
                    if changed and len(calls) == 1:
                        key = ('v1', 'Endpoints', namespace, 'native-service')
                        cluster.objects[key]['subsets'][0]['addresses'][0]['ip'] = '10.42.9.9'
                    return result
                def delete(key, uid, version, **options):
                    native_delete(key, uid, version, **options)
                    if key[1] == 'Namespace':
                        for child in list(cluster.objects):
                            if child[2] == namespace: del cluster.objects[child]
                controller.now = row['expiresAt']; cluster.identity_phase(row, 'retired')
                with patch.object(cluster, 'namespace_inventory', side_effect=inventory), patch.object(cluster, 'delete', side_effect=delete):
                    for _ in range(30): controller.run(settings, 'https://github.com/example/platform.git')
                self.assertFalse(any(key[1] in ('Endpoints', 'PodMetrics') for key, _ in cluster.deleted))
                self.assertGreaterEqual(len(calls), 2)
                self.assertEqual(controller.state['entries'][row['instance']]['phase'], 'retiring' if changed else 'retired')
                self.assertEqual(cluster.get(('v1', 'Namespace', '', namespace)) is not None, changed)

    def test_provider_outage_retains_until_absolute_expiry(self):
        controller, row, settings, cluster, git = self.active()
        git.offline = True
        before = copy.deepcopy(cluster.objects)
        result = controller.run(settings, 'https://github.com/example/platform.git')
        self.assertGreater(result['discovery_unavailable'], 0)
        self.assertEqual({key: value for key, value in cluster.objects.items() if key[3] != 'cloudlab-preview-state'},
                         {key: value for key, value in before.items() if key[3] != 'cloudlab-preview-state'})
        self.assertEqual(cluster.deleted, [])
        controller.now = row['expiresAt']
        cluster.identity_phase(row, 'retired')
        for _ in range(30): controller.run(settings, 'https://github.com/example/platform.git')
        self.assertEqual(controller.state['entries'][row['instance']]['phase'], 'retired')

    def test_native_orphan_cleanup_resumes_captured_legacy_and_lost_delete_reply(self):
        for boundary in ('native', 'stranded', 'lost-reply'):
            with self.subTest(boundary=boundary):
                controller, row, settings, cluster, git = self.active()
                parent = ('argoproj.io/v1alpha1', 'ApplicationSet', 'argocd', names(row)['name'])
                app = cluster.create(generated_application(cluster.get(parent)))
                controller.capture_workloads(controller.state['entries'][row['instance']])
                cluster.identity_phase(row, 'retired'); controller.now = row['expiresAt']
                if boundary == 'stranded':
                    record = controller.state['entries'][row['instance']]
                    record.update(phase='retiring', reason='expired'); controller.save()
                    obj = cluster.get(parent); cluster.delete(parent, obj['metadata']['uid'], obj['metadata']['resourceVersion'], orphan=True)
                    controller = Controller(cluster, git, row['expiresAt'])
                native = cluster.delete
                def delete(key, uid, version, **options):
                    native(key, uid, version, **options)
                    if tuple(key) == parent and boundary == 'lost-reply':
                        raise RuntimeError('lost native delete reply')
                with patch.object(cluster, 'delete', side_effect=delete):
                    for _ in range(30): controller.run(settings, 'https://github.com/example/platform.git')
                self.assertEqual(controller.state['entries'][row['instance']]['phase'], 'retired')
                self.assertIsNone(cluster.get(identity(app)))
                self.assertTrue(next(orphan for key, orphan in cluster.deleted if key == identity(app)))

    def test_orphan_parent_exception_never_adopts_or_ignores_changed_authority(self):
        for change in ('unrecorded', 'uid', 'foreign-ref', 'parent', 'replacement-parent', 'active', 'owner', 'missing-receipt', 'duplicate-receipt', 'lookup'):
            with self.subTest(change=change):
                controller, row, _, cluster, _ = self.active()
                parent = ('argoproj.io/v1alpha1', 'ApplicationSet', 'argocd', names(row)['name'])
                app = cluster.create(generated_application(cluster.get(parent))); key = identity(app)
                record = controller.state['entries'][row['instance']]; controller.capture_workloads(record)
                record['phase'] = 'retiring'
                if change not in ('parent', 'replacement-parent'):
                    obj = cluster.get(parent); cluster.delete(parent, obj['metadata']['uid'], obj['metadata']['resourceVersion'], orphan=True)
                cluster.objects[key]['metadata']['ownerReferences'] = []
                if change == 'unrecorded': record['resources'] = [r for r in record['resources'] if r['key'] != list(key)]
                elif change == 'uid': cluster.objects[key]['metadata']['uid'] = 'foreign'
                elif change == 'foreign-ref': cluster.objects[key]['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                elif change == 'replacement-parent': cluster.objects[parent]['metadata']['uid'] = 'replacement'
                elif change == 'active': record['phase'] = 'active'
                elif change == 'owner': cluster.objects[key]['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
                elif change == 'missing-receipt': record['resources'] = [r for r in record['resources'] if r['key'] != list(parent)]
                elif change == 'duplicate-receipt': record['resources'].append(copy.deepcopy(next(r for r in record['resources'] if r['key'] == list(parent))))
                before = copy.deepcopy(record); deleted = list(cluster.deleted); native = cluster.get
                def get(target):
                    if change == 'lookup' and tuple(target) == parent: raise RuntimeError('API uncertain')
                    return native(target)
                with patch.object(cluster, 'get', side_effect=get), self.assertRaises((ValueError, RuntimeError)):
                    controller.capture_workloads(record)
                self.assertEqual(record, before); self.assertEqual(cluster.deleted, deleted)

    def test_application_delete_rechecks_refs_and_actual_parent_after_capture(self):
        for change in ('foreign-ref', 'parent', 'uid'):
            with self.subTest(change=change):
                controller, row, _, cluster, _ = self.active()
                parent = ('argoproj.io/v1alpha1', 'ApplicationSet', 'argocd', names(row)['name'])
                declaration = cluster.get(parent); app = cluster.create(generated_application(declaration)); key = identity(app)
                record = controller.state['entries'][row['instance']]; controller.capture_workloads(record); record['phase'] = 'retiring'
                cluster.delete(parent, declaration['metadata']['uid'], declaration['metadata']['resourceVersion'], orphan=True)
                controller.capture_workloads(record)
                if change == 'foreign-ref': cluster.objects[key]['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                elif change == 'parent': cluster.create(declaration)
                else: cluster.objects[key]['metadata']['uid'] = 'foreign'
                deleted = list(cluster.deleted)
                with self.assertRaises(ValueError): controller.remove(record, next(r for r in record['resources'] if r['key'] == list(key)))
                self.assertEqual(cluster.deleted, deleted); self.assertIsNotNone(cluster.get(key))

    def test_foreign_pvc_vetoes_cascading_workload_deletion(self):
        controller, row, settings, cluster, git = self.active()
        n = names(row)
        meta = metadata(row, controller.object['metadata']['uid'], 'preview', n['namespace'])
        meta['annotations']['argocd.argoproj.io/tracking-id'] = n['name'] + ':apps/Deployment:' + n['namespace'] + '/preview'
        deployment = cluster.create({'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': meta, 'spec': {}})
        pvc = cluster.create({'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {
            'name': 'foreign-data', 'namespace': n['namespace'], 'ownerReferences': [{'uid': deployment['metadata']['uid']}]}, 'spec': {}})
        git.value['state'] = 'closed'
        results = [controller.run(settings, 'https://github.com/example/platform.git') for _ in range(10)]
        self.assertTrue(any(result['failures'] for result in results))
        self.assertEqual(cluster.get(identity(pvc)), pvc)
        self.assertEqual(cluster.get(identity(deployment)), deployment)
        self.assertFalse(any(key[1] in ('Deployment', 'Namespace') for key, _ in cluster.deleted))

    def test_many_unavailable_candidates_cannot_starve_local_expiry(self):
        controller, row, settings, cluster, git = self.active()
        candidates = [approval(format(number, '032x')) for number in range(1, 20)]
        for candidate in candidates:
            candidate.update(createdAt=2000, expiresAt=5000)
        settings = catalog([row, *candidates])
        settings['privateDiscovery'] = True
        controller.now = row['expiresAt']
        calls = []
        def unavailable(candidate):
            calls.append(candidate['instance'])
            self.assertEqual(controller.state['entries'][row['instance']]['phase'], 'retiring')
            self.assertTrue(any(key[1] == 'HTTPRoute' for key, _ in cluster.deleted))
            raise RuntimeError('Provider unavailable')
        git.verified = unavailable
        result = controller.run(settings, 'https://github.com/example/platform.git')
        self.assertEqual(result['discovery_unavailable'], 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(controller.state['entries'][row['instance']]['reason'], 'expired')

    def test_missing_or_malformed_private_lease_preserves_local_cleanup(self):
        for lease in (None, {}, {'expiresAt': 'invalid'}):
            controller, row, settings, cluster, git = self.active()
            controller.github = GitHub('', private=True, lease=lease)
            controller.now = row['expiresAt']
            cluster.identity_phase(row, 'retired')
            with patch('urllib.request.build_opener') as network:
                for _ in range(30): controller.run(settings, 'https://github.com/example/platform.git')
            self.assertEqual(controller.state['entries'][row['instance']]['phase'], 'retired')
            network.assert_not_called()

    def test_anonymous_budget_includes_blobs_across_twenty_rejected_candidates(self):
        rows = [approval(format(number, '032x')) for number in range(1, 21)]
        for row in rows:
            row.update(expiresAt=10000, sourceDigest='0' * 64)
        settings, cluster, api = catalog(rows), Cluster(), GitHub()
        controller = Controller(cluster, api, 1500)
        responses = source_responses(rows[0])
        calls = []
        def response(path):
            calls.append(path)
            if '/pulls/' in path: return pull(rows[0])
            return responses[path]
        with patch.object(api, 'request', side_effect=response):
            for minute in range(60):
                controller.now = 1500 + 60 * minute
                controller.run(settings, 'https://github.com/example/platform.git')
        self.assertEqual(sum('/pulls/' in path for path in calls), 8)
        self.assertEqual(sum('/contents/' in path for path in calls), 8)
        self.assertEqual(len(calls), 40)
        self.assertLess(len(calls) + 8, 60)
        self.assertEqual(controller.state['entries'], {})

    def test_bad_candidates_reserve_discovery_for_existing_preview_close(self):
        controller, row, settings, cluster, git = self.active()
        candidates = [approval(format(number, '032x')) for number in range(1, 20)]
        settings = catalog([row, *candidates])
        settings['privateDiscovery'] = True
        git.value['state'] = 'closed'
        git.verified = lambda row: (_ for _ in ()).throw(RuntimeError('Provider unavailable'))
        result = controller.run(settings, 'https://github.com/example/platform.git')
        self.assertEqual(result['discovery_unavailable'], 1)
        self.assertEqual(controller.state['entries'][row['instance']]['reason'], 'closed')

    def test_runtime_adapter_cleans_expiry_when_administrator_input_is_unavailable(self):
        for mode in ('missing', 'corrupt', 'binding'):
            controller, row, settings, cluster, git = self.active()
            cluster.identity_phase(row, 'retired')
            if mode != 'missing':
                if mode == 'binding': settings['hostname'] = 'another.internal.example.invalid'
                cluster.create({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
                    'name': 'cloudlab-preview-approvals', 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
                    'data': {'catalog.json': '{' if mode == 'corrupt' else json.dumps(settings),
                             'platformRepository': 'https://github.com/example/platform.git'}})
            with patch.object(runtime, 'Kubernetes', return_value=cluster), patch.object(runtime.time, 'time', return_value=row['expiresAt']), \
                    patch('urllib.request.build_opener') as network:
                for _ in range(30): result = runtime.run()
            state = json.loads(cluster.get(('v1', 'ConfigMap', 'argocd', 'cloudlab-preview-state'))['data']['state.json'])
            self.assertEqual(state['entries'][row['instance']]['phase'], 'retired')
            self.assertEqual(result['input_unavailable'], 1)
            network.assert_not_called()

    def test_runtime_adapter_keeps_foreign_state_a_hard_stop(self):
        controller, row, settings, cluster, git = self.active()
        cluster.objects[('v1', 'ConfigMap', 'argocd', 'cloudlab-preview-state')]['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
        with patch.object(runtime, 'Kubernetes', return_value=cluster), self.assertRaises(ValueError): runtime.run()
        self.assertEqual(cluster.deleted, [])

    def test_delete_api_keeps_uid_version_and_orphan_boundary(self):
        kube = object.__new__(Kubernetes)
        with patch.object(kube, 'request') as request:
            kube.delete(('argoproj.io/v1alpha1', 'ApplicationSet', 'argocd', 'preview-a'), 'uid', '12', orphan=True)
        options = request.call_args.args[2]
        self.assertEqual(options['preconditions'], {'uid': 'uid', 'resourceVersion': '12'})
        self.assertEqual(options['propagationPolicy'], 'Orphan')

    def test_incomplete_collection_cannot_authorize_namespace_delete(self):
        kube = object.__new__(Kubernetes)
        responses = [{'resources': [{'name': 'pods', 'kind': 'Pod', 'namespaced': True, 'verbs': ['list']}]},
                     {'groups': []}, {'metadata': {'continue': 'next-page'}, 'items': []}]
        with patch.object(kube, 'request', side_effect=responses), self.assertRaises(RuntimeError):
            kube.namespace_inventory('cloudlab-preview-' + 'a' * 32)

    def test_missing_recorded_uid_or_version_never_reaches_delete_api(self):
        kube = object.__new__(Kubernetes)
        for uid, version in (('', '12'), ('uid', ''), (None, '12')):
            with self.subTest(uid=uid, version=version), patch.object(kube, 'request') as request:
                with self.assertRaisesRegex(ValueError, 'exact UID and resource version'):
                    kube.delete(('v1', 'Namespace', '', 'cloudlab-preview-' + 'a' * 32), uid, version)
                request.assert_not_called()
