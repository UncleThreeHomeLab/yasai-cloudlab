"""Legacy authority is complete, fail closed, and independent of sync recovery."""
import copy
import fcntl
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest.mock import patch

from playbooks.observability.files import bootstrap, writer_guard as guard


class WriterGuardTests(unittest.TestCase):
    def setUp(self):
        self.payload = {'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                        'configuration': {'enabled': True}, 'components': {name: {} for name in bootstrap.COMPONENTS}}
        self.children = {}
        for component in ('configuration', *bootstrap.COMPONENTS):
            app = bootstrap.application(self.payload, component)
            app['metadata'].update(uid='uid-' + component, resourceVersion='7')
            self.children[app['metadata']['name']] = app
        self.objects = dict(self.children)

    def get(self, kind, name, namespace=None):
        return self.objects.get(name)

    def parent(self):
        public = {'repoURL': self.payload['repository'], 'targetRevision': 'a' * 40,
                  'path': 'platform/observability/gitops', 'helm': {'releaseName': guard.PARENT,
                  'valueFiles': ['$values/services/catalog.json', '$values/platform/observability.yaml'],
                  'valuesObject': {'nativeSource': {'repository': self.payload['repository'], 'revision': 'a' * 40,
                                                   'valuesRepository': 'https://github.com/example/private.git'}}}}
        return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
                'metadata': {'name': guard.PARENT, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': guard.OWNER},
                             'annotations': {'argocd.argoproj.io/skip-reconcile': 'true'}},
                'spec': {'project': guard.PARENT, 'sources': [public, {'repoURL': 'https://github.com/example/private.git',
                         'targetRevision': 'main', 'ref': 'values'}],
                         'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                         'syncPolicy': {'automated': {'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False},
                                        'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}

    def test_absence_or_exact_prepared_parent_allows_normal_legacy_sync(self):
        self.children['cloudlab-prometheus']['operation'] = {'sync': {}}
        self.children['cloudlab-prometheus']['metadata']['annotations'] = {'argocd.argoproj.io/refresh': 'normal'}
        self.children['cloudlab-prometheus']['status'] = {'operationState': {'phase': 'Running'}}
        with patch.object(guard, 'check_fence'):
            guard.inspect(self.get, self.payload['repository'])
            self.objects[guard.PARENT] = self.parent()
            guard.inspect(self.get, self.payload['repository'])

    def test_parent_activation_ambiguity_or_operation_blocks_before_child_tracking(self):
        for change in ('skip', 'automation', 'operation', 'running', 'deletion', 'owner', 'sources', 'branch', 'override', 'files'):
            parent = self.parent()
            if change == 'skip': parent['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'] = 'false'
            if change == 'automation': parent['spec']['syncPolicy']['automated']['enabled'] = True
            if change == 'operation': parent['operation'] = {'sync': {}}
            if change == 'running': parent['status'] = {'operationState': {'phase': 'Running'}}
            if change == 'deletion': parent['metadata']['deletionTimestamp'] = 'fixture'
            if change == 'owner': parent['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            if change == 'sources': parent['spec']['sources'].append({})
            if change == 'branch': parent['spec']['sources'][1]['targetRevision'] = 'other'
            if change == 'override': parent['spec']['sources'][0]['helm']['valuesObject']['untrusted'] = True
            if change == 'files': parent['spec']['sources'][0]['helm']['valueFiles'][0] = '$values/../other.yaml'
            self.objects[guard.PARENT] = parent
            with self.subTest(change=change), patch.object(guard, 'check_fence'), \
                    patch.object(bootstrap, 'get', side_effect=self.get), patch.object(bootstrap, 'kube') as mutate:
                with self.assertRaises(RuntimeError): bootstrap.seed(self.payload, 'configuration')
                mutate.assert_not_called()

    def test_foreign_last_child_and_native_markers_prevent_first_write(self):
        for change in ('owner', 'digest', 'tracking', 'instance', 'sources', 'finalizer', 'ownerReference', 'deletion', 'path', 'destination', 'helm', 'plugin'):
            current = copy.deepcopy(self.children['cloudlab-kiali'])
            if change == 'owner': current['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            if change == 'digest': current['metadata']['annotations'] = {guard.DIGEST: 'b' * 64}
            if change == 'tracking': current['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': 'native'}
            if change == 'instance': current['metadata']['labels']['app.kubernetes.io/instance'] = guard.PARENT
            if change == 'sources': current['spec']['sources'] = [current['spec']['source']]
            if change == 'finalizer': current['metadata']['finalizers'] = ['foreign']
            if change == 'ownerReference': current['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
            if change == 'deletion': current['metadata']['deletionTimestamp'] = 'fixture'
            if change == 'path': current['spec']['source']['path'] = 'foreign'
            if change == 'destination': current['spec']['destination']['namespace'] = 'foreign'
            if change == 'helm': current['spec']['source']['helm']['releaseName'] = 'foreign'
            if change == 'plugin': current['spec']['source']['plugin'] = {'name': 'foreign'}
            self.objects['cloudlab-kiali'] = current
            with self.subTest(change=change), patch.object(guard, 'check_fence'), \
                    patch.object(bootstrap, 'get', side_effect=self.get), patch.object(bootstrap, 'kube') as mutate:
                with self.assertRaises(RuntimeError): bootstrap.seed(self.payload, 'configuration')
                mutate.assert_not_called()

    def test_api_failure_is_not_absence(self):
        with patch.object(guard, 'check_fence'), patch.object(bootstrap, 'get', side_effect=RuntimeError('API denied')), \
                patch.object(bootstrap, 'kube') as mutate:
            with self.assertRaisesRegex(RuntimeError, 'API denied'): bootstrap.seed(self.payload, 'configuration')
            mutate.assert_not_called()

    def test_fence_presence_and_unsafe_ancestors_fail_closed(self):
        safe = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        fence = guard.RETIREMENT_FENCE
        for mode in (stat.S_IFREG | 0o600, stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o700):
            def lstat(path):
                return SimpleNamespace(st_mode=mode, st_uid=0) if path == fence else safe
            with self.subTest(mode=mode), patch.object(guard.os, 'lstat', side_effect=lstat):
                with self.assertRaises(RuntimeError): guard.check_fence()
        for unsafe in (SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
                       SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000),
                       SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)):
            with patch.object(guard.os, 'lstat', return_value=unsafe):
                with self.assertRaises(RuntimeError): guard.check_fence()
        def absent(path):
            if path == fence.parent: raise FileNotFoundError()
            return safe
        with patch.object(guard.os, 'lstat', side_effect=absent):
            guard.check_fence()
        with patch.object(guard.os, 'lstat', side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError): guard.check_fence()

    def test_both_entrypoints_refuse_fence_or_bad_parent_even_for_noop_history(self):
        with tempfile.TemporaryDirectory() as directory:
            for blocker in ('fence', 'parent'):
                if blocker == 'parent':
                    self.objects[guard.PARENT] = self.parent()
                    self.objects[guard.PARENT]['spec']['syncPolicy']['automated']['enabled'] = True
                with self.subTest(blocker=blocker), \
                        patch.object(bootstrap, 'Path', side_effect=lambda name: Path(directory) / Path(name).name), \
                        patch.object(guard, 'check_fence', side_effect=RuntimeError('fence') if blocker == 'fence' else None), \
                        patch.object(bootstrap, 'get', side_effect=self.get), patch.object(bootstrap, 'kube') as mutate:
                    with self.assertRaises(RuntimeError): bootstrap.run(self.payload)
                    with self.assertRaises(RuntimeError): bootstrap.compact_history()
                    mutate.assert_not_called()

    def test_create_race_and_seed_patch_conflict_never_adopt_or_retry(self):
        for absent in (True, False):
            if absent: self.objects.pop('cloudlab-prometheus')
            else: self.objects['cloudlab-prometheus'] = self.children['cloudlab-prometheus']
            payload = copy.deepcopy(self.payload)
            payload['revision'] = 'b' * 40
            with self.subTest(absent=absent), patch.object(guard, 'check_fence'), \
                    patch.object(bootstrap, 'get', side_effect=self.get), \
                    patch.object(bootstrap, 'kube', side_effect=RuntimeError('AlreadyExists' if absent else 'Conflict')) as mutate, \
                    patch.object(bootstrap, 'wait') as wait:
                with self.assertRaises(RuntimeError): bootstrap.seed(payload, 'prometheus')
                self.assertEqual(mutate.call_count, 1)
                self.assertEqual(mutate.call_args.args[0], 'create' if absent else 'patch')
                self.assertNotIn('--server-side', mutate.call_args.args)
                if not absent:
                    self.assertEqual(mutate.call_args.kwargs['document'][:2], [
                        {'op': 'test', 'path': '/metadata/uid', 'value': 'uid-prometheus'},
                        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'}])
                wait.assert_not_called()

    def test_compaction_uses_history_only_while_seeder_holds_main_and_conflicts_fail(self):
        current = self.children['cloudlab-prometheus']
        current['status'] = {'history': [{'source': copy.deepcopy(current['spec']['source'])} for _ in range(2)]}
        with tempfile.TemporaryDirectory() as directory:
            main = Path(directory) / Path(guard.MAIN_LOCK).name
            with main.open('a') as seeder:
                fcntl.flock(seeder, fcntl.LOCK_EX | fcntl.LOCK_NB)
                for conflict in (False, True):
                    paths = []
                    def lock_path(name):
                        paths.append(name)
                        return Path(directory) / Path(name).name
                    with self.subTest(conflict=conflict), patch.object(bootstrap, 'Path', side_effect=lock_path), \
                            patch.object(guard, 'check_fence'), patch.object(bootstrap, 'get', side_effect=self.get), \
                            patch.object(bootstrap, 'kube', side_effect=RuntimeError('Conflict') if conflict else None) as mutate:
                        if conflict:
                            with self.assertRaisesRegex(RuntimeError, 'Conflict'): bootstrap.compact_history()
                        else: self.assertTrue(bootstrap.compact_history()['changed'])
                        self.assertEqual(paths, [guard.HISTORY_LOCK])
                        self.assertEqual(mutate.call_count, 1)
                        self.assertIn('"/metadata/resourceVersion", "value": "7"', mutate.call_args.args[-1])

    def test_recheck_refuses_target_replaced_with_native_child(self):
        count = 0
        def get(kind, name, namespace=None):
            nonlocal count
            if name == 'cloudlab-prometheus':
                count += 1
                if count == 2:
                    current = copy.deepcopy(self.children[name])
                    current['metadata']['annotations'] = {guard.DIGEST: 'b' * 64}
                    return current
            return self.get(kind, name, namespace)
        with patch.object(guard, 'check_fence'), patch.object(bootstrap, 'get', side_effect=get), \
                patch.object(bootstrap, 'kube') as mutate:
            with self.assertRaises(RuntimeError): bootstrap.seed(self.payload, 'prometheus')
            mutate.assert_not_called()

    def test_compaction_recheck_binds_preflight_repository_and_uid(self):
        for change in ('repository', 'uid'):
            reads = 0
            def get(kind, name, namespace=None):
                nonlocal reads
                if name == 'cloudlab-prometheus':
                    reads += 1
                    if reads == 2:
                        current = copy.deepcopy(self.children[name])
                        if change == 'repository':
                            current['spec']['source']['repoURL'] = 'https://github.com/example/foreign.git'
                        else:
                            current['metadata']['uid'] = 'replacement'
                        current['status'] = {'history': [{'source': copy.deepcopy(current['spec']['source'])} for _ in range(2)]}
                        return current
                return self.get(kind, name, namespace)
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, \
                    patch.object(bootstrap, 'Path', side_effect=lambda name: Path(directory) / Path(name).name), \
                    patch.object(guard, 'check_fence'), patch.object(bootstrap, 'get', side_effect=get), \
                    patch.object(bootstrap, 'kube') as mutate:
                with self.assertRaises(RuntimeError): bootstrap.compact_history()
                mutate.assert_not_called()


if __name__ == '__main__':
    unittest.main()
