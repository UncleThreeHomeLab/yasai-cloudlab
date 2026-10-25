import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import source_transition as migration


class SourceTransitionTests(unittest.TestCase):
    def accepted_fixture(self):
        objects = self.fixtures()
        target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'a' * 40}
        root = objects['application.argoproj.io', migration.ROOT_APP]
        root['spec']['source'].update(repoURL='https://github.com/example/platform.git', targetRevision='main',
            helm={'valuesObject': {'identity': {'enabled': True, 'argo': target}}})
        root['status'] = {'sync': {'status': 'Synced', 'revision': 'b' * 40, 'comparedTo': {'source': copy.deepcopy(root['spec']['source'])}},
                          'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}
        project = objects['appproject.argoproj.io', 'cloudlab-root']
        project['spec']['sourceRepos'] = [root['spec']['source']['repoURL']]
        project['spec']['namespaceResourceWhitelist'] = migration.identity_project_rules(project)
        receipt = {'phase': 'accepted', 'target': target, 'root_uid': 'root', 'controller_uid': 'controller', 'project_uid': 'project'}
        arguments = {'repository': root['spec']['source']['repoURL'], 'branch': 'main', 'revision': 'b' * 40,
                     'private_repository': target['valuesRepository']}
        return objects, receipt, arguments

    def test_accepted_binding_reader_is_read_only_and_does_not_require_current_private_catalog_head(self):
        objects, receipt, arguments = self.accepted_fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'identity-values-binding.json').write_text(json.dumps(receipt))
            with patch.object(migration, 'BASE', base), patch.object(migration, 'get', side_effect=lambda *key: objects[key]), \
                    patch.object(migration, 'kube', side_effect=AssertionError('mutation')), \
                    patch.object(migration, 'bind_identity', side_effect=AssertionError('handoff')), \
                    patch.object(migration, 'resume_identity_binding', side_effect=AssertionError('repair')), \
                    patch.object(migration, 'pause', side_effect=AssertionError('pause')), \
                    patch.object(migration, 'grant_identity_source', side_effect=AssertionError('grant')), \
                    patch.object(migration, 'wait_application', side_effect=AssertionError('mutating wait')):
                self.assertEqual(migration.accepted_identity_binding(**arguments), receipt['target'])

    def test_binding_reader_rejects_missing_malformed_pending_or_changed_native_contract(self):
        for change in ('missing', 'malformed', 'phase', 'target-key', 'target-sha', 'private-repo', 'uid', 'deleting', 'root-repo',
                       'branch', 'overlay', 'identity-disabled', 'not-synced', 'revision', 'unhealthy', 'operation', 'compared', 'grant'):
            objects, receipt, arguments = self.accepted_fixture()
            root = objects['application.argoproj.io', migration.ROOT_APP]
            if change == 'phase': receipt['phase'] = 'resumed'
            if change == 'target-key': receipt['target']['unknown'] = True
            if change == 'target-sha': receipt['target']['valuesRevision'] = 'main'
            if change == 'private-repo': arguments['private_repository'] = 'https://github.com/example/other.git'
            if change == 'uid': receipt['controller_uid'] = 'replacement'
            if change == 'deleting': objects['statefulset', migration.CONTROLLER]['metadata']['deletionTimestamp'] = 'synthetic'
            if change == 'root-repo': root['spec']['source']['repoURL'] = 'https://github.com/example/other.git'
            if change == 'branch': arguments['branch'] = 'other'
            if change == 'overlay': root['spec']['source']['helm']['valuesObject']['identity']['argo'] = {'valuesRepository': 'changed'}
            if change == 'identity-disabled': root['spec']['source']['helm']['valuesObject']['identity']['enabled'] = False
            if change == 'not-synced': root['status']['sync']['status'] = 'OutOfSync'
            if change == 'revision': root['status']['sync']['revision'] = 'c' * 40
            if change == 'unhealthy': root['status']['health']['status'] = 'Progressing'
            if change == 'operation': root['operation'] = {'sync': {}}
            if change == 'compared': root['status']['sync'].pop('comparedTo')
            if change == 'grant': objects['appproject.argoproj.io', 'cloudlab-root']['spec']['namespaceResourceWhitelist'].pop()
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                if change != 'missing': (base / 'identity-values-binding.json').write_text('{' if change == 'malformed' else json.dumps(receipt))
                with patch.object(migration, 'BASE', base), patch.object(migration, 'get', side_effect=lambda *key: objects[key]), \
                        patch.object(migration, 'kube', side_effect=AssertionError('mutation')), self.subTest(change=change):
                    with self.assertRaises((ValueError, RuntimeError)): migration.accepted_identity_binding(**arguments)

    def test_binding_reader_rejects_wrong_expected_coordinates_before_native_reads(self):
        _, _, arguments = self.accepted_fixture()
        for changed in ({'repository': '*'}, {'private_repository': arguments['repository']},
                        {'private_repository': 'https://github.com/foreign/private.git'}, {'branch': '*'}, {'revision': 'main'}):
            with patch.object(migration, 'get') as read, self.assertRaises(ValueError):
                migration.accepted_identity_binding(**dict(arguments, **changed))
            read.assert_not_called()

    def test_identity_binding_resumes_sole_controller_when_root_patch_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'checkpoint.json').write_text(json.dumps({'phase': 'accepted'}))
            objects = self.fixtures()
            root = objects['application.argoproj.io', migration.ROOT_APP]
            root['spec']['source'].update(targetRevision='main', helm={'releaseName': 'root'})
            root['metadata']['resourceVersion'] = '1'
            target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'a' * 40}
            writes = []
            def write(*args, **kwargs):
                writes.append(args)
                if args[0] == 'patch': raise RuntimeError('synthetic patch failure')
            with patch.object(migration, 'BASE', base), patch.object(migration, 'get', side_effect=lambda kind, name: objects[kind, name]), \
                    patch.object(migration, 'resume_identity_binding', return_value=False), \
                    patch.object(migration, 'pause'), patch.object(migration, 'kube', side_effect=write):
                with self.assertRaisesRegex(RuntimeError, 'synthetic patch failure'):
                    migration.bind_identity({'private_repository': target['valuesRepository'], 'repository': 'old',
                                             'branch': 'main', 'revision': 'public'}, target)
            self.assertEqual(writes[-1], ('scale', 'statefulset/' + migration.CONTROLLER, '-n', 'argocd', '--replicas=1'))
            patch_body = json.loads(writes[0][-1])
            self.assertEqual(patch_body[0], {'op': 'test', 'path': '/metadata/uid', 'value': 'root'})
            self.assertEqual(patch_body[1]['path'], '/metadata/resourceVersion')
            self.assertEqual(json.loads((base / 'identity-values-binding.json').read_text())['phase'], 'paused')

    def fixtures(self):
        return {
            ('application.argoproj.io', migration.ROOT_APP): {
                'metadata': {'uid': 'root'}, 'spec': {'project': 'cloudlab-root',
                    'source': {'path': 'gitops/roots/public', 'repoURL': 'old'}}},
            ('statefulset', migration.CONTROLLER): {'metadata': {'uid': 'controller'}, 'spec': {'replicas': 1}},
            ('appproject.argoproj.io', 'cloudlab-root'): {'metadata': {'uid': 'project', 'resourceVersion': '1'}, 'spec': {
                'sourceRepos': ['old'], 'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
                'clusterResourceWhitelist': [{'group': '', 'kind': 'Namespace'}],
                'namespaceResourceWhitelist': [{'group': 'argoproj.io', 'kind': kind} for kind in ('Application', 'AppProject')]}}}

    def test_refuses_unknown_ownership_and_active_operations(self):
        items = list(self.fixtures().values())
        self.assertTrue(migration.validate(*items[0:1], items[2], items[1], 'new'))
        for modify in ('operation', 'project', 'replicas'):
            root, controller, project = copy.deepcopy(items)
            if modify == 'operation': root['operation'] = {'sync': {}}
            if modify == 'project': project['spec']['sourceRepos'] = ['*']
            if modify == 'replicas': controller['spec']['replicas'] = 2
            with self.subTest(modify=modify), self.assertRaises(RuntimeError):
                migration.validate(root, project, controller, 'new')

    def test_failure_resumes_controller_then_retry_accepts_without_replacement(self):
        objects = self.fixtures()
        payload = {'repository': 'new', 'branch': 'main', 'revision': 'reviewed'}
        calls = []
        fail_once = [True]
        def mutate(kind, name, document):
            calls.append(('patch', kind))
            if kind == 'application.argoproj.io' and fail_once[0]:
                fail_once[0] = False
                raise RuntimeError('Injected interruption')
            objects[(kind, name)]['spec'].update(document['spec'])
        def kube(*args):
            calls.append(args)
            self.assertNotIn('delete', args)
            if args[0] == 'get': return '{"items": []}'
            return ''
        def converged(*args):
            objects[('appproject.argoproj.io', 'cloudlab-root')]['spec']['sourceRepos'] = ['new']
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            with patch.object(migration, 'BASE', base), patch.object(migration, 'get', side_effect=lambda *key: objects[key]), \
                    patch.object(migration, 'kube', side_effect=kube), patch.object(migration, 'patch', side_effect=mutate), \
                    patch.object(migration, 'wait_application', side_effect=converged):
                with self.assertRaisesRegex(RuntimeError, 'Injected'):
                    migration.run(payload)
                self.assertEqual(calls[-1][-1], '--replicas=1')
                self.assertEqual(json.loads((base / 'source-transition.json').read_text())['phase'], 'paused')
                self.assertTrue(migration.run(payload)['changed'])
                before = len(calls)
                self.assertFalse(migration.run(payload)['changed'])
                self.assertEqual(len(calls), before)
                self.assertEqual(objects[('application.argoproj.io', migration.ROOT_APP)]['metadata']['uid'], 'root')
