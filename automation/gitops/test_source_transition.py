import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import source_transition as migration


class SourceTransitionTests(unittest.TestCase):
    def fixtures(self):
        return {
            ('application.argoproj.io', migration.ROOT_APP): {
                'metadata': {'uid': 'root'}, 'spec': {'project': 'cloudlab-root',
                    'source': {'path': 'gitops/roots/public', 'repoURL': 'old'}}},
            ('statefulset', migration.CONTROLLER): {'metadata': {'uid': 'controller'}, 'spec': {'replicas': 1}},
            ('appproject.argoproj.io', 'cloudlab-root'): {'metadata': {'uid': 'project'}, 'spec': {'sourceRepos': ['old']}}}

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
