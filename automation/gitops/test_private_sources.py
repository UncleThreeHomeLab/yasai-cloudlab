import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import private_bootstrap
from private_sources import PEM_TEMPLATE, resources, sources


ENTRY = {'name': 'fixture', 'repository': 'https://github.com/example/private.git',
         'revision': 'main', 'path': 'gitops'}


class PrivateSourceTests(unittest.TestCase):
    def test_base_has_no_private_dependency_and_omission_never_deletes(self):
        self.assertEqual(sources(''), [])
        with patch.object(private_bootstrap, 'kube') as kube:
            self.assertFalse(private_bootstrap.run({'sources': []})['changed'])
        kube.assert_not_called()

    def test_rejects_unsafe_and_ambiguous_inputs(self):
        for change in ({'name': '../argocd'}, {'path': '../escape'}, {'path': '/absolute'},
                       {'repository': 'https://secret@github.com/example/repo.git'},
                       {'namespace': 'argocd'}, {'revision': '-flag'}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                sources(json.dumps([dict(ENTRY, **change)]))
        with self.assertRaises(RuntimeError):
            sources(json.dumps([ENTRY, ENTRY]))

    def test_projects_and_repository_credentials_are_scoped(self):
        namespace, project, secret, app = resources(ENTRY, 'fixture-store')
        self.assertEqual(project['spec']['sourceRepos'], [ENTRY['repository']])
        self.assertEqual(project['spec']['destinations'][0]['namespace'], namespace['metadata']['name'])
        self.assertNotEqual(namespace['metadata']['name'], 'argocd')
        self.assertEqual(project['spec']['clusterResourceWhitelist'], [])
        forbidden = {'Secret', 'Role', 'RoleBinding', 'Application', 'AppProject', 'ExternalSecret', 'Gateway'}
        self.assertFalse(forbidden & {x['kind'] for x in project['spec']['namespaceResourceWhitelist']})
        self.assertEqual(secret['spec']['target']['template']['data']['project'], project['metadata']['name'])
        self.assertEqual(secret['spec']['secretStoreRef']['name'], 'fixture-store')
        self.assertEqual(secret['spec']['target']['template']['data']['githubAppPrivateKey'], PEM_TEMPLATE)
        self.assertEqual(secret['spec']['dataFrom'], [{'extract': {'key': 'github-argocd'}}])
        self.assertNotIn('data', secret['spec'])
        self.assertEqual(secret['spec']['refreshInterval'], '5m')
        self.assertEqual(secret['spec']['target']['template']['mergePolicy'], 'Replace')
        self.assertNotIn('PRIVATE_KEY', secret['spec']['target']['template']['data'])
        self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
        self.assertNotIn('finalizers', app['metadata'])

    def test_interrupted_configuration_resumes_and_repeat_is_unchanged(self):
        objects = {}
        failure = [True]
        def key(obj): return obj['kind'], obj['metadata']['name']
        def apply(*args, document):
            self.assertNotIn('--force-conflicts', args)
            if document['kind'] == 'ExternalSecret' and failure[0]:
                failure[0] = False
                raise RuntimeError('Injected interruption')
            obj = copy.deepcopy(document)
            obj['metadata']['uid'] = 'uid-' + obj['kind']
            objects[key(obj)] = obj
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'checkpoint.json').write_text('{"phase":"accepted"}')
            with patch.object(private_bootstrap, 'BASE', base), \
                    patch.object(private_bootstrap, 'current', side_effect=lambda obj: objects.get(key(obj))), \
                    patch.object(private_bootstrap, 'kube', side_effect=apply) as kube:
                payload = {'sources': [ENTRY], 'store': 'fixture-store'}
                with self.assertRaisesRegex(RuntimeError, 'Injected'):
                    private_bootstrap.run(payload)
                previous = copy.deepcopy(objects)
                self.assertTrue(private_bootstrap.run(payload)['changed'])
                for name, obj in previous.items():
                    self.assertEqual(objects[name]['metadata']['uid'], obj['metadata']['uid'])
                count = kube.call_count
                self.assertFalse(private_bootstrap.run(payload)['changed'])
                self.assertEqual(count, kube.call_count)

    def test_removal_refuses_a_still_configured_source(self):
        with self.assertRaises(RuntimeError):
            private_bootstrap.remove({'sources': [ENTRY], 'remove': 'fixture'})

    def test_removal_only_deletes_owned_root_and_credentials(self):
        objects = resources(ENTRY, 'fixture-store')
        for obj in objects:
            obj['metadata']['uid'] = 'uid-' + obj['kind']
        state = {'phase': 'accepted', 'identities': {obj['kind']: obj['metadata']['uid'] for obj in objects}}
        def current(query):
            return next((obj for obj in objects if obj['kind'] == query['kind']), None)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            checkpoint = base / 'private-fixture.json'
            checkpoint.write_text(json.dumps(state))
            with patch.object(private_bootstrap, 'BASE', base), \
                    patch.object(private_bootstrap, 'current', side_effect=current), \
                    patch.object(private_bootstrap, 'kube') as kube:
                self.assertTrue(private_bootstrap.remove({'sources': [], 'remove': 'fixture'})['workloads_retained'])
                kinds = [call.args[1] for call in kube.call_args_list]
                self.assertEqual(kinds, ['application.argoproj.io', 'externalsecret.external-secrets.io',
                                         'appproject.argoproj.io'])
                self.assertFalse(private_bootstrap.remove({'sources': [], 'remove': 'fixture'})['changed'])

    def test_removal_rejects_cascading_finalizers(self):
        app = resources(ENTRY, 'fixture-store')[-1]
        app['metadata'].update(uid='app', finalizers=['resources-finalizer.argocd.argoproj.io'])
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'private-fixture.json').write_text('{"phase":"accepted","identities":{"Application":"app"}}')
            with patch.object(private_bootstrap, 'BASE', base), \
                    patch.object(private_bootstrap, 'current', return_value=app), \
                    patch.object(private_bootstrap, 'kube') as kube:
                with self.assertRaisesRegex(RuntimeError, 'ownership mismatch'):
                    private_bootstrap.remove({'sources': [], 'remove': 'fixture'})
                kube.assert_not_called()
