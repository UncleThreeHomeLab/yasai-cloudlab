import copy
import json
import hashlib
import os
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yaml
from playbooks.services.files.contract import ROOT, render
from playbooks.services.files.examples import definitions
from playbooks.services.files import bootstrap
from playbooks.services.tests import source_outage
from playbooks.services.tests.fixtures import catalog_payload, notes_values


class DirectGitTests(unittest.TestCase):
    def test_source_outage_preserves_complete_apply_owner_and_future_pin(self):
        for failure in ('none', 'wait', 'owner', 'sources'):
            with self.subTest(failure=failure):
                payload = catalog_payload()
                app = bootstrap.application(payload)
                app['metadata'].update(uid='original', resourceVersion='1', managedFields=[{
                    'manager': source_outage.OWNER, 'operation': 'Apply',
                    'fieldsV1': {'f:spec': {'f:sources': {}}}}])
                original = copy.deepcopy(app['spec']['sources'])
                def kube(*args, document=None, allow_failure=False):
                    self.assertTrue(allow_failure)
                    self.assertEqual(args[:4], ('apply', '--server-side', '--field-manager=service-platform', '-f'))
                    self.assertNotIn('--force-conflicts', args)
                    self.assertEqual(document['metadata']['uid'], 'original')
                    self.assertEqual(document['metadata']['resourceVersion'], app['metadata']['resourceVersion'])
                    self.assertEqual(document['spec']['syncPolicy'], app['spec']['syncPolicy'])
                    self.assertEqual(document['spec']['project'], app['spec']['project'])
                    if '--dry-run=server' not in args:
                        app['spec'] = copy.deepcopy(document['spec'])
                        app['metadata']['resourceVersion'] += '1'
                    return SimpleNamespace(returncode=0)
                def wait(predicate, label, timeout):
                    if 'refusal' in label and failure != 'none':
                        if failure == 'owner': app['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
                        if failure == 'sources': app['spec']['sources'][1]['targetRevision'] = 'foreign'
                        raise RuntimeError('Injected proof failure')
                with patch.object(source_outage, 'get', return_value=app), \
                        patch.object(source_outage, 'converged', return_value=True), \
                        patch.object(source_outage, 'snapshot', return_value={}), \
                        patch.object(source_outage, 'wait', side_effect=wait), \
                        patch.object(source_outage, 'kube', side_effect=kube) as mutation:
                    if failure == 'none':
                        self.assertTrue(source_outage.run(payload, next_revision='c' * 40)['next_source_pin_server_dry_run'])
                    else:
                        with self.assertRaises(RuntimeError):
                            source_outage.run(payload, next_revision='c' * 40)
                self.assertEqual(mutation.call_count, {'none': 4, 'wait': 3, 'owner': 2, 'sources': 2}[failure])
                if failure in ('none', 'wait'):
                    self.assertEqual(app['spec']['sources'], original)

    def test_source_outage_refuses_update_foreign_or_ambiguous_manager(self):
        for operation, manager, extra in [('Update', 'service-platform', False), ('Apply', 'foreign', False),
                                           ('Apply', 'service-platform', True)]:
            app = bootstrap.application(catalog_payload())
            entry = {'manager': manager, 'operation': operation, 'fieldsV1': {'f:spec': {'f:sources': {}}}}
            app['metadata'].update(uid='original', managedFields=[entry] * (2 if extra else 1))
            with patch.object(source_outage, 'get', return_value=app), \
                    patch.object(source_outage, 'converged', return_value=True), patch.object(source_outage, 'kube') as mutation:
                with self.assertRaises(RuntimeError):
                    source_outage.run(catalog_payload(), next_revision='c' * 40)
            mutation.assert_not_called()

    def test_source_outage_retries_only_resource_version_conflict(self):
        for retryable in (True, False):
            payload = catalog_payload()
            app = bootstrap.application(payload)
            app['metadata'].update(uid='original', resourceVersion='1', managedFields=[{
                'manager': source_outage.OWNER, 'operation': 'Apply', 'fieldsV1': {'f:spec': {'f:sources': {}}}}])
            calls = []
            def kube(*args, document=None, **kwargs):
                calls.append(document)
                if len(calls) == 1:
                    app['metadata']['resourceVersion'] = '2'
                    return SimpleNamespace(returncode=1, stderr='the object has been modified' if retryable else 'foreign conflict')
                self.assertEqual(document['metadata']['resourceVersion'], '2')
                if '--dry-run=server' not in args:
                    app['spec'] = document['spec']
                return SimpleNamespace(returncode=0)
            with patch.object(source_outage, 'get', return_value=app), \
                    patch.object(source_outage, 'converged', return_value=True), patch.object(source_outage, 'snapshot', return_value={}), \
                    patch.object(source_outage, 'wait'), patch.object(source_outage.time, 'sleep'), \
                    patch.object(source_outage, 'kube', side_effect=kube):
                if retryable:
                    self.assertTrue(source_outage.run(payload, next_revision='c' * 40)['private_source_recovered'])
                    self.assertEqual(len(calls), 5)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'Apply failed'):
                        source_outage.run(payload, next_revision='c' * 40)
                    self.assertEqual(len(calls), 1)

    def test_source_outage_refuses_unrelated_spec_and_mutable_next_revision(self):
        payload = catalog_payload()
        for revision in ('main', payload['revision']):
            with self.assertRaises(ValueError), patch.object(source_outage, 'get') as get:
                source_outage.run(payload, next_revision=revision)
            get.assert_not_called()
        app = bootstrap.application(payload)
        app['spec']['project'] = 'foreign'
        app['metadata']['managedFields'] = [{'manager': bootstrap.OWNER, 'operation': 'Apply',
                                             'fieldsV1': {'f:spec': {'f:sources': {}}}}]
        with patch.object(source_outage, 'get', return_value=app), patch.object(source_outage, 'converged', return_value=True), \
                patch.object(source_outage, 'kube') as mutation:
            with self.assertRaises(RuntimeError):
                source_outage.run(payload, next_revision='c' * 40)
        mutation.assert_not_called()

    def test_source_outage_snapshot_accepts_absent_and_empty_collections(self):
        for collection in (None, {'items': []}):
            with self.subTest(collection=collection):
                def get(kind, name=None, namespace=None):
                    if kind == 'namespaces':
                        return {'items': [{'metadata': {'name': 'cloudlab-app-example'}},
                                          {'metadata': {'name': 'foreign'}}]}
                    self.assertEqual(namespace, 'cloudlab-app-example')
                    return collection
                with patch.object(source_outage, 'get', side_effect=get):
                    self.assertEqual(source_outage.snapshot(), {})

    def test_source_outage_snapshot_preserves_uid_and_secret_content(self):
        def get(kind, name=None, namespace=None):
            if kind == 'namespaces':
                return {'items': [{'metadata': {'name': 'cloudlab-app-example'}}]}
            return {'items': [{'metadata': {'name': 'owned', 'namespace': namespace, 'uid': kind},
                               'data': {'fixture': 'content'}}]}
        with patch.object(source_outage, 'get', side_effect=get):
            actual = source_outage.snapshot()
        digest = hashlib.sha256(json.dumps({'fixture': 'content'}, sort_keys=True).encode()).hexdigest()
        self.assertEqual(actual, {kind + '/cloudlab-app-example/owned': [kind, digest]
                                 for kind in ('deployments.apps', 'services', 'secrets', 'persistentvolumeclaims')})

    def test_native_notes_chart_preserves_workload_contract(self):
        definition = definitions('example.invalid', 'https://github.com/example/platform.git', 'a' * 40,
                                 'notes', 'notes')['catalog'][0]['definition']
        issuer = 'https://login.example.invalid/realms/applications'
        for telemetry in (False, True):
            expected = notes_values(definition, issuer, '-----BEGIN CERTIFICATE-----\nfixture', telemetry)
            result = subprocess.run(['helm', 'template', 'notes', str(ROOT / 'apps/notes'),
                '-n', 'cloudlab-app-notes', '-f', '-'], input=json.dumps({
                    'definition': definition, 'issuer': issuer, 'telemetry': telemetry}),
                capture_output=True, text=True, timeout=60, check=True)
            actual = [obj for obj in yaml.safe_load_all(result.stdout) if obj and obj['kind'] != 'ConfigMap']
            desired = [obj for name in ('web', 'api') for obj in render(expected[name], 'cloudlab-app-notes')]
            def normalized(objects):
                for obj in objects:
                    if obj['kind'] == 'Deployment':
                        container = obj['spec']['template']['spec']['containers'][0]
                        container['env'] = [e for e in container['env'] if e['name'] != 'SOURCE_SHA256']
                return sorted(objects, key=lambda obj: (obj['kind'], obj['metadata']['name']))
            self.assertEqual(normalized(actual), normalized(desired))
            self.assertNotIn('BEGIN CERTIFICATE', result.stdout)

    def test_catalog_requires_both_exact_source_revisions(self):
        payload = {'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                   'private_repository': 'https://github.com/example/private.git', 'private_revision': 'b' * 40}
        app = {'spec': {'sources': [
            {'repoURL': payload['repository'], 'targetRevision': payload['revision'], 'path': 'platform/delivery/services',
             'helm': {'valueFiles': ['$values/services/catalog.json', '$values/identity/argo-values.yaml']}},
            {'repoURL': payload['private_repository'], 'targetRevision': 'main', 'ref': 'values'}]},
            'status': {'sync': {'status': 'Synced', 'revisions': ['a' * 40, 'b' * 40]},
                       'health': {'status': 'Healthy'}}}
        with patch.object(bootstrap, 'get', return_value=app):
            self.assertTrue(bootstrap.converged(payload))
            for field, value in (('revisions', ['a' * 40, 'c' * 40]), ('status', 'OutOfSync')):
                changed = copy.deepcopy(app); changed['status']['sync'][field] = value
                with patch.object(bootstrap, 'get', return_value=changed):
                    self.assertFalse(bootstrap.converged(payload))
            changed = copy.deepcopy(app); changed['status']['conditions'] = [{'type': 'ComparisonError'}]
            with patch.object(bootstrap, 'get', return_value=changed):
                self.assertFalse(bootstrap.converged(payload))
