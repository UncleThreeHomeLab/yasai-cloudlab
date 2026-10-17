import copy
import json
import hashlib
import os
import subprocess
import unittest
from unittest.mock import patch
import yaml
from playbooks.services.files.contract import ROOT, render
from playbooks.services.files.examples import definitions
from playbooks.services.files import bootstrap
from playbooks.services.tests import direct_git, source_outage
from playbooks.services.tests.fixtures import notes_values


class DirectGitTests(unittest.TestCase):
    def test_known_fixture_source_manager_recovery_and_repeat(self):
        original = [{'targetRevision': 'public'}, {'targetRevision': 'main'}]
        recovery = {'uid': 'original', 'sources': original, 'manager': 'kubectl-patch', 'time': 'fixture-time'}
        for manager, request in (('kubectl-patch', recovery), (source_outage.OWNER, None),
                                 (source_outage.OWNER, recovery)):
            with self.subTest(manager=manager, recovery=request is not None):
                app = {'metadata': {'uid': 'original', 'labels': {'cloudlab.io/owner': source_outage.OWNER},
                        'managedFields': [{'manager': manager, 'operation': 'Update', 'time': 'fixture-time',
                                           'fieldsV1': {'f:spec': {'f:sources': {}}}}]},
                       'spec': {'sources': copy.deepcopy(original)}}
                def kube(*args):
                    self.assertIn('--field-manager=' + source_outage.OWNER, args)
                    value = json.loads(args[-1])
                    self.assertEqual(value[0]['value'], app['metadata']['uid'])
                    self.assertEqual(value[1]['value'], app['spec']['sources'])
                    app['spec']['sources'] = value[2]['value']
                    app['metadata']['managedFields'][0]['manager'] = source_outage.OWNER
                with patch.object(source_outage, 'get', return_value=app), \
                        patch.object(source_outage, 'converged', return_value=True), \
                        patch.object(source_outage, 'snapshot', return_value={}), \
                        patch.object(source_outage, 'wait'), patch.object(source_outage, 'kube', side_effect=kube) as mutation:
                    result = source_outage.run({}, recovery=request)
                self.assertTrue(result['private_source_recovered'])
                self.assertEqual(app['spec']['sources'], original)
                self.assertEqual(source_outage.source_managers(app), {source_outage.OWNER})
                self.assertEqual(mutation.call_count, 2)

    def test_source_manager_recovery_refuses_unqualified_scope_before_mutation(self):
        original = [{'targetRevision': 'public'}, {'targetRevision': 'main'}]
        recovery = {'uid': 'original', 'sources': original, 'manager': 'kubectl-patch', 'time': 'fixture-time'}
        for case in ('no-request', 'foreign-manager', 'mixed-managers', 'uid', 'sources', 'time', 'owner', 'refs', 'finalizers'):
            with self.subTest(case=case):
                app = {'metadata': {'uid': 'original', 'labels': {'cloudlab.io/owner': source_outage.OWNER},
                        'managedFields': [{'manager': 'kubectl-patch', 'operation': 'Update', 'time': 'fixture-time',
                                           'fieldsV1': {'f:spec': {'f:sources': {}}}}]},
                       'spec': {'sources': copy.deepcopy(original)}}
                request = copy.deepcopy(recovery)
                if case == 'no-request': request = None
                elif case == 'foreign-manager': app['metadata']['managedFields'][0]['manager'] = 'foreign'
                elif case == 'mixed-managers':
                    app['metadata']['managedFields'].append({'manager': source_outage.OWNER,
                                                             'fieldsV1': {'f:spec': {'f:sources': {}}}})
                elif case == 'uid': app['metadata']['uid'] = 'changed'
                elif case == 'sources': app['spec']['sources'][1]['targetRevision'] = 'changed'
                elif case == 'time': app['metadata']['managedFields'][0]['time'] = 'foreign-time'
                elif case == 'owner': app['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
                elif case == 'refs': app['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                elif case == 'finalizers': app['metadata']['finalizers'] = ['foreign']
                with patch.object(source_outage, 'get', return_value=app), \
                        patch.object(source_outage, 'converged', return_value=True), patch.object(source_outage, 'kube') as mutation:
                    with self.assertRaises(RuntimeError):
                        source_outage.run({}, recovery=request)
                mutation.assert_not_called()

    def test_source_outage_repairs_after_failure_and_refuses_changed_owner(self):
        for changed_owner in (False, True):
            with self.subTest(changed_owner=changed_owner):
                original = [{'targetRevision': 'public'}, {'targetRevision': 'main'}]
                app = {'metadata': {'uid': 'original', 'labels': {'cloudlab.io/owner': source_outage.OWNER},
                                    'managedFields': [{'manager': source_outage.OWNER,
                                                       'fieldsV1': {'f:spec': {'f:sources': {}}}}]},
                       'spec': {'sources': copy.deepcopy(original)}}
                def kube(*args):
                    self.assertIn('--field-manager=' + source_outage.OWNER, args)
                    patch_value = json.loads(args[-1])
                    self.assertEqual(patch_value[0], {'op': 'test', 'path': '/metadata/uid', 'value': 'original'})
                    self.assertEqual(patch_value[1]['value'], app['spec']['sources'])
                    app['spec']['sources'] = patch_value[2]['value']
                def fail_then_repair(predicate, label, timeout):
                    if 'refusal' in label:
                        if changed_owner:
                            app['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
                        raise RuntimeError('Injected proof failure')
                    self.assertEqual(app['spec']['sources'], original)
                with patch.object(source_outage, 'get', return_value=app), \
                        patch.object(source_outage, 'converged', return_value=True), \
                        patch.object(source_outage, 'snapshot', return_value={'retained': ['uid', 'hash']}), \
                        patch.object(source_outage, 'kube', side_effect=kube) as mutation, \
                        patch.object(source_outage, 'wait', side_effect=fail_then_repair):
                    message = 'ownership changed' if changed_owner else 'Injected proof failure'
                    with self.assertRaisesRegex(RuntimeError, message):
                        source_outage.run({})
                self.assertEqual(mutation.call_count, 1 if changed_owner else 2)

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

    def test_catalog_acknowledgement_wait_uses_exact_native_gate_and_bound(self):
        payload = {'revision': 'a' * 40, 'private_revision': 'b' * 40}
        with patch.dict(os.environ, {'VM_HOST': 'example.invalid'}), patch.object(direct_git, 'ssh') as ssh:
            direct_git.wait_catalog(payload)
        args, kwargs = ssh.call_args
        self.assertEqual(args[:2], ('VM', 'example.invalid'))
        self.assertIn('wait(lambda:converged(p)', args[2])
        self.assertEqual(json.loads(kwargs['input']), payload)
        self.assertEqual(kwargs['timeout'], 660)

    def test_native_notes_chart_preserves_workload_contract(self):
        definition = definitions('example.invalid', 'https://github.com/example/platform.git', 'a' * 40,
                                 'https://github.com/example/private.git', 'abcdef123456', 'notes', 'notes')['catalog'][0]['definition']
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
