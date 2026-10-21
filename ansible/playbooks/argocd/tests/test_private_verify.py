import copy
import base64
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / 'verification/integration'))
from private_verify import healthy, configuration_healthy, credential_owner, run
from private_failures import credential_failure


class PrivateConvergenceTests(unittest.TestCase):
    def test_main_must_resolve_to_authenticated_configuration_head(self):
        app = {'spec': {'source': {'repoURL': 'private-source', 'targetRevision': 'main'}},
               'status': {'sync': {'revision': 'a' * 40, 'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(configuration_healthy('consumer', 'private-source', 'a' * 40))
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'b' * 40))
            self.assertFalse(configuration_healthy('consumer', 'other-source', 'a' * 40))
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'main'))

    def test_native_private_values_main_requires_authenticated_head_without_relaxing_other_sources(self):
        app = {'spec': {'sources': [{'repoURL': 'public-source', 'targetRevision': 'main'},
                                   {'repoURL': 'private-source', 'targetRevision': 'main', 'ref': 'values'}]},
               'status': {'sync': {'status': 'Synced', 'revisions': ['a' * 40, 'b' * 40]},
                          'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
        original = copy.deepcopy(app)
        with patch('private_verify.get', return_value=app):
            self.assertTrue(configuration_healthy('consumer', 'private-source', 'b' * 40))
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'c' * 40))
        self.assertEqual(app, original)
        for target in ('c' * 40, 'unapproved-branch'):
            changed = copy.deepcopy(app)
            changed['spec']['sources'][1]['targetRevision'] = target
            with patch('private_verify.get', return_value=changed):
                self.assertFalse(configuration_healthy('consumer', 'private-source', 'b' * 40))
        changed = copy.deepcopy(app)
        changed['spec']['sources'].append({'repoURL': 'other-source', 'targetRevision': 'main'})
        changed['status']['sync']['revisions'].append('d' * 40)
        with patch('private_verify.get', return_value=changed):
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'b' * 40))

    def test_private_credential_requires_exact_project_and_ready_eso_owner(self):
        app = {'spec': {'project': 'approved'}}
        secret = {'metadata': {'name': 'source', 'labels': {'argocd.argoproj.io/secret-type': 'repository'},
                               'ownerReferences': [{'kind': 'ExternalSecret', 'uid': 'owner'}]},
                  'data': {key: base64.b64encode(value.encode()).decode() for key, value in {
                      'url': 'private-source', 'project': 'approved', 'githubAppID': '1',
                      'githubAppInstallationID': '2', 'githubAppPrivateKey': 'synthetic'}.items()}}
        external = {'metadata': {'name': 'source', 'uid': 'owner'},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        credential_owner(app, 'private-source', [secret], [external])
        for changed, externals in ((dict(secret, data=dict(secret['data'], project='')), [external]),
                                   (dict(secret, metadata=dict(secret['metadata'], ownerReferences=[])), [external]),
                                   (secret, [dict(external, status={})])):
            with self.subTest(changed=changed['metadata']['name']), self.assertRaises(RuntimeError):
                credential_owner(app, 'private-source', [changed], externals)
        with self.assertRaises(RuntimeError):
            credential_owner(app, 'private-source', [secret, secret], [external])

    def test_missing_private_capability_never_passes_as_verified(self):
        self.assertFalse(run({'sources': []})['private_access_verified'])
        with patch('private_verify.kube', return_value='{"items": []}'), self.assertRaises(RuntimeError):
            run({'sources': [], 'configuration_repository': 'private-source'})

    def test_native_multiple_sources_require_every_pinned_values_revision(self):
        app = {'spec': {'sources': [{'targetRevision': 'main'}, {'targetRevision': 'b' * 40}]},
               'status': {'sync': {'status': 'Synced', 'revisions': ['a' * 40, 'b' * 40]},
                          'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(healthy('cloudlab-argocd'))
        for revisions, target in ((['a' * 40], 'b' * 40), (['a' * 40, 'c' * 40], 'b' * 40),
                                  (['a' * 40, 'main'], 'main')):
            changed = copy.deepcopy(app)
            changed['status']['sync']['revisions'] = revisions
            changed['spec']['sources'][1]['targetRevision'] = target
            with self.subTest(revisions=revisions), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('cloudlab-argocd'))

    def probe(self, failure=None, foreign=False, interrupted=False):
        probe = 'cloudlab-private-credential-check'
        objects = {('secret', 'fixture'): {'data': {'githubAppPrivateKey': 'original-secret'}},
                   ('application.argoproj.io', 'fixture'): {'spec': {'source': {'repoURL': 'https://example.invalid/test'}}}}
        if foreign:
            objects[('secret', probe)] = {'metadata': {'labels': {}}}
        kinds = {'Application': 'application.argoproj.io', 'Secret': 'secret',
                 'AppProject': 'appproject.argoproj.io', 'Namespace': 'namespace'}
        if interrupted:
            for kind in kinds.values():
                objects[kind, probe] = {'metadata': {'labels': {'cloudlab.io/verification': 'private-credential-check'}}}
        calls = []
        def kube(*args, document=None):
            calls.append((args, copy.deepcopy(document)))
            if args[0] == 'create':
                objects[kinds[document['kind']], probe] = copy.deepcopy(document)
            elif args[0] == 'delete':
                objects.pop((args[1], args[2]))
            elif args[0] == 'get':
                return json.dumps({'metadata': {'uid': 'probe-uid'}, 'data': {'proof': 'private-source-converged'}})
        with patch('private_failures.get', side_effect=lambda kind, name: objects.get((kind, name))), \
                patch('private_failures.kube', side_effect=kube), \
                patch('private_failures.mutate') as mutate, patch('private_failures.healthy', return_value=True), \
                patch('private_failures.wait', side_effect=[None, failure, None]):
            if failure or foreign:
                with self.assertRaisesRegex(RuntimeError, 'probe failed|ownership mismatch'):
                    credential_failure('fixture', lambda: {'metadata': {'uid': 'retained-uid'}}, 'retained-uid')
            else:
                credential_failure('fixture', lambda: {'metadata': {'uid': 'retained-uid'}}, 'retained-uid')
        self.assertTrue(all(call.args[0] == probe for call in mutate.call_args_list))
        self.assertTrue(all(args[1:3] == ('secret', probe) for args, _ in calls if args[0] == 'patch'))
        self.assertFalse(any(args[1:2] == ('externalsecret.external-secrets.io',) for args, _ in calls))
        self.assertEqual(objects['secret', 'fixture']['data']['githubAppPrivateKey'], 'original-secret')
        return calls, objects

    def test_successful_probe_only_writes_isolated_credential_and_cleans_up(self):
        calls, objects = self.probe()
        self.assertEqual(sum(args[0] == 'patch' for args, _ in calls), 2)
        self.assertEqual(len(objects), 2)

    def test_provider_independent_failure_cleanup_preserves_working_secret(self):
        calls, objects = self.probe(RuntimeError('probe failed'))
        self.assertEqual(sum(args[0] == 'delete' for args, _ in calls), 4)
        self.assertEqual(len(objects), 2)

    def test_foreign_probe_resource_blocks_all_writes(self):
        calls, _ = self.probe(foreign=True)
        self.assertEqual(calls, [])

    def test_interrupted_fixture_is_removed_before_new_baseline(self):
        calls, objects = self.probe(interrupted=True)
        self.assertEqual([args[0] for args, _ in calls[:4]], ['delete'] * 4)
        self.assertEqual(len(objects), 2)

    def test_retained_resources_can_converge_without_a_new_sync_operation(self):
        app = {'status': {'sync': {'status': 'Synced', 'revision': 'resolved-commit'},
                          'health': {'status': 'Healthy'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(healthy('fixture'))
        for phase in ('Running', 'Failed', 'Error', 'Terminating'):
            changed = copy.deepcopy(app)
            changed['status']['operationState'] = {'phase': phase}
            with self.subTest(phase=phase), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('fixture'))
        for change in ({'sync': {'status': 'Synced'}}, {'conditions': [{'type': 'ComparisonError'}]},
                       {'sync': {'status': 'Unknown', 'revision': 'old'}}):
            changed = copy.deepcopy(app)
            changed['status'].update(change)
            with self.subTest(change=change), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('fixture'))
