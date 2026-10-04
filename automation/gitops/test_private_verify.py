import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'verification/integration'))
from private_verify import healthy, credential_failure


class PrivateConvergenceTests(unittest.TestCase):
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
        with patch('private_verify.get', side_effect=lambda kind, name: objects.get((kind, name))), \
                patch('private_verify.kube', side_effect=kube), \
                patch('private_verify.mutate') as mutate, patch('private_verify.healthy', return_value=True), \
                patch('private_verify.wait', side_effect=[None, failure, None]):
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
