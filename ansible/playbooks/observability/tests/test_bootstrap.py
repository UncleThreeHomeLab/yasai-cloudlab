import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from playbooks.observability.files.bootstrap import application, seed, run, COMPONENTS, history_patches


class BootstrapTests(unittest.TestCase):
    def test_owned_source_update_guards_identity_and_preserves_unrelated_fields(self):
        payload = self.payload()
        current = application(payload, 'prometheus')
        current['metadata'].update(uid='owned', resourceVersion='7')
        current['spec']['unrelated'] = {'retain': True}
        payload['revision'] = 'b' * 40
        payload['components']['prometheus'] = {'large': 'x' * 150000}
        with patch('playbooks.observability.files.bootstrap.get', return_value=current), \
                patch('playbooks.observability.files.bootstrap.kube') as mutate, \
                patch('playbooks.observability.files.bootstrap.wait'):
            self.assertTrue(seed(payload, 'prometheus'))
        args = mutate.call_args.args
        self.assertEqual(args[0], 'patch')
        self.assertEqual(args[-2:], ('--patch-file', '/dev/stdin'))
        self.assertLess(sum(len(arg) for arg in args), 1024)
        patches = mutate.call_args.kwargs['document']
        self.assertGreater(len(json.dumps(patches)), 131072)
        self.assertEqual(patches[:2], [{'op': 'test', 'path': '/metadata/uid', 'value': 'owned'},
                                      {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'}])
        self.assertEqual([p['path'] for p in patches[2:]], ['/spec/source'])
        self.assertEqual(patches[2]['value']['targetRevision'], payload['revision'])
        self.assertEqual(current['spec']['unrelated'], {'retain': True})

    def test_history_recovery_retains_latest_and_refuses_foreign_sources(self):
        current = application(self.payload(), 'prometheus')
        self.assertEqual(current['spec']['revisionHistoryLimit'], 0)
        current['metadata'].update(uid='owned', resourceVersion='7')
        source = current['spec']['source']
        current['status'] = {'history': [{'id': 1, 'source': copy.deepcopy(source)},
                                         {'id': 2, 'source': copy.deepcopy(source)}]}
        patches = history_patches(current)
        self.assertEqual(patches[:2], [{'op': 'test', 'path': '/metadata/uid', 'value': 'owned'},
                                      {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'}])
        self.assertEqual(patches[-1], {'op': 'remove', 'path': '/status/history/0'})
        large = copy.deepcopy(current)
        for row in large['status']['history']:
            row['source']['helm']['valuesObject'] = {'large': 'x' * 400000}
        self.assertLess(len(json.dumps(history_patches(large))), 1024)
        previous = copy.deepcopy(current)
        previous['spec'].pop('revisionHistoryLimit')
        self.assertIn({'op': 'add', 'path': '/spec/revisionHistoryLimit', 'value': 0}, history_patches(previous))
        for change in ('owner', 'repository', 'path', 'application'):
            other = copy.deepcopy(current)
            if change == 'owner': other['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            elif change == 'repository': other['status']['history'][0]['source']['repoURL'] = 'https://foreign.invalid/repo'
            elif change == 'path': other['status']['history'][0]['source']['path'] = 'other'
            else: other['metadata']['name'] = 'unrelated'
            with self.assertRaises(RuntimeError): history_patches(other)
        current['status']['history'] = current['status']['history'][-1:]
        self.assertEqual(history_patches(current), [])

    def test_oversized_inline_source_fails_before_mutation(self):
        payload = self.payload()
        payload['components']['prometheus'] = {'too_large': 'x' * (320 * 1024)}
        with patch('playbooks.observability.files.bootstrap.kube') as mutate:
            with self.assertRaisesRegex(ValueError, 'budget'): seed(payload, 'prometheus')
            mutate.assert_not_called()

    def test_cold_configuration_can_resolve_secrets_before_backend_routes_become_healthy(self):
        payload = self.payload()
        current = application(payload, 'configuration')
        self.assertNotIn('valueFiles', current['spec']['source']['helm'])
        self.assertNotIn('valuesObject', application(payload, 'loki')['spec']['source']['helm'])
        current['status'] = {'health': {'status': 'Degraded'}, 'operationState': {'phase': 'Succeeded'},
            'sync': {'status': 'Synced', 'revision': payload['revision'],
                     'comparedTo': {'source': current['spec']['source']}}}
        def wait(predicate, *_args, **_kwargs): self.assertTrue(predicate())
        with patch('playbooks.observability.files.bootstrap.get', return_value=current), \
                patch('playbooks.observability.files.bootstrap.kube') as mutate, \
                patch('playbooks.observability.files.bootstrap.wait', side_effect=wait):
            self.assertFalse(seed(payload, 'configuration'))
        mutate.assert_not_called()

    def payload(self):
        return {'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                'configuration': {'enabled': True}, 'components': {name: {} for name in COMPONENTS}}

    def test_existing_application_cannot_transfer_from_another_owner_or_source(self):
        payload = self.payload()
        current = application(payload, 'loki')
        with patch('playbooks.observability.files.bootstrap.get', return_value=current), \
                patch('playbooks.observability.files.bootstrap.kube') as kube, \
                patch('playbooks.observability.files.bootstrap.wait'):
            self.assertFalse(seed(payload, 'loki'))
            for change in ('owner', 'namespace', 'repository', 'path'):
                other = copy.deepcopy(current)
                if change == 'owner': other['metadata']['labels']['cloudlab.io/owner'] = 'unrelated'
                if change == 'namespace': other['spec']['destination']['namespace'] = 'argocd'
                if change == 'repository': other['spec']['source']['repoURL'] = 'https://github.com/example/other.git'
                if change == 'path': other['spec']['source']['path'] = 'other'
                with patch('playbooks.observability.files.bootstrap.get', return_value=other):
                    with self.assertRaises(RuntimeError): seed(payload, 'loki')
            kube.assert_not_called()

    def test_monitor_api_bootstrap_order_and_repeat_do_not_toggle_ready_configuration(self):
        for apis in (False, True):
            observed = []
            def seed(payload, name):
                observed.append((name, payload['configuration']['monitoringEnabled']))
                return not apis
            def get(kind, name):
                return {'api': True} if kind == 'crd' and apis else None
            with tempfile.TemporaryDirectory() as directory:
                with patch('playbooks.observability.files.bootstrap.Path', side_effect=lambda _: Path(directory) / 'lock'), \
                        patch('playbooks.observability.files.bootstrap.get', side_effect=get), \
                        patch('playbooks.observability.files.bootstrap.seed', side_effect=seed), \
                        patch('playbooks.observability.files.bootstrap.wait'):
                    result = run(self.payload())
            self.assertEqual(result['changed'], not apis)
            self.assertEqual(observed[0], ('configuration', apis))
            if not apis: self.assertEqual(observed[-1], ('configuration', True))
            else: self.assertEqual(sum(name == 'configuration' for name, _ in observed), 1)
