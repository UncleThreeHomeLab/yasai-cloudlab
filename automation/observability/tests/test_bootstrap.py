import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from automation.observability.bootstrap import application, seed, run, COMPONENTS


class BootstrapTests(unittest.TestCase):
    def test_cold_configuration_can_resolve_secrets_before_backend_routes_become_healthy(self):
        payload = self.payload()
        current = application(payload, 'configuration')
        self.assertNotIn('valueFiles', current['spec']['source']['helm'])
        self.assertNotIn('valuesObject', application(payload, 'loki')['spec']['source']['helm'])
        current['status'] = {'health': {'status': 'Degraded'}, 'operationState': {'phase': 'Succeeded'},
            'sync': {'status': 'Synced', 'revision': payload['revision'],
                     'comparedTo': {'source': current['spec']['source']}}}
        def wait(predicate, *_args, **_kwargs): self.assertTrue(predicate())
        with patch('automation.observability.bootstrap.get', return_value=current), \
                patch('automation.observability.bootstrap.kube') as mutate, \
                patch('automation.observability.bootstrap.wait', side_effect=wait):
            self.assertFalse(seed(payload, 'configuration'))
        mutate.assert_not_called()

    def payload(self):
        return {'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                'configuration': {'enabled': True}, 'components': {name: {} for name in COMPONENTS}}

    def test_existing_application_cannot_transfer_from_another_owner_or_source(self):
        payload = self.payload()
        current = application(payload, 'loki')
        with patch('automation.observability.bootstrap.get', return_value=current), \
                patch('automation.observability.bootstrap.kube') as kube, \
                patch('automation.observability.bootstrap.wait'):
            self.assertFalse(seed(payload, 'loki'))
            for change in ('owner', 'namespace', 'repository', 'path'):
                other = copy.deepcopy(current)
                if change == 'owner': other['metadata']['labels']['cloudlab.io/owner'] = 'unrelated'
                if change == 'namespace': other['spec']['destination']['namespace'] = 'argocd'
                if change == 'repository': other['spec']['source']['repoURL'] = 'https://github.com/example/other.git'
                if change == 'path': other['spec']['source']['path'] = 'other'
                with patch('automation.observability.bootstrap.get', return_value=other):
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
                with patch('automation.observability.bootstrap.Path', side_effect=lambda _: Path(directory) / 'lock'), \
                        patch('automation.observability.bootstrap.get', side_effect=get), \
                        patch('automation.observability.bootstrap.seed', side_effect=seed), \
                        patch('automation.observability.bootstrap.wait'):
                    result = run(self.payload())
            self.assertEqual(result['changed'], not apis)
            self.assertEqual(observed[0], ('configuration', apis))
            if not apis: self.assertEqual(observed[-1], ('configuration', True))
            else: self.assertEqual(sum(name == 'configuration' for name, _ in observed), 1)
