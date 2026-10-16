"""Kiali's scoped namespace reads must also fit its Argo project destinations."""
import unittest
import json
from pathlib import Path
import subprocess
import yaml

from automation.gitops.render import payload
from automation.observability.chart import configuration, render


class KialiProjectTests(unittest.TestCase):
    def test_argo_owns_only_a_readonly_backend_observer_when_enabled(self):
        chart = Path(__file__).resolve().parents[2] / 'platform/delivery/argocd'
        for enabled in (False, True):
            result = subprocess.run(['helm', 'template', 'argocd', str(chart), '--namespace', 'argocd', '-f', '-'],
                input=json.dumps({'kialiBackendObserver': enabled}), text=True, capture_output=True, check=True)
            objects = [obj for obj in yaml.safe_load_all(result.stdout) if obj]
            observers = [obj for obj in objects if obj['metadata']['name'] == 'kiali-backend-observer']
            if not enabled:
                self.assertEqual(observers, [])
                continue
            self.assertEqual({obj['kind'] for obj in observers}, {'Role', 'RoleBinding'})
            self.assertTrue(all(obj['metadata']['namespace'] == 'argocd' for obj in observers))
            role = next(obj for obj in observers if obj['kind'] == 'Role')
            for rule in role['rules']:
                self.assertEqual(set(rule['verbs']), {'get', 'list', 'watch'})
                self.assertFalse({'secrets', 'pods/log', 'pods/portforward'} & set(rule['resources']))
            binding = next(obj for obj in observers if obj['kind'] == 'RoleBinding')
            self.assertEqual(binding['subjects'], [
                {'kind': 'ServiceAccount', 'name': 'cloudlab-kiali', 'namespace': 'cloudlab-observability'}])
            app = next(obj for obj in payload()['roots'] if obj['kind'] == 'Application' and obj['metadata']['name'] == 'cloudlab-argocd')
            source = app['spec'].get('source') or app['spec']['sources'][0]
            self.assertTrue(source['helm']['valuesObject']['kialiBackendObserver'])

    def test_every_namespaced_kiali_resource_has_an_explicit_project_destination(self):
        project = next(obj for obj in payload()['roots'] if obj['kind'] == 'AppProject' and
                       obj['metadata']['name'] == 'cloudlab-observability')
        allowed = {destination['namespace'] for destination in project['spec']['destinations']}
        self.assertNotIn('*', allowed)
        self.assertNotIn('argocd', allowed)
        for obj in render('kiali') + configuration(True):
            namespace = obj['metadata'].get('namespace')
            if namespace:
                with self.subTest(kind=obj['kind'], namespace=namespace):
                    self.assertIn(namespace, allowed)
