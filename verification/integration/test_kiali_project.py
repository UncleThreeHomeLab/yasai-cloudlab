"""Kiali's scoped namespace reads must also fit its Argo project destinations."""
import unittest

from automation.gitops.render import payload
from automation.observability.chart import configuration, render


class KialiProjectTests(unittest.TestCase):
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
