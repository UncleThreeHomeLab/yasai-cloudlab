"""Retired services render only their retained claim, never workloads."""
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / 'charts/service'


def render(*overrides):
    if shutil.which('helm') is None:
        raise unittest.SkipTest('helm renders the service chart')
    command = ['helm', 'template', str(CHART)]
    for key, value in overrides:
        command += ['--set', '%s=%s' % (key, value)]
    completed = subprocess.run(command, capture_output=True, text=True, check=True)
    return [document for document in
            yaml.safe_load_all(completed.stdout) if document]


class RetiredClaimTests(unittest.TestCase):
    def test_retired_with_persistence_renders_only_the_claim(self):
        documents = render(('renderDisabled', 'true'), ('persistence.enabled', 'true'))
        self.assertEqual([document['kind'] for document in documents],
                         ['PersistentVolumeClaim'])
        claim = documents[0]
        self.assertEqual(claim['metadata']['name'], 'synthetic')
        self.assertEqual(claim['spec']['resources']['requests']['storage'], '1Gi')
        self.assertIn('Prune=false', claim['metadata']['annotations'][
            'argocd.argoproj.io/sync-options'])

    def test_retired_without_persistence_renders_nothing(self):
        self.assertEqual(render(('renderDisabled', 'true')), [])

    def test_active_service_keeps_workloads(self):
        kinds = {document['kind'] for document in render()}
        self.assertTrue({'Deployment', 'Service'}.issubset(kinds))
        self.assertNotIn('PersistentVolumeClaim', kinds)


if __name__ == '__main__':
    unittest.main()
