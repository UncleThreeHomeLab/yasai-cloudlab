"""Storage's project permits its reviewed chart but not data or credential objects."""
import subprocess
import unittest

import yaml

from chart import ROOT, render


class StorageProjectTests(unittest.TestCase):
    def test_scoped_project_covers_chart_without_volume_or_secret_authority(self):
        root = ROOT.parents[2] / 'gitops/roots/public'
        rendered = subprocess.check_output(['helm', 'template', 'root', str(root), '--set', 'longhorn.enabled=true'], text=True)
        objects = [x for x in yaml.safe_load_all(rendered) if x]
        project = next(x['spec'] for x in objects if x['kind'] == 'AppProject' and x['metadata']['name'] == 'cloudlab-longhorn')
        self.assertEqual([x['namespace'] for x in project['destinations']], ['longhorn-system'])
        self.assertEqual(len(project['sourceRepos']), 1)
        self.assertNotIn('*', project['sourceRepos'][0])
        cluster = {(x['group'], x['kind']) for x in project['clusterResourceWhitelist']}
        namespaced = {(x['group'], x['kind']) for x in project['namespaceResourceWhitelist']}
        for obj in render():
            group = obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
            self.assertIn((group, obj['kind']), namespaced if obj['metadata'].get('namespace') else cluster)
        for kind in ('Secret', 'PersistentVolumeClaim', 'Volume', 'Application', 'ExternalSecret'):
            self.assertNotIn(kind, {x[1] for x in namespaced})
        self.assertNotIn(('', 'PersistentVolume'), cluster)
        app = next(x for x in objects if x['kind'] == 'Application' and x['metadata']['name'] == 'cloudlab-longhorn')
        self.assertNotIn('finalizers', app['metadata'])
        self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
