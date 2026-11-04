"""Run rendered certificate health customizations through the pinned native Argo CLI."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from render import OPERATOR, payload


class CertificateHealthTests(unittest.TestCase):
    def test_native_health_requires_current_generation_and_prioritizes_issuance(self):
        binary = shutil.which('argocd')
        if not binary:
            self.skipTest('Pinned Argo CLI is required for native Lua execution')
        expected_version = json.loads((OPERATOR / 'artifact.lock.json').read_text())['chart']['app_version']
        version = subprocess.check_output([binary, 'version', '--client', '--short'], text=True, timeout=30)
        self.assertEqual(version.split(':', 1)[-1].strip().split('+')[0], expected_version)
        cm = next(obj for obj in payload()['operator'] if obj['kind'] == 'ConfigMap' and obj['metadata']['name'] == 'argocd-cm')
        self.assertFalse(any('useOpenLibs' in key for key in cm['data']))
        keys = ['resource.customizations.health.cert-manager.io_' + kind for kind in ('Certificate', 'ClusterIssuer')]
        self.assertEqual(cm['data'][keys[0]], cm['data'][keys[1]])
        ready = {'type': 'Ready', 'status': 'True', 'observedGeneration': 2}
        issuing = {'type': 'Issuing', 'status': 'True', 'observedGeneration': 2}
        cases = [({}, 'Progressing'), ({'conditions': []}, 'Progressing'),
                 ({'conditions': [ready | {'observedGeneration': 1}]}, 'Progressing'),
                 ({'conditions': [{'type': 'Ready', 'status': 'True'}]}, 'Progressing'),
                 ({'conditions': [ready]}, 'Healthy'),
                 ({'conditions': [ready | {'status': 'False'}]}, 'Degraded'),
                 ({'conditions': [ready | {'status': 'Unknown'}]}, 'Progressing'),
                 ({'conditions': [ready, issuing]}, 'Progressing'),
                 ({'conditions': [ready, issuing | {'observedGeneration': 1}]}, 'Healthy')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'cm.yaml').write_text(json.dumps(cm))
            for kind in ('Certificate', 'ClusterIssuer'):
                for status, expected in cases:
                    with self.subTest(kind=kind, status=status):
                        resource = {'apiVersion': 'cert-manager.io/v1', 'kind': kind,
                            'metadata': {'name': 'fixture', 'generation': 2}, 'status': status}
                        (root / 'resource.yaml').write_text(json.dumps(resource))
                        result = subprocess.run([binary, 'admin', 'settings', 'resource-overrides', 'health',
                            str(root / 'resource.yaml'), '--argocd-cm-path', str(root / 'cm.yaml'),
                            '--load-cluster-settings=false', '--kubeconfig', '/dev/null'],
                            capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn('STATUS: ' + expected, result.stdout.splitlines())
