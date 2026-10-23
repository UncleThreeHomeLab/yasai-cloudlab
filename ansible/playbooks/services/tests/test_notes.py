"""Platform packaging and workload contracts for the working Notes example."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import json
import yaml
from unittest.mock import patch
from playbooks.services.files.check import run

ROOT = Path(__file__).resolve().parents[4]


class NotesPackagingTests(unittest.TestCase):
    def test_signed_notes_canary_renders_real_frontend_and_preserves_api(self):
        from playbooks.services.files.examples import definitions
        from playbooks.services.files.gitops import resources
        entry = definitions('example.invalid', 'https://github.com/example/public.git', 'a' * 40,
                            'notes', 'notes')['catalog'][0]
        value = entry['definition']
        value['rollouts']['enabled'] = True
        value['ports'].append({'name': 'http-metrics', 'port': 9091})
        value['resources']['limits'] = {'cpu': '200m', 'memory': '256Mi'}
        def render(telemetry=True):
            return subprocess.run(['helm', 'template', 'notes', str(ROOT / 'apps/notes'), '-n', 'cloudlab-app-notes', '-f', '-'],
                input=json.dumps({'definition': value, 'issuer': 'https://login.example.invalid/realms/applications',
                                  'telemetry': telemetry, 'packaged': True, 'imagePullSecrets': []}),
                capture_output=True, text=True, timeout=30)
        result = render()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [row for row in yaml.safe_load_all(result.stdout) if row]
        self.assertEqual([row['metadata']['name'] for row in rows if row['kind'] == 'Rollout'], ['notes-web'])
        self.assertEqual([row['metadata']['name'] for row in rows if row['kind'] == 'Deployment'], ['notes-api'])
        rollout = next(row for row in rows if row['kind'] == 'Rollout')
        self.assertEqual(rollout['spec']['template']['spec']['containers'][0]['command'], ['python', '/app/web.py'])
        analysis = next(row for row in rows if row['kind'] == 'AnalysisTemplate')
        self.assertTrue(all('service="notes-web"' in metric['provider']['prometheus']['query'] for metric in analysis['spec']['metrics']))
        catalog = resources(value, entry['approval'], entry['approval']['repository'], 'a' * 40)
        template = next(row for row in catalog if row['kind'] == 'ApplicationSet')['spec']['template']['spec']
        self.assertIn('notes-web-canary', template['ignoreDifferences'][0]['jqPathExpressions'][0])
        self.assertNotEqual(render(False).returncode, 0)
        value['resources']['limits'] = {'cpu': '400m', 'memory': '384Mi'}
        self.assertIn('exceed the namespace budget', render().stderr)

    def test_telemetry_activation_preserves_shared_api_imports_in_a_fresh_process(self):
        from playbooks.services.files.examples import definitions
        from playbooks.services.tests.fixtures import notes_values as values
        definition = definitions('example.invalid', 'https://github.com/example/public.git', 'a' * 40,
                                 'notes', 'notes')['catalog'][0]['definition']
        compiled = values(definition, 'https://login.example.invalid/realms/applications',
                          '-----BEGIN CERTIFICATE-----\nfixture', telemetry=True)
        for name in ('web', 'api'):
            self.assertIn({'name': 'http-metrics', 'port': 9091}, compiled[name]['ports'])
        python_path = compiled['api']['environment']['PYTHONPATH'].replace('/config/source', str(ROOT / 'apps/notes'))
        with tempfile.TemporaryDirectory() as directory:
            imported = subprocess.run([sys.executable, '-c', 'import api; import telemetry; print("ready")'],
                cwd=directory, env={'PATH': os.environ['PATH'], 'PYTHONPATH': python_path, 'OTEL_ENABLED': '0'},
                capture_output=True, text=True, timeout=30)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual(imported.stdout.strip(), 'ready')

    def test_api_source_change_triggers_only_its_workload_rollout(self):
        from playbooks.services.files.examples import definitions
        from playbooks.services.tests.fixtures import notes_values as values
        definition = definitions('example.invalid','https://github.com/example/public.git','a'*40,
                                 'notes','notes')['catalog'][0]['definition']
        original = Path.read_bytes
        issuer = 'https://login.example.invalid/realms/applications'
        before = values(definition, issuer, '-----BEGIN CERTIFICATE-----\nfixture')
        with patch.object(Path, 'read_bytes', lambda path: b'changed fixture source' if path.name == 'api.py' else original(path)):
            after = values(definition, issuer, '-----BEGIN CERTIFICATE-----\nfixture')
        self.assertNotEqual(before['api']['environment']['SOURCE_SHA256'], after['api']['environment']['SOURCE_SHA256'])
        self.assertEqual(before['web']['environment']['SOURCE_SHA256'], after['web']['environment']['SOURCE_SHA256'])

    def test_chart_and_shared_code_match_authoritative_sources(self):
        self.assertEqual(run()['notes_services'], 2)
