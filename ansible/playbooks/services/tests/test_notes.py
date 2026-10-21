"""Platform packaging and workload contracts for the working Notes example."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from playbooks.services.files.check import run

ROOT = Path(__file__).resolve().parents[4]


class NotesPackagingTests(unittest.TestCase):
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
