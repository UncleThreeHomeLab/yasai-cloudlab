import copy
import json
import subprocess
import unittest
from unittest.mock import patch
import yaml
from playbooks.services.files.contract import ROOT, render
from playbooks.services.files.examples import definitions
from playbooks.services.files import catalog
from playbooks.services.tests.fixtures import notes_values


class DirectGitTests(unittest.TestCase):
    def test_native_notes_chart_preserves_workload_contract(self):
        definition = definitions('example.invalid', 'https://github.com/example/platform.git', 'a' * 40,
                                 'notes', 'notes')['catalog'][0]['definition']
        issuer = 'https://login.example.invalid/realms/applications'
        for telemetry in (False, True):
            expected = notes_values(definition, issuer, '-----BEGIN CERTIFICATE-----\nfixture', telemetry)
            result = subprocess.run(['helm', 'template', 'notes', str(ROOT / 'apps/notes'),
                '-n', 'cloudlab-app-notes', '-f', '-'], input=json.dumps({
                    'definition': definition, 'issuer': issuer, 'telemetry': telemetry}),
                capture_output=True, text=True, timeout=60, check=True)
            actual = [obj for obj in yaml.safe_load_all(result.stdout) if obj and obj['kind'] != 'ConfigMap']
            desired = [obj for name in ('web', 'api') for obj in render(expected[name], 'cloudlab-app-notes')]
            def normalized(objects):
                for obj in objects:
                    if obj['kind'] == 'Deployment':
                        container = obj['spec']['template']['spec']['containers'][0]
                        container['env'] = [e for e in container['env'] if e['name'] != 'SOURCE_SHA256']
                return sorted(objects, key=lambda obj: (obj['kind'], obj['metadata']['name']))
            self.assertEqual(normalized(actual), normalized(desired))
            self.assertNotIn('BEGIN CERTIFICATE', result.stdout)

    def test_catalog_requires_both_exact_source_revisions(self):
        payload = {'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                   'private_repository': 'https://github.com/example/private.git', 'private_revision': 'b' * 40, 'telemetry': False}
        from playbooks.services.tests.fixtures import catalog_application
        app = catalog_application(payload)
        with patch.object(catalog, 'get', return_value=app):
            self.assertTrue(catalog.converged(payload))
            for field, value in (('revisions', ['a' * 40, 'c' * 40]), ('status', 'OutOfSync')):
                changed = copy.deepcopy(app); changed['status']['sync'][field] = value
                with patch.object(catalog, 'get', return_value=changed):
                    self.assertFalse(catalog.converged(payload))
            changed = copy.deepcopy(app); changed['status']['conditions'] = [{'type': 'ComparisonError'}]
            with patch.object(catalog, 'get', return_value=changed):
                self.assertFalse(catalog.converged(payload))
