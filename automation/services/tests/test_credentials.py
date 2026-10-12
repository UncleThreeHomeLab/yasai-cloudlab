import json
import subprocess
import unittest

import yaml

from automation.services.contract import ROOT
from automation.services.tests.fixtures import definition, approval


class CredentialTests(unittest.TestCase):
    def test_one_item_fetch_projects_only_approved_fields(self):
        entry = {'definition': definition(), 'approval': approval(), 'dataBindings': [
            {'name': 'database', 'item': 'cnpg-fixture-production', 'fields': ['username', 'password']}]}
        values = {'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40, 'catalog': [entry]}
        result = subprocess.run(['helm', 'template', 'services', str(ROOT / 'platform/delivery/services'), '-f', '-'],
                                input=json.dumps(values), capture_output=True, text=True, check=True, timeout=60)
        obj = next(o for o in yaml.safe_load_all(result.stdout) if o and o['kind'] == 'ExternalSecret')
        self.assertEqual(obj['spec']['dataFrom'], [{'extract': {'key': 'cnpg-fixture-production'}}])
        template = obj['spec']['target']['template']
        self.assertEqual(template['mergePolicy'], 'Replace')
        self.assertEqual(template['data'], {'username': '{{ .username }}', 'password': '{{ .password }}'})
