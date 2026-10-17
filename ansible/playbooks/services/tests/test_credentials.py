import json
import subprocess
import unittest

import yaml

from playbooks.services.files.contract import ROOT
from playbooks.services.tests.fixtures import definition, approval


class CredentialTests(unittest.TestCase):
    def test_one_item_fetch_projects_only_approved_fields(self):
        value, allowed = definition(), approval()
        value['data'] = {'database': {'name': 'fixture', 'credentialReference': 'database', 'retention': 'retain'}}
        allowed['secretReferences'] = ['database']
        entry = {'definition': value, 'approval': allowed}
        values = {'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40, 'catalog': [entry],
                  'dataApprovals': {'database': {'service': 'synthetic', 'name': 'fixture', 'kind': 'database',
                                                'item': 'cnpg-fixture-production'}}}
        result = subprocess.run(['helm', 'template', 'services', str(ROOT / 'platform/delivery/services'), '-f', '-'],
                                input=json.dumps(values), capture_output=True, text=True, check=True, timeout=60)
        obj = next(o for o in yaml.safe_load_all(result.stdout) if o and o['kind'] == 'ExternalSecret')
        self.assertEqual(obj['spec']['dataFrom'], [{'extract': {'key': 'cnpg-fixture-production'}}])
        template = obj['spec']['target']['template']
        self.assertEqual(template['mergePolicy'], 'Replace')
        self.assertEqual(template['data'], {'username': '{{ .username }}', 'password': '{{ .password }}'})
