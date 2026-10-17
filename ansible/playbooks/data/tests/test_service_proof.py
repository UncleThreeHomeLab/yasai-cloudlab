import unittest

from playbooks.data.files.service_proof import fixture


class ServiceProofTests(unittest.TestCase):
    def test_proof_refuses_production_or_foreign_data_scopes(self):
        name = 'fixture-abcdef123456'
        entry = {'definition': {'name': name, 'data': {'database': {}, 'bucket': {}}},
                 'approval': {'name': name, 'namespace': 'cloudlab-app-' + name}}
        self.assertEqual(fixture(entry), name)
        for key, value in (('name', 'notes'), ('namespace', 'cloudlab-data')):
            original = entry['approval'][key]
            entry['approval'][key] = value
            with self.assertRaises(ValueError): fixture(entry)
            entry['approval'][key] = original
