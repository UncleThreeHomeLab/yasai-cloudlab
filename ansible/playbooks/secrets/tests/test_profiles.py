import json
from pathlib import Path
import unittest


class CredentialProfileTests(unittest.TestCase):
    def test_approved_profiles_match_demonstrated_data_item_shapes(self):
        root = Path(__file__).resolve().parents[4]
        profiles = json.loads((root / 'ansible/playbooks/secrets/files/profiles.json').read_text())
        contract = json.loads((root / 'platform/data/contract.json').read_text())
        self.assertEqual(set(profiles) - {'_note'}, {'database', 'bucket'})
        self.assertEqual(profiles['database']['fields'], contract['items']['cnpg-notes-production'])
        self.assertEqual(profiles['bucket']['fields'], contract['items']['s3-notes-production'])
        for kind, profile in profiles.items():
            if kind.startswith('_'):
                continue
            self.assertEqual(set(profile), {'fields'})
            for field, shape in profile['fields'].items():
                self.assertIn(shape, ('STRING', 'CONCEALED'))
            self.assertIn('CONCEALED', set(profile['fields'].values()))
