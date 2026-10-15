import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from automation.infra.input_recovery import documents, restore
from automation.infra.tests.fixtures import cloudflare_owner


class InputRecoveryTests(unittest.TestCase):
    def fixture(self):
        _, bundle = cloudflare_owner()
        address = 'cloudflare_dns_record.publication["fixture"]'
        plan = {'resource_changes': [{'address': address, 'type': 'cloudflare_dns_record', 'mode': 'managed',
                                     'change': {'before': {'id': 'retained'}, 'after': {'id': 'retained'}}}]}
        expected = {
            'desired.tfvars.json': b'{"fixture": true}',
            'backend.json': json.dumps({'project_id': '123'}, sort_keys=True).encode(),
            'encryption.json': json.dumps({'passphrase': bundle['encryption']['PASSPHRASE']}, sort_keys=True).encode(),
            'inventory.json': json.dumps({address: {'id': 'retained'}}, sort_keys=True).encode(),
            'acceptance.json': b'{"root": "cloudflare", "status": "accepted"}',
            'credentials.env': b'TF_HTTP_USERNAME=synthetic\nTF_HTTP_PASSWORD=synthetic-backend\n'
                               b'CLOUDFLARE_API_TOKEN=synthetic-management\nTF_VAR_dns_api_token=synthetic-dns\n',
        }
        binding = {'root': 'cloudflare', 'inputs': {
            name: hashlib.sha256(raw).hexdigest() for name, raw in expected.items()}}
        return binding, expected, plan, bundle

    def test_exact_recovery_and_repeat_preserve_original_files(self):
        binding, expected, plan, bundle = self.fixture()
        values = documents(binding, expected['desired.tfvars.json'], plan, bundle)
        self.assertEqual(values, expected)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            self.assertEqual(restore(destination, values)['restored_files'], 6)
            stats = {name: (destination / name).stat().st_mtime_ns for name in values}
            self.assertEqual(restore(destination, values)['restored_files'], 0)
            self.assertEqual({name: (destination / name).read_bytes() for name in values}, expected)
            self.assertEqual({name: (destination / name).stat().st_mtime_ns for name in values}, stats)
            self.assertTrue(all((destination / name).stat().st_mode & 0o777 == 0o600 for name in values))

    def test_changed_credentials_inventory_acceptance_or_scope_cannot_be_recreated(self):
        for scenario in ('credentials', 'inventory', 'acceptance', 'scope', 'missing_hash', 'desired', 'newline'):
            with self.subTest(scenario=scenario):
                binding, expected, plan, bundle = self.fixture()
                desired = expected['desired.tfvars.json']
                if scenario == 'credentials': bundle['backend']['TOKEN'] = 'different'
                elif scenario == 'inventory': plan['resource_changes'][0]['change']['before']['id'] = 'different'
                elif scenario == 'acceptance': binding['inputs']['acceptance.json'] = '0' * 64
                elif scenario == 'scope': binding['root'] = 'github'
                elif scenario == 'missing_hash': binding['inputs'].pop('backend.json')
                elif scenario == 'desired': desired = b'{}'
                elif scenario == 'newline': bundle['backend']['TOKEN'] += '\n'
                with self.assertRaises(ValueError): documents(binding, desired, plan, bundle)

    def test_conflict_is_detected_before_any_missing_file_is_created(self):
        _, values, _, _ = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            existing = destination / 'acceptance.json'
            existing.write_bytes(b'existing input must survive')
            with self.assertRaisesRegex(ValueError, 'conflicts'): restore(destination, values)
            self.assertEqual(list(destination.iterdir()), [existing])
            self.assertEqual(existing.read_bytes(), b'existing input must survive')

    def test_symlink_and_incomplete_recovery_are_refused(self):
        _, values, _, _ = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            link = destination / 'redirect'
            link.symlink_to(destination, target_is_directory=True)
            with self.assertRaises(ValueError): restore(link, values)
            incomplete = copy.deepcopy(values)
            incomplete.pop('credentials.env')
            with self.assertRaises(ValueError): restore(destination, incomplete)
