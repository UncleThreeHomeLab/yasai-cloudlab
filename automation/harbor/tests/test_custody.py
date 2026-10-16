import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation.harbor import credentials
from automation.harbor.provider_proof import clean_state


class CustodyTests(unittest.TestCase):
    def test_separate_project_credentials_have_fixed_identity_and_version(self):
        definitions = credentials.definitions()
        self.assertEqual(len(definitions), 4)
        passwords = []
        for project in credentials.PROJECTS:
            for role in ('push', 'pull'):
                fields = definitions[f'harbor-{project}-{role}']
                self.assertEqual(fields['username'][1](), f'robot${project}+{role}')
                self.assertEqual(fields['secret_version'][1](), '1')
                passwords.append(fields['password'][1]())
        self.assertEqual(len(set(passwords)), 4)
        self.assertTrue(all(len(password) >= 48 for password in passwords))

    def test_readback_requires_durable_exact_typed_input(self):
        document = {'fields': [{'label': name, 'type': kind, 'value': value} for name, kind, value in (
            ('username', 'STRING', 'robot$cloudlab-public+pull'),
            ('password', 'CONCEALED', 'synthetic-password-' + 'x' * 32), ('secret_version', 'STRING', '1'))]}
        with patch.object(credentials, 'command', side_effect=[[
                {'id': 'vault-id', 'title': 'harbor-cloudlab-public-pull'}], document]) as call:
            result = credentials.read_robot('writer', 'harbor-cloudlab-public-pull', 'robot$cloudlab-public+pull')
        self.assertEqual(result['secret_version'], '1')
        self.assertEqual(call.call_args_list[1].args[0], ['item', 'get', 'vault-id', '--vault', 'CloudLab'])

    def test_missing_duplicate_and_incompatible_inputs_fail_without_registry_calls(self):
        for inventory in ([], [{'title': 'fixture', 'id': str(number)} for number in (1, 2)]):
            with patch.object(credentials, 'command', return_value=inventory) as call:
                with self.assertRaises(RuntimeError): credentials.read_robot('writer', 'fixture', 'expected')
                self.assertEqual(call.call_count, 1)
        for fields in ([], [{'label': 'username', 'type': 'CONCEALED', 'value': 'wrong-type'}]):
            with patch.object(credentials, 'command', side_effect=[
                    [{'title': 'fixture', 'id': 'id'}], {'fields': fields}]):
                with self.assertRaises(RuntimeError): credentials.read_robot('writer', 'fixture', 'expected')

    def test_state_scan_rejects_plaintext_and_provider_generated_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / 'terraform.tfstate'
            path.write_text(json.dumps({'resources': []}))
            clean_state(directory, 'synthetic-password')
            path.write_text(json.dumps({'resources': [{'type': 'harbor_robot_account', 'instances': [
                {'attributes': {'secret': 'provider-generated-value'}}]}]}))
            with self.assertRaisesRegex(RuntimeError, 'generated password'): clean_state(directory, 'synthetic-password')
            path.write_text('{"password":"synthetic-password"}')
            with self.assertRaisesRegex(RuntimeError, 'leaked'): clean_state(directory, 'synthetic-password')

    def test_incompatible_existing_identity_stops_before_creating_other_inputs(self):
        document = {'fields': [{'label': name, 'type': kind, 'value': value} for name, kind, value in (
            ('username', 'STRING', 'robot$another-project+pull'),
            ('password', 'CONCEALED', 'synthetic-password-' + 'x' * 32), ('secret_version', 'STRING', '1'))]}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(credentials, 'Path', return_value=Path(temporary) / 'lock'), \
                patch.object(credentials, 'dotenv_values', return_value={'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'writer'}), \
                patch.object(credentials, 'ensure_items') as create, \
                patch.object(credentials, 'command', side_effect=[[
                    {'title': 'harbor-cloudlab-public-pull', 'id': 'existing-id'}], document]):
            with self.assertRaisesRegex(RuntimeError, 'identity/version'): credentials.provision()
            create.assert_not_called()

    def test_existing_secret_version_cannot_trigger_implicit_rotation(self):
        document = {'fields': [{'label': name, 'type': kind, 'value': value} for name, kind, value in (
            ('username', 'STRING', 'robot$cloudlab-public+pull'),
            ('password', 'CONCEALED', 'synthetic-password-' + 'x' * 32), ('secret_version', 'STRING', '2'))]}
        with self.assertRaisesRegex(RuntimeError, 'identity/version'):
            credentials.robot_values(document, 'robot$cloudlab-public+pull')


if __name__ == '__main__':
    unittest.main()
