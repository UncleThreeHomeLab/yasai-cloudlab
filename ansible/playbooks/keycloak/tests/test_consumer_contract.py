"""Keep service onboarding independent of the identity writer implementation."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from playbooks.keycloak.files.configuration import compile_state, prepare
from playbooks.keycloak.files.operations import change


class ConsumerContractTests(unittest.TestCase):
    def test_client_lifecycle_uses_one_contract_and_persistent_revocations(self):
        source = {'format': 1, 'realms': {'applications': {
            'memberships': [{'username': 'synthetic-reader', 'groups': ['viewer']}]}}}
        denied = {'format': 1, 'realms': {}}
        definition = {'id': 'notes-ui', 'audience': 'notes-api', 'public': False,
                      'callbacks': ['https://notes.example.invalid/callback'],
                      'roles': ['reader'], 'role_groups': {'reader': ['viewer']}}
        original = copy.deepcopy(source)
        source, denied = change(source, denied, {
            'action': 'provision-client', 'realm': 'applications', 'client': definition})
        self.assertEqual(original['realms']['applications'].get('clients'), None)
        credentials = {'applications': {'notes-ui': 'synthetic-vault-secret-' + 'x' * 32}}
        state = compile_state('applications', 'example.invalid', source, credentials, denied)
        client = state['clients'][0]
        self.assertEqual(client['attributes']['pkce.code.challenge.method'], 'S256')
        self.assertFalse(client['fullScopeAllowed'])
        self.assertFalse(client['directAccessGrantsEnabled'])
        self.assertEqual(client['redirectUris'], definition['callbacks'])
        self.assertEqual(client['protocolMappers'][0]['config']['included.custom.audience'], 'notes-api')
        self.assertIn('/client-notes-ui/reader', state['users'][0]['groups'])
        self.assertNotIn('enabled', state['users'][0])
        credentials['applications']['notes-ui'] = 'synthetic-rotated-secret-' + 'y' * 32
        self.assertEqual(compile_state('applications', 'example.invalid', source, credentials, denied)
                         ['clients'][0]['secret'], credentials['applications']['notes-ui'])
        source, denied = change(source, denied, {
            'action': 'offboard-user', 'realm': 'applications', 'username': 'synthetic-reader'})
        source, denied = change(source, denied, {
            'action': 'disable-client', 'realm': 'applications', 'client_id': 'notes-ui'})
        state = compile_state('applications', 'example.invalid', source, credentials, denied)
        self.assertFalse(state['clients'][0]['enabled'])
        self.assertEqual(state['users'][0]['groups'], [])
        self.assertFalse(state['users'][0]['enabled'])
        with self.assertRaises(ValueError):
            change(source, denied, {'action': 'provision-client', 'realm': 'applications', 'client': definition})
        source, denied = change(source, denied, {
            'action': 'remove-client', 'realm': 'applications', 'client_id': 'notes-ui'})
        self.assertEqual(compile_state('applications', 'example.invalid', source, {}, denied)['clients'], [])
        self.assertIn('notes-ui', denied['realms']['applications']['removed_clients'])

    def test_missing_or_invalid_private_source_never_emits_partial_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary) / 'private'
            output = Path(temporary) / 'imports'
            private.mkdir()
            documents = {'desired_state': {'format': 1, 'realms': {}},
                         'client_secrets': {}, 'revocations': {'format': 1, 'realms': {}}}
            for missing in documents:
                for name, value in documents.items():
                    path = private / name
                    path.unlink(missing_ok=True)
                    if name != missing:
                        path.write_text(json.dumps(value))
                with self.assertRaises(FileNotFoundError):
                    prepare(output, 'example.invalid', private)
                self.assertFalse(output.exists())
            for name, value in documents.items():
                (private / name).write_text(json.dumps(value))
            (private / 'desired_state').write_text('{')
            with self.assertRaises(json.JSONDecodeError):
                prepare(output, 'example.invalid', private)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
