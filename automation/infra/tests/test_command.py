"""Safety checks independent of backend/provider accounts."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation.infra import command


def plan(kind='github_repository', actions=None, before=None, after=None):
    return {'resource_changes': [{'mode': 'managed', 'type': kind, 'address': kind + '.fixture',
                                 'change': {'actions': actions or ['update'],
                                            'before': before or {}, 'after': after or {}}}]}


class ContractTests(unittest.TestCase):
    def inputs(self, directory, root):
        private = Path(directory) / root
        private.mkdir()
        desired = json.loads((command.WORKSPACE / 'infra' / root / 'fixtures.json').read_text())
        documents = {'desired.tfvars.json': desired, 'backend.json': {'project_id': 1},
                     'encryption.json': {'passphrase': 'synthetic-independent-key-for-unit-test'},
                     'acceptance.json': {'root': root, 'status': 'accepted'},
                     'inventory.json': {'synthetic.fixture': {'id': 'synthetic-id'}}}
        for name, document in documents.items():
            (private / name).write_text(json.dumps(document))
        credential = 'CLOUDFLARE_API_TOKEN=synthetic-management\nTF_VAR_dns_api_token=synthetic-dns' if root == 'cloudflare' else 'GITHUB_TOKEN=synthetic-governance'
        (private / 'credentials.env').write_text('TF_HTTP_USERNAME=synthetic\nTF_HTTP_PASSWORD=synthetic-state\n' + credential + '\n')
        return private, desired

    def test_dns_and_management_credentials_stay_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            private, _ = self.inputs(temporary, 'cloudflare')
            with patch.object(command, 'PRIVATE', private.parent), \
                    patch.object(command, 'WORK', Path(temporary) / 'work'), \
                    patch.object(command, 'source_binding', return_value={'revision': 'synthetic', 'source_hash': 'synthetic'}):
                client = command.Client('cloudflare')
            self.assertEqual(client.env['CLOUDFLARE_API_TOKEN'], 'synthetic-management')
            self.assertEqual(client.env['TF_VAR_dns_api_token'], 'synthetic-dns')
            self.assertNotIn('GITHUB_TOKEN', client.env)
            self.assertNotIn('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', client.env)
            self.assertNotIn('VM_PASSWORD', client.env)

    def test_private_input_change_invalidates_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            private, desired = self.inputs(temporary, 'github')
            with patch.object(command, 'PRIVATE', private.parent), \
                    patch.object(command, 'WORK', Path(temporary) / 'work'), \
                    patch.object(command, 'source_binding', return_value={'revision': 'synthetic', 'source_hash': 'synthetic'}):
                client = command.Client('github')
                desired['owner'] = 'synthetic-changed'
                (private / 'desired.tfvars.json').write_text(json.dumps(desired))
                with self.assertRaisesRegex(ValueError, 'inputs changed during the run'):
                    client.unchanged_inputs()
                self.assertNotEqual(json.loads((client.path / 'desired.tfvars.json').read_text())['owner'], desired['owner'])

    def test_removal_and_replacement_rejected_without_resource_lifecycle(self):
        for actions in (['delete'], ['create'], ['delete', 'create'], ['create', 'delete']):
            with self.subTest(actions=actions), self.assertRaises(ValueError):
                command.guarded_changes(plan(actions=actions))

    def test_repository_identity_changes_rejected(self):
        before = {'name': 'fixture', 'visibility': 'public', 'archived': False}
        for key, value in (('name', 'renamed'), ('visibility', 'private'), ('archived', True)):
            after = dict(before, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                command.guarded_changes(plan(before=before, after=after))
        self.assertEqual(command.guarded_changes(plan(before=before, after=dict(before, description='new'))), 1)

    def test_import_and_existing_resource_id_changes_require_maintenance(self):
        with self.assertRaises(ValueError):
            command.guarded_changes(plan('cloudflare_dns_record', before={'id': 'original'}, after={'id': 'new'}))
        document = plan(actions=['no-op'])
        document['resource_changes'][0]['change']['importing'] = {'id': 'existing'}
        with self.assertRaises(ValueError):
            command.guarded_changes(document)
        with self.assertRaises(ValueError):
            command.guarded_changes(plan(before={'id': 'same-name', 'repo_id': 1, 'node_id': 'original'},
                                         after={'id': 'same-name', 'repo_id': 2, 'node_id': 'recreated'}))

    def test_audience_replacement_and_bypass_expansion_rejected(self):
        with self.assertRaises(ValueError):
            command.guarded_changes(plan('cloudflare_zero_trust_access_application',
                                         before={'id': 'same', 'aud': 'original'}, after={'id': 'same', 'aud': 'new'}))
        with self.assertRaises(ValueError):
            command.guarded_changes(plan('github_repository_ruleset', before={'bypass_actors': []},
                                         after={'bypass_actors': [{'actor_id': 1}]}))

    def test_unknown_nested_policy_is_not_silently_discarded(self):
        fixture = json.loads((command.WORKSPACE / 'infra/cloudflare/fixtures.json').read_text())
        command.reject_unknown(fixture, command.SCHEMAS['cloudflare'])
        changed = copy.deepcopy(fixture)
        changed['applications']['fixture']['policies']['z_human']['include'][0]['everyone'] = {}
        with self.assertRaises(ValueError):
            command.reject_unknown(changed, command.SCHEMAS['cloudflare'])

    def test_missing_inputs_fail_before_native_initialization(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(command, 'PRIVATE', Path(temporary) / 'missing'), \
                patch.object(command, 'WORK', Path(temporary) / 'work'), \
                patch.object(command.subprocess, 'run') as native:
            with self.assertRaisesRegex(ValueError, 'before live init or plan'):
                command.Client('github')
            native.assert_not_called()

    def test_changed_binding_rejects_apply_before_native_initialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = object.__new__(command.Client)
            client.path = Path(temporary)
            client.binding = {'revision': 'current', 'root': 'github'}
            (client.path / 'reviewed.tfplan').write_bytes(b'encrypted fixture')
            checksum = command.digest(b'encrypted fixture')
            (client.path / 'plan-binding.json').write_text(json.dumps({'revision': 'old', 'root': 'github', 'plan_hash': checksum}))
            with patch.object(client, 'initialize') as initialize:
                with self.assertRaisesRegex(ValueError, 'exact reviewed plan'):
                    client.apply(checksum)
                initialize.assert_not_called()


if __name__ == '__main__':
    unittest.main()
