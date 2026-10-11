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
