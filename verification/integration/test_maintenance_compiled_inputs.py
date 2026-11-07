"""Committed maintenance policy validates and binds to existing owners.

maintenance.yaml validates against maintenance.schema.json and every
group owner resolves in owners.json; unknown owners fail closed with no
proposal. Draft-only, no-automerge and no-prune invariants hold, and
malformed policies fail. JSON Schema cannot express owner membership;
the owners.json join enforces it, as the agreed scheduler must.
"""
import json
import unittest
from pathlib import Path

import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / 'platform/delivery/dependencies/maintenance.schema.json').read_text())
OWNERS = json.loads((ROOT / 'platform/delivery/dependencies/owners.json').read_text())['owners']


def policy(*groups, **overrides):
    record = {'maintenance': {
        'groups': [{'owner': owner, 'cadence': 'weekly', 'proposal': 'draft',
                    'qualification': 'owner-defined'} for owner in groups],
        'automerge': False, 'pruneBranches': False}}
    record['maintenance'].update(overrides)
    return record


def resolve(record):
    """Group owners must exist; unknown owners select no proposal scope."""
    owners = [group['owner'] for group in record['maintenance']['groups']]
    if any(owner not in OWNERS for owner in owners):
        raise ValueError('Maintenance group selects an unknown owner')
    return owners


class MaintenanceCompiledInputsTests(unittest.TestCase):
    def test_committed_policy_validates_and_binds_existing_owners(self):
        record = yaml.safe_load(
            (ROOT / 'platform/delivery/dependencies/maintenance.yaml').read_text())
        validate(record, SCHEMA)
        self.assertEqual(resolve(record), ['runner', 'image:maintenance'])

    def test_supported_cadences_validate_and_resolve(self):
        for cadence in ('daily', 'weekly', 'monthly'):
            record = policy('runner', groups=[{
                'owner': 'runner', 'cadence': cadence, 'proposal': 'draft',
                'qualification': 'owner-defined'}])
            with self.subTest(cadence=cadence):
                validate(record, SCHEMA)
                self.assertEqual(resolve(record), ['runner'])

    def test_unknown_owner_passes_schema_but_fails_the_join(self):
        record = policy('no-such-owner')
        validate(record, SCHEMA)
        with self.assertRaises(ValueError):
            resolve(record)

    def test_malformed_policies_fail_schema(self):
        group = policy('runner')['maintenance']['groups'][0]
        cases = [
            {},
            {'maintenance': {}},
            policy(),
            policy('runner', automerge=True),
            policy('runner', pruneBranches=True),
            policy('runner', extra='no'),
            {'maintenance': {
                'groups': [dict(group, cadence='hourly')],
                'automerge': False, 'pruneBranches': False}},
            {'maintenance': {
                'groups': [dict(group, proposal='auto')],
                'automerge': False, 'pruneBranches': False}},
            {'maintenance': {
                'groups': [dict(group, qualification='waived')],
                'automerge': False, 'pruneBranches': False}},
            {'maintenance': {
                'groups': [dict(group, owner='')],
                'automerge': False, 'pruneBranches': False}},
            {'maintenance': {
                'groups': [dict(group, extra='no')],
                'automerge': False, 'pruneBranches': False}},
            {'maintenance': {
                'groups': [{'owner': 'runner'}],
                'automerge': False, 'pruneBranches': False}},
        ]
        for record in cases:
            with self.subTest(record=record):
                with self.assertRaises(ValidationError):
                    validate(record, SCHEMA)


if __name__ == '__main__':
    unittest.main()
