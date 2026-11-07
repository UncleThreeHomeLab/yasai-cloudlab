"""Release records validate against their declarative contract and proposer.

The release schema accepts the committed notes record and representative
prices records, rejects malformed records, and agrees with
release.validate() except for primary-component membership and digest
equality, which stay enforced by the proposer alone.
"""
import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

from jsonschema import validate
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / 'platform/delivery/ci/release.schema.json').read_text())

_spec = importlib.util.spec_from_file_location(
    'cloudlab_release', ROOT / 'platform/delivery/ci/publisher/release.py')
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)

DIGEST = 'sha256:' + 'a' * 64
OTHER = 'sha256:' + 'b' * 64


def prices(**overrides):
    record = {'digest': DIGEST, 'source_revision': 'c' * 40,
              'workflow_run_id': '39964443157'}
    record.update(overrides)
    return record


class DeliveryCompiledInputsTests(unittest.TestCase):
    def test_committed_notes_record_validates(self):
        record = json.loads((ROOT / 'apps/releases/notes.json').read_text())
        validate(record, SCHEMA)
        self.assertEqual(release.validate(copy.deepcopy(record)), record)

    def test_single_and_multi_component_prices_records_validate(self):
        validate(prices(), SCHEMA)
        release.validate(prices())
        multi = prices(components={'web': DIGEST, 'worker': OTHER},
                       primary_component='web')
        validate(multi, SCHEMA)
        self.assertEqual(release.validate(copy.deepcopy(multi)), multi)

    def test_malformed_records_fail_schema_and_proposer(self):
        cases = [
            {},
            {'digest': DIGEST, 'source_revision': 'c' * 40},
            prices(digest='sha256:' + 'g' * 64),
            prices(digest='latest'),
            prices(source_revision='main'),
            prices(source_revision='C' * 40),
            prices(workflow_run_id='0'),
            prices(workflow_run_id=39964443157),
            prices(extra='no'),
            prices(components={'web': DIGEST}),
            prices(primary_component='web'),
            prices(components={}, primary_component='web'),
            prices(components={'Web': DIGEST, 'x': DIGEST, 'y': DIGEST,
                               'z': DIGEST, 'w': DIGEST, 'v': DIGEST,
                               'u': DIGEST, 't': DIGEST, 's': DIGEST},
                  primary_component='Web'),
            prices(components={'web': 'latest'}, primary_component='web'),
        ]
        for record in cases:
            with self.subTest(record=record):
                with self.assertRaises(ValidationError):
                    validate(record, SCHEMA)
                with self.assertRaises(ValueError):
                    release.validate(copy.deepcopy(record))

    def test_component_membership_stays_with_the_proposer(self):
        # JSON Schema cannot express cross-field membership; the proposer does.
        for record in (prices(components={'web': DIGEST}, primary_component='api'),
                       prices(components={'web': OTHER}, primary_component='web')):
            with self.subTest(record=record):
                validate(record, SCHEMA)
                with self.assertRaises(ValueError):
                    release.validate(copy.deepcopy(record))


if __name__ == '__main__':
    unittest.main()
