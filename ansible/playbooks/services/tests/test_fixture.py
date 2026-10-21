import unittest
from unittest.mock import Mock, patch

from playbooks.services.tests import fixture


class FixtureTests(unittest.TestCase):
    def test_retirement_proof_stops_when_retained_credential_identity_changes(self):
        name = 'fixture-abcdef123456'
        bundle = {'definition': {'name': name, 'data': {'database': {}, 'bucket': {}}},
                  'approval': {'name': name, 'namespace': 'cloudlab-app-' + name}}
        owner = Mock()
        owner.read.side_effect = [{'retained': {'secret': 'original'}}, {}, {'retained': {'secret': 'changed'}}]
        with patch('playbooks.services.files.owners.Owners', return_value=owner), \
                patch.object(fixture, 'ready'), patch.object(fixture, 'publish') as publish, \
                patch.object(fixture, 'retire'):
            with self.assertRaisesRegex(RuntimeError, 'Retirement changed'): fixture.run(bundle)
            self.assertEqual(publish.call_count, 2)
            self.assertNotIn('fixture-volume', [call.args[0] for call in owner.read.call_args_list])
