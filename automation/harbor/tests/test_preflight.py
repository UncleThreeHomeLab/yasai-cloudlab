import unittest
from unittest.mock import patch

from automation.harbor import preflight


class PreflightTests(unittest.TestCase):
    def test_missing_inputs_never_create_items_or_assume_scope(self):
        with patch.object(preflight, 'command', return_value=[]) as call:
            result = preflight.inspect('reader')
        self.assertEqual(result['missing'], list(preflight.CONTRACT['prerequisites']))
        self.assertFalse(result['scope_permissions_verified'])
        self.assertFalse(result['ready_for_live_acceptance'])
        self.assertEqual(call.call_count, 1)
        self.assertEqual(result['production_mutations'], 0)

    def test_duplicates_and_missing_fields_are_not_reported_ready(self):
        titles = list(preflight.CONTRACT['prerequisites'])
        inventory = [{'title': titles[0], 'id': 'first'}, {'title': titles[0], 'id': 'second'},
                     {'title': titles[1], 'id': 'third'}]
        with patch.object(preflight, 'command', side_effect=[inventory, {'fields': []}]):
            result = preflight.inspect('reader')
        self.assertEqual(result['invalid'][0]['reason'], 'duplicate title')
        self.assertEqual(result['invalid'][1]['fields'], ['APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'])
        self.assertEqual(result['ready'], [])

    def test_ready_inventory_returns_no_values_and_does_not_prove_permissions(self):
        inventory = [{'title': title, 'id': str(index)} for index, title in enumerate(preflight.CONTRACT['prerequisites'])]
        documents = [{'fields': [{'label': name, 'value': 'synthetic-private-value'} for name in fields]}
                     for fields in preflight.CONTRACT['prerequisites'].values()]
        with patch.object(preflight, 'command', side_effect=[inventory, *documents]):
            result = preflight.inspect('reader')
        self.assertNotIn('synthetic-private-value', str(result))
        self.assertFalse(result['scope_permissions_verified'])
        self.assertEqual(result['missing'] + result['invalid'], [])

    def test_repositories_must_be_designated_distinct_and_same_owner(self):
        values = dict(zip(('PRIVATE_CONFIG_REPOSITORY', 'PUBLIC_TEST_REPOSITORY', 'PRIVATE_TEST_REPOSITORY'),
                          ('https://github.com/fixture/config.git', 'https://github.com/fixture/public.git',
                           'https://github.com/fixture/private.git')))
        self.assertEqual(len(preflight.targets(values)), 3)
        values['PRIVATE_TEST_REPOSITORY'] = values['PRIVATE_CONFIG_REPOSITORY']
        with self.assertRaises(ValueError): preflight.targets(values)
        values['PRIVATE_TEST_REPOSITORY'] = 'https://github.com/other/private.git'
        with self.assertRaises(ValueError): preflight.targets(values)
