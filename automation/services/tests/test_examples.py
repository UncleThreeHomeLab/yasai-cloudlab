import unittest

from automation.services.examples import definitions
from automation.services.inputs import validate_catalog


class ExampleTests(unittest.TestCase):
    def test_approved_examples_use_distinct_sources_scopes_and_retained_data(self):
        value = definitions('example.invalid','https://github.com/example/public.git','a'*40,
                            'https://github.com/example/private.git','abcdef123456','notes','notes')
        validate_catalog(value)
        notes, fixture = value['catalog']
        self.assertEqual(notes['approval']['visibility'],'public')
        self.assertEqual(fixture['approval']['visibility'],'private')
        self.assertEqual(notes['definition']['exposure']['class'],'public')
        self.assertEqual(fixture['definition']['exposure']['class'],'private')
        self.assertEqual(fixture['definition']['data']['database']['name'],'fixture_abcdef123456')
        self.assertEqual(fixture['definition']['persistence']['retention'],'retain')
        self.assertNotEqual(value['dataApprovals']['notes-database']['item'], value['dataApprovals']['fixture-database']['item'])
