import unittest
from unittest.mock import patch

from automation.services.owners import Owners
from automation.services.tests.fixtures import definition, approval


class OwnerInputTests(unittest.TestCase):
    def test_missing_current_private_approval_prevents_native_planning(self):
        value = definition()
        value['exposure'] = {'class': 'public', 'hostname': 'service.example.invalid',
                             'access': 'public', 'path': '/', 'port': 8080}
        owner = Owners.__new__(Owners)
        owner.definition, owner.approval = value, approval()
        environment = {'VM_HOST': 'fixture', 'VM_USER': 'fixture', 'VM_PASSWORD': 'fixture'}
        with patch('dotenv.dotenv_values', return_value=environment), \
                patch('automation.services.inputs.catalog', return_value={'catalog': []}), \
                patch('automation.services.owners.Client') as client:
            with self.assertRaisesRegex(ValueError, 'current administrator'): owner.require_private_inputs(value)
            client.assert_not_called()
