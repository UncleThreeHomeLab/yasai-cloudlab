import unittest
from unittest.mock import patch
from unittest.mock import Mock
from types import SimpleNamespace
import copy

from automation.services.owners import Owners
from automation.services.tests.fixtures import definition, approval


class OwnerInputTests(unittest.TestCase):
    def test_observed_access_selectors_must_match_approved_platform_protection(self):
        value = definition()
        value['exposure'] = {'class': 'public', 'hostname': 'service.example.invalid',
                             'access': 'machine', 'path': '/', 'port': 8080}
        owner = Owners.__new__(Owners)
        owner.definition, owner.approval = value, approval()
        owner.bundle = {'application': 'machine'}
        policy = {'id': 'primary', 'decision': 'non_identity', 'include': [{'service_token': {'token_id': 'fixture'}}],
                  'exclude': [], 'require': []}
        owner.client = SimpleNamespace(env={'CLOUDFLARE_API_TOKEN': 'fixture'},
            desired={'account_id': 'fixture', 'applications': {'machine': {'domain': value['exposure']['hostname'], 'policies': {'primary': policy}}}},
            inventory={'cloudflare_zero_trust_access_application.application["machine"]': {'id': 'app', 'aud': 'approved', 'policies': {'primary': False}}})
        actual = {'domain': value['exposure']['hostname'], 'aud': 'approved', 'policies': [{'id': 'primary'}]}
        for changed in (False, True):
            observed = copy.deepcopy(policy)
            if changed: observed['include'] = [{'everyone': {}}]
            api = Mock()
            api.request.side_effect = [actual, [observed]]
            with patch('automation.connectivity.cloudflare.API', return_value=api):
                if changed:
                    with self.assertRaisesRegex(RuntimeError, 'selectors differ'): owner.protection_verified(value)
                else: owner.protection_verified(value)

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
