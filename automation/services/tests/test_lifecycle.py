import unittest
from unittest.mock import Mock

from automation.services.lifecycle import publish, retire
from automation.services.tests.fixtures import definition


class LifecycleTests(unittest.TestCase):
    def value(self):
        value = definition()
        value['exposure'] = {'class': 'public', 'hostname': 'fixture.example.invalid', 'access': 'human', 'path': '/', 'port': 8080}
        return value

    def owners(self):
        result = Mock()
        result.current_exposure.return_value = None
        return result

    def test_each_interruption_reruns_checks_before_publication(self):
        for stage in ('identity_ready', 'backend_ready', 'reachability_verified'):
            owners = self.owners()
            getattr(owners, stage).side_effect = RuntimeError('interrupted')
            with self.subTest(stage=stage), self.assertRaises(RuntimeError): publish(self.value(), owners)
            if stage != 'reachability_verified': owners.dns_publish.assert_not_called()
            getattr(owners, stage).side_effect = None
            owners.reset_mock()
            publish(self.value(), owners)
            calls = [call[0] for call in owners.mock_calls]
            self.assertLess(calls.index('identity_ready'), calls.index('backend_ready'))
            self.assertLess(calls.index('protection_verified'), calls.index('routing_apply'))
            self.assertLess(calls.index('routing_verified'), calls.index('dns_publish'))

    def test_failed_protection_and_missing_inputs_never_publish_or_retire(self):
        for stage in ('require_private_inputs', 'protection_verified', 'routing_verified', 'tls_ready'):
            owners = self.owners()
            getattr(owners, stage).side_effect = RuntimeError('not ready')
            with self.subTest(stage=stage), self.assertRaises(RuntimeError): publish(self.value(), owners)
            owners.dns_publish.assert_not_called()
        owners = self.owners()
        owners.require_private_inputs.side_effect = RuntimeError('missing')
        with self.assertRaises(RuntimeError): retire(self.value(), owners)
        owners.dns_withdraw.assert_not_called()

    def test_removal_withdraws_reachability_before_protection_identity_and_workload(self):
        owners = self.owners()
        retire(self.value(), owners)
        calls = [call[0] for call in owners.mock_calls]
        self.assertLess(calls.index('routing_withdraw'), calls.index('unreachable_verified'))
        self.assertLess(calls.index('unreachable_verified'), calls.index('protection_retire'))
        self.assertLess(calls.index('unreachable_verified'), calls.index('workload_retire'))
        owners.data_retained.assert_called_once()
        self.assertNotIn('data_delete', calls)

    def test_exposure_change_fails_before_mutation(self):
        owners = self.owners()
        owners.current_exposure.return_value = {'class': 'private', 'access': 'tailnet', 'hostname': 'fixture.internal.example.invalid'}
        with self.assertRaises(ValueError): publish(self.value(), owners)
        owners.protection_apply.assert_not_called()
