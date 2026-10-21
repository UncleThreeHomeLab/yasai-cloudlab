import unittest
from unittest.mock import Mock, patch

from playbooks.services.files import verify
from playbooks.services.tests.fixtures import definition, approval


class VerifyTests(unittest.TestCase):
    def test_retired_declaration_checks_route_absence_without_running_fixture_data_tests(self):
        value = definition()
        value['name'] = 'fixture-retained'
        entry = {'definition': value, 'approval': approval(), 'publication': 'retired'}
        with patch('playbooks.services.files.bootstrap.converged', return_value=True), \
                patch.object(verify, 'inspect') as inspect, \
                patch('playbooks.data.files.service_proof.run') as data_proof:
            result = verify.run({'values': {'catalog': [entry]}})
        self.assertEqual(result['services_checked'], 1)
        inspect.assert_called_once_with({'definition': value, 'approval': entry['approval'], 'action': 'route-absent'})
        data_proof.assert_not_called()

    def test_unstable_service_cannot_pass_behavior_acceptance(self):
        entry = {'definition': definition(), 'approval': approval(), 'publication': 'ready'}
        payload = {'values': {'catalog': [entry]}, 'proof_image': 'fixture'}
        with patch('playbooks.services.files.bootstrap.converged', return_value=True), patch.object(verify, 'inspect'), patch.object(verify, 'unauthorized_destination'), \
                patch('playbooks.services.files.transport.run'), patch.object(verify.subprocess, 'run', return_value=Mock(returncode=1)):
            with self.assertRaisesRegex(RuntimeError, 'did not remain stable'): verify.run(payload)
