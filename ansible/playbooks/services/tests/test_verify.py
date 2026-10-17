import unittest
from unittest.mock import Mock, patch

from playbooks.services.files import verify
from playbooks.services.tests.fixtures import definition, approval


class VerifyTests(unittest.TestCase):
    def test_unstable_service_cannot_pass_behavior_acceptance(self):
        entry = {'definition': definition(), 'approval': approval(), 'publication': 'ready'}
        payload = {'values': {'catalog': [entry]}, 'proof_image': 'fixture'}
        with patch('playbooks.services.files.bootstrap.converged', return_value=True), patch.object(verify, 'inspect'), patch.object(verify, 'unauthorized_destination'), \
                patch('playbooks.services.files.transport.run'), patch.object(verify.subprocess, 'run', return_value=Mock(returncode=1)):
            with self.assertRaisesRegex(RuntimeError, 'did not remain stable'): verify.run(payload)
