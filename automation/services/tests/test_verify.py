import unittest
from unittest.mock import Mock, patch

from automation.services import verify
from automation.services.tests.fixtures import definition, approval


class VerifyTests(unittest.TestCase):
    def test_unstable_service_cannot_pass_behavior_acceptance(self):
        entry = {'definition': definition(), 'approval': approval(), 'publication': 'ready'}
        payload = {'values': {'catalog': [entry]}, 'proof_image': 'fixture'}
        with patch.object(verify, 'inspect'), patch.object(verify, 'unauthorized_destination'), \
                patch('automation.services.transport.run'), patch.object(verify.subprocess, 'run', return_value=Mock(returncode=1)):
            with self.assertRaisesRegex(RuntimeError, 'did not remain stable'): verify.run(payload)
