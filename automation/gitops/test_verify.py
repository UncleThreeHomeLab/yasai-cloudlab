from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'verification/integration'))
import verify


class VerificationTests(unittest.TestCase):
    def test_untrusted_probe_has_no_identity_or_trusted_network_label(self):
        doc = verify.pod('fixture', 'probe', 'image@sha256:fixture', 'true')
        self.assertFalse(doc['spec']['automountServiceAccountToken'])
        self.assertNotIn('app.kubernetes.io/part-of', doc['metadata']['labels'])
        self.assertTrue(doc['spec']['securityContext']['runAsNonRoot'])
        self.assertFalse(doc['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'])

    def test_failed_probe_creation_never_deletes_an_existing_pod(self):
        with patch.object(verify, 'kube', side_effect=RuntimeError('Already exists')) as kube:
            with self.assertRaises(RuntimeError):
                verify.verify_pod(verify.pod('fixture', 'probe', 'image', 'true'))
            self.assertEqual(kube.call_count, 1)
