import unittest

from playbooks.observability.files.credentials import definitions


class CredentialTests(unittest.TestCase):
    def test_emergency_identity_and_stable_signing_material_have_separate_custody(self):
        fields = definitions()
        self.assertEqual(set(fields), {'grafana-emergency', 'kiali-signing-key'})
        self.assertEqual(set(fields['grafana-emergency']), {'username', 'password', 'secret_key'})
        self.assertEqual(len(fields['kiali-signing-key']['key'][1]()), 32)
        for field in ('password', 'secret_key'):
            self.assertEqual(fields['grafana-emergency'][field][0], 'CONCEALED')
            self.assertGreaterEqual(len(fields['grafana-emergency'][field][1]()), 48)
