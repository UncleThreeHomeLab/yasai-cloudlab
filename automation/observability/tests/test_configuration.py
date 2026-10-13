import unittest

from automation.observability.configuration import grafana
from automation.identity.configuration import client


class AuthenticationContractTests(unittest.TestCase):
    def test_roles_fail_closed_and_secret_stays_in_file(self):
        settings = grafana('https://login.example.invalid/realms/platform',
                           'https://grafana.internal.example.invalid')
        oauth = settings['ini']['auth.generic_oauth']
        self.assertTrue(oauth['role_attribute_strict'])
        self.assertTrue(oauth['use_pkce'])
        self.assertTrue(oauth['use_refresh_token'])
        self.assertFalse(oauth['allow_assign_grafana_admin'])
        self.assertTrue(oauth['role_attribute_path'].endswith("|| ''"))
        self.assertNotIn('team_ids', oauth)
        self.assertTrue(oauth['client_secret'].startswith('$__file{'))
        self.assertFalse(settings['ini']['auth.anonymous']['enabled'])
        self.assertFalse(settings['ini']['unified_alerting']['enabled'])
        compiled = client(settings['client'], {'grafana': 'x' * 48})
        self.assertEqual(compiled['attributes']['post.logout.redirect.uris'],
                         'https://grafana.internal.example.invalid/login')

    def test_logout_cannot_redirect_to_unapproved_origin(self):
        settings = grafana('https://login.example.invalid/realms/platform',
                           'https://grafana.internal.example.invalid')
        settings['client']['logout_callbacks'] = ['https://attacker.example.invalid/login']
        with self.assertRaises(ValueError): client(settings['client'], {'grafana': 'x' * 48})
        with self.assertRaises(ValueError):
            grafana('https://login.example.invalid/realms/platform', 'https://grafana.example.invalid')


class AuditProjectionTests(unittest.TestCase):
    def test_missing_stale_failed_and_truncated_evidence_has_alerts(self):
        from automation.observability.configuration import audit_rules
        rules = {rule['alert']: rule for rule in audit_rules()['groups'][0]['rules']}
        for realm in ('Platform', 'Applications'):
            expression = rules['KeycloakEvidenceStale' + realm]['expr']
            self.assertIn('absent(', expression)
            self.assertIn('> 900', expression)
        self.assertIn('KeycloakHealthJobFailed', rules)
        self.assertIn('KeycloakAuditIncomplete', rules)

    def test_secret_looking_values_cannot_pass_field_name_allowlisting(self):
        from automation.identity.health import redact
        event = {'time': 100, 'type': 'SecretPassword', 'error': 'SecretPassword',
                 'operationType': 'SecretPassword', 'resourceType': 'SecretPassword',
                 'representation': {'password': 'must-not-export'}}
        self.assertEqual(redact([event]), [{'time': 100}])
        self.assertEqual(redact([event], admin=True), [{'time': 100}])
