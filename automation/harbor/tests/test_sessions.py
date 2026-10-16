from contextlib import nullcontext
from pathlib import Path
import io
import json
import tempfile
import unittest
from unittest.mock import Mock, patch
import yaml

from automation.harbor import sessions


class SessionTests(unittest.TestCase):
    def test_cleanup_cannot_retire_a_foreign_realm_or_credential_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / 'fixture.json'
            request = {'nonce': 'a' * 32, 'realm': 'platform'}
            checkpoint.write_text(json.dumps(request))
            with patch.object(sessions.api, 'WORK', Path(temporary)), patch.object(sessions, 'CHECKPOINT', checkpoint), \
                    patch('automation.identity.owner_enrollment.inputs', return_value=({}, Mock(), {}, {})), \
                    patch('automation.identity.session_setup.environment'), \
                    patch('automation.credentials.vault.fields') as fields, \
                    patch('automation.identity.session_setup.retire') as retire:
                fields.return_value = {'username': 'primary', 'ownership_id': 'a' * 32}
                with self.assertRaises(ValueError): sessions.cleanup()
                retire.assert_not_called()
                fields.return_value = {'username': 'proof-' + 'a' * 32, 'ownership_id': 'a' * 32}
                checkpoint.write_text(json.dumps(dict(request, realm='applications')))
                with self.assertRaises(ValueError): sessions.cleanup()
                retire.assert_not_called()
                checkpoint.write_text(json.dumps(request))
                self.assertTrue(sessions.cleanup()['original_vault_inputs_preserved'])
                self.assertEqual(retire.call_args.args[2:], (request, checkpoint))

    def test_browser_has_no_vault_host_state_or_persistent_profile(self):
        root = Path(__file__).resolve().parents[3]
        services = yaml.safe_load((root / 'automation/harbor/compose.sessions.yaml').read_text())['services']
        browser = services['harbor-browser']
        self.assertEqual(browser['volumes'], ['./browser.mjs:/proof/harbor.mjs:ro'])
        self.assertEqual(browser['logging'], {'driver': 'none'})
        self.assertTrue(browser['read_only'])
        self.assertEqual(browser['cap_drop'], ['ALL'])
        self.assertNotIn('environment', browser)
        self.assertNotIn('ports', browser)
        self.assertNotIn('network_mode', browser)

    def test_browser_evidence_cannot_export_secrets_or_relax_session_bounds(self):
        good = {'browser_cookie_denied_seconds': 240, 'oidc_cli_denied_seconds': 900,
                'last_registry_token_denied_seconds': 1200, 'offboarded_new_login_denied': True,
                'sessions_persisted': False}
        self.assertEqual(sessions.observation(good), good)
        for change in ({'password': 'synthetic'}, {'browser_cookie_denied_seconds': 246},
                       {'last_registry_token_denied_seconds': 1501}, {'oidc_cli_denied_seconds': float('nan')},
                       {'oidc_cli_denied_seconds': True}, {'sessions_persisted': True},
                       {'offboarded_new_login_denied': False}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                sessions.observation(dict(good, **change))
        for raw in (b'', b' ' * 16385):
            with self.assertRaises(RuntimeError): sessions.receive(io.BytesIO(raw))

    def test_human_enrollment_requires_verified_oidc_roles_and_unchanged_accepted_api_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / 'browser/fixture.json'
            client = Mock()
            client.connected.return_value = nullcontext()
            with patch.object(sessions.api, 'WORK', Path(temporary)), \
                    patch.object(sessions, 'CHECKPOINT', checkpoint), \
                    patch.object(sessions.api, 'Client', return_value=client), \
                    patch.object(sessions, 'prepare_viewer', return_value={'disposable_viewer_ready': True}) as enroll:
                for result in ({'changes': 1, 'apply_blocked': None}, {'changes': 0, 'apply_blocked': 'drift'}):
                    client.plan.return_value = result
                    with self.assertRaises(RuntimeError): sessions.prepare()
                    enroll.assert_not_called()
                client.plan.side_effect = ValueError('OIDC prerequisites differ')
                with self.assertRaises(ValueError): sessions.prepare()
                enroll.assert_not_called()
                client.plan.side_effect = None
                client.plan.return_value = {'changes': 0, 'apply_blocked': None}
                self.assertFalse(sessions.prepare()['harbor_browser_acceptance_proven'])
                enroll.assert_called_once_with(checkpoint, 'platform')
                client.plan.assert_called_with(verify=True)
