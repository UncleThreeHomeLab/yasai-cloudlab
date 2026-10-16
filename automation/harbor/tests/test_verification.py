import base64
import json
import io
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

from automation.harbor import verify, recovery


class VerificationTests(unittest.TestCase):
    def test_failure_receipt_keeps_only_exception_type_and_source_locations(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(recovery, 'BASE', Path(directory)), \
                patch.object(recovery, 'application', side_effect=RuntimeError('synthetic-private-value')), \
                patch.object(sys, 'stdin', io.StringIO('{}')):
            previous = os.umask(0o077)
            try:
                with self.assertRaises(SystemExit):
                    runpy.run_module('automation.harbor.verify', run_name='__main__')
            finally:
                os.umask(previous)
            receipt = Path(directory) / 'verification-failure.json'
            self.assertNotIn('synthetic-private-value', receipt.read_text())
            self.assertEqual(json.loads(receipt.read_text())['type'], 'RuntimeError')
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)

    def fixtures(self):
        payload = {'repository': 'https://github.com/fixture/platform.git', 'revision': 'a' * 40,
                   'configuration': {'harborHost': 'harbor.internal.example.invalid', 'loginHost': 'login.example.invalid'}}
        settings = {'auth_mode': 'oidc_auth', 'oidc_endpoint': 'https://login.example.invalid/realms/platform',
                    'oidc_client_id': 'harbor', 'oidc_verify_cert': True, 'self_registration': False,
                    'oidc_auto_onboard': True, 'token_expiration': 5,
                    'project_creation_restriction': 'adminonly', 'oidc_user_claim': 'sub', 'oidc_groups_claim': 'groups'}
        def resource(kind, name=None, namespace=None):
            if kind == 'pvc': return {'items': [{'metadata': {'name': name}} for name in recovery.CLAIMS.values()]}
            if kind == 'storageclass': return {'reclaimPolicy': 'Retain', 'parameters': {
                'recurringJobSelector': '[{"name":"harbor-coordinated","isGroup":true}]'}}
            if kind == 'httproute.gateway.networking.k8s.io': return {'spec': {'hostnames': [payload['configuration']['harborHost']],
                'parentRefs': [{'name': 'cloudlab', 'namespace': 'cloudlab-gateway-private', 'sectionName': 'https'}]}}
            if kind == 'service': return {'spec': {'clusterIP': '10.43.0.100' if namespace.endswith('public') else '10.43.0.101'}}
            raise AssertionError('Unexpected resource request')
        return payload, settings, resource

    def test_public_negative_probe_keeps_valid_public_sni_and_private_host(self):
        payload, settings, resource = self.fixtures()
        def request(url, address, headers):
            if address == '10.43.0.100':
                self.assertEqual(url, 'https://login.example.invalid/v2/')
                self.assertEqual(headers, {'Host': 'harbor.internal.example.invalid'})
                return 404, b''
            if url.endswith('/configurations'):
                return 200, json.dumps({key: {'value': value} for key, value in settings.items()}).encode()
            return 401, b''
        with patch.object(verify, 'get', side_effect=resource), patch.object(verify, 'direct_https', side_effect=request), \
                patch.object(verify, 'application_ready', return_value=True), \
                patch.object(recovery, 'application', return_value={'spec': {'source': {'repoURL': payload['repository']}}}), \
                patch.object(recovery, 'sources', return_value={}), patch.object(recovery, 'fingerprints', return_value={}), \
                patch.object(recovery, 'secret', return_value={'username': base64.b64encode(b'admin'), 'password': base64.b64encode(b'synthetic')}), \
                patch.object(recovery, 'run', return_value={'restored': True}) as restore:
            self.assertTrue(verify.run(payload)['public_gateway_denied'])
            restore.assert_called_once_with('check-local')

    def test_wrong_authentication_mode_stops_before_recovery_or_human_onboarding(self):
        payload, settings, resource = self.fixtures()
        settings['auth_mode'] = 'db_auth'
        with patch.object(verify, 'get', side_effect=resource), \
                patch.object(verify, 'direct_https', return_value=(200, json.dumps({key: {'value': value} for key, value in settings.items()}).encode())), \
                patch.object(verify, 'application_ready', return_value=True), \
                patch.object(recovery, 'application', return_value={'spec': {'source': {'repoURL': payload['repository']}}}), \
                patch.object(recovery, 'sources', return_value={}), \
                patch.object(recovery, 'secret', return_value={'username': base64.b64encode(b'admin'), 'password': base64.b64encode(b'synthetic')}), \
                patch.object(recovery, 'run') as restore:
            with self.assertRaisesRegex(RuntimeError, 'do not create human accounts'): verify.run(payload)
            restore.assert_not_called()
