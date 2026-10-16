import base64
import json
import io
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml
from unittest.mock import call, patch

from automation.harbor import verify, recovery


class VerificationTests(unittest.TestCase):
    def test_deployed_verifier_imports_without_checkout_or_extra_packages(self):
        root = Path(__file__).resolve().parents[3]
        tasks = yaml.safe_load((root / 'ansible/roles/harbor/tasks/main.yml').read_text())
        modules = next(task['loop'] for task in tasks if task.get('name') == 'Install Harbor declaration and recovery owners')
        artifacts = next(task['loop'] for task in tasks if task.get('name') == 'Install the Harbor export policy and independent image pins')
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            for relative in ([f'automation/harbor/{name}' for name in modules] +
                             ['automation/mesh/kube.py', 'automation/gitops/source_revision.py',
                              'automation/identity/health.py'] + [f'platform/harbor/{name}' for name in artifacts]):
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / relative, target)
            result = subprocess.run([sys.executable, '-I', '-S', '-c',
                                     'import sys; sys.path.insert(0, sys.argv[1]); '
                                     'from automation.harbor.verify import oidc_discovery; assert callable(oidc_discovery); '
                                     'from automation.harbor.recovery import ARTIFACTS; import json; '
                                     'assert json.loads((ARTIFACTS / "cosign.lock.json").read_text())["image"]',
                                     str(destination)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_core_discovery_requires_tls_and_the_exact_platform_endpoints(self):
        issuer = 'https://login.example.invalid/realms/platform'
        document = {'issuer': issuer, 'authorization_endpoint': issuer + '/protocol/openid-connect/auth',
                    'token_endpoint': issuer + '/protocol/openid-connect/token',
                    'jwks_uri': issuer + '/protocol/openid-connect/certs'}
        with patch.object(recovery, 'execute', return_value=json.dumps(document).encode()) as execute:
            self.assertTrue(verify.oidc_discovery('login.example.invalid')['trusted_tls'])
            self.assertEqual(execute.call_args.args[0], 'core')
            arguments = execute.call_args.args[1]
            self.assertNotIn('--insecure', arguments)
            self.assertNotIn('--resolve', arguments)
            self.assertIn('--fail', arguments)
            for key in document:
                execute.return_value = json.dumps(dict(document, **{key: 'https://foreign.example.invalid'})).encode()
                with self.subTest(field=key), self.assertRaisesRegex(RuntimeError, 'exact trusted platform issuer'):
                    verify.oidc_discovery('login.example.invalid')
            execute.side_effect = RuntimeError('TLS unavailable')
            with self.assertRaises(RuntimeError): verify.oidc_discovery('login.example.invalid')

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
                patch.object(verify, 'oidc_discovery', return_value={'core_oidc_discovery': True}), \
                patch.object(verify.deployments, 'verify', return_value={'active': False}) as deployed, \
                patch.object(verify, 'application_ready', return_value=True), \
                patch.object(recovery, 'application', return_value={'spec': {'source': {'repoURL': payload['repository']}}}), \
                patch.object(recovery, 'sources', return_value={}), patch.object(recovery, 'fingerprints', return_value={}), \
                patch.object(recovery, 'secret', return_value={'username': base64.b64encode(b'admin'), 'password': base64.b64encode(b'synthetic')}), \
                patch.object(recovery, 'run', return_value={'restored': True}) as restore:
            self.assertTrue(verify.run(payload)['public_gateway_denied'])
            restore.assert_called_once_with('check-local')
            deployed.return_value = {'active': True, 'rollback_replicasets': 10, 'fresh_kubelet_pulls': 4}
            deployed.reset_mock()
            self.assertEqual(verify.run(payload)['deployed_rollback']['fresh_kubelet_pulls'], 4)
            self.assertEqual(deployed.call_args_list, [call(), call(repull=True)])

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
