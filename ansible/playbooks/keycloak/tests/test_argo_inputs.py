import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

import yaml
from playbooks.keycloak.files import inputs
from playbooks.keycloak.files.integrations import argo


class ArgoInputTests(unittest.TestCase):
    def run_inputs(self, recovery=None, security=None, private=False):
        public = {'repository': 'https://github.com/example/platform.git',
                  'services': {'enabled': True, 'revision': 'c' * 40}}
        if private:
            public.update(privateSources={'enabled': True, 'revision': 'd' * 40},
                          admission={'enabled': True}, externalSecrets={'enabled': True, 'reconcile': True})
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        if recovery is not None: values['KEYCLOAK_ARGO_RECOVERY_REVISION'] = recovery
        contract = argo('https://login.example.invalid/realms/platform', 'https://console.example.invalid',
                        ['https://cd.internal.example.invalid'])
        api, client = Mock(), MagicMock()
        api.request.side_effect = [{}, {'token': 'synthetic-token'}]
        catalog = {'catalog': [], 'dataApprovals': {}}
        def read(method, path):
            if '/git/ref/heads/main' in path:
                if security == 'unavailable': raise RuntimeError('Current private Git unavailable')
                return {'object': {'sha': 'a' * 40}}
            if '/contents/services/catalog.json?ref=' in path:
                document = catalog
            elif '/contents/platform/sources.yaml?ref=' in path:
                document = {'sources': []}
            elif '/contents/identity/argo-values.yaml?ref=' in path:
                document = contract['helm']
            elif '/contents/identity/configmap.yaml?ref=' in path:
                current = path.endswith('a' * 40)
                client_state = copy.deepcopy(contract['client'])
                denied = {}
                if current and security == 'changed': client_state['callbacks'] = ['https://foreign.invalid']
                if current and security == 'revoked': denied = {'clients': ['argocd']}
                if current and security == 'removed': denied = {'removed_clients': ['argocd']}
                clients = [] if current and security == 'missing' else [client_state]
                document = {'apiVersion': 'v1', 'kind': 'ConfigMap',
                    'metadata': {'name': 'identity-private-state', 'namespace': 'cloudlab-identity'},
                    'data': {'desired_state': json.dumps({'realms': {'platform': {'clients': clients}}}),
                             'revocations': json.dumps({'realms': {'platform': denied}})}}
            else: raise AssertionError('Unexpected private read: ' + path)
            encoded = yaml.safe_dump(document).encode() if '/identity/' in path else json.dumps(document).encode()
            return {'type': 'file', 'encoding': 'base64', 'size': len(encoded),
                    'content': base64.b64encode(encoded).decode()}
        client.request.side_effect = read
        client.opener.open.return_value.__enter__.return_value.status = 204
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'gitops/roots/public').mkdir(parents=True)
            (root / 'gitops/roots/public/values.yaml').write_text(yaml.safe_dump(public))
            with patch('playbooks.secrets.files.vault.fields', side_effect=[
                        {'API_TOKEN': 'synthetic', 'ZONE_ID': 'synthetic'},
                        {'APP_ID': '1', 'INSTALLATION_ID': '2', 'PRIVATE_KEY': 'synthetic'}]), \
                    patch('playbooks.access.files.cloudflare.API') as cloudflare, \
                    patch('playbooks.access.files.contract.host_rules', return_value=[{'hostname': 'console.example.invalid', 'access': 'human'}]), \
                    patch('playbooks.argocd.files.github_app.app_token', return_value='synthetic'), \
                    patch('playbooks.argocd.files.github_app.verify_installation'), \
                    patch('playbooks.argocd.files.github_setup.GitHub', side_effect=[api, client]), \
                    patch('playbooks.keycloak.files.private_source.inspect', return_value={}), \
                    patch.object(inputs, 'ROOT', root):
                cloudflare.return_value.request.return_value = {'name': 'example.invalid'}
                result = inputs.native_argo(values)
        return result, client

    def test_catalog_and_identity_are_read_at_one_immutable_private_revision(self):
        result, client = self.run_inputs()
        self.assertEqual(result['target']['valuesRevision'], 'a' * 40)
        self.assertEqual(result['serviceActivation']['private_revision'], 'a' * 40)
        self.assertTrue(any('/contents/services/catalog.json?ref=' + 'a' * 40 in call.args[1]
                            for call in client.request.call_args_list))
        self.assertNotIn('currentSecurityProjection', result)
        self.assertFalse(result['privateActivation']['required'])
        self.assertFalse(any('/contents/platform/sources.yaml' in call.args[1] for call in client.request.call_args_list))

    def test_recovery_validates_current_main_before_reading_recorded_revision(self):
        result, client = self.run_inputs('b' * 40)
        self.assertEqual(result['target']['valuesRevision'], 'b' * 40)
        self.assertEqual(result['currentSecurityProjection']['revision'], 'a' * 40)
        paths = [call.args[1] for call in client.request.call_args_list]
        current = paths.index('repos/example/private/contents/identity/configmap.yaml?ref=' + 'a' * 40)
        historical = paths.index('repos/example/private/contents/identity/configmap.yaml?ref=' + 'b' * 40)
        self.assertLess(current, historical)
        self.assertTrue(any('/contents/services/catalog.json?ref=' + 'b' * 40 in path for path in paths))

    def test_recovery_refuses_current_main_revocation_removal_or_changed_client(self):
        for security in ('revoked', 'removed', 'missing', 'changed'):
            with self.subTest(security=security), self.assertRaisesRegex(RuntimeError, 'active exact-callback'):
                self.run_inputs('b' * 40, security)

    def test_recovery_refuses_when_current_private_git_is_unavailable(self):
        with self.assertRaisesRegex(RuntimeError, 'Current private Git unavailable'):
            self.run_inputs('b' * 40, 'unavailable')

    def test_mutable_or_foreign_recovery_input_refuses_before_secret_or_network_reads(self):
        for revision in ('main', 'https://github.com/foreign/private.git', 'a' * 39):
            with self.subTest(revision=revision), patch('playbooks.secrets.files.vault.fields') as read:
                with self.assertRaises(ValueError): inputs.native_argo({'KEYCLOAK_ARGO_RECOVERY_REVISION': revision})
                read.assert_not_called()

    def test_private_registry_uses_same_immutable_revision_in_normal_and_recovery_inputs(self):
        for recovery in (None, 'b' * 40):
            with self.subTest(recovery=recovery):
                result, client = self.run_inputs(recovery, private=True)
                revision = recovery or 'a' * 40
                self.assertEqual(result['privateActivation']['private_revision'], revision)
                self.assertEqual(result['privateActivation']['registry'], {'sources': []})
                paths = [call.args[1] for call in client.request.call_args_list]
                self.assertEqual([path for path in paths if '/contents/platform/sources.yaml' in path],
                                 ['repos/example/private/contents/platform/sources.yaml?ref=' + revision])
