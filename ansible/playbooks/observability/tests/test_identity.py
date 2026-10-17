import unittest
from unittest.mock import patch

from playbooks.keycloak.files.configuration import client
from playbooks.observability.files.identity import contracts


class ClientContractTests(unittest.TestCase):
    def test_local_publication_reads_stdin_before_any_ssh_child(self):
        from playbooks.observability.files.control import identity_prepare
        order = []
        values = {'VM_HOST': 'example.invalid', 'VM_USER': 'fixture', 'VM_PASSWORD': 'synthetic'}
        api = object()
        def inputs():
            order.append('credential')
            return values, api
        def metadata():
            order.append('inspection')
            return {'metadata': True}
        with patch('playbooks.argocd.files.github_setup.inputs', side_effect=inputs), \
                patch('playbooks.observability.files.payload.metadata', side_effect=metadata), \
                patch('playbooks.observability.files.identity.provision', return_value={'private_source_changed': False}) as publish, \
                patch.dict('os.environ', {}, clear=True):
            self.assertEqual(identity_prepare(), {'private_source_changed': False})
        self.assertEqual(order, ['credential', 'inspection'])
        publish.assert_called_once_with({'metadata': True}, values, api)

    def test_machine_access_does_not_reuse_human_oidc_clients(self):
        metadata = {'loginHost': 'login.example.invalid', 'grafanaHost': 'grafana.internal.example.invalid',
                    'kialiHost': 'kiali.internal.example.invalid'}
        for contract in contracts(metadata):
            configured = client(contract, {contract['id']: 'x' * 48})
            self.assertFalse(configured['serviceAccountsEnabled'])
            self.assertFalse(configured['directAccessGrantsEnabled'])
            self.assertFalse(configured['implicitFlowEnabled'])
            self.assertEqual(configured['attributes']['pkce.code.challenge.method'], 'S256')
            self.assertFalse(configured['publicClient'])
