import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.services.files.remote import inspect
from playbooks.services.tests.fixtures import definition, approval


class ReadinessTests(unittest.TestCase):
    def test_identity_reference_requires_authenticated_inventory_provider_and_retirement_intent(self):
        import base64
        from playbooks.keycloak.files.configuration import client
        value, allowed = definition(), approval()
        value['oidc'] = {'enabled': True, 'clientReference': 'synthetic'}
        allowed['identityClient'] = {'realm': 'applications', 'client': 'synthetic'}
        declared = {'id': 'synthetic', 'audience': 'synthetic-api', 'public': True,
            'callbacks': ['https://synthetic.example.invalid/callback'], 'scopes': ['profile'], 'roles': [], 'role_groups': {}}
        configuration = {'realms': {'applications': {'clients': [declared]}}}
        revocations = {'realms': {'applications': {'clients': [], 'removed_clients': []}}}
        identity = {'spec': {'source': {'helm': {'valuesObject': {'adminHost': 'identity-admin.internal.example.invalid'}}}}}
        external = {'metadata': {'uid': 'eso'}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        secret = {'metadata': {'ownerReferences': [{'uid': 'eso'}]},
                  'data': {'client_secret': base64.b64encode(b'x' * 48).decode()}}
        def get(kind, name=None, namespace=None):
            if name == 'cloudlab-public-root': return {'status': {'sync': {'revision': 'b' * 40}}}
            if name == 'cloudlab-identity': return identity
            if kind == 'secret': return secret
            if kind == 'externalsecret.external-secrets.io': return external
            raise AssertionError((kind, name))
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owned'}))
            with patch('playbooks.services.files.remote.get', side_effect=get), \
                    patch('playbooks.services.files.remote.application_ready', return_value=True), \
                    patch('playbooks.keycloak.files.bootstrap.BASE', Path(folder)), \
                    patch('playbooks.keycloak.files.ownership.accepted_application', autospec=True, return_value='c' * 40) as native, \
                    patch('playbooks.keycloak.files.ownership.accepted_private_inventory', autospec=True,
                          return_value=(configuration, revocations, 'd' * 40)) as inventory, \
                    patch('playbooks.keycloak.files.bootstrap.reconciled', return_value=True), \
                    patch('playbooks.keycloak.files.client_readiness.verify', autospec=True) as provider:
                request = {'definition': value, 'approval': allowed, 'action': 'identity'}
                inspect(request)
                provider.assert_called_once_with('applications', client(declared, {}), 'identity-admin.internal.example.invalid')
                provider.reset_mock(); inventory.reset_mock(); native.return_value = None
                with self.assertRaisesRegex(RuntimeError, 'accepted native'): inspect(request)
                inventory.assert_not_called(); provider.assert_not_called(); native.return_value = 'c' * 40
                for tombstone in ('clients', 'removed_clients'):
                    revocations['realms']['applications'][tombstone] = ['synthetic']
                    with self.assertRaisesRegex(RuntimeError, 'lifecycle intent'): inspect(request)
                    revocations['realms']['applications'][tombstone] = []
                retired = dict(request, action='identity-retired')
                with self.assertRaisesRegex(RuntimeError, 'lifecycle intent'): inspect(retired)
                declared['enabled'] = False
                revocations['realms']['applications']['clients'] = ['synthetic']
                inspect(retired)
                self.assertFalse(provider.call_args.args[1]['enabled'])
                declared['enabled'] = True; revocations['realms']['applications']['clients'] = []
                declared['public'] = False
                with self.assertRaisesRegex(RuntimeError, 'client type'): inspect(request)
                value['oidc']['secretReference'] = 'synthetic-oidc'
                value['secrets'] = [{'name': 'synthetic-oidc', 'mountPath': '/secrets/oidc'}]
                allowed['identityClient']['secretReference'] = 'synthetic-oidc'; allowed['secretReferences'] = ['synthetic-oidc']
                inspect(request)
                external['status']['conditions'][0]['status'] = 'False'
                provider.reset_mock()
                with self.assertRaisesRegex(RuntimeError, 'not ready and ESO-owned'): inspect(request)
                provider.assert_not_called()

    def test_identity_follows_current_public_source_without_reusing_bootstrap_revision(self):
        from playbooks.services.files.contract import identity_request
        value = definition()
        value['exposure'] = {'class': 'public', 'hostname': 'notes.example.invalid', 'access': 'public', 'path': '/', 'port': 8080}
        value['oidc'] = {'enabled': True, 'realm': 'applications', 'client': 'notes-web', 'public': True,
                         'audience': 'notes-api', 'callbackPaths': ['/callback'], 'scopes': ['profile'],
                         'roleMapping': {'reader': ['viewer']}}
        desired = identity_request(value, {})['client']
        source = {'repoURL': 'https://github.com/example/platform.git', 'targetRevision': 'main'}
        root = {'spec': {'source': source}, 'status': {'sync': {'revision': 'b' * 40}}}
        identity = {'spec': {'source': dict(source, path='platform/identity/keycloak')}}
        def get(kind, name=None, namespace=None):
            if name == 'identity-private-state':
                return {'data': {'desired_state': json.dumps({'realms': {'applications': {'clients': [desired]}}}),
                                 'revocations': json.dumps({'realms': {}})}}
            if name == 'cloudlab-identity-private': return {'status': {'sync': {'revision': 'private'}}}
            if name == 'cloudlab-public-root': return root
            if name == 'cloudlab-identity': return identity
            raise AssertionError(name)
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owned', 'revision': 'a' * 40}))
            with patch('playbooks.services.files.remote.get', side_effect=get), \
                    patch('playbooks.services.files.remote.application_ready', return_value=True), \
                    patch('playbooks.keycloak.files.bootstrap.BASE', Path(folder)), \
                    patch('playbooks.keycloak.files.ownership.accepted_application', autospec=True, return_value=None), \
                    patch('playbooks.keycloak.files.ownership.accepted_private_inventory', autospec=True) as inventory, \
                    patch('playbooks.keycloak.files.bootstrap.reconciled', return_value=True) as reconciled:
                request = {'definition': value, 'approval': approval(), 'action': 'identity'}
                inspect(request)
                inventory.assert_not_called()
                reconciled.assert_called_once_with('b' * 40, 'owned')
                for field, wrong in (('repoURL', 'https://github.com/example/unapproved.git'), ('targetRevision', 'other'), ('path', 'other')):
                    original = identity['spec']['source'][field]
                    identity['spec']['source'][field] = wrong
                    with self.assertRaises(RuntimeError): inspect(request)
                    identity['spec']['source'][field] = original
                reconciled.return_value = False
                with self.assertRaises(RuntimeError): inspect(request)

    def test_identity_uses_authenticated_native_pin_and_preserves_readiness_gates(self):
        from playbooks.services.files.contract import identity_request
        value = definition()
        value['exposure'] = {'class': 'public', 'hostname': 'notes.example.invalid', 'access': 'public', 'path': '/', 'port': 8080}
        value['oidc'] = {'enabled': True, 'realm': 'applications', 'client': 'notes-web', 'public': True,
                         'audience': 'notes-api', 'callbackPaths': ['/callback'], 'scopes': ['profile'],
                         'roleMapping': {'reader': ['viewer']}}
        desired = identity_request(value, {})['client']
        configuration = {'realms': {'applications': {'clients': [desired]}}}
        revocations = {'realms': {}}
        source = {'repoURL': 'https://github.com/example/platform.git', 'targetRevision': 'main'}
        root = {'spec': {'source': source}, 'status': {'sync': {'revision': 'b' * 40}}}
        identity = {'spec': {'source': dict(source, targetRevision='c' * 40, path='platform/identity/keycloak')}}
        def get(kind, name=None, namespace=None):
            if name == 'cloudlab-public-root': return root
            if name == 'cloudlab-identity': return identity
            raise AssertionError(name)
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owned', 'revision': 'a' * 40}))
            with patch('playbooks.services.files.remote.get', side_effect=get), \
                    patch('playbooks.services.files.remote.application_ready', return_value=True), \
                    patch('playbooks.keycloak.files.bootstrap.BASE', Path(folder)), \
                    patch('playbooks.keycloak.files.ownership.accepted_application', autospec=True, return_value='c' * 40) as accepted, \
                    patch('playbooks.keycloak.files.ownership.accepted_private_inventory', autospec=True,
                          return_value=(configuration, revocations, 'd' * 40)) as inventory, \
                    patch('playbooks.keycloak.files.bootstrap.reconciled', return_value=True) as reconciled:
                request = {'definition': value, 'approval': approval(), 'action': 'identity'}
                inspect(request)
                accepted.assert_called_once_with(identity, base=Path(folder))
                inventory.assert_called_once_with(base=Path(folder))
                reconciled.assert_called_once_with('c' * 40, 'owned')
                reconciled.reset_mock()
                inventory.reset_mock()
                accepted.side_effect = RuntimeError('Native owner rejected')
                with self.assertRaisesRegex(RuntimeError, 'Native owner rejected'): inspect(request)
                reconciled.assert_not_called()
                inventory.assert_not_called()
                accepted.side_effect = None
                reconciled.return_value = False
                with self.assertRaisesRegex(RuntimeError, 'writer is not converged'): inspect(request)
                reconciled.return_value = True
                inventory.side_effect = RuntimeError('Private identity source is not converged')
                with self.assertRaisesRegex(RuntimeError, 'Private identity source'): inspect(request)
                inventory.side_effect = None
                configuration['realms']['applications']['clients'] = []
                with self.assertRaisesRegex(RuntimeError, 'exact approved contract'): inspect(request)
                configuration['realms']['applications']['clients'] = [desired]
                revocations['realms']['applications'] = {'clients': [value['oidc']['client']]}
                with self.assertRaisesRegex(RuntimeError, 'exact approved contract'): inspect(request)

    def test_private_host_denial_uses_verified_public_tls_and_requires_http_404(self):
        value = definition()
        value['exposure'] = {'class': 'private', 'hostname': 'service.internal.example.invalid',
                             'access': 'tailnet', 'path': '/', 'port': 8080}
        def get(kind, name=None, namespace=None):
            if kind.startswith('httproute.'):
                return {'spec': {'hostnames': ['cd.example.invalid']}}
            if name == 'cloudlab-istio': return {'spec': {'clusterIP': '10.43.0.1'}}
            if name == 'cloudlab-tailnet':
                return {'status': {'loadBalancer': {'ingress': [{'ip': '100.64.0.1'}]}}}
            raise AssertionError((kind, name))
        request = {'action': 'private-boundary', 'definition': value, 'approval': approval()}
        with patch('playbooks.services.files.remote.get', side_effect=get), \
                patch('playbooks.services.files.remote.direct_https', return_value=(404, b'')) as https:
            self.assertEqual(inspect(request), {'privatePeer': '100.64.0.1'})
            self.assertEqual(https.call_args.args[0], 'https://cd.example.invalid/')
            self.assertEqual(https.call_args.args[2]['Host'], value['exposure']['hostname'])
            for status in (200, 401, 403):
                https.return_value = (status, b'')
                with self.assertRaisesRegex(RuntimeError, 'reachable'): inspect(request)

    def test_pinned_parent_source_and_exact_external_source_are_required(self):
        value, allowed = definition(), approval()
        platform = {'repoURL': 'https://github.com/example/platform.git', 'targetRevision': 'b' * 40}
        source = dict(platform, path='charts/service', helm={'valuesObject': value})
        application = {'spec': {'project': allowed['name'], 'destination': {
            'server': 'https://kubernetes.default.svc', 'namespace': allowed['namespace']},
            'sources': [source, {'repoURL': allowed['repository'], 'targetRevision': allowed['revision'], 'ref': 'values'}]},
            'status': {'health': {'status': 'Healthy'}, 'sync': {'status': 'Synced'}}}
        deployment = {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1, 'availableReplicas': value['replicas']},
                      'spec': {'template': {'spec': {'containers': [{'image': value['image']}]}}}}
        def get(kind, name=None, namespace=None):
            if kind.startswith('application.'):
                return {'spec': {'source': platform}} if name == 'cloudlab-services' else application
            if kind == 'deployment': return deployment
            if kind == 'resourcequota': return {'spec': {'hard': {'requests.cpu': '1'}}}
            raise AssertionError(kind)
        request = {'action': 'backend', 'definition': value, 'approval': allowed}
        with patch('playbooks.services.files.remote.get', side_effect=get):
            inspect(request)
            original = copy.deepcopy(application)
            for index, field, wrong in ((0, 'targetRevision', 'c' * 40), (0, 'path', 'unapproved'),
                                        (1, 'targetRevision', 'd' * 40), (1, 'repoURL', platform['repoURL'])):
                application['spec']['sources'][index][field] = wrong
                with self.assertRaises(RuntimeError): inspect(request)
                application = copy.deepcopy(original)
            allowed['repository'] = platform['repoURL']
            application['spec'].pop('sources')
            application['spec']['source'] = copy.deepcopy(original['spec']['sources'][0])
            inspect(request)
