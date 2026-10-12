import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation.identity.configuration import initialize_primary
from automation.identity.owner_enrollment import membership
from automation.identity.chart import render
from automation.identity.session_fixture import enroll


class OwnerEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.profile = {'email': 'owner@example.invalid', 'verified': True}
        self.source = {'realms': {'platform': {'memberships': [
            {'username': 'operator-owner', 'groups': ['platform-admin'], 'profile': self.profile}]},
            'applications': {'clients': [{'id': 'notes-web'}], 'memberships': []}}}
        self.revoked = {'realms': {}}
        self.values = {'username': 'operator-owner', 'email': self.profile['email'],
                       'password': 'independent-secret-' * 4, 'ownership_id': 'a' * 32}

    def test_only_applications_membership_changes_and_repeat_preserves(self):
        result = membership(self.source, self.revoked, self.values)
        self.assertEqual(result['realms']['platform'], self.source['realms']['platform'])
        self.assertEqual(result['realms']['applications']['clients'], [{'id': 'notes-web'}])
        self.assertEqual(result['realms']['applications']['memberships'], [
            {'username': 'operator-owner', 'groups': ['platform-admin'], 'profile': self.profile}])
        self.assertEqual(membership(result, self.revoked, self.values), result)
        self.assertEqual(self.source['realms']['applications']['memberships'], [])

    def test_refuses_revocation_changed_membership_and_unverified_owner(self):
        for realm in ('platform', 'applications'):
            with self.assertRaises(ValueError):
                membership(self.source, {'realms': {realm: {'users': ['operator-owner']}}}, self.values)
        source = copy.deepcopy(self.source)
        source['realms']['platform']['memberships'][0]['profile']['verified'] = False
        with self.assertRaises(ValueError): membership(source, self.revoked, self.values)
        source = membership(self.source, self.revoked, self.values)
        source['realms']['applications']['memberships'][0]['groups'] = ['viewer']
        with self.assertRaises(ValueError): membership(source, self.revoked, self.values)

    def test_creation_only_requires_private_owner_and_preserves_enrolled_password(self):
        state = {'realm': 'applications', 'users': [{'username': 'operator-owner',
            'groups': ['/platform-admin'], 'email': self.profile['email'], 'emailVerified': True}]}
        values = {'applications_username': self.values['username'], 'applications_password': self.values['password'],
                  'ownership_id': self.values['ownership_id'], 'email': self.values['email'], 'email_verified': 'true'}
        result = initialize_primary(state, [], values, email_matches=[])
        self.assertEqual(result['users'][0]['requiredActions'], ['webauthn-register'])
        self.assertNotIn('realmRoles', result['users'][0])
        self.assertEqual(result['users'][0]['credentials'][0]['userLabel'], 'initial')
        self.assertEqual(initialize_primary(state, result['users'], values, email_matches=result['users']), state)
        with self.assertRaises(ValueError): initialize_primary(state, [{'username': 'operator-owner'}], values, email_matches=[])
        with self.assertRaises(ValueError): initialize_primary(state, [], values)
        with self.assertRaises(ValueError): initialize_primary(state, [], values, email_matches=[{'username': 'another-owner', 'id': 'foreign'}])
        with self.assertRaises(ValueError): initialize_primary(state, [{'username': 'another-owner'}], values, email_matches=[])
        with self.assertRaises(ValueError): initialize_primary(state, [dict(result['users'][0], id='owned')], values,
            email_matches=[dict(result['users'][0], id='foreign')])
        state['users'][0]['enabled'] = False
        with self.assertRaises(ValueError): initialize_primary(state, [], values, email_matches=[])

    def test_chart_uses_only_applications_writer_after_lease_and_retains_eso(self):
        values = {'enabled': True, 'reconciliationEnabled': True, 'privateStateEnabled': True,
                  'bootstrapAdminEnabled': False, 'trustedProxyAddresses': ['10.0.0.1'], 'databaseCA': 'fixture-ca',
                  'operation': {'action': 'initialize-owner', 'realm': 'applications', 'nonce': 'a' * 32}}
        objects = render(values)
        pod = next(o for o in objects if o['kind'] == 'Job')['spec']['template']['spec']
        init = pod['initContainers'][0]['args'][0]
        self.assertLess(init.index('acquire_sync();'), init.index("prepare_application_owner('/imports'"))
        self.assertNotIn('prepare_removal(', init)
        self.assertIn('KEYCLOAK_LOGINREALM="applications"', pod['containers'][0]['args'][0])
        secret = next(o for o in objects if o['kind'] == 'ExternalSecret' and o['metadata']['name'] == 'keycloak-applications-owner')
        self.assertEqual(secret['spec']['dataFrom'], [{'extract': {'key': 'keycloak-applications-owner'}}])
        staged = render(dict(values, operation=dict(values['operation'], action='prepare-owner')))
        self.assertFalse(any(o['kind'] == 'Job' for o in staged))
        with self.assertRaises(ValueError): render(dict(values, operation=dict(values['operation'], realm='platform')))

    def test_staging_can_create_delivery_before_independent_secret_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owned', 'revision': 'b' * 40}))
            app = {'metadata': {'uid': 'owned', 'resourceVersion': '1', 'labels': {'cloudlab.io/owner': 'identity-bootstrap'}},
                   'spec': {'source': {'targetRevision': 'b' * 40, 'helm': {'valuesObject': {
                       'bootstrapAdminEnabled': False, 'loginHost': 'login.example.invalid',
                       'adminHost': 'identity-admin.internal.example.invalid'}}}}}
            from automation.identity.maintenance import OWNER
            app['metadata']['labels']['cloudlab.io/owner'] = OWNER
            def get(kind, name=None, namespace=None):
                if name == 'cloudlab-keycloak': return {'metadata': {'generation': 1}}
                if name == 'cloudlab-identity-private': return {'spec': {'source': {'repoURL': 'private'}}}
                if name == 'cloudlab-identity': return app
                return None
            def secret(name):
                return {'keycloak-client-secrets': {'client_secrets': '{}'},
                        'keycloak-primary-admin': {'platform_username': 'operator-owner'},
                        'keycloak-realm-writers': {'applications_client_secret': 'scoped'}}[name]
            with patch('automation.identity.maintenance.BASE', root), \
                    patch('automation.mesh.kube.get', side_effect=get), \
                    patch('automation.mesh.kube.condition', return_value=True), \
                    patch('automation.mesh.kube.application_ready', return_value=True), \
                    patch('automation.mesh.kube.wait', side_effect=lambda predicate, *a, **k: self.assertTrue(predicate())), \
                    patch('automation.mesh.kube.kube') as kube, \
                    patch('automation.identity.bootstrap.writer_idle', return_value=True) as idle, \
                    patch('automation.identity.bootstrap.reconciled', return_value=True), \
                    patch('automation.identity.bootstrap.private_inputs', return_value=(self.source, self.revoked, 'revision')), \
                    patch('automation.identity.configuration.compile_state', return_value={'users': []}), \
                    patch('automation.identity.emergency.vault_secret', side_effect=secret), \
                    patch('automation.identity.configuration.private_request', side_effect=lambda url, **k: [] if '/users?' in url else {'access_token': 'scoped'}), \
                    patch('automation.identity.emergency.phase_sync_patches', return_value=[{}, {'op': 'add', 'path': '/operation', 'value': {}}]):
                result = enroll({'nonce': 'a' * 32}, stage=True, application_owner=True)
            self.assertTrue(result['normal_writers_paused'])
            self.assertEqual(idle.call_count, 2)
            self.assertEqual(result['realm_changes'], 0)
            patches = json.loads(kube.call_args.args[-1])
            self.assertEqual(next(row['value'] for row in patches if row['path'].endswith('/valuesObject/operation')),
                             {'action': 'prepare-owner', 'realm': 'applications', 'nonce': 'a' * 32})
