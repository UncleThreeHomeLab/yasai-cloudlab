import copy
import unittest

from automation.identity.configuration import initialize_primary
from automation.identity.owner_enrollment import membership
from automation.identity.chart import render


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
        result = initialize_primary(state, [], values)
        self.assertEqual(result['users'][0]['requiredActions'], ['webauthn-register'])
        self.assertNotIn('realmRoles', result['users'][0])
        self.assertEqual(initialize_primary(state, result['users'], values), state)
        with self.assertRaises(ValueError): initialize_primary(state, [{'username': 'operator-owner'}], values)
        state['users'][0]['enabled'] = False
        with self.assertRaises(ValueError): initialize_primary(state, [], values)

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
