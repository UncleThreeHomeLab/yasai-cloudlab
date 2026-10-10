import json
import copy
import yaml
import subprocess
import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from urllib.error import HTTPError

from automation.identity.configuration import exact_url, baseline, bootstrap_writer, bootstrap_health, client, compile_state, prepare, prepare_master, prepare_removal, restrict_password_grants, bootstrap_retirement, initialize_primary
from automation.identity.rotation import replacement, inventory, request_scope
from automation.identity.lifecycle import remove
from automation.identity.lease import available, previous_writer_done
from automation.identity.operations import change, private_files
from automation.identity.health import redact, proxy_privacy
from automation.identity.tokens import access_token, identity_token
from automation.identity.maintenance import set_maintenance, recover_startup
from automation.identity.recovery import verify_restored, signature_state, restore_configuration
from automation.identity.integrations import argo, access
from automation.identity.access_provider import prepare as prepare_access_provider
from automation.identity.isolated_restore import policies, pod, client_inventory, run as restore_issuer
from automation.identity.access_inputs import names
from automation.gitops.source_revision import matches_revision
from automation.gitops.private_sources import PEM_TEMPLATE
from automation.identity.bootstrap import application, private_resources, discover
from automation.identity.private_source import publish, argo_values, decode_contents
from automation.identity.argo import validate as validate_native_argo
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class IdentityTests(unittest.TestCase):
    def test_browser_login_copies_preserve_passkeys_and_reject_conflicting_items(self):
        from automation.identity.credentials import primary_login_items
        primary = {'master_username': 'master-fixture', 'platform_username': 'operator-fixture',
                   'master_password': 'x' * 64, 'platform_password': 'y' * 64, 'ownership_id': 'a' * 32}
        hosts = {'loginHost': 'login.example.invalid', 'adminHost': 'identity-admin.internal.example.invalid'}
        items = {}
        writes = []
        def command(arguments, token, document=None):
            if arguments[:2] == ['item', 'list']:
                return [{'id': title, 'title': title} for title in items]
            if arguments[:2] == ['item', 'get']:
                return copy.deepcopy(items[arguments[2]])
            self.assertEqual(arguments[:3], ['item', 'create', '-'])
            writes.append(copy.deepcopy(document))
            items[document['title']] = dict(copy.deepcopy(document), id=document['title'])
            return items[document['title']]
        with patch('automation.identity.credentials.command', side_effect=command):
            first = primary_login_items('private-writer', primary, hosts)
            self.assertEqual(len(first['created']), 2)
            self.assertFalse(first['passkeys_created'])
            enrolled = items['keycloak-master-admin-login']
            enrolled['fields'].append({'id': 'passkey', 'type': 'PASSKEY', 'value': 'private-authenticator'})
            before = copy.deepcopy(items)
            self.assertEqual(len(primary_login_items('private-writer', primary, hosts)['preserved']), 2)
            self.assertEqual(items, before)
            self.assertEqual(len(writes), 2)
            enrolled['fields'][0]['value'] = 'unrelated-person'
            with self.assertRaises(RuntimeError): primary_login_items('private-writer', primary, hosts)
            self.assertEqual(len(writes), 2)

    def test_session_offboarding_requires_applied_private_tombstone_and_exact_identity(self):
        from automation.identity import lifecycle
        request = {'realm': 'applications', 'username': 'fixture-person',
                   'user_id': '12345678-1234-1234-1234-123456789abc', 'email': 'fixture@example.invalid'}
        user = dict(request, id=request['user_id'], enabled=False, emailVerified=True)
        user.pop('realm'); user.pop('user_id')
        private = {'format': 1, 'realms': {'applications': {'memberships': [{'username': request['username'], 'groups': []}]}}}
        registry = {'format': 1, 'realms': {'applications': {'users': [request['username']]}}}
        rows = [user]
        writes = []
        def api(url, **kwargs):
            if url.endswith('/token'): return {'access_token': 'private-token'}
            if '/users?' in url: return rows
            if url.endswith('/credentials'): return [{'id': 'retained', 'type': 'webauthn'}]
            if url.endswith('/sessions'): return []
            writes.append((url, kwargs))
            self.assertTrue(url.endswith('/logout'))
            self.assertEqual(kwargs['method'], 'POST')
            self.assertEqual(kwargs['accepted_statuses'], (204,))
        resources = {
            'cloudlab-identity': {'metadata': {'uid': 'owned', 'labels': {'cloudlab.io/owner': 'cloudlab-identity-bootstrap'}},
                  'spec': {'source': {'helm': {'valuesObject': {'adminHost': 'identity-admin.internal.example.invalid'}}}}},
            'cloudlab-identity-private': {'spec': {'source': {'repoURL': 'private-source'}}},
            'keycloak-realm-writers': {'metadata': {'ownerReferences': [{'uid': 'eso', 'kind': 'ExternalSecret'}]},
                                      'data': {'applications_client_secret': base64.b64encode(b'x' * 48).decode()}},
        }
        with tempfile.TemporaryDirectory() as directory, patch.object(lifecycle, 'BASE', Path(directory)), \
                patch.object(lifecycle, 'get', side_effect=lambda kind, name, ns=None: {
                    'metadata': {'uid': 'eso'}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
                    if kind == 'externalsecret.external-secrets.io' else resources[name]), \
                patch.object(lifecycle, 'application_ready', return_value=True), \
                patch.object(lifecycle, 'private_request', side_effect=api), \
                patch('automation.identity.bootstrap.private_inputs', side_effect=lambda payload: (private, registry, 'private-sha')):
            (Path(directory) / 'ownership.json').write_text(json.dumps({'uid': 'owned', 'phase': 'scoped', 'revision': 'public-sha'}))
            self.assertTrue(lifecycle.offboard(request)['keycloak_sessions_invalidated'])
            self.assertEqual(len(writes), 1)
            for changed in ({'id': '87654321-1234-1234-1234-123456789abc'}, {'enabled': True}, {'emailVerified': False}, {'email': 'other@example.invalid'}):
                rows[:] = [dict(user, **changed)]
                with self.assertRaises(RuntimeError): lifecycle.offboard(request)
                self.assertEqual(len(writes), 1)
            rows[:] = [user]
            registry['realms']['applications']['users'] = []
            with self.assertRaises(RuntimeError): lifecycle.offboard(request)
            self.assertEqual(len(writes), 1)

    def test_offboarding_rejects_machine_master_and_incomplete_identity_before_io(self):
        from automation.identity.lifecycle import offboard_scope
        request = {'realm': 'applications', 'username': 'fixture-person',
                   'user_id': '12345678-1234-1234-1234-123456789abc', 'email': 'fixture@example.invalid'}
        for changed in ({'realm': 'master'}, {'username': 'service-account-realm-writer'}, {'user_id': 'x' * 36},
                        {'email': 'fixture@\nexample.invalid'}, {'extra': True}):
            with self.assertRaises(ValueError): offboard_scope(dict(request, **changed))

    def test_platform_session_offboarding_refuses_prior_access_provider_before_remote_changes(self):
        from automation.identity import lifecycle
        from contextlib import contextmanager
        @contextmanager
        def transaction():
            yield Mock(load=Mock(return_value={'identity_provider': {'phase': 'prepared', 'id': 'dedicated'}}))
        request = {'realm': 'platform', 'username': 'fixture-person',
                   'user_id': '12345678-1234-1234-1234-123456789abc', 'email': 'fixture@example.invalid'}
        with patch('dotenv.dotenv_values', return_value={}), \
                patch('automation.connectivity.checkpoint.transaction', transaction), \
                patch('automation.connectivity.preflight.ssh') as ssh:
            with self.assertRaisesRegex(RuntimeError, 'accepted dedicated Access cutover'):
                lifecycle.local_offboard(request)
            ssh.assert_not_called()

    def test_access_revocation_preserves_device_identity_and_does_not_claim_session_denial(self):
        from automation.identity import lifecycle
        from contextlib import contextmanager
        account = 'a' * 32
        state = {'identity_provider': {'phase': 'accepted', 'id': 'dedicated', 'binding': {'account': account}},
                 'objects': {'app:fixture.example.invalid': {'id': 'application'}}}
        @contextmanager
        def transaction():
            yield Mock(load=Mock(return_value=state))
        request = {'realm': 'platform', 'username': 'fixture-person',
                   'user_id': '12345678-1234-1234-1234-123456789abc', 'email': 'fixture@example.invalid'}
        api = Mock()
        api.request.side_effect = [{'policies': [{'decision': 'allow'}], 'allowed_idps': ['dedicated']}, True]
        with patch('dotenv.dotenv_values', return_value={'VM_HOST': 'fixture'}), \
                patch('automation.connectivity.checkpoint.transaction', transaction), \
                patch('automation.credentials.vault.fields', return_value={'API_TOKEN': 'private', 'ACCOUNT_ID': account}), \
                patch('automation.connectivity.cloudflare.API', return_value=api), \
                patch('automation.connectivity.preflight.ssh', return_value='{"keycloak_sessions_invalidated":true}'):
            result = lifecycle.local_offboard(request)
        self.assertFalse(result['access_session_denial_measured'])
        self.assertEqual(api.request.call_args.args, ('POST', 'accounts/' + account + '/access/organizations/revoke_user',
            {'email': 'fixture@example.invalid', 'devices': False, 'warp_session_reauth': False}))

    def test_private_request_accepts_empty_204_for_session_logout(self):
        from automation.identity.configuration import private_request
        from unittest.mock import MagicMock
        response = MagicMock(status=204)
        response.read.return_value = b''
        response.__enter__.return_value = response
        with patch('urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = response
            self.assertIsNone(private_request('https://identity.example.invalid/logout', token='private',
                              method='POST', accepted_statuses=(204,)))
            self.assertEqual(opener.return_value.open.call_args.args[0].get_method(), 'POST')

    def test_only_scheduled_writers_skip_busy_valid_leases(self):
        from automation.identity import lease
        from unittest.mock import MagicMock
        current = {'spec': {'holderIdentity': 'other'}}
        with patch.object(lease, 'Path') as paths, patch.object(lease.ssl, 'create_default_context'), \
                patch.object(lease, 'owned_lease', return_value=current), \
                patch.object(lease, 'available', return_value=False), \
                patch.object(lease.urllib.request, 'urlopen') as request:
            paths.return_value.joinpath.return_value.read_text.return_value = 'private'
            self.assertFalse(lease.acquire(skip_busy=True))
            with self.assertRaisesRegex(RuntimeError, 'holds the lease'):
                lease.acquire()
            request.assert_not_called()
        with patch.object(lease, 'Path') as paths, patch.object(lease.ssl, 'create_default_context'), \
                patch.object(lease, 'owned_lease', side_effect=RuntimeError('conflicting ownership')):
            paths.return_value.joinpath.return_value.read_text.return_value = 'private'
            with self.assertRaisesRegex(RuntimeError, 'conflicting ownership'):
                lease.acquire(skip_busy=True)
        with patch.object(lease, 'Path') as paths, patch.object(lease.ssl, 'create_default_context'), \
                patch.object(lease, 'owned_lease', return_value={'spec': {}}), \
                patch.object(lease, 'available', return_value=True), \
                patch.dict('os.environ', {'POD_UID': 'current'}), \
                patch.object(lease.urllib.request, 'urlopen') as request:
            paths.return_value.joinpath.return_value.read_text.return_value = 'private'
            for status in (409, 403, 500):
                request.side_effect = HTTPError('https://kubernetes.default.svc', status, 'failed', None, None)
                if status == 409:
                    self.assertFalse(lease.acquire(skip_busy=True))
                else:
                    with self.assertRaises(HTTPError): lease.acquire(skip_busy=True)
                with self.assertRaises(HTTPError): lease.acquire()

    def test_live_protocol_check_redacts_audit_and_requires_public_token_and_denied_admin(self):
        from automation.identity import verify
        values = {'loginHost': 'login.example.invalid', 'adminHost': 'identity-admin.internal.example.invalid'}
        expiry = [300]
        responses = []
        def request(url, **kwargs):
            responses.append((url, kwargs))
            if url.endswith('/token'):
                return {'access_token': 'private-token', 'token_type': 'Bearer', 'expires_in': expiry[0]}
            if '/users?' in url:
                self.assertEqual(kwargs['accepted_statuses'], (403,))
                return {'error': 'Forbidden'}
            return [{'time': 1, 'type': 'LOGIN', 'operationType': 'UPDATE',
                     'username': 'private-user', 'ipAddress': 'private-address', 'representation': 'private'}]
        with patch.object(verify, 'check', return_value={'discovery': True, 'jwks': True}), \
                patch.object(verify, 'private_request', side_effect=request), \
                patch.object(verify, 'proxy_privacy', return_value={'public_management_paths_denied': 10}):
            result = verify.protocols(values, dict(platform='x' * 32, applications='y' * 32))
            self.assertTrue(result['realms']['platform']['public_client_credentials_token'])
            for sensitive in ('private-user', 'private-address', 'private-token', 'representation'):
                self.assertNotIn(sensitive, json.dumps(result))
            self.assertEqual(result['realms']['platform']['audit']['login'], [{'time': 1, 'type': 'LOGIN'}])
            token_urls = [url for url, _ in responses if url.endswith('/token')]
            self.assertTrue(all(url.startswith('https://login.example.invalid/') for url in token_urls))
            expiry[0] = 301
            with self.assertRaisesRegex(RuntimeError, 'bounded credential contract'):
                verify.protocols(values, dict(platform='x' * 32, applications='y' * 32))

    def test_live_audit_credentials_reject_replaced_eso_and_unready_sources(self):
        from automation.identity import verify
        external = {'metadata': {'uid': 'owner', 'generation': 1},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        secret = {'metadata': {'ownerReferences': [{'kind': 'ExternalSecret', 'uid': 'owner'}]},
                  'data': {realm + '_client_secret': base64.b64encode(b'x' * 32).decode()
                           for realm in ('platform', 'applications')}}
        with patch.object(verify, 'get', side_effect=lambda kind, *args: external if kind.startswith('externalsecret') else secret):
            self.assertEqual(verify.credentials(), dict(platform='x' * 32, applications='x' * 32))
            secret['metadata']['ownerReferences'][0]['uid'] = 'foreign'
            with self.assertRaisesRegex(RuntimeError, 'ready ESO-owned'):
                verify.credentials()
            secret['metadata']['ownerReferences'][0]['uid'] = 'owner'
            external['status']['conditions'][0]['status'] = 'False'
            with self.assertRaisesRegex(RuntimeError, 'ready ESO-owned'):
                verify.credentials()

    def test_identity_http_clients_identify_themselves_without_browser_impersonation(self):
        from unittest.mock import MagicMock
        from automation.identity.health import json_get
        from automation.identity.configuration import private_request
        for read, agent in ((json_get, 'CloudLab-Identity-Health/1.0'),
                            (private_request, 'CloudLab-Identity-Reconciler/1.0')):
            opener = MagicMock()
            opener.open.return_value.status = 200
            opener.open.return_value.read.return_value = b'{"ok":true}'
            response = opener.open.return_value.__enter__.return_value
            response.status = 200
            response.geturl.return_value = 'https://login.example.invalid/probe'
            response.read.return_value = b'{"ok":true}'
            with patch('urllib.request.build_opener', return_value=opener):
                self.assertEqual(read('https://login.example.invalid/probe'), {'ok': True})
            self.assertEqual(opener.open.call_args.args[0].get_header('User-agent'), agent)

    def test_runtime_lease_create_and_competing_creator_preserve_owner(self):
        from automation.identity.lease import owned_lease, OWNER
        endpoint = 'https://kubernetes.default.svc/apis/coordination.k8s.io/v1/namespaces/cloudlab-identity/leases/identity-writer'
        row = {'metadata': {'name': 'identity-writer', 'namespace': 'cloudlab-identity',
               'uid': 'owned', 'resourceVersion': '9', 'labels': {'cloudlab.io/owner': OWNER}}, 'spec': {}}
        for responses in ([HTTPError(endpoint, 404, 'missing', None, None), row],
                          [HTTPError(endpoint, 404, 'missing', None, None),
                           HTTPError(endpoint, 409, 'competing creator', None, None), row]):
            request = Mock(side_effect=responses)
            self.assertEqual(owned_lease(request, 'cloudlab-identity', endpoint), row)
            created = request.call_args_list[1]
            self.assertEqual(created.args[0], 'POST')
            self.assertEqual(created.kwargs['url'], endpoint.rsplit('/', 1)[0])
            self.assertNotIn('ownerReferences', created.args[1]['metadata'])
        for changes in ({'labels': {}}, {'uid': ''}, {'deletionTimestamp': 'pending'},
                        {'finalizers': ['foreign']}, {'namespace': 'foreign'}):
            request = Mock(return_value=dict(row, metadata=dict(row['metadata'], **changes)))
            with self.assertRaisesRegex(RuntimeError, 'conflicting ownership'):
                owned_lease(request, 'cloudlab-identity', endpoint)
            request.assert_called_once_with('GET')

    def test_runtime_lease_does_not_create_on_forbidden_or_failed_api(self):
        from automation.identity.lease import owned_lease
        for status in (401, 403, 500):
            request = Mock(side_effect=HTTPError('https://kubernetes.default.svc', status, 'denied', None, None))
            with self.assertRaises(HTTPError): owned_lease(request, 'cloudlab-identity', 'https://kubernetes.default.svc/leases/identity-writer')
            request.assert_called_once_with('GET')

    def test_private_owner_accepts_only_eso_cleanup_on_unchanged_resource(self):
        from automation.identity.bootstrap import check_private_owner, OWNER
        metadata = {'uid': 'owned', 'labels': {'cloudlab.io/owner': OWNER},
                    'finalizers': ['externalsecrets.external-secrets.io/externalsecret-cleanup']}
        check_private_owner('ExternalSecret', {'metadata': metadata}, 'owned')
        for kind, changes, saved in (
                ('Application', {}, 'owned'), ('ExternalSecret', {}, 'replacement'),
                ('ExternalSecret', {'finalizers': metadata['finalizers'] + ['foreign']}, 'owned'),
                ('ExternalSecret', {'deletionTimestamp': 'pending'}, 'owned'),
                ('ExternalSecret', {'ownerReferences': [{'uid': 'foreign'}]}, 'owned'),
                ('ExternalSecret', {'labels': {}}, 'owned')):
            with self.subTest(kind=kind, changes=changes), self.assertRaisesRegex(RuntimeError, 'owner conflicts'):
                check_private_owner(kind, {'metadata': dict(metadata, **changes)}, saved)
        with self.assertRaises(RuntimeError): check_private_owner('ExternalSecret', None, 'owned')

    def test_phase_wait_rejects_stale_source_and_busy_writer(self):
        from automation.identity.bootstrap import reconciled, writer_idle
        app = {'metadata': {'uid': 'owned'}, 'spec': {'source': {'helm': {'valuesObject': {'primary': True}}}},
               'status': {'sync': {'comparedTo': {'source': {'helm': {'valuesObject': {'primary': False}}}}}}}
        with patch('automation.identity.bootstrap.get', return_value=app), \
                patch('automation.identity.bootstrap.application_ready', return_value=True):
            self.assertFalse(reconciled('same-revision', 'owned'))
            app['status']['sync']['comparedTo']['source'] = copy.deepcopy(app['spec']['source'])
            self.assertTrue(reconciled('same-revision', 'owned'))
            app['status']['operationState'] = {'phase': 'Failed', 'syncResult': {'revision': 'same-revision'}}
            with self.assertRaisesRegex(RuntimeError, 'preserve the phase checkpoint'):
                reconciled('same-revision', 'owned')
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                reconciled('same-revision', 'replacement')
        lease = {'spec': {'holderIdentity': 'prior', 'renewTime': '1970-01-01T00:00:00Z', 'leaseDurationSeconds': 240}}
        pods = {'items': [{'metadata': {'uid': 'prior'}, 'status': {'phase': 'Running'}}]}
        with patch('automation.identity.bootstrap.get', side_effect=lambda kind, *a, **kw: lease if kind == 'lease' else pods), \
                patch('automation.identity.bootstrap.time.time', return_value=300):
            self.assertFalse(writer_idle())
            pods['items'][0]['status']['phase'] = 'Succeeded'
            self.assertTrue(writer_idle())
        with patch('automation.identity.bootstrap.get', return_value={'spec': lease['spec']}), \
                patch('automation.identity.bootstrap.time.time', return_value=239):
            self.assertFalse(writer_idle())

    def test_machine_bootstrap_validates_private_source_without_creating_people_early(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = {'format': 1, 'realms': {'platform': {'memberships': [
                {'username': 'operator-fixture', 'groups': ['platform-admin']}]}}}
            for field, value in {'desired_state': source, 'revocations': {'format': 1, 'realms': {}},
                                 'client_secrets': {'platform': {}, 'applications': {}}}.items():
                (base / field).write_text(json.dumps(value))
            for realm in ('platform', 'applications'):
                (base / (realm + '_client_secret')).write_text('x' * 64)
                (base / (realm + '_health_secret')).write_text('y' * 64)
            docs = prepare(base / 'out', 'login.example.invalid', base, base)
            self.assertTrue(all(user['username'].startswith('service-account-') for user in docs['platform']['users']))
            primary = prepare(base / 'out', 'login.example.invalid', base, base, primary=True)
            self.assertTrue(any(user['username'] == 'operator-fixture' for user in primary['platform']['users']))
            (base / 'desired_state').unlink()
            with self.assertRaises(FileNotFoundError): prepare(base / 'out', 'login.example.invalid', base, base)

    def test_primary_preparation_validates_both_realms_before_writing_creation_inputs(self):
        from automation.identity.configuration import prepare_primary
        values = {'master_username': 'master-fixture', 'platform_username': 'operator-fixture',
                  'master_password': 'x' * 64, 'platform_password': 'y' * 64,
                  'ownership_id': 'a' * 32, 'email': 'fixture@example.invalid', 'email_verified': 'true'}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for key, value in dict(values, username='bootstrap', password='z' * 64).items():
                (base / key).write_text(value)
            master = {'realm': 'master'}
            platform = {'realm': 'platform', 'users': [{'username': 'operator-fixture', 'groups': ['/platform-admin']}]}
            (base / 'master-bootstrap.json').write_text(json.dumps(master))
            (base / 'platform.json').write_text(json.dumps(platform))
            with patch('automation.identity.configuration.private_request', side_effect=[
                    {'access_token': 'fixture'}, [{'realm': 'master'}, {'realm': 'platform'}], [], {'attributes': []}, {},
                    [{'username': 'operator-fixture', 'attributes': {}}], {'attributes': []}, {}]):
                with self.assertRaisesRegex(ValueError, 'unrelated existing account'):
                    prepare_primary(base, base, base, 'identity-admin.internal.example.invalid')
            self.assertEqual(json.loads((base / 'master-bootstrap.json').read_text()), master)
            self.assertEqual(json.loads((base / 'platform.json').read_text()), platform)
            with patch('automation.identity.configuration.private_request', side_effect=[
                    {'access_token': 'fixture'}, [{'realm': 'master'}, {'realm': 'platform'}],
                    [], {'attributes': []}, {}, [], {'attributes': []}, {}]):
                prepare_primary(base, base, base, 'identity-admin.internal.example.invalid')
            for filename in ('master-bootstrap', 'platform'):
                created = json.loads((base / (filename + '.json')).read_text())
                steady = json.loads((base / (filename + '.steady.json')).read_text())
                self.assertIn('credentials', created['users'][0])
                self.assertTrue(all('credentials' not in user and 'enabled' not in user for user in steady.get('users', [])))

    def test_primary_profile_keeps_unmanaged_fields_and_marker_admin_only(self):
        from automation.identity.configuration import primary_profile
        profile = {'attributes': [{'name': 'username', 'permissions': {'edit': ['user', 'admin']}}],
                   'groups': [{'name': 'unrelated'}], 'unmanagedAttributePolicy': 'ADMIN_VIEW'}
        state = primary_profile({'realm': 'platform'}, profile, {'unrelated': 'preserved',
            'de.adorsys.keycloak.config.import-checksum-primary': 'old-output'})
        self.assertEqual(state['userProfile']['attributes'][:-1], profile['attributes'])
        self.assertEqual(state['userProfile']['groups'], profile['groups'])
        self.assertEqual(state['userProfile']['unmanagedAttributePolicy'], 'ADMIN_VIEW')
        self.assertEqual(state['userProfile']['attributes'][-1]['permissions'], {'view': ['admin'], 'edit': ['admin']})
        self.assertEqual(state['attributes'], {'unrelated': 'preserved', 'userProfileEnabled': 'true'})
        self.assertEqual(primary_profile(state, state['userProfile'], state['attributes']), state)
        self.assertEqual(len(profile['attributes']), 1)
        for unsafe in ({}, {'attributes': [{'name': 'duplicate'}, {'name': 'duplicate'}]}):
            with self.assertRaises(ValueError): primary_profile({'realm': 'master'}, unsafe, {})

    def test_private_github_contents_accept_line_wrapping_but_reject_garbage(self):
        encoded = base64.b64encode(b'complete-private-source').decode()
        self.assertEqual(decode_contents({'content': encoded[:8] + '\r\n' + encoded[8:] + '\n'}), b'complete-private-source')
        for invalid in (encoded + '$', encoded[:8] + ' ' + encoded[8:]):
            with self.assertRaises(ValueError): decode_contents({'content': invalid})
        with self.assertRaises(RuntimeError): decode_contents({'content': 'A' * (2 * 1024 * 1024 + 1)})

    def test_primary_initialization_is_private_creation_only_and_preserves_offboarding(self):
        values = {'master_username': 'master-fixture', 'platform_username': 'operator-fixture',
                  'master_password': 'x' * 64, 'platform_password': 'y' * 64,
                  'ownership_id': 'a' * 32, 'email': 'fixture@example.invalid', 'email_verified': 'true'}
        state = {'realm': 'platform', 'users': [{'username': 'operator-fixture', 'groups': ['/platform-admin']}]}
        initialized = initialize_primary(state, [], values)
        user = initialized['users'][0]
        self.assertEqual(user['requiredActions'], ['webauthn-register'])
        self.assertEqual(user['credentials'][0]['value'], values['platform_password'])
        existing = dict(user, enabled=False, credentials=[{'type': 'webauthn'}])
        self.assertEqual(initialize_primary(state, [existing], values), state)
        self.assertNotIn('enabled', state['users'][0])
        master = initialize_primary({'realm': 'master'}, [], values)
        self.assertEqual(master['users'][0]['realmRoles'], ['admin'])
        self.assertEqual(initialize_primary({'realm': 'master'}, master['users'], values), {'realm': 'master'})
        with self.assertRaisesRegex(ValueError, 'unrelated existing account'):
            initialize_primary(state, [{'username': 'operator-fixture', 'attributes': {}}], values)
        for unsafe in ({'email_verified': 'false'}, {'platform_password': 'short'}, {'ownership_id': 'wrong'}):
            with self.assertRaises(ValueError): initialize_primary(state, [], dict(values, **unsafe))
        with self.assertRaisesRegex(ValueError, 'private source'):
            initialize_primary({'realm': 'platform'}, [], values)
        state['users'][0]['enabled'] = False
        with self.assertRaisesRegex(ValueError, 'private source'):
            initialize_primary(state, [], values)

    def test_access_provider_repeat_drift_rotation_preserve_prior_and_hide_secrets(self):
        from automation.connectivity.test_reconcile import Provider
        api, state = Provider(), {}
        account, previous = 'a' * 32, 'prior-provider'
        path = 'accounts/' + account + '/access/identity_providers'
        prior = {'id': previous, 'name': 'Prior provider', 'type': 'onetimepin', 'config': {}}
        api.objects[path + '/' + previous] = copy.deepcopy(prior)
        contract = access('https://login.example.invalid/realms/platform', 'fixture', 'x' * 64)
        saved = []
        def run():
            return prepare_access_provider(api, account, previous, contract, state, lambda value: saved.append(copy.deepcopy(value)))
        self.assertTrue(run()['changed'])
        self.assertEqual(api.objects[path + '/' + previous], prior)
        identifier = state['identity_provider']['id']
        api.objects[path + '/' + identifier]['config']['client_secret'] = '********'
        api.writes.clear()
        self.assertFalse(run()['changed'])
        self.assertEqual(api.writes, [])
        api.objects[path + '/' + identifier]['config']['pkce_enabled'] = False
        self.assertTrue(run()['changed'])
        api.writes.clear()
        contract = access('https://login.example.invalid/realms/platform', 'fixture', 'y' * 64)
        self.assertTrue(run()['changed'])
        self.assertEqual(api.writes, [('PUT', path + '/' + identifier)])
        self.assertEqual(api.objects[path + '/' + previous], prior)
        self.assertNotIn('x' * 64, json.dumps(saved))
        self.assertNotIn('y' * 64, json.dumps(saved))
        self.assertFalse(run()['browser_and_credential_acceptance'])

    def test_access_provider_refuses_foreign_lost_and_ambiguous_creation(self):
        from automation.connectivity.test_reconcile import Provider
        api, state = Provider(), {}
        account, previous = 'a' * 32, 'prior-provider'
        path = 'accounts/' + account + '/access/identity_providers'
        api.objects[path + '/' + previous] = {'id': previous, 'name': 'Prior provider', 'type': 'onetimepin'}
        contract = access('https://login.example.invalid/realms/platform', 'fixture', 'x' * 64)
        api.interrupt_create = True
        with self.assertRaisesRegex(RuntimeError, 'connection lost'):
            prepare_access_provider(api, account, previous, contract, state, lambda value: None)
        api.writes.clear()
        with self.assertRaisesRegex(RuntimeError, 'explicit identity recovery'):
            prepare_access_provider(api, account, previous, contract, state, lambda value: None)
        self.assertEqual(api.writes, [])
        with self.assertRaisesRegex(RuntimeError, 'without an owner'):
            prepare_access_provider(api, account, previous, contract, {}, lambda value: None)
        state['identity_provider']['id'] = 'lost'
        with self.assertRaisesRegex(RuntimeError, 'recreation refused'):
            prepare_access_provider(api, account, previous, contract, state, lambda value: None)
        unsafe = copy.deepcopy(contract)
        unsafe['provider']['config']['pkce_enabled'] = False
        with self.assertRaises(ValueError):
            prepare_access_provider(api, account, previous, unsafe, {}, lambda value: None)
        self.assertEqual(api.writes, [])

    def test_failed_initial_server_recovery_resumes_and_refuses_foreign_maintenance(self):
        from automation.identity import maintenance
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'ownership.json').write_text(json.dumps({'phase': 'server', 'uid': 'owned'}))
            app = {'metadata': {'uid': 'owned', 'labels': {'cloudlab.io/owner': maintenance.OWNER}},
                   'spec': {'source': {'helm': {'valuesObject': {
                       'enabled': True, 'serverEnabled': True, 'reconciliationEnabled': False}}}}}
            server = {'metadata': {'uid': 'server'}, 'status': {'conditions': []}}
            stateful = {'metadata': {'uid': 'set', 'ownerReferences': [{'uid': 'server'}]},
                        'status': {'updateRevision': 'corrected'}}
            failed = {'metadata': {'ownerReferences': [{'uid': 'set'}], 'labels': {'controller-revision-hash': 'failed'}},
                      'status': {'containerStatuses': [{'state': {'waiting': {'reason': 'CrashLoopBackOff'}}}]}}
            objects = {'application.argoproj.io': app, 'keycloak.k8s.keycloak.org': server,
                       'statefulset': stateful, 'pod': failed}
            values = app['spec']['source']['helm']['valuesObject']
            with patch.object(maintenance, 'BASE', base), \
                    patch.object(maintenance, 'get', side_effect=lambda kind, *args: objects[kind]), \
                    patch.object(maintenance, '_set_maintenance') as cycle:
                values['maintenance'] = True
                with self.assertRaisesRegex(RuntimeError, 'Another maintenance boundary'):
                    recover_startup()
                cycle.assert_not_called()
                values['maintenance'] = False
                cycle.side_effect = [True, RuntimeError('interrupted resume')]
                with self.assertRaisesRegex(RuntimeError, 'interrupted resume'):
                    recover_startup()
                self.assertEqual(json.loads((base / 'startup-recovery.json').read_text())['phase'], 'starting')
                cycle.reset_mock(side_effect=True)
                self.assertTrue(recover_startup()['changed'])
                cycle.assert_called_once_with(False, {'application_uid': 'owned', 'keycloak_uid': 'server'})
                server['status']['conditions'] = [{'type': 'Ready', 'status': 'True'}]
                self.assertFalse(recover_startup()['changed'])
                (base / 'ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owned'}))
                with self.assertRaisesRegex(RuntimeError, 'server-only identity owner'):
                    recover_startup()

    def test_startup_maintenance_refuses_replaced_resources_before_mutation(self):
        from automation.identity import maintenance
        identities = {'application_uid': 'owned', 'keycloak_uid': 'server'}
        app = {'metadata': {'uid': 'replaced', 'labels': {'cloudlab.io/owner': maintenance.OWNER}}}
        with patch.object(maintenance, 'get', return_value=app), patch.object(maintenance, 'kube') as writer:
            with self.assertRaisesRegex(RuntimeError, 'resource identity changed'):
                maintenance._set_maintenance(True, identities)
            writer.assert_not_called()
        app['metadata']['uid'] = 'owned'
        app['spec'] = {'source': {'helm': {'valuesObject': {'enabled': True, 'maintenance': False}}}}
        with patch.object(maintenance, 'get', side_effect=[app, {'metadata': {'uid': 'replaced'}}]), \
                patch.object(maintenance, 'wait', side_effect=lambda check, *args, **kwargs: check()), \
                patch.object(maintenance, 'kube') as writer:
            with self.assertRaisesRegex(RuntimeError, 'resource identity changed'):
                maintenance._set_maintenance(False, identities)
            writer.assert_not_called()
    def test_proxy_privacy_rejects_spoofed_issuers_redirects_and_reachable_management(self):
        import urllib.error
        from unittest.mock import MagicMock
        def discovery(url, **kwargs):
            issuer = url.removesuffix('/.well-known/openid-configuration')
            return {'issuer': issuer, 'token_endpoint': issuer + '/protocol/openid-connect/token'}
        opener = MagicMock()
        opener.open.side_effect = lambda request, **kwargs: (_ for _ in ()).throw(
            urllib.error.HTTPError(request.full_url, 403, 'denied', {}, None))
        with patch('automation.identity.health.json_get', side_effect=discovery) as read, \
                patch('automation.identity.health.urllib.request.build_opener', return_value=opener):
            result = proxy_privacy('login.example.invalid')
            self.assertTrue(result['canonical_proxy_headers'])
            self.assertEqual(result['public_management_paths_denied'], 10)
            self.assertEqual(read.call_args.kwargs['headers']['X-Forwarded-Host'], 'forbidden.invalid')
            for status in (200, 302, 401, 500):
                opener.open.side_effect = None
                opener.open.return_value.__enter__.return_value.status = status
                with self.assertRaisesRegex(RuntimeError, 'not denied at the gateway'):
                    proxy_privacy('login.example.invalid')
        with patch('automation.identity.health.json_get', return_value={'issuer': 'https://forbidden.invalid'}), \
                self.assertRaisesRegex(RuntimeError, 'changed the stable identity issuer'):
            proxy_privacy('login.example.invalid')

    def test_gateway_proxy_trust_survives_pod_replacement_but_rejects_host_network_or_wrong_range(self):
        host_network = [False]
        suffix = [10]
        def objects(kind, name=None, namespace=None):
            if kind == 'certificate.cert-manager.io':
                return {'metadata': {}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]},
                        'spec': {'dnsNames': ['*.internal.example.invalid']}}
            if kind == 'nodes': return {'items': [{'metadata': {'name': 'node'}, 'spec': {'podCIDR': '10.42.0.0/24'}}]}
            if kind == 'pods': return {'items': [{'metadata': {'labels': {'gateway.networking.k8s.io/gateway-name': 'cloudlab'}},
                'spec': {'nodeName': 'node', 'hostNetwork': host_network[0]}, 'status': {'podIP': '10.42.0.' + str(suffix[0])}}]}
            if kind == 'cluster.postgresql.cnpg.io': return {'metadata': {'uid': 'cluster'},
                'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
            if kind == 'secret': return {'metadata': {'ownerReferences': [{'uid': 'cluster'}]},
                'data': {'ca.crt': base64.b64encode(b'fixture-ca').decode()}}
            if kind == 'database.postgresql.cnpg.io': return {'spec': {'name': 'keycloak', 'owner': 'keycloak'}}
            raise AssertionError('Unexpected API read')
        with patch('automation.identity.bootstrap.get', side_effect=objects):
            initial = discover()
            suffix[0] = 27
            self.assertEqual(discover()['trustedProxyAddresses'], initial['trustedProxyAddresses'])
            self.assertEqual(initial['trustedProxyAddresses'], ['10.42.0.0/24'])
            host_network[0] = True
            with self.assertRaisesRegex(RuntimeError, 'verified node Pod range'): discover()

    def test_native_argo_handoff_rejects_changed_private_revision_or_unsafe_configuration(self):
        contract = argo('https://login.example.invalid/realms/platform', 'https://console.example.invalid',
                        ['https://cd.internal.example.invalid'])
        target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'a' * 40}
        payload = {'values': {'loginHost': 'login.example.invalid'}, 'argo': {
            'target': target, 'configuration': contract['helm'], 'client': contract['client']}}
        source = {'format': 1, 'realms': {'platform': {'clients': [contract['client']]}}}
        revoked = {'format': 1, 'realms': {}}
        self.assertEqual(validate_native_argo(payload, source, revoked, 'a' * 40), target)
        with self.assertRaisesRegex(RuntimeError, 'advanced'):
            validate_native_argo(payload, source, revoked, 'b' * 40)
        revoked['realms']['platform'] = {'clients': ['argocd']}
        with self.assertRaisesRegex(RuntimeError, 'active exact-callback'):
            validate_native_argo(payload, source, revoked, 'a' * 40)
        unsafe = copy.deepcopy(payload)
        unsafe['argo']['configuration']['argo-cd']['configs']['cm']['admin.enabled'] = True
        with self.assertRaisesRegex(ValueError, 'scoped producer'):
            validate_native_argo(unsafe, source, {'format': 1, 'realms': {}}, 'a' * 40)

    def test_private_argo_values_validate_immutable_scope_and_active_callback_inventory(self):
        from unittest.mock import Mock
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        contract = argo('https://login.example.invalid/realms/platform', 'https://console.example.invalid',
                        ['https://cd.internal.example.invalid'])
        source = {'format': 1, 'realms': {'platform': {'clients': [contract['client']]}}}
        revoked = {'format': 1, 'realms': {}}
        files = private_files(source, revoked, {}, 'login.example.invalid', contract)
        def api_client():
            api = Mock()
            api.request.side_effect = [{'full_name': 'example/private', 'private': True,
                'description': 'Managed by CloudLab repository setup: private-config'}, *[
                {'type': 'file', 'encoding': 'base64', 'size': len(content.encode()),
                 'content': base64.b64encode(content.encode()).decode()} for content in files.values()]]
            return api
        inputs = ('a' * 40, 'https://login.example.invalid/realms/platform', 'https://console.example.invalid',
                  ['https://cd.internal.example.invalid'])
        self.assertEqual(argo_values(api_client(), values, *inputs), contract)
        with self.assertRaises(ValueError): argo_values(api_client(), values, 'main', *inputs[1:])
        unsafe = copy.deepcopy(contract)
        unsafe['helm']['argo-cd']['server'] = {'extraArgs': ['--insecure']}
        files['identity/argo-values.yaml'] = yaml.safe_dump(unsafe['helm'])
        with self.assertRaisesRegex(RuntimeError, 'scoped native'):
            argo_values(api_client(), values, *inputs)
        revoked['realms']['platform'] = {'clients': ['argocd']}
        files = private_files(source, revoked, {}, 'login.example.invalid', contract)
        with self.assertRaisesRegex(RuntimeError, 'active exact-callback'):
            argo_values(api_client(), values, *inputs)

    def test_private_retry_rejects_unrelated_branch_changes_before_pull_request_creation(self):
        from unittest.mock import Mock
        api = Mock()
        api.request.side_effect = [
            {'full_name': 'example/private', 'private': True, 'description': 'Managed by CloudLab repository setup: private-config'},
            {'object': {'sha': 'a' * 40}}, None, {'object': {'sha': 'b' * 40}},
            {'parents': [{'sha': 'a' * 40}]}, {'total_commits': 1, 'files': [
                {'filename': 'identity/configmap.yaml', 'status': 'added'},
                {'filename': 'unrelated.yaml', 'status': 'modified'}]}]
        with self.assertRaisesRegex(RuntimeError, 'scoped change'):
            publish(api, {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'},
                    {'identity/configmap.yaml': 'private inputs'})
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_empty_private_repository_seed_contains_no_identity_data(self):
        from unittest.mock import Mock
        api = Mock()
        content = 'private inputs'
        api.request.side_effect = [
            {'full_name': 'example/private', 'private': True, 'size': 0, 'description': 'Managed by CloudLab repository setup: private-config'},
            RuntimeError('GitHub repository operation failed: HTTP 409'), {}, {'object': {'sha': 'a' * 40}},
            {'content': base64.b64encode(content.encode()).decode()}]
        self.assertFalse(publish(api, {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'},
                                 {'identity/configmap.yaml': content})['private_source_changed'])
        writes = [call for call in api.request.call_args_list if call.args[0] != 'GET']
        self.assertEqual(len(writes), 1)
        self.assertTrue(writes[0].args[1].endswith('/contents/.gitkeep'))
        self.assertEqual(writes[0].args[2]['content'], '')

    def test_private_publication_repeat_does_not_write_or_remove_an_omitted_overlay(self):
        from unittest.mock import Mock
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        api = Mock()
        content = 'complete private input'
        api.request.side_effect = [
            {'full_name': 'example/private', 'private': True, 'description': 'Managed by CloudLab repository setup: private-config'},
            {'object': {'sha': 'a' * 40}}, {'content': base64.b64encode(content.encode()).decode()}]
        result = publish(api, values, {'identity/configmap.yaml': content})
        self.assertFalse(result['private_source_changed'])
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))
        self.assertFalse(any('argo-values' in call.args[1] for call in api.request.call_args_list))

    def test_private_publication_rejects_a_public_target_and_unbounded_file_changes(self):
        from unittest.mock import Mock
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        api = Mock()
        api.request.return_value = {'full_name': 'example/private', 'private': False,
            'description': 'Managed by CloudLab repository setup: private-config'}
        with self.assertRaises(RuntimeError): publish(api, values, {'identity/configmap.yaml': 'inputs'})
        api.request.return_value['private'] = True
        with self.assertRaises(ValueError): publish(api, values, {'identity/configmap.yaml': 'inputs', 'other.yaml': 'workload'})
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_native_argo_routes_require_tls_and_only_gateway_network_access(self):
        root = Path(__file__).resolve().parents[2]
        overlay = argo('https://login.example.invalid/realms/platform', 'https://console.example.invalid',
                       ['https://cd.internal.example.invalid'])['helm']
        result = subprocess.run(['helm', 'template', 'argocd', str(root / 'platform/delivery/argocd'),
            '--namespace', 'argocd', '-f', '-'], input=json.dumps(overlay), text=True, capture_output=True, check=True)
        objects = {(obj['kind'], obj['metadata']['name']): obj for obj in yaml.safe_load_all(result.stdout) if obj}
        certificate = objects['Certificate', 'argocd-native-identity']['spec']
        self.assertEqual(certificate['dnsNames'], ['console.example.invalid', 'cd.internal.example.invalid'])
        self.assertEqual(certificate['secretName'], 'argocd-server-tls')
        tls = objects['BackendTLSPolicy', 'argocd-native-identity']['spec']['validation']
        self.assertEqual(tls, {'hostname': 'console.example.invalid', 'wellKnownCACertificates': 'System'})
        ingress = objects['NetworkPolicy', 'argocd-native-identity']['spec']['ingress']
        self.assertEqual({peer['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name']
                          for rule in ingress for peer in rule['from']},
                         {'cloudlab-gateway-public', 'cloudlab-gateway-private'})
        self.assertEqual({port['port'] for rule in ingress for port in rule['ports']}, {8080})
        values = {'zone': 'example.invalid', 'argo': {'public': 'console.example.invalid', 'private': 'cd.internal.example.invalid'}}
        result = subprocess.run(['helm', 'template', 'gateways', str(root / 'platform/connectivity/gateways'),
            '-f', str(root / 'platform/connectivity/gateways/values.json'), '-f', '-'],
            input=json.dumps(values), text=True, capture_output=True, check=True)
        routes = [obj for obj in yaml.safe_load_all(result.stdout) if obj and obj['kind'] == 'HTTPRoute']
        self.assertEqual({obj['metadata']['namespace'] for obj in routes},
                         {'cloudlab-gateway-public', 'cloudlab-gateway-private'})
        self.assertTrue(all(obj['spec']['rules'][0]['backendRefs'] == [
            {'name': 'argocd-server', 'namespace': 'argocd', 'port': 443}] for obj in routes))

    def test_argo_public_and_private_origins_have_exact_registered_callbacks(self):
        import yaml
        state = argo('https://login.example.invalid/realms/platform', 'https://cd.example.invalid',
                     ['https://cd.internal.example.invalid'])
        self.assertEqual(state['client']['callbacks'], ['https://cd.example.invalid/auth/callback',
            'https://cd.example.invalid/pkce/verify', 'https://cd.internal.example.invalid/auth/callback',
            'https://cd.internal.example.invalid/pkce/verify'])
        self.assertEqual(yaml.safe_load(state['helm']['argo-cd']['configs']['cm']['additionalUrls']),
                         ['https://cd.internal.example.invalid'])
        for additional in (['https://cd.example.invalid'], ['https://other.invalid', 'https://extra.invalid'],
                           ['https://unsafe.invalid/path'], 'https://unsafe.invalid', None, [], {}, False):
            with self.assertRaises((ValueError, TypeError)):
                argo('https://login.example.invalid/realms/platform', 'https://cd.example.invalid', additional)

    def test_restore_inventory_reads_all_pages_and_rejects_duplicate_results(self):
        first = [{'clientId': 'client-' + str(i)} for i in range(100)]
        last = [{'clientId': 'retired'}]
        with patch('automation.identity.isolated_restore.request', side_effect=[first, last]) as read:
            self.assertEqual(client_inventory('applications', 'private-token'), first + last)
            self.assertIn('first=100&max=100', read.call_args.args[0])
        with patch('automation.identity.isolated_restore.request', side_effect=[first, first]), \
             self.assertRaisesRegex(RuntimeError, 'ambiguous'):
            client_inventory('applications', 'private-token')

    def test_isolated_restore_allows_no_gateway_or_external_identity_peers(self):
        documents = policies()
        self.assertEqual({d['metadata']['namespace'] for d in documents}, {'cloudlab-data-restore'})
        ingress = documents[0]['spec']['ingress']
        self.assertTrue(all('podSelector' in peer and 'namespaceSelector' not in peer
                            for rule in ingress for peer in rule['from']))
        self.assertEqual({p['port'] for rule in ingress for p in rule['ports']}, {8443})
        self.assertNotIn('ipBlock', json.dumps(documents))
        self.assertNotIn('gateway', json.dumps(documents))
        egress = documents[0]['spec']['egress']
        self.assertEqual({p['port'] for rule in egress for p in rule['ports']}, {53, 5432, 8443})
        fixture = pod('test', 'probe', 'python@sha256:' + 'a' * 64, ['python'], memory='64Mi')
        self.assertFalse(fixture['spec']['automountServiceAccountToken'])
        self.assertTrue(fixture['spec']['securityContext']['runAsNonRoot'])
        self.assertEqual(fixture['spec']['containers'][0]['securityContext']['capabilities'], {'drop': ['ALL']})

    def test_isolated_restore_missing_source_or_foreign_target_prevents_all_writes(self):
        with patch('automation.identity.isolated_restore.kube') as mutate:
            self.assertFalse(restore_issuer({}, lambda *args: '')['identity_issuer_restore_proven'])
            with patch('automation.identity.isolated_restore.get', return_value={'metadata': {'labels': {}}}), \
                 self.assertRaises(RuntimeError):
                restore_issuer({'identity': {}}, lambda *args: '')
            def objects(kind, name, namespace=None):
                if kind == 'namespace': return {'metadata': {'labels': {'cloudlab.io/fixture': 'application-data-restore'}}}
                if name == 'cloudlab-identity-private': return {'status': {'sync': {'revision': 'a' * 40}}}
                return None
            with patch('automation.identity.isolated_restore.get', side_effect=objects), \
                 patch('automation.identity.isolated_restore.application_ready', return_value=False), \
                 self.assertRaisesRegex(RuntimeError, 'source is unavailable'):
                restore_issuer({'identity': {}}, lambda *args: '')
            mutate.assert_not_called()

    def test_private_bundle_contains_no_secret_and_never_removes_an_omitted_overlay(self):
        source = self.source()
        source['realms']['applications']['clients'][0]['public'] = False
        credentials = {'applications': {'reference': 'private-client-secret-' + 'x' * 32}}
        revoked = {'format': 1, 'realms': {}}
        files = private_files(source, revoked, credentials, 'login.example.invalid')
        self.assertEqual(set(files), {'identity/configmap.yaml'})
        self.assertNotIn(credentials['applications']['reference'], files['identity/configmap.yaml'])
        import yaml
        manifest = yaml.safe_load(files['identity/configmap.yaml'])
        self.assertEqual(json.loads(manifest['data']['desired_state']), source)
        self.assertEqual(json.loads(manifest['data']['revocations']), revoked)
        overlay = argo('https://login.example.invalid/realms/platform', 'https://cd.example.invalid',
                       ['https://cd.internal.example.invalid'])
        files = private_files(source, revoked, credentials, 'login.example.invalid', overlay)
        self.assertEqual(yaml.safe_load(files['identity/argo-values.yaml']), overlay['helm'])

    def test_monthly_maintenance_cannot_overlap_another_identity_operation(self):
        import fcntl
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            with (base / 'owner.lock').open('a') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch('automation.identity.maintenance.BASE', base), \
                     patch('automation.identity.maintenance.get', return_value={
                         'metadata': {'labels': {'cloudlab.io/owner': 'cloudlab-identity-bootstrap'}}}), \
                     patch('automation.identity.maintenance._set_maintenance') as apply:
                    with self.assertRaisesRegex(RuntimeError, 'Another identity operation'):
                        set_maintenance(True)
                    apply.assert_not_called()

    def test_restore_disables_existing_removed_client_without_recreating_absent_objects(self):
        source = {'format': 1, 'realms': {}}
        denied = {'format': 1, 'realms': {'applications': {
            'clients': ['retired', 'absent'], 'removed_clients': ['retired', 'absent']}}}
        state = restore_configuration('applications', 'login.example.invalid', source, {}, denied,
                                      [{'clientId': 'retired'}, {'clientId': 'unrelated'}])
        self.assertEqual(state['clients'], [{'clientId': 'retired', 'enabled': False}])
        for inventory in (None, {}, [{'clientId': 'retired'}, {'clientId': 'retired'}]):
            with self.assertRaises(ValueError):
                restore_configuration('applications', 'login.example.invalid', source, {}, denied, inventory)
        broken = {'format': 1, 'realms': {'platform': {'users': 'malformed'}}}
        with self.assertRaises(ValueError):
            restore_configuration('applications', 'login.example.invalid', source, {}, broken, [])

    def test_expired_lease_never_overlaps_an_existing_running_or_unknown_writer(self):
        lease = {'holderIdentity': 'prior'}
        for phase in ('Running', 'Pending', 'Unknown'):
            self.assertFalse(previous_writer_done(lease, [{'metadata': {'uid': 'prior'}, 'status': {'phase': phase}}]))
        for phase in ('Succeeded', 'Failed'):
            self.assertTrue(previous_writer_done(lease, [{'metadata': {'uid': 'prior'}, 'status': {'phase': phase}}]))
        self.assertTrue(previous_writer_done(lease, []))

    def test_malformed_revocation_registry_cannot_create_phantom_users_or_clients(self):
        for field in ('users', 'clients', 'removed_clients'):
            for value in ('reference', {'reference': True}, ['reference', 'reference'], [False]):
                with self.assertRaises(ValueError):
                    compile_state('applications', 'login.example.invalid', self.source(), revocations={
                        'format': 1, 'realms': {'applications': {field: value}}})
        for version in (True, 1.0):
            source = self.source()
            source['format'] = version
            with self.assertRaises(ValueError): compile_state('applications', 'login.example.invalid', source)

    def test_exact_callbacks_reject_invisible_characters_and_empty_userinfo(self):
        for callback in ('https://@example.invalid/callback', 'https://:@example.invalid/callback',
                         'https://example.invalid/callback\t', 'https://example.invalid/callback space',
                         'https://example.invalid:private/callback'):
            with self.assertRaises(ValueError): exact_url(callback)

    def test_pinned_private_argo_overlay_preserves_self_owner_and_project_scope(self):
        chart = Path(__file__).resolve().parents[2] / 'gitops/roots/public'
        inputs = {'identity': {'enabled': True, 'argo': {'valuesRepository': 'https://github.com/fixture/private.git', 'valuesRevision': 'a' * 40}}}
        result = subprocess.run(['helm', 'template', 'cloudlab-public-root', str(chart), '--namespace', 'argocd', '-f', '-'],
            input=json.dumps(inputs), text=True, capture_output=True, check=True)
        objects = list(yaml.safe_load_all(result.stdout))
        indexed = {(obj['kind'], obj['metadata']['name']): obj for obj in objects if obj}
        argo_app = indexed['Application', 'cloudlab-argocd']['spec']
        self.assertNotIn('source', argo_app)
        self.assertEqual(argo_app['sources'][0]['helm']['valueFiles'], ['$identity/identity/argo-values.yaml'])
        self.assertEqual(argo_app['sources'][1]['targetRevision'], 'a' * 40)
        self.assertFalse(argo_app['syncPolicy']['automated']['prune'])
        root = indexed['Application', 'cloudlab-public-root']
        self.assertEqual(root['spec']['source']['helm']['valuesObject']['identity'], inputs['identity'])
        self.assertNotIn(inputs['identity']['argo']['valuesRepository'], indexed['AppProject', 'cloudlab-root']['spec']['sourceRepos'])
        secret = indexed['ExternalSecret', 'cloudlab-argocd-identity-source']['spec']
        self.assertEqual(secret['target']['deletionPolicy'], 'Retain')
        self.assertEqual(secret['target']['template']['data']['project'], 'cloudlab-platform')
        self.assertEqual(secret['target']['template']['data']['githubAppPrivateKey'], PEM_TEMPLATE)
        self.assertEqual(indexed['Namespace', 'cloudlab-identity']['metadata']['labels']['cloudlab.io/gateway'], 'public')
        self.assertEqual(indexed['Namespace', 'cloudlab-identity-admin']['metadata']['labels']['cloudlab.io/gateway'], 'private')
        operator = subprocess.run(['helm', 'template', 'operator', str(chart.parents[2] / 'platform/identity/keycloak'),
            '--set', 'enabled=true', '--set', 'serverEnabled=false'], text=True, capture_output=True, check=True)
        self.assertFalse(any(obj['kind'] == 'Namespace' for obj in yaml.safe_load_all(operator.stdout) if obj))
        inputs['identity']['argo']['valuesRevision'] = 'main'
        rejected = subprocess.run(['helm', 'template', 'root', str(chart), '-f', '-'], input=json.dumps(inputs), text=True, capture_output=True)
        self.assertNotEqual(rejected.returncode, 0)

    def test_multi_source_convergence_requires_exact_private_values_revision(self):
        app = {'spec': {'sources': [{'targetRevision': 'main'}, {'targetRevision': 'a' * 40}]},
               'status': {'sync': {'revisions': ['public', 'a' * 40]}}}
        self.assertTrue(matches_revision(app, 'public'))
        self.assertFalse(matches_revision(app, 'old-public'))
        app['status']['sync']['revisions'][1] = 'b' * 40
        self.assertFalse(matches_revision(app, 'public'))
        app['status']['sync']['revisions'] = ['public']
        self.assertFalse(matches_revision(app, 'public'))
        self.assertTrue(matches_revision({'status': {'sync': {'revision': 'public'}}}, 'public'))

    def test_protocol_hostname_cannot_inherit_circular_access_or_public_admin_routing(self):
        public, private = names([{'name': 'fixture', 'access': 'human'}], ['argocd'])
        self.assertEqual(public[-1], {'name': 'login', 'access': 'public'})
        self.assertIn('identity-admin', private)
        self.assertEqual(names(public, private), (public, private))
        with self.assertRaises(ValueError): names([{'name': 'login', 'access': 'human'}], ['argocd'])
        with self.assertRaises(ValueError): names([{'name': 'identity-admin', 'access': 'public'}], ['argocd'])

    def test_password_grants_are_closed_without_master_or_unmanaged_client_changes(self):
        original = compile_state('applications', 'login.example.invalid', self.source())
        secured = restrict_password_grants(original)
        self.assertEqual(secured['clients'][:-1], original['clients'])
        self.assertEqual(secured['clients'][-1], {'clientId': 'admin-cli', 'directAccessGrantsEnabled': False})
        self.assertNotIn('enabled', secured['clients'][-1])
        self.assertNotIn('secret', secured['clients'][-1])
        with self.assertRaises(ValueError): restrict_password_grants({'realm': 'master'})
        retirement = bootstrap_retirement('temporary-bootstrap')
        self.assertEqual(retirement['users'], [{'username': 'temporary-bootstrap', 'enabled': False}])
        self.assertFalse(retirement['clients'][0]['directAccessGrantsEnabled'])
        self.assertNotIn('credentials', retirement['users'][0])
        with self.assertRaises(ValueError): bootstrap_retirement('service-account-realm-writer')

    def test_client_role_groups_are_explicit_scoped_and_reject_undeclared_roles(self):
        source = self.source()
        configured = source['realms']['applications']['clients'][0]
        configured.update(roles=['reader'], role_groups={'reader': ['viewer']})
        source['realms']['applications']['memberships'] = [{'username': 'fixture-reader', 'groups': ['viewer']}]
        state = compile_state('applications', 'login.example.invalid', source)
        viewer = next(group for group in state['groups'] if group['name'] == 'viewer')
        self.assertNotIn('clientRoles', viewer)
        client_group = next(group for group in state['groups'] if group['name'] == 'client-reference')
        self.assertEqual(client_group['subGroups'], [{'name': 'reader', 'clientRoles': {'reference': ['reader']}}])
        self.assertEqual(state['users'][0]['groups'], ['/viewer', '/client-reference/reader'])
        self.assertNotIn('clientRoles', next(group for group in state['groups'] if group['name'] == 'developer'))
        configured['role_groups'] = {'admin': ['viewer']}
        with self.assertRaises(ValueError): compile_state('applications', 'login.example.invalid', source)
        configured['role_groups'] = {'reader': ['unmanaged']}
        with self.assertRaises(ValueError): compile_state('applications', 'login.example.invalid', source)

    def test_credential_inventory_rejects_public_retired_or_missing_private_clients(self):
        operation = {'action': 'rotate', 'realm': 'applications', 'client_id': 'reference'}
        source = self.source()
        def objects(kind, identifier, namespace):
            if identifier == 'cloudlab-identity': return {'metadata': {'labels': {'cloudlab.io/owner': 'cloudlab-identity-bootstrap'}},
                'spec': {'source': {'helm': {'valuesObject': {'adminHost': 'identity-admin.internal.example.invalid'}}}}}
            return {'metadata': {'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-identity-private:/ConfigMap:fixture'}},
                    'data': {'desired_state': json.dumps(source), 'revocations': json.dumps({'format': 1, 'realms': {}})}}
        with patch('automation.identity.bootstrap.private_inputs', return_value=(source, {'format': 1, 'realms': {}}, 'private')):
            with patch('automation.mesh.kube.get', side_effect=objects), self.assertRaises(ValueError): inventory(operation)
            source['realms']['applications']['clients'][0]['public'] = False
            with patch('automation.mesh.kube.get', side_effect=objects): self.assertIn('callback', inventory(operation))
            source['realms']['applications']['clients'][0]['enabled'] = False
            with patch('automation.mesh.kube.get', side_effect=objects), self.assertRaises(ValueError): inventory(operation)

    def test_initial_confidential_secret_can_precede_publication_without_reenabling_retired_clients(self):
        proposed = dict(self.source()['realms']['applications']['clients'][0], public=False)
        request = {'action': 'provision', 'realm': 'applications', 'client_id': 'reference', 'client': proposed}
        app = {'metadata': {'labels': {'cloudlab.io/owner': 'cloudlab-identity-bootstrap'}},
               'spec': {'source': {'helm': {'valuesObject': {'adminHost': 'identity-admin.internal.example.invalid'}}}}}
        source, revoked = {'format': 1, 'realms': {}}, {'format': 1, 'realms': {}}
        with patch('automation.mesh.kube.get', return_value=app), \
                patch('automation.identity.bootstrap.private_inputs', return_value=(source, revoked, 'private')):
            self.assertEqual(inventory(request)['callback'], proposed['callbacks'][0])
            revoked['realms']['applications'] = {'clients': ['reference'], 'removed_clients': ['reference']}
            with self.assertRaises(ValueError): inventory(request)
        for change in ({'action': 'rotate'}, {'client': dict(proposed, public=True)},
                       {'client': dict(proposed, callbacks=['https://unsafe.invalid/*'])},
                       {'client': dict(proposed, enabled=False)}):
            with self.assertRaises(ValueError): request_scope(dict(request, **change))

    def test_removal_waits_for_expiry_and_uses_only_existing_argo_owner(self):
        source = {'format': 1, 'realms': {'applications': {'clients': []}}}
        registry = {'format': 1, 'realms': {'applications': {'clients': ['reference'], 'removed_clients': ['reference']}}}
        app = {'metadata': {'uid': 'owned', 'labels': {'cloudlab.io/owner': 'cloudlab-identity-bootstrap'}},
               'spec': {'source': {'helm': {'valuesObject': {'privateStateEnabled': True,
                   'adminHost': 'identity-admin.internal.example.invalid', 'loginHost': 'login.example.invalid'}}}}}
        app['status'] = {'sync': {'comparedTo': {'source': copy.deepcopy(app['spec']['source'])}}}
        def objects(kind, identifier, namespace):
            if identifier == 'cloudlab-identity': return app
            if identifier == 'cloudlab-identity-private': return {'status': {'sync': {'revision': 'fixture'}}}
            if identifier == 'identity-private-state': return {'metadata': {'annotations': {
                'argocd.argoproj.io/tracking-id': 'cloudlab-identity-private:/ConfigMap:fixture'}},
                'data': {'desired_state': json.dumps(source), 'revocations': json.dumps(registry)}}
            if identifier == 'keycloak-client-secrets': return {'data': {'client_secrets': base64.b64encode(
                json.dumps({'platform': {}, 'applications': {}}).encode()).decode()}}
            if identifier == 'keycloak-realm-writers': return {'data': {'applications_client_secret': base64.b64encode(b'x' * 48).decode()}}
            if identifier == 'identity-writer': return {'spec': {}}
            raise AssertionError('Unexpected resource access')
        writes = []
        def patch_app(*args):
            writes.append(args)
            self.assertEqual(args[1], 'application.argoproj.io')
            operation = json.loads(args[-1])['spec']['source']['helm']['valuesObject']['operation']
            values = app['spec']['source']['helm']['valuesObject']
            if operation is None: values.pop('operation', None)
            else: values['operation'] = operation
            app['status']['sync']['comparedTo']['source'] = copy.deepcopy(app['spec']['source'])
        waits = []
        def checked_wait(predicate, label, timeout):
            waits.append(label)
            self.assertTrue(predicate())
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'ownership.json').write_text(json.dumps({'uid': 'owned', 'phase': 'scoped', 'revision': 'fixture'}))
            Path(directory, 'remove-applications-reference.json').write_text(json.dumps({
                'request': {'realm': 'applications', 'client_id': 'reference'}, 'application_uid': 'owned', 'disabled_verified_at': 0}))
            with patch('automation.identity.lifecycle.BASE', Path(directory)), \
                    patch('automation.identity.lifecycle.get', side_effect=objects), \
                    patch('automation.identity.lifecycle.kube', side_effect=patch_app), \
                    patch('automation.identity.lifecycle.application_ready', return_value=True), \
                    patch('automation.identity.lifecycle.wait', side_effect=checked_wait), \
                    patch('automation.identity.lifecycle.time.time', return_value=1000), \
                    patch('automation.identity.lifecycle.private_request', side_effect=[
                        {'access_token': 'fixture'}, [{'clientId': 'reference', 'enabled': False}],
                        {'access_token': 'fixture'}, []]):
                result = remove({'realm': 'applications', 'client_id': 'reference'})
            self.assertTrue(result['client_removed'])
            self.assertTrue(json.loads(Path(directory, 'remove-applications-reference.json').read_text())['complete'])
        self.assertEqual(len(writes), 2)
        self.assertEqual(waits[0], 'disabled client session and token expiry')
        self.assertEqual(waits[-1], 'normal writer convergence after removal')
        self.assertNotIn('operation', app['spec']['source']['helm']['valuesObject'])

    def test_removal_requires_scoped_owner_before_any_configuration_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'ownership.json').write_text(json.dumps({'uid': 'expected', 'phase': 'scoped'}))
            with patch('automation.identity.lifecycle.BASE', Path(directory)), patch('automation.identity.lifecycle.get',
                    return_value={'metadata': {'uid': 'foreign', 'labels': {}}}), \
                    patch('automation.identity.lifecycle.kube') as writer, self.assertRaises(RuntimeError):
                remove({'realm': 'applications', 'client_id': 'reference'})
            writer.assert_not_called()
        with self.assertRaises(ValueError): remove({'realm': 'master', 'client_id': 'reference'})

    def test_vault_client_rotation_preserves_unrelated_secrets_and_metadata(self):
        document = {'title': 'keycloak-client-secrets', 'id': 'fixture-item', 'category': 'SECURE_NOTE',
                    'tags': ['cloudlab-managed'], 'fields': [
                        {'label': 'client_secrets', 'type': 'CONCEALED', 'value': json.dumps({
                            'platform': {'target': 'a' * 48, 'other': 'b' * 48}, 'applications': {}})},
                        {'label': 'unrelated', 'type': 'STRING', 'value': 'preserve'}]}
        operation = {'action': 'rotate', 'realm': 'platform', 'client_id': 'target'}
        changed, old, new = replacement(document, operation, 'c' * 48)
        self.assertEqual((old, new), ('a' * 48, 'c' * 48))
        self.assertEqual(json.loads(changed['fields'][0]['value'])['platform']['other'], 'b' * 48)
        self.assertEqual(changed['fields'][1], document['fields'][1])
        self.assertEqual(changed['id'], document['id'])
        preserved, old, new = replacement(document, dict(operation, action='provision'), 'c' * 48)
        self.assertEqual(preserved, document)
        self.assertEqual(old, new)
        with self.assertRaises(ValueError): replacement(document, dict(operation, client_id='absent'), 'c' * 48)
        with self.assertRaises(ValueError): replacement(document, dict(operation, realm='master'), 'c' * 48)
        with self.assertRaises(ValueError): replacement(document, operation, 'short')
        document['tags'] = []
        with self.assertRaises(ValueError): replacement(document, operation, 'c' * 48)

    def test_master_bootstrap_preserves_unrelated_attributes_and_private_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'username').write_text('fixture')
            Path(directory, 'password').write_text('fixture')
            with patch('automation.identity.configuration.private_request', side_effect=[
                    {'access_token': 'fixture-token'}, {'attributes': {'unrelated': 'preserve',
                        'de.adorsys.keycloak.config.import-checksum-default': 'old-output'}}]):
                prepare_master(directory, 'identity-admin.internal.example.invalid', directory)
            value = json.loads(Path(directory, 'master-bootstrap.json').read_text())
        self.assertEqual(value['attributes']['unrelated'], 'preserve')
        self.assertEqual(value['attributes']['frontendUrl'], 'https://identity-admin.internal.example.invalid')
        self.assertNotIn('de.adorsys.keycloak.config.import-checksum-default', value['attributes'])

    def test_master_browser_origin_is_private_and_never_imports_users_or_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            prepare_master(directory, 'identity-admin.internal.example.invalid')
            value = json.loads(Path(directory, 'master-bootstrap.json').read_text())
        self.assertEqual(value['realm'], 'master')
        self.assertEqual(value['attributes']['frontendUrl'], 'https://identity-admin.internal.example.invalid')
        self.assertNotIn('users', value)
        self.assertNotIn('clients', value)
        self.assertNotIn('components', value)
        self.assertEqual(value['webAuthnPolicyUserVerificationRequirement'], 'required')
    def test_private_identity_source_cannot_deploy_workloads_or_prune_on_fetch_failure(self):
        project, credential, app = private_resources({'private_repository': 'https://github.com/fixture/private.git', 'private_branch': 'main'})
        self.assertEqual(project['spec']['namespaceResourceWhitelist'], [{'group': '', 'kind': 'ConfigMap'}])
        self.assertEqual(project['spec']['clusterResourceWhitelist'], [])
        self.assertEqual(project['spec']['destinations'][0]['namespace'], 'cloudlab-identity')
        self.assertEqual(credential['spec']['target']['template']['data']['project'], project['metadata']['name'])
        self.assertEqual(credential['spec']['target']['deletionPolicy'], 'Retain')
        self.assertEqual(app['spec']['source']['directory'], {'include': 'configmap.yaml'})
        self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
        self.assertFalse(app['spec']['syncPolicy']['automated']['allowEmpty'])
    def test_runtime_owner_preserves_lease_and_never_enables_operator_or_real_clients(self):
        payload = {'repository': 'https://github.com/fixture/platform.git', 'branch': 'main', 'values': {
            'loginHost': 'login.example.invalid', 'adminHost': 'identity-admin.internal.example.invalid',
            'database': 'keycloak', 'databaseRole': 'keycloak',
            'databaseHost': 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local', 'databasePort': 5432,
            'databaseCA': 'fixture-ca', 'trustedProxyAddresses': ['10.42.0.10/32']}}
        for phase in ('server', 'bootstrap', 'primary', 'scoped'):
            spec = application(payload, phase)['spec']
            self.assertNotIn('ignoreDifferences', spec)
            self.assertIn('RespectIgnoreDifferences=true', spec['syncPolicy']['syncOptions'])
            self.assertFalse(spec['syncPolicy']['automated']['prune'])
            self.assertFalse(spec['source']['helm']['valuesObject']['operatorEnabled'])
            self.assertEqual(spec['source']['helm']['valuesObject']['bootstrapMode'], phase in ('bootstrap', 'primary'))
            self.assertEqual(spec['source']['helm']['valuesObject']['primaryAdminEnabled'], phase == 'primary')
        for unsafe in ('10.0.0.0/8', '0.0.0.0/0', '203.0.114.0/24'):
            payload['values']['trustedProxyAddresses'] = [unsafe]
            with self.assertRaises(ValueError): application(payload, 'server')
        payload['values']['trustedProxyAddresses'] = ['10.42.0.0/24']
        application(payload, 'server')
        payload['values']['adminHost'] = 'admin.other.invalid'
        with self.assertRaises(ValueError): application(payload, 'server')
    def test_parent_health_cannot_advance_an_unready_identity_server(self):
        from automation.identity import bootstrap
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'ownership.json').write_text(json.dumps({'phase': 'server', 'uid': 'owned'}))
            app = {'metadata': {'uid': 'owned', 'labels': {'cloudlab.io/owner': bootstrap.OWNER}},
                   'spec': {'source': {'helm': {'valuesObject': {}}}}}
            server = {'metadata': {'generation': 1}, 'status': {'conditions': [{'type': 'Ready', 'status': 'False'}]}}
            with patch.object(bootstrap, 'BASE', base), patch.object(bootstrap, 'application', return_value={}), \
                    patch.object(bootstrap, 'prerequisites'), patch.object(bootstrap, 'application_ready', return_value=True), \
                    patch.object(bootstrap, 'get', side_effect=lambda kind, *args: app if kind.startswith('application.') else server), \
                    patch.object(bootstrap, 'kube') as writes:
                with self.assertRaisesRegex(RuntimeError, 'Previous identity phase must converge'):
                    bootstrap.run({'revision': 'public'}, 'bootstrap')
                writes.assert_not_called()
    def test_oidc_integration_contracts_reject_unsafe_issuers_and_unscoped_rbac(self):
        value = argo('https://login.example.invalid/realms/platform', 'https://argo.example.invalid',
                     ['https://cd.internal.example.invalid'])
        self.assertTrue(value['client']['public'])
        cm = value['helm']['argo-cd']['configs']['cm']
        oidc = yaml.safe_load(cm['oidc.config'])
        self.assertTrue(oidc['enablePKCEAuthentication'])
        self.assertNotIn('offline_access', oidc['requestedScopes'])
        chart = Path(__file__).resolve().parents[2] / 'platform/delivery/argocd'
        rendered = subprocess.run(['helm', 'template', 'argocd', str(chart), '--namespace', 'argocd', '-f', '-'],
            input=json.dumps(value['helm']), text=True, capture_output=True, check=True)
        objects = list(yaml.safe_load_all(rendered.stdout))
        config = next(obj for obj in objects if obj and obj['kind'] == 'ConfigMap' and obj['metadata']['name'] == 'argocd-cm')
        self.assertIsInstance(config['data']['oidc.config'], str)
        self.assertEqual(yaml.safe_load(config['data']['oidc.config']), oidc)
        rbac = value['helm']['argo-cd']['configs']['rbac']
        self.assertEqual(rbac['policy.default'], 'role:no-access')
        self.assertNotIn('role:readonly', rbac['policy.csv'])
        self.assertNotIn('exec,', rbac['policy.csv'])
        for origin in ('http://argo.example.invalid', 'https://argo.example.invalid/path', 'https://argo.example.invalid?next=unsafe'):
            with self.assertRaises(ValueError): argo('https://login.example.invalid/realms/platform', origin)
        provider = access('https://login.example.invalid/realms/platform', 'fixture-team', 'x' * 48)
        self.assertFalse(provider['client']['public'])
        self.assertTrue(provider['provider']['config']['pkce_enabled'])
        with self.assertRaises(ValueError): access('https://login.example.invalid/realms/master', 'fixture', 'x' * 48)
        with self.assertRaises(ValueError): access('https://login.example.invalid/realms/platform', 'fixture.evil', 'x' * 48)
    def test_health_identity_has_only_event_reads(self):
        state = bootstrap_health(bootstrap_writer(baseline('platform', 'login.example.invalid'), 'x' * 48), 'y' * 48)
        self.assertEqual(state['users'][1]['clientRoles'], {'realm-management': ['view-events']})
        self.assertEqual(state['clientScopeMappings']['realm-management'][1], {'client': 'realm-health', 'roles': ['view-events']})
        self.assertFalse(state['clients'][1]['standardFlowEnabled'])
        self.assertFalse(state['clients'][1]['fullScopeAllowed'])

    def test_revocations_cannot_disable_machine_account(self):
        with self.assertRaises(ValueError):
            compile_state('applications', 'login.example.invalid', self.source(), revocations={
                'format': 1, 'realms': {'applications': {'users': ['service-account-realm-writer']}}})
    def test_restored_signing_state_matches_before_session_invalidation(self):
        rows = '[{"component_id":"fixture","name":"privateKey","hash":"fixture-hash"}]'
        def sql(statement, database):
            if 'component_config' in statement: return rows
            if 'WHERE enabled=false' in statement: return '1'
            if 'user_entity' in statement: return '3'
            if 'information_schema' in statement: return '["offline_user_session","offline_client_session"]'
            return ''
        value = {'identity': {'database': 'keycloak', 'role': 'keycloak', 'captured_at': 0,
                 'users': 3, 'disabled_users': 1, 'signing_state_sha256': signature_state(sql, 'keycloak')}}
        with patch('automation.identity.recovery.time.time', return_value=100):
            evidence = verify_restored(value, sql)
        self.assertEqual(evidence['identity_data_age_seconds'], 100)
        self.assertFalse(evidence['restored_identity_issuer_exposed'])
        self.assertTrue(evidence['membership_revocation_review_required_before_reopening'])
        value['identity']['signing_state_sha256'] = 'wrong'
        with self.assertRaises(RuntimeError): verify_restored(value, sql)

    def test_backup_hook_preserves_platform_without_identity_and_rejects_foreign_owner(self):
        with patch('automation.identity.maintenance.get', return_value=None), patch('automation.identity.maintenance.kube') as writer:
            self.assertFalse(set_maintenance(True))
            writer.assert_not_called()
        with patch('automation.identity.maintenance.get', return_value={'metadata': {'labels': {}}}), self.assertRaises(RuntimeError):
            set_maintenance(True)
    def test_bootstrap_writer_has_no_browser_or_cross_realm_role(self):
        state = bootstrap_writer(baseline('applications', 'login.example.invalid'), 'x' * 48)
        writer = state['clients'][0]
        self.assertFalse(writer['standardFlowEnabled'])
        self.assertFalse(writer['directAccessGrantsEnabled'])
        self.assertTrue(writer['serviceAccountsEnabled'])
        self.assertEqual(set(state['users'][0]['clientRoles']), {'realm-management'})
        self.assertNotIn('realm-admin', state['users'][0]['clientRoles']['realm-management'])
        self.assertNotIn('users', baseline('applications', 'login.example.invalid'))

    def test_signed_tokens_reject_malformed_grants_and_id_token_confusion(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        encode = lambda data: base64.urlsafe_b64encode(data).decode().rstrip('=')
        numbers = key.public_key().public_numbers()
        jwks = {'keys': [{'kid': 'fixture', 'kty': 'RSA', 'use': 'sig', 'alg': 'RS256',
                         'e': encode(numbers.e.to_bytes(3, 'big')),
                         'n': encode(numbers.n.to_bytes(256, 'big'))}]}
        claims = {'iss': 'https://login.example.invalid/realms/applications', 'aud': ['reference-api'],
                  'typ': 'Bearer', 'sub': 'fixture', 'iat': 50, 'exp': 200, 'roles': ['reader']}

        def token(value):
            message = encode(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'fixture'}).encode())
            message += '.' + encode(json.dumps(value).encode())
            return message + '.' + encode(key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256()))

        self.assertEqual(access_token(token(claims), jwks, claims['iss'], 'reference-api', 'reader', 100), claims)
        for patch in ({'roles': 'reader'}, {'roles': {'reader': True}}, {'aud': {'reference-api': True}},
                      {'typ': 'ID'}, {'exp': True}, {'exp': float('nan')}, {'sub': ['fixture']}, {'iat': 101}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                access_token(token(dict(claims, **patch)), jwks, claims['iss'], 'reference-api', 'reader', 100)
        id_claims = dict(claims, typ='ID', aud=['reference', 'other'], nonce='expected', azp='other')
        with self.assertRaises(ValueError):
            identity_token(token(id_claims), jwks, claims['iss'], 'reference', 'expected', 100)
        with self.assertRaises(ValueError):
            access_token(token(claims)[:-4] + 'AAAA', jwks, claims['iss'], 'reference-api', 'reader', 100)

    def source(self):
        return {'format': 1, 'realms': {'applications': {'clients': [
            {'id': 'reference', 'public': True, 'audience': 'reference-api',
             'callbacks': ['https://reference.example.invalid/callback'], 'roles': ['reader']}],
            'memberships': [{'username': 'fixture-person', 'groups': ['viewer']}]}}}

    def test_nested_role_group_cannot_match_platform_admin_rbac(self):
        source = self.source()
        configured = source['realms']['applications']['clients'][0]
        configured.update(roles=['platform-admin'], role_groups={'platform-admin': ['viewer']})
        state = compile_state('applications', 'login.example.invalid', source)
        self.assertIn('/client-reference/platform-admin', state['users'][0]['groups'])
        mapper = next(row for row in state['clients'][0]['protocolMappers'] if row['name'] == 'groups')
        self.assertEqual(mapper['config']['full.path'], 'true')
        policy = argo('https://login.example.invalid/realms/platform',
                      'https://cd.example.invalid', ['https://cd.internal.example.invalid'])['helm']['argo-cd']['configs']['rbac']['policy.csv']
        self.assertIn('g, /platform-admin, role:admin', policy.splitlines())
        self.assertNotIn('g, platform-admin, role:admin', policy.splitlines())
        self.assertNotIn('g, /client-reference/platform-admin, role:admin', policy.splitlines())

    def test_offboarding_overrides_memberships_and_client(self):
        denied = {'format': 1, 'realms': {'applications': {'users': ['fixture-person'], 'clients': ['reference']}}}
        state = compile_state('applications', 'login.example.invalid', self.source(), revocations=denied)
        self.assertFalse(state['clients'][0]['enabled'])
        self.assertEqual(state['users'], [{'username': 'fixture-person', 'groups': [], 'enabled': False}])
        self.assertEqual(state, compile_state('applications', 'login.example.invalid', self.source(), revocations=denied))

    def test_unmanaged_credentials_keys_and_master_are_absent(self):
        state = compile_state('applications', 'login.example.invalid', self.source())
        self.assertNotIn('enabled', state['users'][0])
        self.assertNotIn('credentials', state['users'][0])
        self.assertNotIn('components', state)
        with self.assertRaises(ValueError):
            baseline('master', 'login.example.invalid')
        source = self.source()
        source['realms']['master'] = {}
        with self.assertRaises(ValueError):
            compile_state('applications', 'login.example.invalid', source)

    def test_reject_unrestricted_imports_and_missing_source(self):
        source = self.source()
        source['realms']['applications']['users'] = []
        with self.assertRaises(ValueError):
            compile_state('applications', 'login.example.invalid', source)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                prepare(Path(directory) / 'output', 'login.example.invalid', directory)
            self.assertFalse((Path(directory) / 'output').exists())

    def test_unsafe_redirect_and_reserved_clients_rejected(self):
        value = self.source()['realms']['applications']['clients'][0]
        for callback in ('https://reference.example.invalid/*', 'http://example.invalid/callback',
                         'https://u:p@example.invalid/callback', 'https://example.invalid/%2fadmin',
                         'https://example.invalid/callback?next=evil', 'https://example.invalid/callback#fragment'):
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                client(dict(value, callbacks=[callback]), {})
        with self.assertRaises(ValueError):
            client(dict(value, id='realm-management'), {})

    def test_public_secret_rejected_and_confidential_secret_required(self):
        value = self.source()['realms']['applications']['clients'][0]
        with self.assertRaises(ValueError):
            client(value, {'reference': 'x' * 48})
        with self.assertRaises(ValueError):
            client(dict(value, public=False), {})
        self.assertEqual(client(dict(value, public=False), {'reference': 'x' * 48})['secret'], 'x' * 48)

    def test_platform_requires_password_and_verified_webauthn(self):
        for realm in ('platform', 'applications'):
            state = baseline(realm, 'login.example.invalid')
            self.assertEqual(state['webAuthnPolicyUserVerificationRequirement'], 'required')
            self.assertEqual([e['requirement'] for e in state['authenticationFlows'][1]['authenticationExecutions']],
                             ['REQUIRED', 'REQUIRED'])
            self.assertFalse(state['resetPasswordAllowed'])

    def test_lease_never_steals_active_or_unknown_holder(self):
        self.assertTrue(available({}, 0))
        self.assertFalse(available({'holderIdentity': 'other'}, 999))
        spec = {'holderIdentity': 'other', 'renewTime': '1970-01-01T00:00:00Z', 'leaseDurationSeconds': 240}
        self.assertFalse(available(spec, 239))
        self.assertTrue(available(spec, 240))

    def test_client_retirement_is_idempotent_and_prevents_reprovision(self):
        registry = {'format': 1, 'realms': {}}
        operation = {'action': 'retire-client', 'realm': 'applications', 'client_id': 'reference'}
        source, registry = change(self.source(), registry, operation)
        self.assertEqual((source, registry), change(source, registry, operation))
        with self.assertRaises(ValueError):
            change(source, registry, {'action': 'provision-client', 'realm': 'applications',
                                    'client': self.source()['realms']['applications']['clients'][0]})

    def test_scoped_removal_never_recreates_client_and_stale_source_fails_closed(self):
        registry = {'format': 1, 'realms': {}}
        remove = {'action': 'remove-client', 'realm': 'applications', 'client_id': 'reference'}
        with self.assertRaises(ValueError): change(self.source(), registry, remove)
        source, registry = change(self.source(), registry, dict(remove, action='retire-client'))
        source, registry = change(source, registry, remove)
        self.assertEqual((source, registry), change(source, registry, remove))
        self.assertEqual(compile_state('applications', 'login.example.invalid', source, revocations=registry)['clients'], [])
        with self.assertRaises(ValueError):
            compile_state('applications', 'login.example.invalid', self.source(), revocations=registry)
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            (private / 'desired_state').write_text(json.dumps(source))
            (private / 'revocations').write_text(json.dumps(registry))
            (private / 'client_secrets').write_text(json.dumps({'platform': {}, 'applications': {}}))
            prepare_removal(private / 'imports', 'applications', 'reference', private)
            self.assertEqual(json.loads((private / 'imports/remove.json').read_text()), {'realm': 'applications', 'clients': []})
            (private / 'desired_state').unlink()
            with self.assertRaises(FileNotFoundError): prepare_removal(private / 'other', 'applications', 'reference', private)
            self.assertFalse((private / 'other').exists())

    def test_human_offboarding_rejects_unmanaged_user(self):
        with self.assertRaises(ValueError):
            change(self.source(), {'format': 1, 'realms': {}},
                   {'action': 'offboard-user', 'realm': 'applications', 'username': 'unrelated-person'})

    def test_audit_drops_personal_data_and_admin_representations(self):
        event = {'time': 100, 'type': 'LOGIN', 'userId': 'private-id', 'ipAddress': 'private-address',
                 'details': {'username': 'private-name'}, 'representation': 'private-credential',
                 'resourcePath': 'private-client', 'operationType': 'UPDATE', 'resourceType': 'CLIENT'}
        self.assertEqual(redact([event]), [{'time': 100, 'type': 'LOGIN'}])
        self.assertEqual(redact([event], admin=True), [{'time': 100, 'operationType': 'UPDATE', 'resourceType': 'CLIENT'}])
        with self.assertRaises(ValueError):
            redact([{}] * 1001)


if __name__ == '__main__':
    unittest.main()
