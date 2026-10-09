import json
import copy
import yaml
import subprocess
import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation.identity.configuration import exact_url, baseline, bootstrap_writer, bootstrap_health, client, compile_state, prepare, prepare_master, prepare_removal, restrict_password_grants, bootstrap_retirement
from automation.identity.rotation import replacement, inventory
from automation.identity.lifecycle import remove
from automation.identity.lease import available, previous_writer_done
from automation.identity.operations import change, private_files
from automation.identity.health import redact
from automation.identity.tokens import access_token, identity_token
from automation.identity.maintenance import set_maintenance
from automation.identity.recovery import verify_restored, signature_state, restore_configuration
from automation.identity.integrations import argo, access
from automation.identity.isolated_restore import policies, pod, client_inventory, run as restore_issuer
from automation.identity.access_inputs import names
from automation.gitops.source_revision import matches_revision
from automation.gitops.private_sources import PEM_TEMPLATE
from automation.identity.bootstrap import application, private_resources
from automation.identity.private_source import publish
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class IdentityTests(unittest.TestCase):
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
        with patch('automation.mesh.kube.get', side_effect=objects), self.assertRaises(ValueError): inventory(operation)
        source['realms']['applications']['clients'][0]['public'] = False
        with patch('automation.mesh.kube.get', side_effect=objects): self.assertIn('callback', inventory(operation))
        source['realms']['applications']['clients'][0]['enabled'] = False
        with patch('automation.mesh.kube.get', side_effect=objects), self.assertRaises(ValueError): inventory(operation)

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
                    {'access_token': 'fixture-token'}, {'attributes': {'unrelated': 'preserve'}}]):
                prepare_master(directory, 'identity-admin.internal.example.invalid', directory)
            value = json.loads(Path(directory, 'master-bootstrap.json').read_text())
        self.assertEqual(value['attributes']['unrelated'], 'preserve')
        self.assertEqual(value['attributes']['frontendUrl'], 'https://identity-admin.internal.example.invalid')

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
        for phase in ('server', 'bootstrap', 'scoped'):
            spec = application(payload, phase)['spec']
            self.assertEqual(spec['ignoreDifferences'][0]['jsonPointers'], ['/spec'])
            self.assertIn('RespectIgnoreDifferences=true', spec['syncPolicy']['syncOptions'])
            self.assertFalse(spec['syncPolicy']['automated']['prune'])
            self.assertFalse(spec['source']['helm']['valuesObject']['operatorEnabled'])
            self.assertEqual(spec['source']['helm']['valuesObject']['bootstrapMode'], phase == 'bootstrap')
        payload['values']['adminHost'] = 'admin.other.invalid'
        with self.assertRaises(ValueError): application(payload, 'server')
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
