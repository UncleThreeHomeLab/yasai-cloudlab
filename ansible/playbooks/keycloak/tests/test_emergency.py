import copy
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from playbooks.keycloak.files import emergency, lease, maintenance, bootstrap, ownership
from playbooks.keycloak.files.configuration import prepare_retirement, private_request
from playbooks.keycloak.files.chart import render


class EmergencyTests(unittest.TestCase):
    def test_native_handoff_freezes_main_with_historical_receipts_and_refuses_changed_chart(self):
        document = {'installationRevision': ownership.INSTALLATION_REVISION, 'loginHost': 'login.example.invalid',
            'adminHost': 'identity-admin.internal.example.invalid', 'database': 'keycloak', 'databaseRole': 'keycloak',
            'databaseHost': 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local', 'databasePort': 5432, 'databaseCA': 'fixture-ca',
            'trustedProxyAddresses': ['10.42.0.0/24'], 'retiredEmergencyItem': 'keycloak-emergency-' + 'a' * 32}
        spec = ownership.installation_values(document); spec['source']['targetRevision'] = 'main'
        app = {'metadata': {'uid': 'app', 'resourceVersion': '1', 'generation': 1, 'labels': {'cloudlab.io/owner': bootstrap.OWNER}}, 'spec': spec}
        public = {'identity': {'application': {'enabled': False}}, 'observability': {'enabled': False}}
        project = {'metadata': {'uid': 'project', 'generation': 1, 'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/AppProject:argocd/cloudlab-identity'}},
            'spec': {'sourceRepos': [ownership.PUBLIC_REPOSITORY]}}
        desired = {'AppProject': {'spec': {'sourceRepos': [ownership.PUBLIC_REPOSITORY, 'https://github.com/example/private.git']}}}
        root = {'metadata': {'uid': 'root', 'generation': 1}, 'spec': {'approved': 'root-source'}}
        target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
        server = {'metadata': {'uid': 'server', 'generation': 1}, 'spec': {'instances': 1}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = {'phase': 'scoped', 'uid': 'app', 'revision': 'e' * 40}
            retired = {'phase': 'accepted', 'nonce': 'a' * 32, 'application_uid': 'app', 'keycloak_uid': 'server', 'revision': 'd' * 40}
            for name, data in (('ownership', state), ('retirement', retired)): (base / (name + '.json')).write_text(json.dumps(data))
            retirement_bytes = (base / 'retirement.json').read_bytes()
            def freeze(*args, **kwargs):
                captured = json.loads((base / 'ownership.json').read_text())
                self.assertEqual(captured['native']['phase'], 'prepared')
                patches = json.loads(args[-1])
                self.assertEqual(patches[:2], [{'op': 'test', 'path': '/metadata/uid', 'value': 'app'},
                    {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '2'}])
                self.assertEqual(patches[2], {'op': 'test', 'path': '/spec', 'value': app['spec']})
                self.assertEqual(patches[-1]['value'], ownership.INSTALLATION_REVISION)
                app['spec']['source']['targetRevision'] = ownership.INSTALLATION_REVISION
            from playbooks.data.files import native
            clock = Mock(return_value=100)
            idle = Mock(return_value=False)
            change = None
            def late_wait(check, *args, **kwargs):
                self.assertTrue(charts.called)
                self.assertEqual(kwargs['timeout'], 300)
                idle.return_value = False; self.assertFalse(check())
                app['metadata']['resourceVersion'] = str(int(app['metadata']['resourceVersion']) + 1)
                for obj in (app, root): obj['metadata']['generation'] += 1
                if change == 'spec': app['spec']['source']['helm']['valuesObject']['maintenance'] = 0
                if change == 'project-generation': project['metadata']['generation'] += 1
                if change == 'server-generation': server['metadata']['generation'] += 1
                clock.return_value = 1000
                idle.return_value = True; self.assertTrue(check())
            def published(*args, **kwargs):
                self.assertEqual(kwargs['deadline'], clock() + 120)
                return public, 'f' * 40 if change == 'authority' else 'c' * 40
            def observe(kind, name, namespace):
                if kind.startswith('keycloak.'): return server
                if kind == 'appproject.argoproj.io': return project
                if kind == 'application.argoproj.io': return app if name == bootstrap.APP else root
                return None
            with patch.object(ownership, 'installation_context', side_effect=lambda **kwargs: (public, 'c' * 40, target, {}, desired,
                    root, project, clock() + 180)), patch.object(ownership.time, 'monotonic', clock), \
                    patch.object(ownership, 'get', side_effect=observe), \
                    patch.object(ownership, 'application_ready', return_value=True), patch.object(native, 'matches_revision', return_value=True), \
                    patch.object(native, 'receipt', side_effect=lambda path: json.loads(path.read_text())), \
                    patch.object(native.source_snapshot, 'chart_files', return_value={'Chart.yaml': b'unchanged'}) as charts, \
                    patch.object(native, 'published_source', side_effect=published), patch.object(native, 'root_guard', return_value=target), \
                    patch.object(bootstrap, 'writer_idle', idle), patch('playbooks.istio.files.kube.wait', side_effect=late_wait), \
                    patch('playbooks.istio.files.kube.kube', side_effect=freeze) as write:
                self.assertTrue(ownership.prepare_native({}, app, state, retired, base=base))
                self.assertEqual([obj['metadata']['generation'] for obj in (app, root)], [2, 2])
                self.assertFalse(ownership.prepare_native({}, app, state, retired, base=base))
                self.assertEqual(write.call_count, 1)
                self.assertEqual((base / 'retirement.json').read_bytes(), retirement_bytes)
                app['spec']['source']['targetRevision'] = 'main'; state.pop('native'); state['revision'] = 'e' * 40
                (base / 'ownership.json').write_text(json.dumps(state)); before = (base / 'ownership.json').read_bytes()
                charts.side_effect = [{'Chart.yaml': b'old'}, {'Chart.yaml': b'changed'}]
                with self.assertRaisesRegex(RuntimeError, 'cannot upgrade code'):
                    ownership.prepare_native({}, app, state, retired, base=base)
                self.assertEqual(write.call_count, 1); self.assertEqual((base / 'ownership.json').read_bytes(), before)
                app['spec']['source']['targetRevision'] = ownership.INSTALLATION_REVISION
                with self.assertRaisesRegex(RuntimeError, 'recorded initial main'):
                    ownership.prepare_native({}, app, state, retired, base=base)
                app['spec']['source']['targetRevision'] = 'b' * 40
                with self.assertRaisesRegex(RuntimeError, 'accepted idle scoped'):
                    ownership.prepare_native({}, app, state, retired, base=base)
                self.assertEqual(write.call_count, 1); self.assertEqual((base / 'ownership.json').read_bytes(), before)
                charts.side_effect = None
                app['spec']['source']['targetRevision'] = 'main'
                baseline = copy.deepcopy(app)
                change = 'spec'
                with self.assertRaisesRegex(RuntimeError, 'scope changed while waiting'):
                    ownership.prepare_native({}, app, state, retired, base=base)
                app.clear(); app.update(copy.deepcopy(baseline))
                change = 'authority'
                with self.assertRaisesRegex(RuntimeError, 'authority or private binding changed'):
                    ownership.prepare_native({}, app, state, retired, base=base)
                self.assertEqual(write.call_count, 1); self.assertEqual((base / 'ownership.json').read_bytes(), before)
                for change, obj in (('project-generation', project), ('server-generation', server)):
                    with self.subTest(change=change):
                        generation = obj['metadata']['generation']
                        with self.assertRaisesRegex(RuntimeError, 'scope changed while waiting'):
                            ownership.prepare_native({}, app, state, retired, base=base)
                        self.assertEqual(write.call_count, 1)
                        self.assertEqual((base / 'ownership.json').read_bytes(), before)
                        obj['metadata']['generation'] = generation

    def test_native_owner_exact_parent_pin_and_four_operational_fields(self):
        document = {'installationRevision': ownership.INSTALLATION_REVISION, 'loginHost': 'login.example.invalid',
            'adminHost': 'identity-admin.internal.example.invalid', 'database': 'keycloak', 'databaseRole': 'keycloak',
            'databaseHost': 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local', 'databasePort': 5432, 'databaseCA': 'fixture-ca',
            'trustedProxyAddresses': ['10.42.0.0/24'], 'retiredEmergencyItem': 'keycloak-emergency-' + 'a' * 32}
        app = {'metadata': {'uid': 'app', 'labels': {'cloudlab.io/owner': bootstrap.OWNER}, 'ownerReferences': [
            {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': bootstrap.APP, 'uid': 'parent', 'controller': True, 'blockOwnerDeletion': True}]},
            'spec': ownership.installation_values(document)}
        project = {'metadata': {'uid': 'project', 'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/AppProject:argocd/cloudlab-identity'}},
            'spec': {'sourceRepos': [ownership.PUBLIC_REPOSITORY, 'https://github.com/example/private.git']}}
        parent = {'metadata': {'uid': 'parent', 'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/cloudlab-identity'}},
            'spec': {'fixed': 'native-contract'}, 'status': {'conditions': [{'type': 'ParametersGenerated', 'status': 'True'}]}}
        desired = {'ApplicationSet': copy.deepcopy(parent), 'AppProject': copy.deepcopy(project)}
        public = {'identity': {'application': {'enabled': True}}, 'observability': {'enabled': False}}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            captured = {'phase': 'prepared', 'root_uid': 'root', 'project_uid': 'project', 'application_uid': 'app', 'keycloak_uid': 'server',
                'original_revision': 'main', 'values': copy.deepcopy(app['spec']['source']['helm']['valuesObject'])}
            state = {'phase': 'scoped', 'uid': 'app', 'revision': ownership.INSTALLATION_REVISION, 'native': captured}
            (base / 'ownership.json').write_text(json.dumps(state))
            (base / 'retirement.json').write_text(json.dumps({'phase': 'accepted', 'application_uid': 'app', 'keycloak_uid': 'server'}))
            from playbooks.data.files import native
            def read(kind, *args):
                if kind.startswith('keycloak.'): return {'metadata': {'uid': 'server'}}
                if kind.startswith('applicationset.'): return parent
                return {'metadata': {'uid': 'reader' if kind.startswith('externalsecret.') else 'secret'}}
            with patch.object(ownership, 'installation_context', return_value=(public, 'c' * 40, {'valuesRepository': 'https://github.com/example/private.git'}, {}, desired,
                    {'metadata': {'uid': 'root'}}, project, 999)) as context, patch.object(ownership, 'get', side_effect=read), \
                    patch.object(native, 'receipt', side_effect=lambda path: json.loads(path.read_text())), \
                    patch.object(native, 'source_credentials') as credentials, patch.object(ownership, 'application_ready', return_value=True):
                with self.assertRaisesRegex(RuntimeError, 'retained owner before operations'):
                    ownership.accepted_application(app, revision=ownership.INSTALLATION_REVISION, base=base)
                self.assertEqual(ownership.accepted_application(app, revision=ownership.INSTALLATION_REVISION, base=base, register=True), ownership.INSTALLATION_REVISION)
                self.assertEqual(json.loads((base / 'ownership.json').read_text())['native']['phase'], 'accepted')
                before = (base / 'ownership.json').read_bytes()
                values = app['spec']['source']['helm']['valuesObject']
                values.update(maintenance=True, operation={'action': 'prepare-proof-user'}, bootstrapAdminEnabled=True, retiredEmergencyItem='keycloak-emergency-' + 'b' * 32)
                self.assertEqual(ownership.accepted_application(app, base=base), ownership.INSTALLATION_REVISION)
                context.reset_mock(); credentials.reset_mock()
                with patch.object(emergency, 'BASE', base), self.assertRaisesRegex(RuntimeError, 'requested pin changed'):
                    emergency.phase_sync_patches(app, 'b' * 40)
                context.assert_not_called(); credentials.assert_not_called()
                app['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                with self.assertRaisesRegex(RuntimeError, 'controller ownership changed'):
                    ownership.accepted_application(app, base=base)
                self.assertEqual((base / 'ownership.json').read_bytes(), before)

    def test_accepted_retirement_restores_only_its_exact_source_pin(self):
        revision = 'a' * 40
        retirement = {'phase': 'accepted', 'revision': revision, 'application_uid': 'owned'}
        current = {'metadata': {'uid': 'owned', 'resourceVersion': '42'},
                   'spec': {'source': {'targetRevision': revision, 'helm': {'valuesObject': {}}}}}
        desired = {'spec': {'source': {'targetRevision': 'main'}}}
        original = copy.deepcopy(current)
        self.assertEqual(bootstrap.branch_handoff_patches(current, desired, retirement), [
            {'op': 'test', 'path': '/metadata/uid', 'value': 'owned'},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '42'},
            {'op': 'test', 'path': '/spec/source/targetRevision', 'value': revision},
            {'op': 'replace', 'path': '/spec/source/targetRevision', 'value': 'main'}])
        self.assertEqual(current, original)
        self.assertEqual(bootstrap.branch_handoff_patches(current, desired, None), [])
        for change in ('pending', 'foreign', 'syncing', 'maintenance', 'operation'):
            app, record = copy.deepcopy(current), dict(retirement)
            if change == 'pending': record['phase'] = 'finishing'
            elif change == 'foreign': app['metadata']['uid'] = 'foreign'
            elif change == 'syncing': app['operation'] = {'sync': {}}
            else: app['spec']['source']['helm']['valuesObject'][change] = True
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                bootstrap.branch_handoff_patches(app, desired, record)
        for target in ('main', 'unrelated-pin'):
            current['spec']['source']['targetRevision'] = target
            self.assertEqual(bootstrap.branch_handoff_patches(current, desired, retirement), [])

    def test_phase_sync_runs_hooks_without_pruning_at_frozen_revision(self):
        revision = 'a' * 40
        patches = emergency.phase_sync_patches({}, revision)
        self.assertEqual(patches[0]['value'], revision)
        sync = patches[1]['value']['sync']
        self.assertEqual(sync['revision'], revision)
        self.assertFalse(sync['prune'])
        self.assertEqual(sync['syncStrategy'], {'hook': {}})
        self.assertNotIn('resources', sync)
        for invalid in ('main', '', 'A' * 40, 'a' * 39):
            with self.assertRaises(RuntimeError): emergency.phase_sync_patches({}, invalid)
        with self.assertRaises(RuntimeError):
            emergency.phase_sync_patches({'operation': {'sync': {}}}, revision)

    def test_current_private_email_preserves_legacy_master_input_and_revocation_gate(self):
        primary = {'platform_username': 'operator-fixture', 'email': 'master@example.invalid'}
        member = {'username': 'operator-fixture', 'groups': ['platform-admin']}
        source = {'realms': {'platform': {'memberships': [member]}}}
        revoked = {'realms': {'platform': {'users': []}}}
        private = {'spec': {'source': {'repoURL': 'https://example.invalid/private.git'}}}
        with patch.object(emergency, 'get', return_value=private), \
                patch.object(emergency, 'private_inputs', return_value=(source, revoked, 'revision')):
            self.assertEqual(emergency.current_private({}, primary), primary['email'])
            member['profile'] = {'email': 'platform@example.invalid', 'verified': True}
            self.assertEqual(emergency.current_private({}, primary), 'platform@example.invalid')
            self.assertEqual(primary['email'], 'master@example.invalid')
            revoked['realms']['platform']['users'].append(primary['platform_username'])
            with self.assertRaises(RuntimeError): emergency.current_private({}, primary)
        with patch.object(emergency, 'get', return_value=private), \
                patch.object(emergency, 'private_inputs', side_effect=RuntimeError('Source unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'Source unavailable'):
                emergency.current_private({}, primary)

    def test_empty_admin_denial_is_measured_by_http_status_not_json_body(self):
        for status in (401, 403):
            with self.subTest(status=status), patch('urllib.request.build_opener') as opener:
                opener.return_value.open.side_effect = HTTPError('https://admin.example.invalid', status, 'Denied', {}, io.BytesIO())
                self.assertEqual(private_request('https://admin.example.invalid', token='private-token',
                    accepted_statuses=(200, 401, 403), with_status=True), (status, None))
    def operation(self, action='seed-emergency'):
        return {'action': action, 'client': 'emergency-' + 'a' * 32,
                'item': 'keycloak-emergency-' + 'a' * 32,
                'keycloakUID': '12345678-1234-1234-1234-123456789abc',
                'bootstrapUsername': 'temporary-bootstrap',
                'bootstrapUserId': '23456789-1234-1234-1234-123456789abc'}

    def test_real_browser_mfa_requires_owned_credentials_role_uv_and_recent_browser_event(self):
        primary = {'master_username': 'master-fixture', 'platform_username': 'operator-fixture', 'ownership_id': 'a' * 32}
        changes = {}
        def request(url, **kwargs):
            realm = 'master' if '/admin/realms/master' in url else 'platform'
            if '/users?' in url:
                return [dict({'id': realm, 'username': primary[realm + '_username'], 'enabled': True,
                              'emailVerified': True, 'attributes': {'cloudlab-primary-owner': ['a' * 32]}}, **changes.get('user', {}))]
            if url.endswith('/credentials'): return changes.get('credentials', [{'type': 'webauthn'}])
            if url.endswith('/realm/composite'): return changes.get('roles', [{'name': 'admin'}])
            if url.endswith('/groups'): return changes.get('groups', [{'path': '/platform-admin'}])
            if '/events?' in url:
                return changes.get('events', [{'userId': realm, 'time': 999000,
                    'clientId': 'security-admin-console' if realm == 'master' else 'argocd'}])
            if url.endswith('/executions'):
                return [{'providerId': 'auth-username-password-form', 'requirement': 'REQUIRED'},
                        {'providerId': 'webauthn-authenticator', 'requirement': changes.get('requirement', 'REQUIRED')}]
            return dict({'browserFlow': 'cloudlab-privileged', 'webAuthnPolicyUserVerificationRequirement': 'required',
                         'accessTokenLifespan': 300}, **changes.get('settings', {}))
        with patch.object(emergency, 'private_request', side_effect=request):
            self.assertEqual(emergency.human_mfa('https://admin.example.invalid', 'private-token', primary, 1000),
                             {'master': 'master', 'platform': 'platform'})
            for change in ({'credentials': []}, {'roles': []}, {'groups': [{'path': '/nested/platform-admin'}]},
                           {'events': [{'userId': 'master', 'time': 999000, 'clientId': 'admin-cli'}]},
                           {'events': [{'userId': 'master', 'time': 0, 'clientId': 'security-admin-console'}]},
                           {'requirement': 'ALTERNATIVE'}, {'settings': {'webAuthnPolicyUserVerificationRequirement': 'preferred'}},
                           {'settings': {'accessTokenLifespan': 3600}}, {'user': {'enabled': False}},
                           {'user': {'requiredActions': ['webauthn-register']}}, {'user': {'attributes': {}}}):
                with self.subTest(change=change):
                    changes.clear(); changes.update(change)
                    with self.assertRaises(RuntimeError):
                        emergency.human_mfa('https://admin.example.invalid', 'private-token', primary, 1000)

    def test_custody_cannot_be_inferred_from_missing_or_numeric_input(self):
        with patch.object(emergency, 'get') as api:
            for value in ({}, None, {'recovery_custody_confirmed': 1}, {'recovery_custody_confirmed': False},
                          {'recovery_custody_confirmed': True, 'extra': True}):
                with self.assertRaises(ValueError): emergency.prepare(value)
            api.assert_not_called()

    def test_offline_guard_rejects_live_changed_or_starting_server(self):
        server = {'metadata': {'uid': 'owned'}, 'spec': {'instances': 0}}
        pods = []
        account = Mock()
        account.joinpath.return_value.read_text.return_value = 'cloudlab-identity'
        with patch.object(lease, 'Path', return_value=account), \
                patch.object(lease, 'api_request', side_effect=lambda method, url: {'items': pods} if url.endswith('/pods') else server):
            lease.offline_guard('owned')
            server['spec']['instances'] = 1
            with self.assertRaises(RuntimeError): lease.offline_guard('owned')
            server['spec']['instances'] = 0
            with self.assertRaises(RuntimeError): lease.offline_guard('foreign')
            pods.append({'metadata': {'labels': {'app': 'keycloak'}}, 'status': {'phase': 'Pending'}})
            with self.assertRaises(RuntimeError): lease.offline_guard('owned')

    def test_retirement_compiler_disables_only_exact_bootstrap_user_or_temporary_client(self):
        operation = self.operation('retire-bootstrap')
        user = {'id': operation['bootstrapUserId'], 'username': operation['bootstrapUsername']}
        def request(url, **kwargs):
            if url.endswith('/token'): return {'access_token': 'private-token'}
            if '/clients?' in url: return [{'clientId': operation['client']}]
            return user
        with tempfile.TemporaryDirectory() as directory, patch('playbooks.keycloak.files.configuration.private_request', side_effect=request):
            root = Path(directory)
            (root / 'client_id').write_text(operation['client']); (root / 'client_secret').write_text('x' * 64)
            prepare_retirement(root / 'imports', operation, 'admin.example.invalid', root)
            value = json.loads((root / 'imports/master-retirement.json').read_text())
            self.assertEqual(value['users'], [{'id': operation['bootstrapUserId'], 'username': operation['bootstrapUsername'], 'enabled': False}])
            self.assertEqual(value['clients'], [{'clientId': 'admin-cli', 'directAccessGrantsEnabled': False}])
            user['id'] = 'foreign'
            with self.assertRaises(RuntimeError): prepare_retirement(root / 'rejected', operation, 'admin.example.invalid', root)
            self.assertFalse((root / 'rejected').exists())
            operation['action'] = 'retire-emergency'
            prepare_retirement(root / 'imports', operation, 'admin.example.invalid', root)
            self.assertEqual(json.loads((root / 'imports/master-retirement.json').read_text()),
                             {'realm': 'master', 'clients': [{'clientId': operation['client'], 'enabled': False}]})

    def test_retirement_jobs_share_lease_and_require_offline_server_before_seed(self):
        values = {'enabled': True, 'operatorEnabled': False, 'reconciliationEnabled': True, 'privateStateEnabled': True,
                  'databaseCA': 'fixture-ca', 'trustedProxyAddresses': ['10.43.0.1/32'], 'maintenance': True,
                  'operation': self.operation()}
        objects = render(values)
        seed_objects = objects
        job = next(row for row in objects if row['kind'] == 'Job')
        self.assertEqual(job['metadata']['annotations']['argocd.argoproj.io/hook'], 'PreSync')
        self.assertEqual(next(row['spec']['instances'] for row in objects if row['kind'] == 'Keycloak'), 0)
        pod = job['spec']['template']['spec']
        self.assertEqual(pod['serviceAccountName'], 'identity-writer')
        self.assertIn('acquire();', pod['initContainers'][0]['args'][0])
        self.assertIn('offline_guard(', pod['initContainers'][0]['args'][0])
        self.assertLess(job['spec']['activeDeadlineSeconds'] + pod['terminationGracePeriodSeconds'], 240)
        self.assertTrue(next(row['spec']['suspend'] for row in objects if row['kind'] == 'CronJob' and row['metadata']['name'] == 'identity-reconcile'))
        values['maintenance'] = False
        with self.assertRaises(ValueError): render(values)
        values['operation']['action'] = 'retire-bootstrap'
        objects = render(values)
        jobs = [row for row in objects if row['kind'] == 'Job']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['metadata']['annotations']['argocd.argoproj.io/hook'], 'PostSync')
        images = json.loads((Path(__file__).parents[4] / 'platform/identity/keycloak/artifact.lock.json').read_text())['images']
        self.assertEqual(jobs[0]['spec']['template']['spec']['containers'][0]['image'], images['config_cli'])
        values['operation']['action'] = 'retire-emergency'
        retired = render(values)
        for rows in (seed_objects, objects, retired):
            pod = next(row for row in rows if row['kind'] == 'Job')['spec']['template']['spec']
            self.assertIs(pod['automountServiceAccountToken'], False)
            self.assertEqual([mount for mount in pod['initContainers'][0]['volumeMounts'] if mount['name'] == 'kubernetes-api'],
                             [{'name': 'kubernetes-api', 'mountPath': '/var/run/secrets/kubernetes.io/serviceaccount', 'readOnly': True}])
            self.assertFalse(any(mount['name'] == 'kubernetes-api' for container in pod['containers']
                                 for mount in container['volumeMounts']))
        values['operation']['client'] = 'realm-writer'
        with self.assertRaises(ValueError): render(values)

    def test_backup_cannot_restart_a_pending_offline_recovery(self):
        app = {'metadata': {'labels': {'cloudlab.io/owner': maintenance.OWNER}}}
        with tempfile.TemporaryDirectory() as directory, patch.object(maintenance, 'BASE', Path(directory)), \
                patch.object(maintenance, 'get', return_value=app), patch.object(maintenance, '_set_maintenance') as change:
            (Path(directory) / 'retirement.json').write_text(json.dumps({'phase': 'seeding'}))
            with self.assertRaises(RuntimeError): maintenance.set_maintenance(False)
            change.assert_not_called()

    def test_retired_bootstrap_input_cannot_return_in_scoped_apply(self):
        payload = {'repository': 'https://github.com/example/platform.git', 'branch': 'main', 'values': {
            'loginHost': 'login.example.invalid', 'adminHost': 'identity-admin.internal.example.invalid',
            'database': 'keycloak', 'databaseRole': 'keycloak', 'databaseHost': 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local',
            'databasePort': 5432, 'databaseCA': 'fixture-ca', 'trustedProxyAddresses': ['10.43.0.1/32']}}
        self.assertFalse(bootstrap.application(payload, 'scoped', retired=True, retired_item='keycloak-emergency-' + 'a' * 32)['spec']['source']['helm']['valuesObject']['bootstrapAdminEnabled'])
        with self.assertRaises(ValueError): bootstrap.application(payload, 'primary', retired=True)
        with tempfile.TemporaryDirectory() as directory, patch.object(bootstrap, 'BASE', Path(directory)), \
                patch.object(bootstrap, 'prerequisites') as prerequisites:
            (Path(directory) / 'retirement.json').write_text(json.dumps({'phase': 'seeding'}))
            with self.assertRaises(RuntimeError): bootstrap.run(payload, 'scoped')
            prerequisites.assert_not_called()

    def test_accepted_retirement_repeat_can_follow_new_public_revision_without_reenabling_inputs(self):
        saved = {'phase': 'accepted', 'nonce': 'a' * 32, 'application_uid': 'owned', 'keycloak_uid': 'server', 'revision': 'older'}
        values = {'bootstrapAdminEnabled': False, 'retiredEmergencyItem': 'keycloak-emergency-' + 'a' * 32}
        app = {'spec': {'source': {'helm': {'valuesObject': values}}}}
        with tempfile.TemporaryDirectory() as directory, patch.object(emergency, 'BASE', Path(directory)), \
                patch.object(emergency, 'owner', return_value=({'uid': 'owned', 'revision': 'newer'}, app, {'metadata': {'uid': 'server'}})), \
                patch.object(emergency, 'kube') as writes, patch.object(emergency, 'condition', return_value=True), \
                patch.object(emergency, 'reconciled', return_value=True):
            (Path(directory) / 'retirement.json').write_text(json.dumps(saved))
            self.assertFalse(emergency.run('a' * 32)['changed'])
            writes.assert_not_called()
            for key, value in (('bootstrapAdminEnabled', True), ('maintenance', True),
                               ('operation', {'action': 'seed-emergency'}), ('retiredEmergencyItem', 'foreign')):
                with self.subTest(key=key):
                    old = copy.deepcopy(values)
                    values[key] = value
                    with self.assertRaises(RuntimeError): emergency.run('a' * 32)
                    values.clear(); values.update(old)

    def test_retired_secrets_remain_owned_without_server_or_writer_mounts(self):
        values = {'enabled': True, 'bootstrapAdminEnabled': False,
                  'databaseCA': 'fixture-ca',
                  'retiredEmergencyItem': 'keycloak-emergency-' + 'a' * 32,
                  'loginHost': 'login.example.invalid', 'adminHost': 'identity-admin.internal.example.invalid',
                  'reconciliationEnabled': True, 'trustedProxyAddresses': ['10.43.0.1/32']}
        objects = render(values)
        secrets = [row for row in objects if row['kind'] == 'ExternalSecret']
        self.assertTrue({'keycloak-bootstrap-admin', 'keycloak-emergency'} <= {row['metadata']['name'] for row in secrets})
        server = next(row for row in objects if row['kind'] == 'Keycloak')
        self.assertNotIn('bootstrapAdmin', server['spec'])
        jobs = [row for row in objects if row['kind'] == 'Job']
        for job in jobs:
            self.assertNotIn('keycloak-emergency', json.dumps(job['spec']))
            self.assertNotIn('keycloak-bootstrap-admin', json.dumps(job['spec']))

    def test_unknown_phase_and_advanced_pending_revision_cannot_mutate(self):
        saved = {'phase': 'unknown', 'nonce': 'a' * 32, 'application_uid': 'owned', 'keycloak_uid': 'server', 'revision': 'old'}
        with tempfile.TemporaryDirectory() as directory, patch.object(emergency, 'BASE', Path(directory)), \
                patch.object(emergency, 'owner', return_value=({'uid': 'owned', 'revision': 'old'}, {}, {'metadata': {'uid': 'server'}})), \
                patch.object(emergency, 'kube') as writes:
            path = Path(directory) / 'retirement.json'
            path.write_text(json.dumps(saved))
            with self.assertRaises(RuntimeError): emergency.run('a' * 32)
            saved['phase'] = 'seeding'; saved['revision'] = 'older'
            path.write_text(json.dumps(saved))
            with self.assertRaises(RuntimeError): emergency.run('a' * 32)
            writes.assert_not_called()

    def test_finishing_resume_preserves_retired_inputs_and_checkpoints_only_after_convergence(self):
        saved = {'phase': 'finishing', 'nonce': 'a' * 32, 'application_uid': 'owned',
                 'keycloak_uid': 'server', 'revision': 'b' * 40, 'bootstrap_username': 'temporary',
                 'bootstrap_user_id': 'user', 'temporary_token_denial_measured': True}
        app = {'metadata': {'uid': 'owned', 'resourceVersion': '1'}, 'spec': {'source': {'helm': {
            'valuesObject': {'adminHost': 'admin.example.invalid', 'operation': None}}}}}
        with tempfile.TemporaryDirectory() as directory, patch.object(emergency, 'BASE', Path(directory)), \
                patch.object(emergency, 'owner', return_value=({'uid': 'owned', 'revision': 'b' * 40}, app, {'metadata': {'uid': 'server'}})), \
                patch.object(emergency, 'get', return_value=app), patch.object(emergency, 'kube') as writes, \
                patch.object(emergency, 'wait', side_effect=lambda check, *args, **kwargs: self.assertTrue(check())), \
                patch.object(emergency, 'writer_idle', return_value=True), patch.object(emergency, 'reconciled', return_value=True):
            path = Path(directory) / 'retirement.json'
            path.write_text(json.dumps(saved))
            self.assertTrue(emergency.run('a' * 32)['bootstrap_admin_retired'])
            self.assertEqual(json.loads(path.read_text())['phase'], 'accepted')
            patches = json.loads(writes.call_args.args[-1])
            changes = {row['path'].split('/')[-1]: row['value'] for row in patches
                       if row['op'] == 'add' and row['path'].startswith('/spec/source/helm/valuesObject/')}
            self.assertIn({'op': 'remove', 'path': '/spec/source/helm/valuesObject/operation'}, patches)
            self.assertEqual(changes, {'maintenance': False,
                'bootstrapAdminEnabled': False, 'retiredEmergencyItem': 'keycloak-emergency-' + 'a' * 32})

    def test_self_disable_hook_failure_requires_exact_disabled_state_and_authentication_denial(self):
        saved = {'phase': 'retiring-service', 'nonce': 'a' * 32, 'application_uid': 'owned',
                 'keycloak_uid': 'server', 'revision': 'b' * 40, 'bootstrap_username': 'temporary', 'bootstrap_user_id': 'user'}
        app = {'metadata': {'uid': 'owned', 'resourceVersion': '1'}, 'spec': {'source': {'helm': {
            'valuesObject': {'adminHost': 'admin.example.invalid', 'database': 'keycloak'}}}}}
        failure = 'Identity reconciliation failed at the requested revision; preserve the phase checkpoint'
        for enabled, error, passes in (('f', failure, True), ('t', failure, False), ('f', 'foreign owner', False)):
            with self.subTest(enabled=enabled, error=error), tempfile.TemporaryDirectory() as directory, \
                    patch.object(emergency, 'BASE', Path(directory)), \
                    patch.object(emergency, 'owner', return_value=({'uid': 'owned', 'revision': 'b' * 40}, app, {'metadata': {'uid': 'server'}})), \
                    patch.object(emergency, 'get', return_value=app), patch.object(emergency, 'kube'), \
                    patch.object(emergency, 'wait', side_effect=lambda check, *args, **kwargs: self.assertTrue(check())), \
                    patch.object(emergency, 'writer_idle', return_value=True), \
                    patch.object(emergency, 'reconciled', side_effect=[RuntimeError(error), True]), \
                    patch.object(emergency, 'sql', side_effect=['t', enabled]) as queries, \
                    patch.object(emergency, 'token', return_value='private-token'), \
                    patch.object(emergency, 'vault_secret', return_value={'client_id': 'emergency-' + 'a' * 32, 'client_secret': 'private-secret'}), \
                    patch.object(emergency, 'private_request', side_effect=[{'error': 'invalid_client'}, (401, None)]) as requests:
                path = Path(directory) / 'retirement.json'
                path.write_text(json.dumps(saved))
                if passes:
                    self.assertTrue(emergency.run('a' * 32)['temporary_token_denial_measured'])
                    self.assertEqual(json.loads(path.read_text())['phase'], 'accepted')
                    self.assertTrue(requests.call_args.kwargs['with_status'])
                else:
                    with self.assertRaises(RuntimeError): emergency.run('a' * 32)
                    self.assertEqual(json.loads(path.read_text())['phase'], 'retiring-service')
                    requests.assert_not_called()
                for query in queries.call_args_list:
                    self.assertTrue(query.args[0].startswith('SELECT c.enabled FROM client c JOIN realm r'))
                    self.assertEqual(query.args[1], 'keycloak')


if __name__ == '__main__':
    unittest.main()
