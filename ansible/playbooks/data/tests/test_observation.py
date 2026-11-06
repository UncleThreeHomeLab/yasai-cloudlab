"""Independent native settings and operation boundaries; all sources are synthetic."""
import base64
from contextlib import ExitStack, contextmanager
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

from fixtures import native_observation
from playbooks.data.files import control, native


class ObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = native_observation()

    def setUp(self):
        self.fixture = copy.deepcopy(self.template)
        self.objects = self.fixture['objects']
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.read = self.stack.enter_context(patch.object(native, 'get', side_effect=lambda kind, name=None, namespace=None: self.objects.get((kind, name, namespace))))
        self.stack.enter_context(patch.object(control, 'get', self.read))
        self.stack.enter_context(patch.object(native, 'receipt', side_effect=lambda path, **kwargs: self.fixture['binding'] if path == native.BINDING
            else json.loads(path.read_text()) if path.name == 'cold-maintenance.json' else self.fixture['state']))
        self.head = self.stack.enter_context(patch.object(native.source_snapshot, 'request', return_value={'protected': True, 'commit': {'sha': 'd' * 40}}))
        self.public_events = []
        @contextmanager
        def metadata(state, *, deadline):
            self.assertEqual(state, self.fixture['state'])
            self.public_events.append('open')
            try: yield self.head
            finally: self.public_events.append('closed')
        self.public_session = self.stack.enter_context(patch.object(native, 'public_metadata', side_effect=metadata))
        self.raw = self.stack.enter_context(patch.object(native.source_snapshot, 'read_url', return_value=yaml.safe_dump(self.fixture['committed']).encode()))
        self.chart = self.stack.enter_context(patch.object(native.source_snapshot, 'chart_files', autospec=True, return_value=self.fixture['files']))
        self.api, self.client = Mock(), Mock()
        self.api.request.side_effect = [{'app_id': 1, 'repository_selection': 'selected',
            'permissions': {'contents': 'read', 'metadata': 'read'}}, {'token': 'synthetic-token'}]
        def private(method, path, **kwargs):
            if method == 'DELETE': return None
            if path == 'repos/example/private':
                return {'full_name': 'example/private', 'private': True, 'default_branch': 'main'}
            for filename, document in zip(native.value_files(self.fixture['committed']), self.fixture['documents']):
                if '/contents/' + filename + '?ref=' + 'b' * 40 in path:
                    raw = document if isinstance(document, bytes) else json.dumps(document).encode()
                    return {'type': 'file', 'path': filename, 'encoding': 'base64', 'size': len(raw),
                        'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                        'content': base64.b64encode(raw).decode()}
            raise AssertionError('Unexpected private request')
        self.client.request.side_effect = private
        self.stack.enter_context(patch.object(native, 'GitHub', side_effect=[self.api, self.client]))
        self.stack.enter_context(patch.object(native, 'app_token', return_value='synthetic-app-token'))

    def test_acquires_once_and_revokes_before_repeated_settings_reads(self):
        selected = 'services/catalog-v2.yaml'
        self.fixture['committed']['services']['catalogPath'] = selected
        self.raw.return_value = yaml.safe_dump(self.fixture['committed']).encode()
        self.objects['application.argoproj.io', native.APP, 'argocd']['spec']['sources'][0]['helm']['valueFiles'][-1] = '$values/' + selected
        self.objects['externalsecret.external-secrets.io', 'cloudlab-argocd-identity-source', 'argocd']['metadata']['finalizers'] = [native.ESO_FINALIZER]
        acquire = native.authenticated_inputs
        render = native.render_settings
        def private(*args, **kwargs):
            self.assertEqual(self.public_events, ['open', 'closed'])
            return acquire(*args, **kwargs)
        def settings(*args, **kwargs):
            self.assertEqual(self.public_events, ['open', 'closed'])
            return render(*args, **kwargs)
        with patch.object(native, 'published_source', wraps=native.published_source) as published, \
                patch.object(native, 'authenticated_inputs', side_effect=private), \
                patch.object(native, 'render_settings', side_effect=settings):
            source = control.operation()
            for _ in range(4):
                self.assertEqual(control.settings(source), self.fixture['expected'])
        self.public_session.assert_called_once()
        self.assertEqual(self.public_events, ['open', 'closed'])
        self.assertIs(published.call_args.kwargs['fetch'], self.head)
        self.assertIs(self.chart.call_args.kwargs['fetch'], self.head)
        self.assertEqual(published.call_args.kwargs['deadline'], self.public_session.call_args.kwargs['deadline'])
        self.assertEqual(self.chart.call_args.kwargs['deadline'], self.public_session.call_args.kwargs['deadline'])
        self.assertEqual(self.head.call_count, 1)
        self.assertEqual(self.raw.call_count, 1)
        self.assertEqual(self.chart.call_count, 1)
        reads = [call.args for call in self.client.request.call_args_list]
        self.assertEqual(len(reads), 5)
        self.assertEqual(reads[-1], ('DELETE', 'installation/token'))
        self.assertEqual(self.api.request.call_args.args[2], {'repositories': ['private'], 'permissions': {'contents': 'read'}})
        self.assertIn(('GET', 'repos/example/private/contents/' + selected + '?ref=' + 'b' * 40), reads)
        self.assertFalse(any('/contents/services/catalog.json?' in args[1] for args in reads))

    def test_root_guard_accepts_only_legacy_or_exact_versioned_identity_receipt(self):
        original = copy.deepcopy(self.fixture['binding'])
        self.assertEqual(native.root_guard(self.fixture['state'], self.fixture['public'], 'd' * 40), original['target'])
        for value in (1, None, True, 0, 2, '1'):
            self.fixture['binding'] = dict(copy.deepcopy(original), namespaceGuardContract=value)
            with self.subTest(value=value):
                if type(value) is int and value == 1:
                    self.assertEqual(native.root_guard(self.fixture['state'], self.fixture['public'], 'd' * 40), original['target'])
                else:
                    with self.assertRaises(RuntimeError):
                        native.root_guard(self.fixture['state'], self.fixture['public'], 'd' * 40)
        self.fixture['binding'] = dict(original, namespaceGuardContract=1, unexpected=True)
        with self.assertRaises(RuntimeError): native.root_guard(self.fixture['state'], self.fixture['public'], 'd' * 40)

    def test_public_metadata_failure_prevents_private_acquisition_and_writes(self):
        for failure in ('read', 'cleanup'):
            self.public_events.clear(); self.head.reset_mock(); self.chart.reset_mock()
            self.head.side_effect = RuntimeError('Synthetic public read failure') if failure == 'read' else None
            @contextmanager
            def metadata(state, *, deadline):
                self.assertEqual(state, self.fixture['state'])
                self.public_events.append('open')
                try: yield self.head
                finally:
                    self.public_events.append('closed')
                    if failure == 'cleanup': raise RuntimeError('Synthetic public cleanup failure')
            with self.subTest(failure=failure), patch.object(native, 'public_metadata', side_effect=metadata) as session, \
                    patch.object(native, 'render_settings') as render, patch.object(native, 'kube') as write, \
                    patch.object(control, 'sql') as sql, patch.object(control, 'grants') as grants, patch.object(control, 's3') as s3:
                with self.assertRaisesRegex(RuntimeError, 'Synthetic public ' + failure + ' failure'):
                    control.reconcile()
                session.assert_called_once(); self.head.assert_called_once()
                self.assertEqual(self.public_events, ['open', 'closed'])
                self.assertEqual(self.chart.call_count, 0 if failure == 'read' else 1)
                self.api.request.assert_not_called(); self.client.request.assert_not_called()
                render.assert_not_called(); write.assert_not_called()
                sql.assert_not_called(); grants.assert_not_called(); s3.assert_not_called()

    def test_missing_selected_catalog_revokes_without_legacy_fallback(self):
        from playbooks.argocd.files.github_setup import GitHubHTTPError
        self.fixture['committed']['services']['catalogPath'] = 'services/catalog-v2.yaml'
        self.raw.return_value = yaml.safe_dump(self.fixture['committed']).encode()
        read = self.client.request.side_effect
        def missing(method, path, **kwargs):
            if '/contents/services/catalog-v2.yaml?' in path:
                raise GitHubHTTPError(404)
            return read(method, path, **kwargs)
        self.client.request.side_effect = missing
        with patch.object(native, 'render_settings') as render, patch.object(control, 'grants') as sql, patch.object(control, 's3') as s3:
            with self.assertRaises(GitHubHTTPError): control.reconcile()
            render.assert_not_called(); sql.assert_not_called(); s3.assert_not_called()
        reads = [call.args for call in self.client.request.call_args_list]
        self.assertEqual(reads[-1], ('DELETE', 'installation/token'))
        self.assertFalse(any('/contents/services/catalog.json?' in args[1] for args in reads))

    def test_identity_reader_matches_actual_root_render(self):
        actual = self.objects['externalsecret.external-secrets.io', 'cloudlab-argocd-identity-source', 'argocd']
        self.assertEqual(actual['spec'], native.reader_spec(self.fixture['target']['valuesRepository']))
        self.assertEqual(native.source_credentials(self.fixture['target']['valuesRepository'])['APP_ID'], '1')

    def test_reader_rejects_unknown_eso_and_all_secret_finalizers(self):
        name = 'cloudlab-argocd-identity-source'
        external = self.objects['externalsecret.external-secrets.io', name, 'argocd']
        for finalizers in (['foreign'], [native.ESO_FINALIZER, 'foreign']):
            external['metadata']['finalizers'] = finalizers
            with self.assertRaises(RuntimeError): native.source_credentials(self.fixture['target']['valuesRepository'])
        external['metadata']['finalizers'] = [native.ESO_FINALIZER]
        self.objects['secret', name, 'argocd']['metadata']['finalizers'] = [native.ESO_FINALIZER]
        with self.assertRaises(RuntimeError): native.source_credentials(self.fixture['target']['valuesRepository'])

    def test_forged_settings_same_uid_fail_before_any_sql_or_s3_write(self):
        obj = self.objects['configmap', native.SETTINGS, 'cloudlab-data']
        values = json.loads(obj['data']['settings']); values['bucket'] = 'foreign-bucket'
        obj['data']['settings'] = json.dumps(values)
        with patch.object(control, 'grants') as sql, patch.object(control, 's3') as s3:
            with self.assertRaisesRegex(RuntimeError, 'content differs'):
                control.reconcile()
            sql.assert_not_called(); s3.assert_not_called()
        self.assertEqual(self.client.request.call_args.args, ('DELETE', 'installation/token'))

    def test_coordinated_root_child_pin_drift_cannot_change_independent_authority(self):
        root = self.objects['application.argoproj.io', 'cloudlab-public-root', 'argocd']
        root['spec']['source']['helm']['valuesObject']['data'] = {'configuration': {'revision': 'e' * 40}}
        root['status']['sync']['comparedTo']['source'] = copy.deepcopy(root['spec']['source'])
        self.objects['application.argoproj.io', native.APP, 'argocd']['spec']['sources'][0]['targetRevision'] = 'e' * 40
        with self.assertRaisesRegex(RuntimeError, 'override conflicts'):
            control.operation()
        self.chart.assert_not_called(); self.api.request.assert_not_called()

    def test_missing_or_foreign_reader_fails_before_private_authentication(self):
        for change in ('missing', 'owner', 'project', 'url', 'tracking'):
            with self.subTest(change=change):
                self.objects = copy.deepcopy(self.template['objects'])
                secret = self.objects['secret', 'cloudlab-argocd-identity-source', 'argocd']
                if change == 'missing': self.objects.pop(('secret', 'cloudlab-argocd-identity-source', 'argocd'))
                if change == 'owner': secret['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                if change in ('project', 'url'): secret['data'][change] = base64.b64encode(b'foreign').decode()
                if change == 'tracking': self.objects['externalsecret.external-secrets.io', 'cloudlab-argocd-identity-source', 'argocd']['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
                with self.assertRaises(RuntimeError): control.operation()
        self.api.request.assert_not_called()

    def test_revocation_failure_prevents_repair(self):
        read = self.client.request.side_effect
        def failing(method, path, **kwargs):
            if method == 'DELETE': raise RuntimeError('Synthetic revocation failure')
            return read(method, path, **kwargs)
        self.client.request.side_effect = failing
        with patch.object(control, 'grants') as sql, patch.object(control, 's3') as s3:
            with self.assertRaisesRegex(RuntimeError, 'revocation failure'): control.reconcile()
            sql.assert_not_called(); s3.assert_not_called()

    def test_malformed_raw_private_inputs_revoke_before_helm_or_any_write(self):
        documents = copy.deepcopy(self.fixture['documents'])
        cases = []
        for field, value in (('identity', {}), ('identity', {'enabled': True, 'database': 'keycloak'}),
                             ('identity', {'enabled': 1, 'database': 'keycloak', 'role': 'keycloak'}),
                             ('maintenance', True), ('sharedInputs', False)):
            profile = copy.deepcopy(documents[1]); profile[field] = value
            cases.append((field + repr(value), 1, profile))
        certificate = copy.deepcopy(documents[0]); certificate['database'] = 'foreign'
        cases.append(('misplaced certificate database', 0, certificate))
        certificate = copy.deepcopy(documents[0]); certificate['production'] = 'true'
        cases.append(('certificate raw type', 0, certificate))
        catalog = copy.deepcopy(documents[2]); catalog['maintenance'] = True
        cases.append(('misplaced catalog operation', 2, catalog))
        catalog = copy.deepcopy(documents[2]); catalog['catalog'][0]['definition']['data']['database']['name'] = 1
        cases.append(('nested request raw type', 2, catalog))
        catalog = copy.deepcopy(documents[2]); next(iter(catalog['dataApprovals'].values()))['name'] = False
        cases.append(('approval raw type', 2, catalog))
        cases += [('duplicate profile', 1, (yaml.safe_dump(documents[1]) + 'database: notes\n').encode()),
                  ('duplicate nested identity', 1, json.dumps(documents[1]).replace('"enabled": true', '"enabled": false, "enabled": true').encode()),
                  ('multiple documents', 1, (yaml.safe_dump(documents[1]) + '---\n' + yaml.safe_dump(documents[1])).encode()),
                  ('alias expansion', 1, yaml.safe_dump(documents[1]).replace('bucket: notes', 'bucket: &scope notes').replace('database: notes', 'database: *scope', 1).encode())]
        for label, index, invalid in cases:
            with self.subTest(case=label):
                self.fixture['documents'] = copy.deepcopy(documents)
                self.fixture['documents'][index] = invalid
                self.client.request.reset_mock()
                self.api.request.side_effect = [{'app_id': 1, 'repository_selection': 'selected',
                    'permissions': {'contents': 'read', 'metadata': 'read'}}, {'token': 'synthetic-token'}]
                with patch.object(native, 'GitHub', side_effect=[self.api, self.client]), \
                        patch.object(native, 'render_settings') as render, patch.object(native, 'kube') as binding, \
                        patch.object(control, 'sql') as sql, patch.object(control, 'grants') as grants, patch.object(control, 's3') as s3:
                    with self.assertRaisesRegex(RuntimeError, 'raw schema'): control.reconcile()
                    render.assert_not_called(); binding.assert_not_called()
                    sql.assert_not_called(); grants.assert_not_called(); s3.assert_not_called()
                self.assertEqual(self.client.request.call_args.args, ('DELETE', 'installation/token'))
                paths = [call.args[1] for call in self.client.request.call_args_list if '/contents/' in call.args[1]]
                self.assertEqual(len(paths), len(set(paths)))

    def test_empty_root_or_child_operation_denies_normal_and_recorded_recovery(self):
        original = copy.deepcopy(self.objects)
        for recovery in (False, True):
            for name in ('cloudlab-public-root', native.APP):
                with self.subTest(recovery=recovery, application=name), tempfile.TemporaryDirectory() as directory, \
                        patch.object(control, 'BASE', Path(directory)):
                    self.objects = copy.deepcopy(original)
                    if recovery:
                        checkpoint = Path(directory) / 'cold-maintenance.json'
                        checkpoint.write_text('{"started_at":1}'); checkpoint.chmod(0o600)
                        native.record_operation({key: self.objects['application.argoproj.io', key, 'argocd'] for key in (native.APP, native.SEAWEED)},
                                                native.APP, {'hibernated': False})
                    obj = self.objects['application.argoproj.io', name, 'argocd']
                    obj['operation'] = {}
                    obj['status']['operationState'] = {'phase': 'Running', 'operation': {
                        'initiatedBy': {'automated': True}, 'sync': {'revisions': ['a' * 40, 'b' * 40]}}}
                    self.api.request.side_effect = [{'app_id': 1, 'repository_selection': 'selected',
                        'permissions': {'contents': 'read', 'metadata': 'read'}}, {'token': 'synthetic-token'}]
                    with patch.object(native, 'GitHub', side_effect=[self.api, self.client]), \
                            patch.object(native, 'kube') as binding, patch.object(control, 'sql') as sql, \
                            patch.object(control, 'grants') as grants, patch.object(control, 's3') as s3:
                        with self.assertRaises(RuntimeError):
                            source = control.operation(recovery=recovery)
                            control.reconcile(source)
                        binding.assert_not_called(); sql.assert_not_called(); grants.assert_not_called(); s3.assert_not_called()

    def test_recorded_patch_waits_for_new_settings_during_automated_sync(self):
        source = control.operation()
        root = self.objects['application.argoproj.io', 'cloudlab-public-root', 'argocd']
        original = copy.deepcopy(root)
        def apply(*args, **kwargs):
            self.assertEqual(args[2], 'cloudlab-public-root')
            document = json.loads(args[-1])
            self.assertEqual([row['path'] for row in document[:3]], ['/metadata/uid', '/metadata/resourceVersion', '/spec'])
            self.assertEqual(document[2]['value'], original['spec'])
            self.assertEqual(document[-1]['path'], '/spec/source/helm/valuesObject')
            self.assertEqual(document[-1]['value']['identity'], original['spec']['source']['helm']['valuesObject']['identity'])
            root['spec']['source']['helm']['valuesObject'] = document[-1]['value']
            root['operation'] = {'initiatedBy': {'automated': True}, 'sync': {'revision': 'd' * 40}}
            root['status']['operationState']['phase'] = 'Running'
        def converge(predicate, *args, **kwargs):
            if args[0] == 'data operational Root convergence':
                self.assertFalse(predicate())
                root.pop('operation'); root['status']['operationState']['phase'] = 'Succeeded'
                root['status']['sync']['comparedTo']['source'] = copy.deepcopy(root['spec']['source'])
                app = self.objects['application.argoproj.io', native.APP, 'argocd']
                app['spec']['sources'][0]['helm']['valuesObject'].update(source.flags)
                app['operation'] = {'initiatedBy': {'automated': True}, 'sync': {'revisions': ['a' * 40, 'b' * 40]}}
                app['status']['operationState']['phase'] = 'Running'
                self.assertTrue(predicate()); return
            self.assertIsNone(predicate())
            self.objects['configmap', native.SETTINGS, 'cloudlab-data']['data']['settings'] = json.dumps(source.expected)
            self.assertTrue(predicate())
        with patch.object(native, 'kube', side_effect=apply), patch.object(native, 'wait', side_effect=converge):
            source.patch(native.APP, {'maintenance': True})
        self.assertTrue(source.settings()['maintenance'])
        self.assertEqual(self.chart.call_count, 1)
        app = self.objects['application.argoproj.io', native.APP, 'argocd']
        app['operation']['initiatedBy'] = {'username': 'foreign'}
        with self.assertRaisesRegex(RuntimeError, 'identity or ownership'): source.settings()

    def test_root_intent_recovery_and_foreign_root_refusal_do_not_patch_child(self):
        source = control.operation()
        root = self.objects['application.argoproj.io', 'cloudlab-public-root', 'argocd']
        baseline = copy.deepcopy(root)
        for field in ('uid', 'spec'):
            if field == 'uid': root['metadata']['uid'] = 'foreign'
            else: root['spec']['source']['helm']['valuesObject']['data'] = {'configuration': {'revision': 'e' * 40}}
            with patch.object(native, 'kube') as write, self.assertRaises(RuntimeError): source.patch(native.APP, {'maintenance': True})
            write.assert_not_called(); root.clear(); root.update(copy.deepcopy(baseline))
        # A lost response leaves the Root flags themselves as durable intent.
        def lost(*args, **kwargs):
            self.assertEqual(args[2], 'cloudlab-public-root')
            root['spec']['source']['helm']['valuesObject'] = json.loads(args[-1])[-1]['value']
            raise RuntimeError('synthetic lost response')
        with patch.object(native, 'kube', side_effect=lost), self.assertRaisesRegex(RuntimeError, 'lost response'):
            source.patch(native.APP, {'maintenance': True})
        root['status']['sync']['comparedTo']['source'] = copy.deepcopy(root['spec']['source'])
        self.api.request.side_effect = [{'app_id': 1, 'repository_selection': 'selected',
            'permissions': {'contents': 'read', 'metadata': 'read'}}, {'token': 'synthetic-token'}]
        clock = Mock(return_value=100)
        def converge(predicate, *args, **kwargs):
            if args[0] == 'data operational Root convergence': clock.return_value = 800
            if args[0] == 'data operational child convergence':
                self.assertIsNone(predicate())
                self.objects['application.argoproj.io', native.APP, 'argocd']['spec']['sources'][0]['helm']['valuesObject']['maintenance'] = True
            if args[0] == 'data operational settings recovery':
                self.assertIsNone(predicate())
                settings = copy.deepcopy(self.fixture['expected']); settings['maintenance'] = True
                self.objects['configmap', native.SETTINGS, 'cloudlab-data']['data']['settings'] = json.dumps(settings)
            self.assertTrue(predicate())
        with patch.object(native, 'GitHub', side_effect=[self.api, self.client]) as github, patch.object(native.time, 'monotonic', clock), \
                patch.object(native, 'wait', side_effect=converge), \
                patch.object(native, 'kube') as write:
            sessions = self.public_session.call_count
            recovered = control.operation(recovery=True)
            self.assertTrue(recovered.settings()['maintenance'])
            self.assertEqual(self.public_session.call_count, sessions)
            self.assertEqual(github.call_args_list[0].kwargs['deadline'], 920)
            write.assert_not_called()

    def test_legacy_historical_settings_and_timer_never_fetch_missing_profile(self):
        from playbooks.data.files.initial_bootstrap import application
        self.fixture['state'].pop('settings_uid')
        for name in (native.APP, native.SEAWEED):
            obj = self.objects['application.argoproj.io', name, 'argocd']
            desired = application({'repository': self.fixture['public']['repository'], 'branch': 'main'},
                'data-configuration' if name == native.APP else 'seaweedfs', self.fixture['expected'] if name == native.APP else None)
            desired['metadata']['uid'] = obj['metadata']['uid']
            self.objects['application.argoproj.io', name, 'argocd'] = desired
        self.assertEqual(control.settings(), self.fixture['expected'])
        with patch.object(control, 'grants', return_value=False), patch.object(control, 'reload_s3', return_value=False), \
                patch.object(control, 's3') as s3, patch('playbooks.data.files.requests.reconcile', return_value=False), \
                patch('playbooks.data.files.public_ca.reconcile', return_value=False):
            s3.return_value.ensure_bucket.return_value = False
            self.assertFalse(control.reconcile())
        self.head.assert_not_called(); self.raw.assert_not_called(); self.chart.assert_not_called()
        self.api.request.assert_not_called(); self.client.request.assert_not_called()

    def test_legacy_owner_and_registered_native_downgrade_never_fall_back(self):
        from playbooks.data.files.initial_bootstrap import application
        for name in (native.APP, native.SEAWEED):
            original = self.objects['application.argoproj.io', name, 'argocd']
            obj = application({'repository': self.fixture['public']['repository'], 'branch': 'main'},
                'data-configuration' if name == native.APP else 'seaweedfs', self.fixture['expected'] if name == native.APP else None)
            obj['metadata']['uid'] = original['metadata']['uid']
            self.objects['application.argoproj.io', name, 'argocd'] = obj
        with self.assertRaisesRegex(RuntimeError, 'cannot downgrade'): control.settings()
        self.fixture['state'].pop('settings_uid')
        self.objects['application.argoproj.io', native.APP, 'argocd']['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'legacy identity'): control.settings()
        self.head.assert_not_called(); self.api.request.assert_not_called()

    def test_recorded_legacy_cold_resume_allows_only_own_sync_after_main_advanced(self):
        from playbooks.data.files.initial_bootstrap import application
        from playbooks.data.files import volumes
        self.fixture['state'].pop('settings_uid')
        for name in (native.APP, native.SEAWEED):
            values = copy.deepcopy(self.fixture['expected']) if name == native.APP else {'seaweedfs': {c: {'replicas': 0} for c in native.COMPONENTS}}
            if name == native.APP:
                values.update(maintenance=True, hibernated=True)
            obj = application({'repository': self.fixture['public']['repository'], 'branch': 'main'},
                'data-configuration' if name == native.APP else 'seaweedfs', values)
            obj['metadata']['uid'] = self.fixture['state']['applications'][name]
            obj['status'] = {'sync': {'revision': 'e' * 40}, 'operationState': {'phase': 'Running'}}
            obj['operation'] = {'initiatedBy': {'automated': True}, 'sync': {'revision': 'e' * 40}}
            self.objects['application.argoproj.io', name, 'argocd'] = obj
        self.assertNotEqual(self.fixture['state']['revision'], 'e' * 40)
        app = self.objects['application.argoproj.io', native.APP, 'argocd']
        seaweed = self.objects['application.argoproj.io', native.SEAWEED, 'argocd']
        with tempfile.TemporaryDirectory() as directory, patch.object(control, 'BASE', Path(directory)):
            checkpoint = Path(directory) / 'cold-maintenance.json'
            checkpoint.write_text('{"started_at":1}'); checkpoint.chmod(0o600)
            # An old busy checkpoint cannot invent operation authority.
            with self.assertRaisesRegex(RuntimeError, 'legacy identity'): control.operation(recovery=True)
            native.record_operation({native.APP: app, native.SEAWEED: seaweed}, native.APP, {'hibernated': True})
            saved = json.loads(checkpoint.read_text())['operation']
            self.assertEqual(saved['revisions'], {native.APP: ['e' * 40], native.SEAWEED: ['e' * 40]})
            app['operation']['initiatedBy'] = {'username': 'foreign'}
            with self.assertRaisesRegex(RuntimeError, 'legacy identity'): control.operation(recovery=True)
            app['operation']['initiatedBy'] = {'automated': True}
            writes = []
            def get(kind, name=None, namespace=None):
                if kind == 'application.argoproj.io': return self.objects[kind, name, namespace]
                if kind == 'cluster.postgresql.cnpg.io':
                    return {'metadata': {}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
                return {'spec': {'replicas': 1}}
            def patch_values(*args, **kwargs):
                if args[0] != 'patch': return
                name = args[2]; writes.append(name)
                value = json.loads(args[-1])['spec']['source']['helm']['valuesObject']
                self.objects['application.argoproj.io', name, 'argocd']['spec']['source']['helm']['valuesObject'].update(value)
            with patch.object(volumes, 'get', side_effect=get), patch.object(volumes, 'kube', side_effect=patch_values), \
                    patch.object(volumes, 'wait', side_effect=lambda predicate, *a, **k: self.assertTrue(predicate())), \
                    patch.object(control, 'maintenance') as maintenance, \
                    patch('playbooks.keycloak.files.maintenance.set_maintenance'):
                volumes.resume()
            self.assertEqual(writes, [native.SEAWEED, native.APP])
            maintenance.assert_called_once_with(False, False)
            self.assertFalse(checkpoint.exists())
        self.head.assert_not_called(); self.client.request.assert_not_called()

    def test_legacy_readiness_requires_new_spec_comparison_but_allows_main_advance(self):
        from playbooks.data.files.initial_bootstrap import application
        expected = application({'repository': self.fixture['public']['repository'], 'branch': 'main'},
            'data-configuration', self.fixture['expected'])
        expected['metadata']['uid'] = 'legacy-owner'
        actual = copy.deepcopy(expected)
        actual['status'] = {'sync': {'revision': 'e' * 40, 'status': 'Synced', 'comparedTo': {'source': {}}},
                            'health': {'status': 'Healthy'}}
        self.objects['application.argoproj.io', native.APP, 'argocd'] = actual
        self.assertFalse(control.legacy_ready(expected))
        actual['status']['sync']['comparedTo']['source'] = copy.deepcopy(expected['spec']['source'])
        self.assertTrue(control.legacy_ready(expected))
        actual['spec']['source']['helm']['valuesObject']['bucket'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'intent changed'): control.legacy_ready(expected)
