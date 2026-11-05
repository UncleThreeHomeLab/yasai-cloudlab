"""Prepared handoff authority, real entrypoint fences and recoverable registration."""
from contextlib import ExitStack
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml
from fixtures import native_observation
from playbooks.data.files import backup, capture, initial_bootstrap, control, handoff, native, restore, volumes


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = native_observation()

    def setUp(self):
        self.fixture = copy.deepcopy(self.template)
        self.objects = self.fixture['objects']
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.base = Path(directory)
        self.stack.enter_context(patch.object(control, 'BASE', self.base))
        self.stack.enter_context(patch.object(initial_bootstrap, 'BASE', self.base))
        self.read = lambda kind, name=None, namespace=None: self.objects.get((kind, name, namespace))
        self.stack.enter_context(patch.object(native, 'get', side_effect=self.read))
        self.stack.enter_context(patch.object(control, 'get', side_effect=self.read))
        self.stack.enter_context(patch.object(initial_bootstrap, 'get', side_effect=self.read))
        self.stack.enter_context(patch.object(native, 'receipt', side_effect=lambda path, **kwargs:
            self.fixture['binding'] if path == native.BINDING else json.loads(path.read_text()) if path.exists() else {}))
        self.head = self.stack.enter_context(patch.object(native, 'published_source', side_effect=lambda *a, **k:
            (self.fixture['committed'], 'd' * 40)))
        self.charts = self.stack.enter_context(patch.object(native.source_snapshot, 'chart_files', return_value=self.fixture['files']))
        self.stack.enter_context(patch.object(native, 'authenticated_inputs', return_value=self.fixture['documents']))
        self.stack.enter_context(patch.object(native, 'render_settings', return_value=self.fixture['expected']))
        self.inventory = self.stack.enter_context(patch.object(handoff, 'resources', return_value={'fixture': {'uid': 'preserved'}}))
        self.native_objects = copy.deepcopy(self.objects)
        owner = self.fixture['state']; owner.pop('settings_uid')
        control.atomic(self.base / 'ownership.json', owner)
        for name in (native.APP, native.SEAWEED):
            obj = initial_bootstrap.application({'repository': self.fixture['public']['repository'], 'branch': 'main'},
                'data-configuration' if name == native.APP else 'seaweedfs', self.fixture['expected'] if name == native.APP else None)
            obj['metadata']['uid'] = owner['applications'][name]
            obj['status'] = {'sync': {'status': 'Synced'}, 'health': {'status': 'Healthy'}}
            self.objects['application.argoproj.io', name, 'argocd'] = obj
        self.objects.pop(('configmap', native.SETTINGS, control.NAMESPACE))
        for kind in ('secret', 'externalsecret.external-secrets.io'):
            self.objects.pop((kind, native.APP + '-source', 'argocd'))
        self.objects['secrets', None, 'argocd']['items'] = [self.objects['secret', 'cloudlab-argocd-identity-source', 'argocd']]
        project = self.objects['appproject.argoproj.io', native.APP, 'argocd']
        project['spec']['sourceRepos'] = [self.fixture['public']['repository']]
        project['spec']['namespaceResourceWhitelist'].remove({'group': '', 'kind': 'ConfigMap'})
        self.fixture['committed']['data']['configuration']['enabled'] = False
        root = self.objects['application.argoproj.io', 'cloudlab-public-root', 'argocd']
        root['spec'].pop('ignoreDifferences')
        root['spec']['syncPolicy']['syncOptions'].remove('RespectIgnoreDifferences=true')

    def arm(self):
        return handoff.prepare(self.fixture['target'])

    def activate(self):
        for key, value in self.native_objects.items():
            self.objects[key] = copy.deepcopy(value)
        self.fixture['committed']['data']['configuration']['enabled'] = True

    def omit_legacy_image(self):
        app = self.objects['application.argoproj.io', native.APP, 'argocd']
        app['spec']['source']['helm']['valuesObject'] = copy.deepcopy(self.fixture['expected'])
        app['spec']['source']['helm']['valuesObject'].pop('postgresImage')
        app['status']['sync'].update(revision='d' * 40, comparedTo={'source': copy.deepcopy(app['spec']['source'])})
        cluster = next(obj for obj in native.render_objects(self.fixture['files'],
            [app['spec']['source']['helm']['valuesObject']]) if obj['kind'] == 'Cluster')
        cluster['metadata'].update(uid='existing-cluster', namespace=control.NAMESPACE)
        cluster['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = native.APP + ':postgresql.cnpg.io/Cluster:cloudlab-data/cloudlab-postgres'
        self.objects['cluster.postgresql.cnpg.io', 'cloudlab-postgres', control.NAMESPACE] = cluster
        return app, cluster

    def first_binding(self):
        self.fixture['binding'] = {}  # Initial binding has no previously accepted profile.
        self.fixture['committed']['data']['configuration']['enabled'] = True
        evidence = dict(self.fixture['committed']['data']['configuration'], required=True,
            repository=self.fixture['public']['repository'], settings=self.fixture['expected'])
        with control.locked():
            handoff.prepare_binding(evidence, self.fixture['target'],
                self.objects['application.argoproj.io', 'cloudlab-public-root', 'argocd'],
                lambda kind, name: self.read(kind, name, 'argocd'))

    def test_real_chart_omitted_image_default_arms_both_entrypoints_without_mutating_legacy(self):
        for first in (False, True):
            self.setUp()
            with self.subTest(first_binding=first), patch.object(control, 'kube') as write:
                app, cluster = self.omit_legacy_image()
                before = copy.deepcopy(app)
                self.head.reset_mock(); self.charts.reset_mock()
                self.first_binding() if first else self.arm()
                value = handoff.state()['handoff']
                self.assertEqual(value['settings'], self.fixture['expected'])
                self.assertEqual(app, before)
                self.assertNotIn('postgresImage', value['specs'][native.APP]['source']['helm']['valuesObject'])
                self.assertEqual(cluster['spec']['imageName'], value['settings']['postgresImage'])
                self.assertEqual(self.head.call_count, 1)
                self.assertEqual(self.charts.call_args.args[0], {'repository': self.fixture['public']['repository'],
                    'revision': 'd' * 40, 'path': 'platform/data/configuration'})
                self.assertFalse((self.base / 'desired.json').exists())
                write.assert_not_called()
                self.fixture['binding'] = copy.deepcopy(self.template['binding'])
                self.activate()
                with control.locked():
                    self.assertEqual(handoff.complete_locked().settings(), self.fixture['expected'])

    def test_omitted_image_rejects_default_drift_foreign_cluster_and_unknown_fields_before_journal(self):
        for case in ('chart-default', 'live-image', 'projection-image', 'cluster-owner', 'unknown-field', 'stale-revision', 'stale-source', 'public-pins'):
            for first in (False, True):
                if case == 'public-pins' and not first:
                    continue
                self.setUp()
                with self.subTest(case=case, first_binding=first), patch.object(control, 'kube') as write:
                    app, cluster = self.omit_legacy_image()
                    if case == 'chart-default':
                        files = dict(self.fixture['files'])
                        files['values.yaml'] = files['values.yaml'].replace(self.fixture['expected']['postgresImage'].encode(),
                            self.fixture['expected']['postgresImage'].replace('ebf391', 'ffffff').encode())
                        self.charts.side_effect = lambda source, **kwargs: files if source['revision'] == 'd' * 40 else self.fixture['files']
                    if case == 'live-image': cluster['spec']['imageName'] = 'foreign'
                    if case == 'projection-image': self.fixture['expected']['postgresImage'] = 'foreign'
                    if case == 'cluster-owner': cluster['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
                    if case == 'unknown-field': app['spec']['source']['helm']['valuesObject']['unknownField'] = True
                    if case == 'stale-revision': app['status']['sync']['revision'] = 'e' * 40
                    if case == 'stale-source': app['status']['sync']['comparedTo']['source']['path'] = 'foreign'
                    if case == 'public-pins':
                        self.head.side_effect = lambda *args, **kwargs: (dict(self.fixture['committed'], data={
                            'enabled': True, 'configuration': dict(self.fixture['committed']['data']['configuration'], revision='e' * 40)}), 'd' * 40)
                    before = (self.base / 'ownership.json').read_bytes()
                    with self.assertRaises(RuntimeError):
                        self.first_binding() if first else self.arm()
                    self.assertEqual((self.base / 'ownership.json').read_bytes(), before)
                    self.assertIsNone(handoff.journal(handoff.state()))
                    self.assertFalse((self.base / 'desired.json').exists())
                    write.assert_not_called()

    def test_prepare_repeat_and_first_registration_require_original_evidence(self):
        self.assertTrue(self.arm())
        before = (self.base / 'ownership.json').stat().st_mtime_ns
        self.assertFalse(self.arm())
        self.assertEqual((self.base / 'ownership.json').stat().st_mtime_ns, before)
        with self.assertRaisesRegex(RuntimeError, 'private binding target'):
            handoff.binding_target(dict(self.fixture['target'], valuesRevision='e' * 40))
        self.activate()
        self.head.reset_mock()
        with control.locked():
            source = handoff.complete_locked()
        self.assertEqual(source.settings(), self.fixture['expected'])
        self.assertEqual(self.head.call_count, 1)
        self.assertEqual(handoff.state()['settings_uid'], 'uid-settings')
        self.assertEqual(handoff.journal(handoff.state())['phase'], 'completed')
        with control.locked():
            handoff.complete_locked()

    def test_foreign_names_missing_journal_and_recreated_cm_refuse_adoption(self):
        self.objects['configmap', native.SETTINGS, control.NAMESPACE] = {'metadata': {'uid': 'foreign'}}
        with self.assertRaisesRegex(RuntimeError, 'cannot adopt'):
            self.arm()
        self.assertIsNone(handoff.journal(handoff.state()))
        self.objects.pop(('configmap', native.SETTINGS, control.NAMESPACE))
        self.activate()
        with control.locked(), self.assertRaisesRegex(RuntimeError, 'pre-effect'):
            handoff.complete_locked()

    def test_competing_same_scope_reader_is_rejected_before_arming(self):
        duplicate = copy.deepcopy(self.native_objects['secret', native.APP + '-source', 'argocd'])
        duplicate['metadata']['name'] = 'other-reader'
        self.objects['secrets', None, 'argocd']['items'].append(duplicate)
        with self.assertRaisesRegex(RuntimeError, 'competing'):
            self.arm()
        self.assertIsNone(handoff.journal(handoff.state()))

    def test_rotation_reservation_survives_failure_and_blocks_arm_until_verified(self):
        attempt = 'f' * 32
        self.assertFalse(handoff.rotation_reserve(attempt)['completed'])
        with self.assertRaisesRegex(RuntimeError, 'pending data operation'):
            self.arm()
        with self.assertRaisesRegex(RuntimeError, 'different credential rotation'):
            handoff.rotation_reserve('e' * 32)
        from playbooks.data.files import rotation
        with patch('playbooks.istio.files.kube.get', return_value=None), self.assertRaises(KeyError):
            rotation.remote({'attempt': attempt})
        self.assertTrue((self.base / handoff.ROTATION).exists())
        self.assertFalse(handoff.rotation_reserve(attempt)['completed'])
        control.atomic(self.base / 'rotation-receipt.json', {'attempt': attempt, 'rotated_and_verified': True})
        self.assertTrue(handoff.rotation_reserve(attempt)['completed'])
        self.assertFalse((self.base / handoff.ROTATION).exists())

    def test_armed_rotation_remote_refuses_before_credential_or_resource_effects(self):
        from playbooks.data.files import rotation
        self.arm()
        with patch.object(control, 'kube') as write, patch.object(control, 'operation') as observe:
            with self.assertRaisesRegex(RuntimeError, 'handoff blocks'):
                rotation.remote({'attempt': 'f' * 32})
            write.assert_not_called(); observe.assert_not_called()

    def test_rotation_marks_verified_attempt_before_releasing_reservation(self):
        from playbooks.data.files import rotation, verify
        from playbooks.data.files.s3 import S3Error
        attempt = 'f' * 32
        handoff.rotation_reserve(attempt)
        payload = {'attempt': attempt,
            'cnpg-notes-production': {'old': {'password': 'old'}, 'new': {'password': 'new'}},
            's3-notes-production': {'old': {'ACCESS_KEY_ID': 'old', 'SECRET_ACCESS_KEY': 'old'},
                                    'new': {'ACCESS_KEY_ID': 'new', 'SECRET_ACCESS_KEY': 'new'}}}
        client = Mock(access='new', secret='new', endpoint='https://example.invalid')
        old = Mock(); old.request.side_effect = S3Error(403)
        atomic = control.atomic
        def durable(path, value):
            if path.name == 'rotation-receipt.json':
                self.assertTrue((self.base / handoff.ROTATION).exists())
            return atomic(path, value)
        with patch('playbooks.istio.files.kube.get', return_value=None), patch('playbooks.istio.files.kube.kube'), \
                patch('playbooks.istio.files.kube.wait', side_effect=lambda predicate, *a, **k: self.assertTrue(predicate())), \
                patch.object(control, 'secret', return_value={'password': 'new'}), patch.object(control, 's3', return_value=client), \
                patch.object(control, 'reconcile'), patch('playbooks.data.files.s3.S3', return_value=old), \
                patch.object(verify, 'sql_client'), patch.object(verify, 'pod_query', side_effect=[Mock(returncode=1), Mock(returncode=0)]), \
                patch.object(rotation, 'cleanup_sql'), patch.object(control, 'atomic', side_effect=durable):
            self.assertTrue(rotation.remote(payload)['rotated_and_verified'])
        self.assertEqual(json.loads((self.base / 'rotation-receipt.json').read_text())['attempt'], attempt)
        self.assertFalse((self.base / handoff.ROTATION).exists())

    def test_registration_forgeries_pins_and_resource_changes_preserve_armed_journal(self):
        self.arm(); self.activate()
        cm = self.objects['configmap', native.SETTINGS, control.NAMESPACE]
        cm['data']['settings'] = json.dumps(dict(self.fixture['expected'], bucket='foreign'))
        with control.locked(), self.assertRaisesRegex(RuntimeError, 'content differs'):
            handoff.complete_locked()
        self.assertNotIn('settings_uid', handoff.state())
        cm['data']['settings'] = json.dumps(self.fixture['expected'])
        self.fixture['committed']['data']['configuration']['revision'] = 'e' * 40
        with control.locked(), self.assertRaisesRegex(RuntimeError, 'coordinates changed'):
            handoff.complete_locked()
        self.fixture['committed']['data']['configuration']['revision'] = 'a' * 40
        self.inventory.return_value = {'fixture': {'uid': 'foreign'}}
        with control.locked(), self.assertRaisesRegex(RuntimeError, 'resources'):
            handoff.complete_locked()

    def test_completed_registration_never_accepts_recreated_uid(self):
        self.arm(); self.activate()
        with control.locked(): handoff.complete_locked()
        self.objects['configmap', native.SETTINGS, control.NAMESPACE]['metadata']['uid'] = 'recreated'
        with control.locked(), self.assertRaisesRegex(RuntimeError, 'registered native identity'):
            handoff.complete_locked()

    def test_arm_rechecks_lock_and_pending_operation_before_recording(self):
        with control.locked(), self.assertRaisesRegex(RuntimeError, 'owner lock'):
            self.arm()
        self.assertIsNone(handoff.journal(handoff.state()))
        control.atomic(self.base / 'cold-maintenance.json', {'started_at': 1})
        with self.assertRaisesRegex(RuntimeError, 'pending data operation'):
            self.arm()
        self.assertIsNone(handoff.journal(handoff.state()))

    def test_armed_capture_backup_topology_and_restore_fail_before_any_effect(self):
        self.arm()
        with patch.object(backup, 'require_window'), patch.object(control, 'atomic') as write, \
                patch.object(control, 'sql') as sql, patch.object(control, 'kube') as kube, \
                patch.object(backup, 'Repository') as repository:
            for call in (lambda: backup.run('monthly'), lambda: capture.capture(),
                         lambda: control.maintenance(True), lambda: volumes.stop(),
                         lambda: restore.run({})):
                with self.subTest(call=call), self.assertRaisesRegex(RuntimeError, 'handoff blocks'):
                    call()
            write.assert_not_called(); sql.assert_not_called(); kube.assert_not_called(); repository.assert_not_called()
        self.assertFalse((self.base / 'pending-volume.json').exists())

    def test_timer_finishes_armed_transition_once_and_readonly_probe_never_registers(self):
        self.arm(); self.activate()
        self.assertEqual(handoff.probe(), 'observe')
        self.assertNotIn('settings_uid', handoff.state())
        with patch.object(control, 'grants', return_value=False), patch.object(control, 'reload_s3', return_value=False), \
                patch.object(control, 's3') as s3, patch('playbooks.data.files.requests.reconcile', return_value=False), \
                patch('playbooks.data.files.public_ca.reconcile', return_value=False), control.locked():
            s3.return_value.ensure_bucket.return_value = False
            self.assertFalse(control.reconcile())
        self.assertEqual(handoff.journal(handoff.state())['phase'], 'completed')

    def test_legacy_scope_changes_are_blocked_but_normal_repair_observation_remains(self):
        self.arm()
        self.assertIs(native.operation(), False)
        app = self.objects['application.argoproj.io', native.APP, 'argocd']
        with self.assertRaisesRegex(RuntimeError, 'desired-scope'):
            initial_bootstrap.configure({'repository': self.fixture['public']['repository'], 'branch': 'main',
                'values': dict(self.fixture['expected'], bucket='foreign')})
        app['spec']['source']['helm']['valuesObject']['bucket'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'scope or operation'):
            native.operation()
        with patch.object(initial_bootstrap, 'Path') as legacy_inputs, patch.object(initial_bootstrap, 'kube') as write:
            with self.assertRaises(RuntimeError): initial_bootstrap.configure({})
            legacy_inputs.assert_not_called(); write.assert_not_called()

    def test_task_publication_and_probe_precede_legacy_resolution(self):
        root = Path(__file__).resolve().parents[4] / 'ansible/playbooks'
        main = yaml.safe_load((root / 'data/tasks/main.yml').read_text())
        self.assertIn('metadata', main[0]['ansible.builtin.command'])
        self.assertIn('ansible.builtin.assert', main[1])
        self.assertEqual(main[2]['ansible.builtin.import_tasks'], 'runtime.yml')
        self.assertEqual(main[3]['ansible.builtin.import_tasks'], 'source.yml')
        runtime = yaml.safe_load((root / 'data/tasks/runtime.yml').read_text())
        self.assertFalse(any('inputs.py' in str(task) for task in runtime))
        source = yaml.safe_load((root / 'data/tasks/source.yml').read_text())
        self.assertEqual(source[0]['ansible.builtin.command']['argv'][-1], 'probe')
        self.assertIn('initial', source[1]['when'])
        argo = yaml.safe_load((root / 'keycloak/argo-login.yml').read_text())[0]['tasks']
        self.assertIn('expected_target', str(argo[1]))
        self.assertEqual(argo[2]['ansible.builtin.import_tasks'], 'tasks/runtime.yml')

    def test_probe_rejects_replaced_accepted_owner_and_preserves_partial_seed(self):
        self.assertEqual(handoff.probe(), 'observe')
        self.objects['application.argoproj.io', native.APP, 'argocd']['metadata']['uid'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'missing or replaced'):
            handoff.probe()
        self.objects['application.argoproj.io', native.APP, 'argocd']['metadata']['uid'] = self.fixture['state']['applications'][native.APP]
        owner = handoff.state(); owner['applications'].pop(native.SEAWEED)
        control.atomic(self.base / 'ownership.json', owner)
        self.objects.pop(('application.argoproj.io', native.SEAWEED, 'argocd'))
        self.assertEqual(handoff.probe(), 'initial')

    def test_accepted_legacy_attests_missing_coordinates_without_reapplying(self):
        owner = handoff.state(); owner.pop('publicSource')
        control.atomic(self.base / 'ownership.json', owner)
        payload = {'repository': self.fixture['public']['repository'], 'branch': 'main'}
        with patch.object(initial_bootstrap, 'kube') as kube, patch.object(control, 'sql') as sql, \
                patch.object(control, 's3') as s3:
            self.assertTrue(initial_bootstrap.configure(payload))
            before = (self.base / 'ownership.json').stat().st_mtime_ns
            self.assertFalse(initial_bootstrap.configure(payload))
            self.assertEqual(before, (self.base / 'ownership.json').stat().st_mtime_ns)
            self.assertEqual(handoff.state()['publicSource'], payload)
            self.assertFalse((self.base / 'desired.json').exists())
            for changed in (dict(payload, branch='foreign'), dict(payload, repository='https://github.com/example/foreign.git')):
                with self.assertRaisesRegex(RuntimeError, 'Published metadata'):
                    initial_bootstrap.configure(changed)
            owner = handoff.state(); owner['publicSource'] = dict(payload, branch='foreign')
            control.atomic(self.base / 'ownership.json', owner)
            with self.assertRaisesRegex(RuntimeError, 'source changed'):
                initial_bootstrap.configure(payload)
            kube.assert_not_called(); sql.assert_not_called(); s3.assert_not_called()

    def test_public_metadata_never_resolves_legacy_fields_even_on_publication_failure(self):
        from playbooks.data.files import inputs
        with patch.object(inputs, 'fields') as fields, patch.object(inputs, 'committed_payload', return_value={
                'repository': 'https://github.com/example/platform.git', 'branch': 'main', 'revision': 'a' * 40}):
            self.assertNotIn('values', inputs.metadata())
            fields.assert_not_called()
        with patch.object(inputs, 'fields') as fields, patch.object(inputs, 'committed_payload', side_effect=RuntimeError('unpublished')):
            with self.assertRaisesRegex(RuntimeError, 'unpublished'):
                inputs.metadata()
            fields.assert_not_called()


class OptionalAuthorityTests(unittest.TestCase):
    def test_missing_broken_and_redirected_authority_before_bootstrap_or_binding(self):
        from playbooks.argocd.files.data_activation import binding_fence
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            base = Path(directory)
            with patch.object(control, 'BASE', base), patch.object(native, 'get', return_value=None) as read:
                self.assertEqual(handoff.probe(), 'initial')
                leaf = base / 'ownership.json'
                leaf.symlink_to(base / 'absent')
                read.reset_mock()
                for action in (handoff.probe, lambda: binding_fence(None)):
                    with self.assertRaisesRegex(RuntimeError, 'unsafe ownership'):
                        action()
                read.assert_not_called()
                leaf.unlink()
            redirected = base / 'redirected'; redirected.symlink_to(base, target_is_directory=True)
            with patch.object(control, 'BASE', redirected), self.assertRaisesRegex(RuntimeError, 'unsafe ownership'):
                handoff.state()
            unsafe = base / 'unsafe'; unsafe.mkdir(mode=0o777); unsafe.chmod(0o777)
            with patch.object(control, 'BASE', unsafe), self.assertRaisesRegex(RuntimeError, 'unsafe ownership'):
                handoff.state()
            with patch.object(control, 'BASE', base):
                (base / handoff.ROTATION).symlink_to(base / 'absent')
                with self.assertRaisesRegex(RuntimeError, 'unsafe ownership'):
                    handoff.rotation_reserve('f' * 32)


class RotationLocalFenceTests(unittest.TestCase):
    def documents(self):
        from playbooks.data.files.rotation import FIELDS
        return {title: {'id': title + '-id', 'title': title, 'category': 'SECURE_NOTE', 'tags': ['cloudlab-managed'],
                        'fields': [{'label': name, 'value': 'synthetic-old'} for name in names]}
                for title, names in FIELDS.items()}

    def test_reservation_rejection_precedes_any_vault_edit(self):
        from playbooks.data.files import rotation
        docs = self.documents()
        def command(args, *unused):
            if args[:2] == ['item', 'list']:
                return [{'id': value['id'], 'title': key} for key, value in docs.items()]
            if args[:2] == ['item', 'get']:
                return copy.deepcopy(next(value for value in docs.values() if value['id'] == args[2]))
            raise AssertionError('Vault writes are forbidden before reservation')
        environment = {'VM_HOST': 'example.invalid', 'VM_USER': 'synthetic', 'VM_PASSWORD': 'synthetic',
                       'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'synthetic-only'}
        with tempfile.TemporaryDirectory() as directory, patch('dotenv.dotenv_values', return_value=environment), \
                patch.object(rotation, 'Path', side_effect=lambda name: Path(directory) / Path(name).name), \
                patch('playbooks.secrets.files.provision.command', side_effect=command) as vault, \
                patch('playbooks.access.files.preflight.ssh', side_effect=RuntimeError('Prepared handoff blocks rotation')):
            with self.assertRaisesRegex(RuntimeError, 'handoff blocks'):
                rotation.local()
            self.assertFalse(any(call.args[0][:2] == ['item', 'edit'] for call in vault.call_args_list))

    def test_completed_attempt_retry_cleans_checkpoint_without_reediting(self):
        from playbooks.data.files import rotation
        docs = self.documents(); attempt = 'f' * 32
        checkpoint = {'attempt': attempt, 'documents': {name: {'old': value, 'new': value} for name, value in docs.items()}}
        environment = {'VM_HOST': 'example.invalid', 'VM_USER': 'synthetic', 'VM_PASSWORD': 'synthetic',
                       'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'synthetic-only'}
        with tempfile.TemporaryDirectory() as directory:
            pending = Path(directory) / 'data-rotation-pending.json'
            control.atomic(pending, checkpoint)
            with patch('dotenv.dotenv_values', return_value=environment), \
                    patch.object(rotation, 'Path', side_effect=lambda name: Path(directory) / Path(name).name), \
                    patch('playbooks.secrets.files.provision.command', return_value=[]) as vault, \
                    patch('playbooks.access.files.preflight.ssh', return_value=json.dumps({'attempt': attempt, 'completed': True})):
                self.assertTrue(rotation.local()['already_verified'])
                self.assertEqual(vault.call_count, 1)
                self.assertEqual(vault.call_args.args[0][:2], ['item', 'list'])
            self.assertFalse(pending.exists())
