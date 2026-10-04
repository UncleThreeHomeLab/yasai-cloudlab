"""Backup ownership must not expose credentials or revive a released writer."""
import json
import copy
import subprocess
import yaml
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import backup_gitops as backup
from backup_chart import REPOSITORY, payload, render
from backup_parity import verify


class BackupChartTests(unittest.TestCase):
    def test_existing_declarations_and_secret_only_bootstrap_have_parity(self):
        verify()

    def test_private_inputs_are_values_not_credentials_or_new_sources(self):
        data = payload({'store': 'cloudlab', 'bucket': 'synthetic-private-bucket', 'region': 'fixture-region'})
        self.assertEqual(data['app']['spec']['source']['path'], 'platform/storage/longhorn-backup')
        self.assertEqual(data['app']['spec']['source']['helm']['valuesObject']['destination']['bucket'], 'synthetic-private-bucket')
        self.assertNotIn('Secret', [obj['kind'] for obj in data['items']])
        self.assertNotIn('finalizers', data['app']['metadata'])
        self.assertFalse(data['app']['spec']['syncPolicy']['automated']['prune'])

    def test_destination_cannot_inject_another_url_or_template(self):
        for bucket in ('bucket@elsewhere', 'bucket/path', '{{ template }}', 'bucket\nother'):
            with self.subTest(bucket=bucket), self.assertRaisesRegex(ValueError, 'destination'):
                render({'store': 'cloudlab', 'bucket': bucket, 'region': 'fixture'})

    def test_project_allows_only_backup_declarations_in_storage_namespace(self):
        raw = subprocess.check_output(['helm', 'template', 'cloudlab-public-root',
            str(REPOSITORY / 'gitops/roots/public'), '--set', 'longhornBackup.enabled=true'], text=True)
        project = next(obj for obj in yaml.safe_load_all(raw) if obj and obj['kind'] == 'AppProject'
                       and obj['metadata']['name'] == 'cloudlab-longhorn-backup')
        self.assertEqual(project['spec']['clusterResourceWhitelist'], [])
        self.assertEqual(project['spec']['destinations'], [
            {'server': 'https://kubernetes.default.svc', 'namespace': 'longhorn-system'}])
        self.assertEqual({x['kind'] for x in project['spec']['namespaceResourceWhitelist']},
                         {'ExternalSecret', 'BackupTarget', 'RecurringJob'})
        self.assertFalse(any('*' in source for source in project['spec']['sourceRepos']))


class BackupOwnershipTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        patched = patch.object(backup, 'BASE', self.base)
        patched.start()
        self.addCleanup(patched.stop)
        self.payload = {'items': [], 'inventory': [], 'app': {}, 'enabled': True,
                        'secret': 'fixture', 'revision': 'reviewed'}

    def state(self, phase):
        backup.record({'phase': phase, 'owner': 'argocd', 'identities': {},
                       'digest': backup.hashlib.sha256(b'[]').hexdigest(), 'credential': {}})

    def test_released_bootstrap_never_rewrites_resources_or_secrets(self):
        for phase in ('released', 'accepted'):
            self.state(phase)
            with patch.object(backup, 'apply') as apply, patch.object(backup, 'get') as read:
                self.assertFalse(backup.run(self.payload, 'credential-seed')['changed'])
                self.assertFalse(backup.run(self.payload, 'seed')['changed'])
                apply.assert_not_called()
                read.assert_not_called()

    def test_unfinished_operator_blocks_the_next_ownership_transition(self):
        (self.base / 'ownership.json').write_text(json.dumps({'phase': 'released'}))
        with patch.object(backup, 'get', return_value={'kind': 'Application'}), patch.object(backup, 'apply') as apply:
            with self.assertRaisesRegex(RuntimeError, 'Accept the storage operator'):
                backup.run(self.payload, 'credential-seed')
            apply.assert_not_called()
        self.assertFalse((self.base / backup.CHECKPOINT).exists())

    def test_foreign_application_or_cascading_deletion_is_rejected(self):
        self.state('released')
        operator = {'status': {'sync': {'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
        for current in ({'metadata': {'labels': {'cloudlab.io/owner': 'foreign'}}},
                        {'metadata': {'labels': {'cloudlab.io/owner': backup.OWNER}, 'finalizers': ['cascade']}}):
            with self.subTest(current=current), patch.object(backup, 'get', side_effect=[operator, current]), patch.object(backup, 'kube') as mutate:
                with self.assertRaisesRegex(RuntimeError, 'another owner or deletion policy'):
                    backup.run(self.payload, 'configure')
                mutate.assert_not_called()

    def test_recovery_rejects_a_running_writer(self):
        self.state('accepted')
        self.payload['app'] = {'spec': {'syncPolicy': {'automated': {'enabled': False}}}}
        with patch.object(backup, 'get', return_value={'spec': {'syncPolicy': {'automated': {'enabled': True}}}}), patch.object(backup, 'apply') as apply:
            with self.assertRaisesRegex(RuntimeError, 'Suspend the backup Argo writer'):
                backup.run(self.payload, 'recover')
            apply.assert_not_called()

    def test_interruption_resumes_without_reapplying_and_preserves_identity(self):
        self.payload = payload({'store': 'cloudlab', 'bucket': 'fixture-bucket', 'region': 'fixture-region'})
        self.payload['enabled'] = True
        self.payload['revision'] = 'reviewed'
        (self.base / 'ownership.json').write_text(json.dumps({'phase': 'accepted'}))
        objects = {obj['kind']: copy.deepcopy(obj) for obj in self.payload['items']}
        for kind, obj in objects.items():
            obj['metadata'].update(uid=kind + '-uid', managedFields=[{'manager': 'cloudlab'}])
        operator = {'metadata': {'name': 'cloudlab-longhorn'},
                    'status': {'sync': {'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
        def get(obj):
            if obj.get('metadata', {}).get('name') == 'cloudlab-longhorn':
                return operator
            return objects.get(obj['kind'])
        def kube(*args, objects=None):
            if args[0] == 'apply':
                for obj in objects:
                    live = copy.deepcopy(obj)
                    live['metadata']['uid'] = obj['kind'] + '-uid'
                    live['status'] = {'sync': {'status': 'Synced', 'revision': 'reviewed'},
                                      'health': {'status': 'Healthy'}}
                    state_objects[obj['kind']] = live
        state_objects = objects
        identities = {obj['kind']: obj['metadata']['uid'] for obj in objects.values()}
        credential = {'uid': 'secret-uid', 'content': 'unchanged'}
        seed_payload = dict(self.payload, items=[objects['ExternalSecret']])
        with patch.object(backup, 'get', side_effect=get), \
                patch.object(backup, 'identities', return_value=identities), \
                patch.object(backup, 'secret_receipt', return_value=credential), \
                patch.object(backup, 'apply') as apply, patch.object(backup, 'kube', side_effect=kube):
            self.assertEqual(backup.run(seed_payload, 'credential-seed')['phase'], 'preparing')
            self.assertEqual(backup.run(self.payload, 'seed-stop')['phase'], 'seeded')
            apply.reset_mock()
            self.assertFalse(backup.run(seed_payload, 'credential-seed')['changed'])
            self.assertEqual(backup.run(self.payload, 'seed')['phase'], 'released')
            apply.assert_not_called()
            self.assertTrue(backup.run(self.payload, 'configure')['changed'])
            for obj in self.payload['items']:
                objects[obj['kind']]['metadata']['annotations'] = {
                    'argocd.argoproj.io/tracking-id': 'cloudlab-longhorn-backup:fixture'}
            self.assertEqual(backup.run(self.payload, 'accept')['phase'], 'accepted')
            self.assertFalse(backup.run(self.payload, 'accept')['changed'])

    def test_interruption_after_release_is_forbidden(self):
        self.state('released')
        with self.assertRaisesRegex(RuntimeError, 'precede writer release'):
            backup.run(self.payload, 'seed-stop')

    def test_changed_credential_blocks_release_after_interruption(self):
        self.state('seeded')
        with patch.object(backup, 'get', return_value=None), \
                patch.object(backup, 'identities', return_value={}), \
                patch.object(backup, 'secret_receipt', return_value={'uid': 'replacement'}), \
                patch.object(backup, 'apply') as apply:
            with self.assertRaisesRegex(RuntimeError, 'credential changed'):
                backup.run(self.payload, 'seed')
            apply.assert_not_called()

    def test_active_operation_blocks_recovery_even_with_automation_disabled(self):
        self.state('accepted')
        self.payload['app'] = {'spec': {'syncPolicy': {'automated': {'enabled': False}}}}
        current = dict(self.payload['app'], operation={'sync': {}})
        with patch.object(backup, 'get', return_value=current), patch.object(backup, 'apply') as apply:
            with self.assertRaises(backup.PendingConvergence):
                backup.run(self.payload, 'recover')
            apply.assert_not_called()
