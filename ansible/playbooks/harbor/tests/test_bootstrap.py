"""Native Harbor declarations preserve ownership, chart semantics and recovery exclusion."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from playbooks.harbor.files import recovery
from playbooks.harbor.files.chart import render
from playbooks.harbor.tests.fixtures import native_application


class BootstrapTests(unittest.TestCase):
    def test_native_server_keeps_identity_and_only_overrides_private_runtime_fields(self):
        result, value = native_application()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value['metadata']['uid'], 'retained-application')
        self.assertFalse(value['spec']['syncPolicy']['automated']['prune'])
        self.assertEqual(value['spec']['destination']['namespace'], 'cloudlab-harbor')
        helm = value['spec']['source']['helm']
        self.assertEqual(helm['valueFiles'], ['values.json'])
        self.assertEqual(set(helm['valuesObject']['harbor']), {'externalURL', 'core'})
        full = json.loads((recovery.ARTIFACTS / 'server/values.json').read_text())
        full['harbor']['externalURL'] = helm['valuesObject']['harbor']['externalURL']
        full['harbor']['core']['hostAliases'] = helm['valuesObject']['harbor']['core']['hostAliases']
        self.assertEqual(render('server', full), render('server', helm['valuesObject']))

    def test_native_configuration_keeps_only_the_private_origin_and_gateway_contract(self):
        result, value = native_application(configuration=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value['metadata']['name'], 'cloudlab-harbor-configuration')
        self.assertEqual(value['spec']['source']['path'], 'platform/harbor')
        self.assertNotIn('valueFiles', value['spec']['source']['helm'])
        self.assertEqual(value['spec']['source']['helm']['valuesObject'], {'enabled': True,
            'harborHost': 'harbor.internal.example.invalid', 'loginHost': 'login.example.invalid',
            'gatewayIP': '10.43.0.100'})

    def test_foreign_application_and_scope_are_never_adopted(self):
        current = {'metadata': {'uid': 'retained', 'labels': {'cloudlab.io/owner': 'harbor-platform'}},
            'spec': {'project': 'cloudlab-harbor', 'destination': {
                'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-harbor'},
                'source': {'repoURL': 'https://github.com/fixture/platform.git', 'path': 'platform/harbor/server'}}}
        for mutation in ('owner', 'finalizer', 'parent', 'project', 'namespace', 'repository', 'path'):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(current)
                if mutation == 'owner': changed['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
                elif mutation == 'finalizer': changed['metadata']['finalizers'] = ['foreign']
                elif mutation == 'parent': changed['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                elif mutation == 'project': changed['spec']['project'] = 'foreign'
                elif mutation == 'namespace': changed['spec']['destination']['namespace'] = 'foreign'
                elif mutation == 'repository': changed['spec']['source']['repoURL'] = 'https://github.com/fixture/foreign.git'
                else: changed['spec']['source']['path'] = 'foreign'
                result, value = native_application(current=changed)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)

    @unittest.skipUnless(Path('/.dockerenv').exists(), 'Shared lock fixture must run inside Compose')
    def test_native_flock_and_retained_recovery_use_the_same_exclusion(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(recovery, 'BASE', Path(folder)):
            marker = Path(folder) / 'native-operation'
            command = ['flock', '--nonblock', '/run/lock/cloudlab-harbor.lock', 'touch', str(marker)]
            with recovery.locked():
                self.assertNotEqual(subprocess.run(command).returncode, 0)
                self.assertFalse(marker.exists())
            self.assertEqual(subprocess.run(command).returncode, 0)
            self.assertTrue(marker.exists())
