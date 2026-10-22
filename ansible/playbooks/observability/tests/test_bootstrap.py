"""Native telemetry declarations retain field ownership and dependency boundaries."""
import copy
import unittest

from playbooks.observability.tests.fixtures import native_application


class BootstrapTests(unittest.TestCase):
    def test_initial_configuration_keeps_monitors_disabled_until_apis_exist(self):
        result, value = native_application(monitoring=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value['metadata']['uid'], 'retained-application')
        helm = value['spec']['source']['helm']
        self.assertNotIn('valueFiles', helm)
        self.assertFalse(helm['valuesObject']['monitoringEnabled'])
        self.assertEqual(helm['valuesObject']['apiPeers'], ['192.0.2.1/32', '192.0.2.2/32'])
        self.assertFalse(value['spec']['syncPolicy']['automated']['prune'])

    def test_static_backend_values_come_directly_from_git(self):
        result, value = native_application('loki')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value['spec']['source']['helm'], {'releaseName': 'cloudlab-loki', 'valueFiles': ['values.json']})

    def test_foreign_application_or_scope_cannot_be_adopted(self):
        current = {'metadata': {'uid': 'retained', 'labels': {'cloudlab.io/owner': 'observability-platform'}},
            'spec': {'project': 'cloudlab-observability', 'destination': {
                'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-observability'},
                'source': {'repoURL': 'https://github.com/fixture/platform.git', 'path': 'platform/observability/loki'}}}
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
                result, value = native_application('loki', current=changed)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)
