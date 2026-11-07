import types
import unittest
from unittest.mock import patch

from playbooks.admission.files import verify

IMAGE = 'harbor.example.test/app/notes@sha256:' + '1' * 64


def deployment(name, image=IMAGE, account='notes-api'):
    return {'metadata': {'name': name},
            'spec': {'template': {'spec': {'serviceAccountName': account,
                                           'containers': [{'name': 'app', 'image': image}]}}}}


class WorkloadSourceTests(unittest.TestCase):
    def test_first_sorted_deployment_supplies_image_and_account(self):
        with patch.object(verify, 'get', return_value={'items': [
                deployment('b-second'), deployment('a-first', IMAGE, 'first-sa')]}):
            self.assertEqual(verify.workload_source('cloudlab-app-notes'), (IMAGE, 'first-sa'))

    def test_namespace_without_deployments_reports_no_source(self):
        with patch.object(verify, 'get', return_value={'items': []}):
            self.assertIsNone(verify.workload_source('cloudlab-app-notes'))

    def test_unpinned_or_default_source_fails_closed(self):
        cases = [{'items': [deployment('a', 'harbor.example.test/app/notes:latest')]},
                 {'items': [deployment('a', IMAGE, 'default')]},
                 {'items': [deployment('a', IMAGE, '')]}]
        for payload in cases:
            with self.subTest(payload=payload):
                with patch.object(verify, 'get', return_value=payload):
                    with self.assertRaises(RuntimeError):
                        verify.workload_source('cloudlab-app-notes')

    def test_probe_carries_mirrored_image_and_account(self):
        document = verify.probe('cloudlab-app-notes', IMAGE, 'notes-api')
        self.assertEqual(document['spec']['serviceAccountName'], 'notes-api')
        self.assertEqual(document['spec']['containers'][0]['image'], IMAGE)

    def test_admission_mutable_control_strips_the_mirrored_digest(self):
        seen = []

        def fake_run(document):
            seen.append(document)
            return types.SimpleNamespace(returncode=0, stderr='')
        with patch.object(verify, 'dry_run', side_effect=fake_run):
            with self.assertRaises(RuntimeError):
                verify.admission('cloudlab-app-notes', True, IMAGE, 'notes-api')
        self.assertEqual(seen[0]['spec']['containers'][0]['image'], IMAGE)
        self.assertEqual(seen[1]['spec']['containers'][0]['image'], IMAGE.split('@')[0])

    def test_composition_label_must_carry_the_approved_value(self):
        base = {'cloudlab.io/owner': 'service-platform', 'istio.io/dataplane-mode': 'ambient',
                'cloudlab.io/service-secrets': 'approved', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
                'pod-security.kubernetes.io/enforce': 'privileged', 'pod-security.kubernetes.io/audit': 'restricted',
                'pod-security.kubernetes.io/warn': 'restricted'}
        row = {'metadata': {'name': 'cloudlab-app-taskopotamus',
                            'labels': dict(base, **{'cloudlab.io/composition': 'approved'})}}
        self.assertTrue(verify.namespace_profile(row))
        row['metadata']['labels']['cloudlab.io/composition'] = 'evil'
        with self.assertRaises(RuntimeError):
            verify.namespace_profile(row)

    def test_namespaces_fence_composition_and_skip_empty_shells(self):
        def row(name, labels):
            return {'metadata': {'name': name, 'labels': labels}}
        ordinary = {'cloudlab.io/owner': 'service-platform', 'istio.io/dataplane-mode': 'ambient',
                    'cloudlab.io/service-secrets': 'approved', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
                    'pod-security.kubernetes.io/enforce': 'restricted'}
        composition = dict(ordinary, **{'cloudlab.io/composition': 'approved',
                                        'pod-security.kubernetes.io/enforce': 'privileged',
                                        'pod-security.kubernetes.io/audit': 'restricted',
                                        'pod-security.kubernetes.io/warn': 'restricted'})
        workloads = [row('cloudlab-app-taskopotamus', composition),
                     row('cloudlab-app-notes', ordinary),
                     row('cloudlab-app-fixture', ordinary)]
        sources = {'cloudlab-app-notes': (IMAGE, 'notes-api')}
        with patch.object(verify, 'namespace_admission') as fenced, \
                patch.object(verify, 'workload_source', side_effect=lambda ns: sources.get(ns)) as sourced, \
                patch.object(verify, 'admission') as admitted, \
                patch.object(verify, 'ephemeral_admission', return_value=True):
            self.assertEqual(verify.namespaces(workloads, True, []), (1, 1, 1))
        self.assertEqual(fenced.call_count, 3)
        self.assertEqual(sorted(call.args[0] for call in sourced.call_args_list),
                         ['cloudlab-app-fixture', 'cloudlab-app-notes'])
        admitted.assert_called_once_with('cloudlab-app-notes', True, IMAGE, 'notes-api')

    def test_ephemeral_container_mirrors_the_live_target_image(self):
        target = {'metadata': {'name': 'live', 'labels': {}},
                  'spec': {'serviceAccountName': 'notes-api',
                           'containers': [{'name': 'app', 'image': IMAGE,
                                           'livenessProbe': {'exec': {'command': ['true']}},
                                           'resources': {'requests': {'cpu': '1'}}}]}}
        seen = []

        def fake_kube(*args, document=None, allow_failure=False):
            container = document['spec']['ephemeralContainers'][0]
            seen.append((container['image'], 'resources' in container,
                         'livenessProbe' in container))
            if len(seen) == 1:
                return types.SimpleNamespace(returncode=0, stderr='')
            return types.SimpleNamespace(
                returncode=1, stderr='Workload images must use an immutable SHA-256 digest.')
        with patch.object(verify, 'get', return_value={'items': [target]}), \
                patch.object(verify, 'condition', return_value=True), \
                patch.object(verify, 'kube', side_effect=fake_kube):
            self.assertTrue(verify.ephemeral_admission('cloudlab-app-notes', True))
        self.assertEqual(seen[0], (IMAGE, False, False))
        self.assertEqual(seen[1][0], IMAGE.split('@')[0])


if __name__ == '__main__':
    unittest.main()
