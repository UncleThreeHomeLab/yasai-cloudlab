"""Ensure review normalization cannot hide changes to immutable fields or images."""

import copy
import unittest

from chart_parity import container_images, differences, index, normalize, semantic_digest


class ParityTests(unittest.TestCase):
    def setUp(self):
        self.resource = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
                         'metadata': {'name': 'longhorn-ui', 'namespace': 'longhorn-system',
                                      'labels': {'app': 'longhorn-ui'}},
                         'spec': {'selector': {'matchLabels': {'app': 'longhorn-ui'}},
                                  'template': {'metadata': {'labels': {'app': 'longhorn-ui'}},
                                               'spec': {'containers': [{'image': 'locked'}]}}}}

    def test_packaging_labels_only_are_ignored(self):
        changed = copy.deepcopy(self.resource)
        changed['metadata']['labels']['helm.sh/chart'] = 'longhorn-1.13.0'
        self.assertEqual(normalize(self.resource, 'longhorn'), normalize(changed, 'longhorn'))
        changed['spec']['selector']['matchLabels']['helm.sh/chart'] = 'longhorn-1.13.0'
        self.assertTrue(differences(normalize(self.resource, 'longhorn'), normalize(changed, 'longhorn')))

    def test_image_and_service_account_drift_are_not_hidden(self):
        for field, value in [('containers', [{'image': 'mutable:latest'}]), ('serviceAccountName', 'other')]:
            changed = copy.deepcopy(self.resource)
            changed['spec']['template']['spec'][field] = value
            self.assertTrue(differences(normalize(self.resource, 'longhorn'), normalize(changed, 'longhorn')))

    def test_unknown_label_value_and_duplicate_identity_fail(self):
        self.resource['metadata']['labels']['helm.sh/chart'] = 'longhorn-next'
        with self.assertRaises(ValueError):
            normalize(self.resource, 'longhorn')
        with self.assertRaises(ValueError):
            index([self.resource, self.resource])

    def test_storage_policy_change_survives_yaml_normalization(self):
        base = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'longhorn-default-setting'},
                'data': {'default-setting.yaml': 'v1-data-engine: "true"\n'}}
        changed = copy.deepcopy(base)
        changed['data']['default-setting.yaml'] = 'v1-data-engine: false\n'
        self.assertNotEqual(normalize(base, 'longhorn'), normalize(changed, 'longhorn'))

    def test_only_reviewed_eso_crd_sync_options_are_normalized(self):
        baseline = {'apiVersion': 'apiextensions.k8s.io/v1', 'kind': 'CustomResourceDefinition',
                    'metadata': {'name': 'fixture.example.com', 'annotations': {'controller-gen': 'fixture'}},
                    'spec': {'scope': 'Namespaced'}}
        candidate = copy.deepcopy(baseline)
        candidate['metadata']['annotations']['argocd.argoproj.io/sync-options'] = 'ServerSideApply=true,Prune=false,Delete=false'
        self.assertEqual(normalize(baseline, 'external_secrets'), normalize(candidate, 'external_secrets'))
        candidate['spec']['scope'] = 'Cluster'
        self.assertNotEqual(normalize(baseline, 'external_secrets'), normalize(candidate, 'external_secrets'))
        candidate['metadata']['annotations']['argocd.argoproj.io/sync-options'] = 'Replace=true'
        with self.assertRaises(ValueError):
            normalize(candidate, 'external_secrets')

    def test_image_scan_includes_init_containers_and_other_registries(self):
        self.resource['spec']['template']['spec']['initContainers'] = [{'image': 'other.example/tool:latest'}]
        self.assertEqual(set(container_images([self.resource])), {'locked', 'other.example/tool:latest'})

    def test_review_contract_detects_spec_and_identity_changes(self):
        baseline = semantic_digest([self.resource], 'longhorn')
        changed = copy.deepcopy(self.resource)
        changed['spec']['selector']['matchLabels']['app'] = 'different'
        self.assertNotEqual(semantic_digest([changed], 'longhorn'), baseline)
        changed = copy.deepcopy(self.resource)
        changed['metadata']['name'] = 'different'
        self.assertNotEqual(semantic_digest([changed], 'longhorn'), baseline)


if __name__ == '__main__':
    unittest.main()
