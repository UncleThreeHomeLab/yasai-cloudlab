"""Native issuance keeps staging boundaries and refuses changed ownership."""
import copy
import hashlib
import unittest

from playbooks.certificates.tests.fixtures import native_application


class ConfigurationTests(unittest.TestCase):
    def test_native_application_retains_zone_branch_uid_and_non_destructive_policy(self):
        result, value = native_application()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value['metadata']['uid'], 'retained-application')
        self.assertEqual(value['spec']['source']['targetRevision'], 'main')
        self.assertEqual(value['spec']['source']['helm']['valuesObject'], {'zone': 'example.invalid', 'production': True})
        self.assertFalse(value['spec']['syncPolicy']['automated']['prune'])
        self.assertFalse(any('Force' in option or 'Replace' in option for option in value['spec']['syncPolicy']['syncOptions']))

    def test_initial_staging_never_enables_production(self):
        state = {'phase': 'staging', 'zone_hash': hashlib.sha256(b'example.invalid').hexdigest()}
        result, value = native_application(state=state, current={}, receipt=False, production=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(value['spec']['source']['helm']['valuesObject']['production'])
        self.assertNotIn('uid', value['metadata'])

    def test_zone_checkpoint_replacement_and_missing_staging_refuse_before_render(self):
        baseline = {'phase': 'accepted', 'zone_hash': hashlib.sha256(b'example.invalid').hexdigest(),
            'application_uid': 'retained-application',
            'staging': {'certificate_uid': 'retained-staging', 'secret_uid': 'retained-staging-secret'}}
        for values in ({'receipt': False}, {'current': {}},
                {'state': dict(baseline, zone_hash='foreign')},
                {'state': dict(baseline, application_uid='replaced')},
                {'state': dict(baseline, phase='foreign')},
                {'state': {key: value for key, value in baseline.items() if key != 'staging'}}):
            with self.subTest(values=values):
                result, value = native_application(**values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)

    def test_foreign_owner_finalizer_parent_and_scope_refuse_before_render(self):
        baseline = {'metadata': {'uid': 'retained-application', 'labels': {'cloudlab.io/owner': 'cloudlab-certificates-bootstrap'}},
            'spec': {'project': 'cloudlab-certificates', 'destination': {
                'server': 'https://kubernetes.default.svc', 'namespace': 'cert-manager'},
                'source': {'repoURL': 'https://github.com/fixture/platform.git', 'path': 'platform/certificates/configuration'}}}
        for field in ('owner', 'finalizer', 'parent', 'project', 'namespace', 'repository', 'path'):
            current = copy.deepcopy(baseline)
            if field == 'owner': current['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            elif field == 'finalizer': current['metadata']['finalizers'] = ['foreign']
            elif field == 'parent': current['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
            elif field == 'project': current['spec']['project'] = 'foreign'
            elif field == 'namespace': current['spec']['destination']['namespace'] = 'foreign'
            elif field == 'repository': current['spec']['source']['repoURL'] = 'https://github.com/fixture/foreign.git'
            else: current['spec']['source']['path'] = 'foreign'
            with self.subTest(field=field):
                result, value = native_application(current=current)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)
