"""Native access refuses changed identities and keeps the accepted Argo contract."""
import copy
import hashlib
import unittest

from playbooks.access.tests.fixtures import native_application


class NativeConfigurationTests(unittest.TestCase):
    def test_native_application_keeps_branch_namespace_administrator_and_uid(self):
        result, value = native_application()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value['metadata']['uid'], 'retained-access')
        self.assertEqual(value['spec']['source']['targetRevision'], 'main')
        self.assertEqual(value['spec']['source']['helm']['valuesObject'], {'administrator': 'admin@example.invalid'})
        self.assertEqual(value['spec']['destination']['namespace'], 'tailscale')
        self.assertFalse(value['spec']['syncPolicy']['automated']['prune'])

    def test_preparing_checkpoint_can_resume_before_initial_application_creation(self):
        state = {'phase': 'preparing', 'administrator': hashlib.sha256(b'admin@example.invalid').hexdigest()}
        result, value = native_application(current={}, state=state)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('uid', value['metadata'])

    def test_changed_administrator_missing_checkpoint_or_application_is_refused(self):
        baseline = {'phase': 'configured', 'administrator': hashlib.sha256(b'admin@example.invalid').hexdigest(),
                    'application_uid': 'retained-access'}
        for arguments in ({'receipt': False}, {'current': {}},
                {'state': dict(baseline, administrator='b' * 64)},
                {'state': dict(baseline, application_uid='replaced')},
                {'state': dict(baseline, phase='foreign')}):
            with self.subTest(arguments=arguments):
                result, value = native_application(**arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)

    def test_foreign_application_fields_fail_before_render_or_write(self):
        baseline = {'metadata': {'uid': 'retained-access', 'labels': {'cloudlab.io/owner': 'cloudlab-access-bootstrap'}},
            'spec': {'project': 'cloudlab-access', 'destination': {
                'server': 'https://kubernetes.default.svc', 'namespace': 'tailscale'},
                'source': {'repoURL': 'https://github.com/fixture/platform.git', 'path': 'platform/connectivity/access'}}}
        for change in ('owner', 'finalizer', 'parent', 'project', 'namespace', 'repository', 'path'):
            current = copy.deepcopy(baseline)
            if change == 'owner': current['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            elif change == 'finalizer': current['metadata']['finalizers'] = ['foreign']
            elif change == 'parent': current['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
            elif change == 'project': current['spec']['project'] = 'foreign'
            elif change == 'namespace': current['spec']['destination']['namespace'] = 'foreign'
            elif change == 'repository': current['spec']['source']['repoURL'] = 'https://github.com/fixture/foreign.git'
            else: current['spec']['source']['path'] = 'foreign'
            with self.subTest(change=change):
                result, value = native_application(current=current)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)
