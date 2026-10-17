import copy
import json
import unittest
from unittest.mock import Mock, patch

import bootstrap
from playbooks.argocd.files.sync_recovery import recovered_secret_sync


class SecretRecoveryTests(unittest.TestCase):
    revision = 'a' * 40

    def fixture(self, identity=False):
        namespace = 'cloudlab-identity' if identity else 'argocd'
        source = {'repoURL': 'https://example.invalid/lab.git', 'targetRevision': 'main',
                  'path': 'platform/identity/keycloak' if identity else 'gitops/roots/public'}
        app = {'metadata': {'name': 'cloudlab-identity' if identity else 'cloudlab-public-root',
                           'namespace': 'argocd', 'uid': 'retained', 'resourceVersion': '7'},
               'spec': {'project': 'cloudlab-identity' if identity else 'cloudlab-root',
                        'source': source, 'destination': {'server': 'https://kubernetes.default.svc', 'namespace': namespace}},
               'status': {'sync': {'revision': self.revision, 'comparedTo': {'source': copy.deepcopy(source)}},
                          'operationState': {'phase': 'Failed', 'finishedAt': '2026-10-15T12:00:00Z',
                                             'syncResult': {'source': copy.deepcopy(source), 'resources': [
                                                 {'group': 'external-secrets.io', 'kind': 'ExternalSecret',
                                                  'namespace': namespace, 'name': 'credential', 'hookPhase': 'Failed'}]}}}}
        secret = {'metadata': {'generation': 3}, 'status': {'conditions': [
            {'type': 'Ready', 'status': 'True', 'observedGeneration': 3,
             'lastTransitionTime': '2026-10-15T19:00:00Z'}]}}
        return app, secret

    def test_retry_preserves_source_and_requests_unpruned_sync_with_identity_guards(self):
        for identity in (False, True):
            app, secret = self.fixture(identity)
            before = copy.deepcopy(app)
            reader = Mock(return_value=secret)
            result = recovered_secret_sync(app, self.revision, reader)
            self.assertEqual(app, before)
            self.assertEqual(result[:2], [
                {'op': 'test', 'path': '/metadata/uid', 'value': 'retained'},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'}])
            self.assertEqual(result[2]['path'], '/operation')
            self.assertEqual(result[2]['value']['sync'], {
                'revision': self.revision, 'prune': False, 'syncStrategy': {'hook': {}}})
            reader.assert_called_once_with('credential', app['spec']['destination']['namespace'])

    def test_refuses_unrelated_busy_changed_or_unresolved_failures(self):
        for scenario in ('unknown', 'project', 'path', 'namespace', 'busy', 'deleted', 'revision',
                         'compared', 'failed_source', 'success', 'missing_failure', 'job_failure',
                         'cross_namespace', 'error_condition', 'unready', 'stale', 'stale_generation',
                         'malformed_time', 'missing_secret', 'second_failure'):
            with self.subTest(scenario=scenario):
                app, secret = self.fixture()
                operation = app['status']['operationState']
                failed = operation['syncResult']['resources'][0]
                ready = secret['status']['conditions'][0]
                if scenario == 'unknown': app['metadata']['name'] = 'other'
                elif scenario == 'project': app['spec']['project'] = 'other'
                elif scenario == 'path': app['spec']['source']['path'] = 'other'
                elif scenario == 'namespace': app['metadata']['namespace'] = 'other'
                elif scenario == 'busy': app['operation'] = {'sync': {}}
                elif scenario == 'deleted': app['metadata']['deletionTimestamp'] = 'pending'
                elif scenario == 'revision': app['status']['sync']['revision'] = 'b' * 40
                elif scenario == 'compared': app['status']['sync']['comparedTo']['source'] = {}
                elif scenario == 'failed_source': operation['syncResult']['source'] = {}
                elif scenario == 'success': operation['phase'] = 'Succeeded'
                elif scenario == 'missing_failure': failed['hookPhase'] = 'Succeeded'
                elif scenario == 'job_failure': failed.update(group='batch', kind='Job')
                elif scenario == 'cross_namespace': failed['namespace'] = 'other'
                elif scenario == 'error_condition': app['status']['conditions'] = [{'type': 'ComparisonError'}]
                elif scenario == 'unready': ready['status'] = 'False'
                elif scenario == 'stale': ready['lastTransitionTime'] = operation['finishedAt']
                elif scenario == 'stale_generation': ready['observedGeneration'] = 2
                elif scenario == 'malformed_time': ready['lastTransitionTime'] = 'unknown'
                elif scenario == 'missing_secret': secret = None
                elif scenario == 'second_failure': operation['finishedAt'] = '2026-10-15T20:00:00Z'
                self.assertEqual(recovered_secret_sync(app, self.revision, Mock(return_value=secret)), [])

    def test_historical_sync_error_does_not_hide_recovered_secret_evidence(self):
        app, secret = self.fixture()
        app['status']['conditions'] = [{'type': 'SyncError'}]
        self.assertTrue(recovered_secret_sync(app, self.revision, Mock(return_value=secret)))

    def test_root_wait_requests_retry_then_waits_for_real_success(self):
        app, secret = self.fixture()
        success = copy.deepcopy(app)
        success['status']['sync']['status'] = 'Synced'
        success['status']['health'] = {'status': 'Healthy'}
        success['status']['operationState']['phase'] = 'Succeeded'
        with patch.object(bootstrap, 'get', side_effect=[app, secret, success]), \
                patch.object(bootstrap, 'kube') as write, patch.object(bootstrap.time, 'sleep'):
            self.assertEqual(bootstrap.wait_application('cloudlab-public-root', self.revision), self.revision)
        self.assertEqual(write.call_args.args[:3], ('patch', 'application.argoproj.io', 'cloudlab-public-root'))
        self.assertEqual(json.loads(write.call_args.args[-1])[-1]['path'], '/operation')
