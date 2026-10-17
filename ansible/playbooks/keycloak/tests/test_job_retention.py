import copy
from datetime import datetime, timezone
import unittest

from playbooks.keycloak.files.bootstrap import completed_job_retention


class JobRetentionTests(unittest.TestCase):
    def test_rendered_identity_jobs_have_bounded_completion_retention(self):
        from playbooks.keycloak.files.chart import render
        objects = render({'enabled': True, 'operatorEnabled': False, 'reconciliationEnabled': True,
                          'privateStateEnabled': True, 'trustedProxyAddresses': ['10.43.0.1/32'], 'databaseCA': 'fixture-ca'})
        jobs = [obj['spec']['jobTemplate'] if obj['kind'] == 'CronJob' else obj
                for obj in objects if obj['kind'] in ('Job', 'CronJob')]
        self.assertTrue(jobs)
        self.assertTrue(all(job['spec']['ttlSecondsAfterFinished'] == 3600 for job in jobs))

    def fixture(self):
        timestamp = lambda value: datetime.fromtimestamp(value, timezone.utc).isoformat()
        crons = {name: {'metadata': {'uid': name + '-uid'}, 'status': {'lastSuccessfulTime': timestamp(9900)},
                        'spec': {'jobTemplate': {'spec': {'ttlSecondsAfterFinished': 3600}}}}
                 for name in ('identity-health', 'identity-reconcile')}
        job = {'metadata': {'name': 'identity-health-123', 'namespace': 'cloudlab-identity', 'uid': 'retained-job',
                            'resourceVersion': '7', 'ownerReferences': [{'apiVersion': 'batch/v1', 'kind': 'CronJob',
                            'name': 'identity-health', 'uid': 'identity-health-uid', 'controller': True}]},
               'spec': {'template': {'spec': {'serviceAccountName': 'identity-health'}}},
               'status': {'conditions': [{'type': 'Failed', 'status': 'True', 'lastTransitionTime': timestamp(1000)}]}}
        return job, crons

    def test_old_owned_failures_receive_only_guarded_retention_after_recovery(self):
        job, crons = self.fixture()
        before = copy.deepcopy(job)
        patches = completed_job_retention(job, crons, True, 10000)
        self.assertEqual(job, before)
        self.assertEqual(patches, [
            {'op': 'test', 'path': '/metadata/uid', 'value': 'retained-job'},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'},
            {'op': 'add', 'path': '/spec/ttlSecondsAfterFinished', 'value': 3600}])
        job['spec']['ttlSecondsAfterFinished'] = 3600
        self.assertEqual(completed_job_retention(job, crons, True, 10000), [])

    def test_active_foreign_recent_failure_or_unhealthy_owner_history_is_preserved(self):
        for scenario in ('active', 'foreign_uid', 'foreign_namespace', 'unfinished', 'deleted', 'already_bounded',
                         'latest_failure', 'stale_health', 'missing_reconcile', 'malformed_time'):
            with self.subTest(scenario=scenario):
                job, crons = self.fixture()
                if scenario == 'active': job['status']['active'] = 1
                elif scenario == 'foreign_uid': job['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                elif scenario == 'foreign_namespace': job['metadata']['namespace'] = 'other'
                elif scenario == 'unfinished': job['status']['conditions'] = []
                elif scenario == 'deleted': job['metadata']['deletionTimestamp'] = 'pending'
                elif scenario == 'already_bounded': job['spec']['ttlSecondsAfterFinished'] = 120
                elif scenario == 'latest_failure': job['status']['conditions'][0]['lastTransitionTime'] = datetime.fromtimestamp(9950, timezone.utc).isoformat()
                elif scenario == 'stale_health': crons['identity-health']['status']['lastSuccessfulTime'] = datetime.fromtimestamp(8000, timezone.utc).isoformat()
                elif scenario == 'missing_reconcile': crons['identity-reconcile'] = {}
                elif scenario == 'malformed_time': job['status']['conditions'][0]['lastTransitionTime'] = 'invalid'
                self.assertEqual(completed_job_retention(job, crons, True, 10000), [])

    def test_retirement_hook_requires_accepted_retirement_and_exact_tracking(self):
        job, crons = self.fixture()
        job['metadata'].update(name='identity-bootstrap-retirement', ownerReferences=[], annotations={
            'argocd.argoproj.io/tracking-id': 'cloudlab-identity:batch/Job:cloudlab-identity/identity-bootstrap-retirement'})
        job['spec']['template']['spec']['serviceAccountName'] = 'identity-writer'
        self.assertTrue(completed_job_retention(job, crons, True, 10000))
        self.assertEqual(completed_job_retention(job, crons, False, 10000), [])
        job['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
        self.assertEqual(completed_job_retention(job, crons, True, 10000), [])

    def test_invalid_declared_retention_fails_without_patching_jobs(self):
        job, crons = self.fixture()
        for ttl in (0, -1, 86401, '3600', True):
            crons['identity-health']['spec']['jobTemplate']['spec']['ttlSecondsAfterFinished'] = ttl
            with self.assertRaises(RuntimeError): completed_job_retention(job, crons, True, 10000)
