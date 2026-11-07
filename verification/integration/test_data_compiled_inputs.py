"""Compiled data inputs survive the chart-to-reconciler round trip.

Renders platform/data/configuration with representative merged values, feeds
the rendered desired-state ConfigMap through reconcile.load_desired, and
checks the grants SQL, bucket manifest, and workload guards for the
synthetic prices service alongside the platform database.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'platform/data/configuration/runtime'))

import reconcile

POSTGRES_IMAGE = ('ghcr.io/cloudnative-pg/postgresql:18.4-standard-trixie@sha256:'
                  'ebf3919504d7523a63e8e2fee9b051211de714644b36469275558c624afd50ec')
PYTHON_IMAGE = ('python:3.13-slim-bookworm@sha256:'
                '5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed')


def merged_values():
    return {
        'sharedInputs': True,
        'zone': 'example.test',
        'production': False,
        's3Host': 's3.internal.example.test',
        'database': 'notes',
        'applicationRole': 'notes_app',
        'migrationRole': 'notes_migration',
        'backupRole': 'cloudlab_backup',
        'bucket': 'notes',
        'maintenance': False,
        'hibernated': False,
        'postgresImage': POSTGRES_IMAGE,
        'identity': {'enabled': False, 'database': 'keycloak', 'role': 'keycloak'},
        'catalog': [{
            'approval': {'name': 'prices', 'namespace': 'cloudlab-app-prices'},
            'definition': {'data': {
                'database': {'name': 'prices', 'credentialReference': 'prices-db',
                             'retention': 'retain'},
                'bucket': {'name': 'prices-history',
                           'credentialReference': 'prices-bucket', 'retention': 'retain'}}},
            'publication': 'ready'}],
        'dataApprovals': {
            'prices-db': {'kind': 'database', 'service': 'prices', 'name': 'prices',
                          'item': 'cnpg-prices-production',
                          'migrationItem': 'cnpg-prices-migration',
                          'applicationRole': 'prices_app',
                          'migrationRole': 'prices_migration'},
            'prices-bucket': {'kind': 'bucket', 'service': 'prices',
                              'name': 'prices-history',
                              'item': 's3-prices-production'}},
    }


def render(values):
    if shutil.which('helm') is None:
        raise unittest.SkipTest('helm renders the data reconciler chart')
    with tempfile.TemporaryDirectory() as workspace:
        work = Path(workspace)
        (work / 'values.yaml').write_text(yaml.safe_dump(values))
        rendered = subprocess.check_output(
            ['helm', 'template', '--kube-version', '1.36',
             '--show-only', 'templates/reconciler.yaml',
             '-f', str(work / 'values.yaml'),
             str(ROOT / 'platform/data/configuration')],
            text=True, timeout=120)
    return [doc for doc in yaml.safe_load_all(rendered) if doc]


def configmap(documents, name):
    return next(doc for doc in documents
                if doc.get('kind') == 'ConfigMap'
                and doc['metadata']['name'] == name)


class DataCompiledInputsTests(unittest.TestCase):
    def test_rendered_desired_state_loads_and_matches_sql(self):
        documents = render(merged_values())
        desired = reconcile.load_desired_text(
            configmap(documents, 'data-desired-state')['data']['desired.json'])
        self.assertEqual(desired['s3Host'], 's3.internal.example.test')
        self.assertEqual(
            [(row['name'], row['owner'], row['secret'], row['applicationRole'])
             for row in desired['databases']],
            [('notes', 'notes_migration', 'notes-migration', 'notes_app'),
             ('prices', 'prices_migration', 'prices-migration', 'prices_app')])
        self.assertEqual(desired['buckets'], ['notes', 'prices-history'])
        grants = configmap(documents, 'data-grants')['data']
        self.assertEqual(sorted(grants), ['notes.sql', 'prices.sql'])
        self.assertIn('REVOKE ALL ON DATABASE "prices" FROM PUBLIC;', grants['prices.sql'])
        self.assertIn('GRANT CONNECT ON DATABASE "prices" TO "prices_app";',
                      grants['prices.sql'])
        self.assertIn('GRANT USAGE ON SCHEMA public TO "prices_app";', grants['prices.sql'])
        self.assertIn('ALTER DEFAULT PRIVILEGES FOR ROLE "prices_migration" IN SCHEMA public '
                      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "prices_app";',
                      grants['prices.sql'])
        self.assertNotIn('CREATE ON SCHEMA public TO "prices_app"', grants['prices.sql'])
        cron = next(doc for doc in documents if doc.get('kind') == 'CronJob')
        self.assertEqual(cron['metadata']['name'], 'application-data-reconciler')
        self.assertEqual(cron['spec']['schedule'], '*/5 * * * *')
        self.assertIs(cron['spec']['suspend'], False)
        pod = cron['spec']['jobTemplate']['spec']['template']['spec']
        self.assertEqual(pod['serviceAccountName'], 'data-reconciler')
        self.assertIs(pod['automountServiceAccountToken'], False)
        self.assertEqual(pod['initContainers'][0]['image'], PYTHON_IMAGE)
        self.assertEqual(pod['containers'][0]['image'], POSTGRES_IMAGE)
        self.assertEqual(pod['containers'][0]['env'][2],
                         {'name': 'PGSSLMODE', 'value': 'verify-full'})
        grants = pod['containers'][0]['args'][0]
        self.assertIn('psql -d "$name" -v ON_ERROR_STOP=1 -f "$sql"', grants)
        self.assertIn('case "$name" in', grants)
        job = next(doc for doc in documents if doc.get('kind') == 'Job')
        self.assertEqual(job['metadata']['annotations']['argocd.argoproj.io/hook'],
                         'PostSync')
        account = next(doc for doc in documents
                       if doc.get('kind') == 'ServiceAccount')
        self.assertIs(account['automountServiceAccountToken'], False)

    def test_maintenance_suspends_and_skips_sync_job(self):
        values = merged_values()
        values['maintenance'] = True
        documents = render(values)
        cron = next(doc for doc in documents if doc.get('kind') == 'CronJob')
        self.assertIs(cron['spec']['suspend'], True)
        self.assertEqual([doc for doc in documents if doc.get('kind') == 'Job'], [])

    def test_identity_database_renders_revoke_only_sql(self):
        values = merged_values()
        values['identity'] = {'enabled': True, 'database': 'keycloak', 'role': 'keycloak'}
        documents = render(values)
        grants = configmap(documents, 'data-grants')['data']
        self.assertEqual(sorted(grants), ['keycloak.sql', 'notes.sql', 'prices.sql'])
        self.assertEqual(
            grants['keycloak.sql'],
            'REVOKE ALL ON DATABASE "keycloak" FROM PUBLIC;\n'
            'REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n')

    def test_buckets_reconcile_without_delete_path(self):
        document = {'s3Host': 's3.internal.example.test', 'databases': [],
                    'buckets': ['notes', 'prices-history']}
        script = iter([200, 404, 200, 200])
        calls = []

        def transport(method, path, headers):
            calls.append((method, path))
            return next(script)

        self.assertEqual(
            reconcile.ensure_buckets(document, 'admin', 'secret', 'us-east-1',
                                     transport=transport),
            ['prices-history'])
        self.assertEqual(calls, [('HEAD', '/notes/'), ('HEAD', '/prices-history/'),
                                 ('PUT', '/prices-history/'), ('HEAD', '/prices-history/')])
        self.assertNotIn('DELETE', [method for method, _ in calls])

        def refused(method, path, headers):
            return 403

        with self.assertRaises(RuntimeError):
            reconcile.ensure_buckets(document, 'admin', 'secret', 'us-east-1',
                                     transport=refused)
        with self.assertRaises(RuntimeError):
            reconcile.ensure_buckets(document, '', '', 'us-east-1', transport=transport)

    def test_invalid_desired_state_rejected(self):
        base = {'s3Host': 's3.internal.example.test',
                'databases': [{'name': 'prices', 'owner': 'prices_migration',
                               'secret': 'prices-migration',
                               'applicationRole': 'prices_app'}],
                'buckets': ['prices-history']}
        cases = [
            dict(base, s3Host='s3.evil.example'),
            dict(base, databases=[]),
            dict(base, buckets=[]),
            dict(base, databases=[dict(base['databases'][0], name='postgres')]),
            dict(base, databases=[dict(base['databases'][0], name='pg_shadow')]),
            dict(base, databases=[dict(base['databases'][0],
                                      applicationRole='prices_migration')]),
            dict(base, databases=[dict(base['databases'][0], secret='Prices_Migration')]),
            dict(base, buckets=['Prices_History']),
            dict(base, buckets=['prices-history', 'prices-history']),
            dict(base, databases=[base['databases'][0], base['databases'][0]]),
            dict(base, extra=True),
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    reconcile.load_desired_text(json.dumps(case))


if __name__ == '__main__':
    unittest.main()
