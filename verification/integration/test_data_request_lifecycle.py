"""Data/storage request lifecycle: provision, guards, removal, alternate path.

Renders the data owner (platform/data/configuration), the service owner
(platform/delivery/services) and the public root with offline fixtures:

- valid/provision: an approved catalog request provisions Database, scoped
  roles/grants, bucket repair entries, scoped delivery and storage budgets
  without operator apply, and renders no restore workload;
- collision/quota/refusal: overlapping names/roles/buckets, over-budget
  storage and unapproved requests fail closed;
- retention: removing a request withdraws access while retained settings
  (reclaim, deletion and prune guards) stay on the rendered resources;
- alternate path: the selected catalog path reaches both consumers, unknown
  paths are refused, and alternate-file content carries the same contract.
"""
import copy
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
SERVICE_IMAGE = ('python:3.13-slim-bookworm@sha256:' + 'a' * 64)
FIXTURE_CATALOG = ROOT / 'verification/integration/fixtures/data-catalog-lifecycle.yaml'


def prices_entry():
    return {
        'approval': {'name': 'prices', 'namespace': 'cloudlab-app-prices'},
        'definition': {'data': {
            'database': {'name': 'prices', 'credentialReference': 'prices-db',
                         'retention': 'retain'},
            'bucket': {'name': 'prices-history',
                       'credentialReference': 'prices-bucket',
                       'retention': 'retain'}}},
        'publication': 'ready'}


def prices_approvals():
    return {
        'prices-db': {'kind': 'database', 'service': 'prices', 'name': 'prices',
                      'item': 'cnpg-prices-production',
                      'migrationItem': 'cnpg-prices-migration',
                      'applicationRole': 'prices_app',
                      'migrationRole': 'prices_migration'},
        'prices-bucket': {'kind': 'bucket', 'service': 'prices',
                          'name': 'prices-history',
                          'item': 's3-prices-production'}}


def base_data_values():
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
        'catalog': [prices_entry()],
        'dataApprovals': prices_approvals(),
    }


def require_helm():
    if shutil.which('helm') is None:
        raise unittest.SkipTest('helm renders the request charts')


def helm_template(chart, values=None, stdin=None, show_only=None):
    command = ['helm', 'template', '--kube-version', '1.36']
    if show_only:
        command += ['--show-only', show_only]
    if stdin is not None:
        command += [chart.name, str(chart), '-f', '-']
        return subprocess.run(command, input=json.dumps(stdin), capture_output=True,
                              text=True, timeout=180)
    with tempfile.TemporaryDirectory() as workspace:
        work = Path(workspace)
        (work / 'values.yaml').write_text(yaml.safe_dump(values))
        command += ['-f', str(work / 'values.yaml'), str(chart)]
        return subprocess.run(command, capture_output=True, text=True, timeout=180)


def render_data(values):
    require_helm()
    completed = helm_template(ROOT / 'platform/data/configuration', values=values)
    if completed.returncode:
        raise AssertionError('data render failed: ' + completed.stderr[-2000:])
    return [doc for doc in yaml.safe_load_all(completed.stdout) if doc]


def render_data_error(values):
    require_helm()
    completed = helm_template(ROOT / 'platform/data/configuration', values=values)
    if not completed.returncode:
        raise AssertionError('data render unexpectedly succeeded')
    return completed.stderr


def service_definition(**overrides):
    definition = {
        'name': 'prices', 'owner': 'platform', 'image': SERVICE_IMAGE,
        'replicas': 1, 'command': ['python'],
        'ports': [{'name': 'http', 'port': 8080}],
        'health': {'readiness': {'path': '/', 'port': 'http'},
                   'liveness': {'path': '/', 'port': 'http'}},
        'resources': {'requests': {'cpu': '50m', 'memory': '32Mi'},
                      'limits': {'cpu': '200m', 'memory': '128Mi'}},
        'environment': {}, 'secrets': [], 'configMaps': [],
        'persistence': {'enabled': False, 'size': '1Gi', 'mountPath': '/data',
                        'retention': 'retain'},
        'exposure': {'class': 'none'}, 'data': {}, 'oidc': {'enabled': False},
        'monitoring': {'enabled': False}, 'rollouts': {'enabled': False},
        'initCommand': [],
    }
    definition.update(overrides)
    return definition


def service_approval(**overrides):
    approval = {'name': 'prices',
                'repository': 'https://github.com/example/prices.git',
                'revision': 'c' * 40, 'valuesPath': 'apps/prices.yaml',
                'namespace': 'cloudlab-app-prices',
                'secretReferences': [], 'configMaps': [], 'egress': []}
    approval.update(overrides)
    return approval


def services_values(entries, **extra):
    values = {'repository': 'https://github.com/example/platform.git',
              'revision': 'd' * 40, 'catalog': entries}
    values.update(extra)
    return values


def render_services(values):
    require_helm()
    completed = helm_template(ROOT / 'platform/delivery/services',
                              values=values,
                              show_only='templates/catalog.yaml')
    if completed.returncode:
        raise AssertionError('services render failed: ' + completed.stderr[-2000:])
    return [doc for doc in yaml.safe_load_all(completed.stdout) if doc]


def render_services_error(values):
    require_helm()
    completed = helm_template(ROOT / 'platform/delivery/services',
                              values=values,
                              show_only='templates/catalog.yaml')
    if not completed.returncode:
        raise AssertionError('services render unexpectedly succeeded')
    return completed.stderr


def render_services_data(values):
    require_helm()
    completed = helm_template(ROOT / 'platform/delivery/services',
                              values=values, show_only='templates/data.yaml')
    if completed.returncode:
        raise AssertionError('services data render failed: '
                             + completed.stderr[-2000:])
    return [doc for doc in yaml.safe_load_all(completed.stdout) if doc]


def render_services_data_or_empty(values):
    """data.yaml renders nothing once its entry is removed; helm reports an
    empty --show-only template as not found, which is the expected signal."""
    require_helm()
    completed = helm_template(ROOT / 'platform/delivery/services',
                              values=values, show_only='templates/data.yaml')
    if completed.returncode:
        if 'could not find template templates/data.yaml' in completed.stderr:
            return []
        raise AssertionError('services data render failed: '
                             + completed.stderr[-2000:])
    return [doc for doc in yaml.safe_load_all(completed.stdout) if doc]


def render_root(stdin):
    require_helm()
    completed = helm_template(ROOT / 'gitops/roots/public', stdin=stdin)
    return completed


def find(documents, kind, name=None):
    matches = [doc for doc in documents if doc.get('kind') == kind
               and (name is None or doc['metadata']['name'] == name)]
    if name is not None:
        if len(matches) != 1:
            raise AssertionError('expected one %s/%s, found %d'
                                 % (kind, name, len(matches)))
        return matches[0]
    return matches


class ProvisionTests(unittest.TestCase):
    def test_approved_request_provisions_database_roles_and_delivery(self):
        documents = render_data(base_data_values())
        database = find(documents, 'Database', 'prices')
        self.assertEqual(database['spec']['name'], 'prices')
        self.assertEqual(database['spec']['owner'], 'prices_migration')
        self.assertEqual(database['spec']['cluster'], {'name': 'cloudlab-postgres'})
        self.assertEqual(database['spec']['databaseReclaimPolicy'], 'retain')
        self.assertIn('Prune=false', database['metadata']['annotations'][
            'argocd.argoproj.io/sync-options'])
        for name, item in (('prices-application', 'cnpg-prices-production'),
                           ('prices-migration', 'cnpg-prices-migration')):
            secret = find(documents, 'ExternalSecret', name)
            self.assertEqual(secret['spec']['target']['deletionPolicy'], 'Retain')
            self.assertEqual(secret['spec']['dataFrom'],
                             [{'extract': {'key': item}}])
        cluster = find(documents, 'Cluster', 'cloudlab-postgres')
        roles = {role['name']: role for role in cluster['spec']['managed']['roles']}
        self.assertEqual(roles['prices_app']['passwordSecret'],
                         {'name': 'prices-application'})
        self.assertEqual(roles['prices_migration']['passwordSecret'],
                         {'name': 'prices-migration'})
        self.assertTrue(roles['prices_app']['login'])
        self.assertFalse(roles['prices_app']['superuser'])
        hba = cluster['spec']['postgresql']['pg_hba']
        self.assertIn('hostssl prices prices_app all scram-sha-256', hba)
        self.assertIn('hostssl prices prices_migration all scram-sha-256', hba)
        policy = find(documents, 'NetworkPolicy', 'postgres-private')
        consumers = [rule for rule in policy['spec']['ingress']
                     if rule.get('from') == [{'namespaceSelector': {'matchLabels': {
                         'kubernetes.io/metadata.name': 'cloudlab-app-prices'}}}]]
        self.assertEqual(len(consumers), 1)
        self.assertEqual(consumers[0]['ports'],
                         [{'protocol': 'TCP', 'port': 5432}])
        settings = json.loads(find(
            documents, 'ConfigMap', 'cloudlab-data-settings')['data']['settings'])
        self.assertEqual(
            settings['serviceRequests'],
            [{'service': 'prices', 'namespace': 'cloudlab-app-prices',
              'database': {'name': 'prices', 'applicationRole': 'prices_app',
                           'migrationRole': 'prices_migration',
                           'applicationItem': 'cnpg-prices-production',
                           'migrationItem': 'cnpg-prices-migration'},
              'bucket': {'name': 'prices-history',
                         'item': 's3-prices-production'}}])
        desired = reconcile.load_desired_text(find(
            documents, 'ConfigMap', 'data-desired-state')['data']['desired.json'])
        self.assertEqual(
            [(row['name'], row['owner'], row['secret'], row['applicationRole'])
             for row in desired['databases']],
            [('notes', 'notes_migration', 'notes-migration', 'notes_app'),
             ('prices', 'prices_migration', 'prices-migration', 'prices_app')])
        self.assertEqual(desired['buckets'], ['notes', 'prices-history'])
        grants = find(documents, 'ConfigMap', 'data-grants')['data']
        self.assertIn('GRANT CONNECT ON DATABASE "prices" TO "prices_app";',
                      grants['prices.sql'])
        s3config = find(documents, 'ExternalSecret', 'cloudlab-s3-config')
        template = s3config['spec']['target']['template']['data']['seaweedfs_s3_config']
        self.assertIn('"name":"prices"', template)
        self.assertIn('Read:prices-history', template)

    def test_rendered_data_owner_has_no_restore_workload(self):
        documents = render_data(base_data_values())
        batch = [(doc['kind'], doc['metadata']['name'])
                 for doc in documents if doc.get('kind') in ('Job', 'CronJob')]
        self.assertEqual(sorted(batch),
                         [('CronJob', 'application-data-reconciler'),
                          ('Job', 'application-data-reconciler-sync')])
        scripts = []
        for doc in documents:
            if doc.get('kind') not in ('Job', 'CronJob'):
                continue
            pod = doc['spec']['jobTemplate']['spec']['template']['spec'] \
                if doc['kind'] == 'CronJob' else doc['spec']['template']['spec']
            for container in (pod['initContainers'] + pod['containers']):
                scripts.extend(container.get('command', []))
                scripts.extend(str(arg) for arg in container.get('args', []))
        self.assertNotIn('restore', ' '.join(scripts).lower())

    def test_approved_request_delivers_scoped_service_credentials(self):
        entry = {'approval': service_approval(
                     secretReferences=['prices-database', 'prices-objects']),
                 'definition': service_definition(data={
                     'database': {'name': 'prices',
                                  'credentialReference': 'prices-database',
                                  'retention': 'retain'},
                     'bucket': {'name': 'prices-history',
                                'credentialReference': 'prices-objects',
                                'retention': 'retain'}}),
                 'publication': 'ready'}
        documents = render_services_data(services_values(
            [entry], dataApprovals={
                'prices-database': {'kind': 'database', 'service': 'prices',
                                    'name': 'prices',
                                    'item': 'cnpg-prices-production'},
                'prices-objects': {'kind': 'bucket', 'service': 'prices',
                                   'name': 'prices-history',
                                   'item': 's3-prices-production'}}))
        self.assertEqual({doc['metadata']['name'] for doc in documents},
                         {'prices-database', 'prices-objects'})
        for doc in documents:
            self.assertEqual(doc['metadata']['namespace'], 'cloudlab-app-prices')
            self.assertEqual(doc['spec']['target']['deletionPolicy'], 'Retain')
            fields = doc['spec']['target']['template']['data']
            self.assertIn('Required data secret field is missing or empty',
                          ' '.join(fields.values()))
        by_name = {doc['metadata']['name']: doc for doc in documents}
        self.assertEqual(sorted(by_name['prices-database']['spec']['target']
                                ['template']['data']),
                         ['password', 'username'])
        self.assertEqual(by_name['prices-database']['spec']['dataFrom'],
                         [{'extract': {'key': 'cnpg-prices-production'}}])
        self.assertEqual(by_name['prices-objects']['spec']['dataFrom'],
                         [{'extract': {'key': 's3-prices-production'}}])


def shop_entry(**overrides):
    entry = {
        'approval': {'name': 'shop', 'namespace': 'cloudlab-app-shop'},
        'definition': {'data': {
            'database': {'name': 'shop', 'credentialReference': 'shop-db',
                         'retention': 'retain'}}},
        'publication': 'ready'}
    entry.update(overrides)
    return entry


def shop_approval(**overrides):
    approval = {'kind': 'database', 'service': 'shop', 'name': 'shop',
                'item': 'cnpg-shop-production',
                'migrationItem': 'cnpg-shop-migration',
                'applicationRole': 'shop_app', 'migrationRole': 'shop_migration'}
    approval.update(overrides)
    return approval


class GuardTests(unittest.TestCase):
    def test_colliding_requests_fail_closed(self):
        cases = []
        values = base_data_values()
        values['catalog'].append(shop_entry())
        values['catalog'][1]['definition']['data']['database']['name'] = 'prices'
        values['dataApprovals']['shop-db'] = shop_approval(name='prices')
        cases.append((values, 'database or role scopes overlap'))
        values = base_data_values()
        values['catalog'].append(shop_entry(definition={'data': {'bucket': {
            'name': 'prices-history', 'credentialReference': 'shop-bucket',
            'retention': 'retain'}}}))
        values['dataApprovals']['shop-bucket'] = {
            'kind': 'bucket', 'service': 'shop', 'name': 'prices-history',
            'item': 's3-shop-production'}
        cases.append((values, 'service buckets overlap'))
        values = base_data_values()
        values['dataApprovals']['prices-db']['applicationRole'] = 'notes_app'
        cases.append((values, 'protected platform identity'))
        for values, fragment in cases:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, render_data_error(values))

    def test_unapproved_requests_fail_closed(self):
        values = base_data_values()
        values['dataApprovals']['prices-db']['service'] = 'shop'
        self.assertIn('exact administrator approval',
                      render_data_error(values))
        values = base_data_values()
        del values['dataApprovals']['prices-db']
        self.assertIn('exact administrator approval',
                      render_data_error(values))
        values = base_data_values()
        values['catalog'][0]['definition']['data']['database']['retention'] = 'delete'
        self.assertIn('retention', render_data_error(values))
        values = base_data_values()
        values['catalog'][0]['definition']['data']['database']['name'] = 'postgres'
        self.assertIn('/catalog/0/definition/data/database/name',
                      render_data_error(values))
        values = base_data_values()
        values['serviceRequests'] = [{'service': 'prices',
                                      'namespace': 'cloudlab-app-prices'}]
        self.assertIn('must derive only from the complete catalog',
                      render_data_error(values))
        values = base_data_values()
        del values['catalog']
        self.assertIn('catalog', render_data_error(values))

    def test_unapproved_service_delivery_fails_closed(self):
        entry = {'approval': service_approval(
                     secretReferences=['prices-database', 'prices-objects']),
                 'definition': service_definition(data={
                     'database': {'name': 'prices',
                                  'credentialReference': 'prices-database',
                                  'retention': 'retain'}}),
                 'publication': 'ready'}
        values = services_values([entry], dataApprovals={
            'prices-database': {'kind': 'database', 'service': 'shop',
                                'name': 'prices',
                                'item': 'cnpg-prices-production'}})
        self.assertIn('Unapproved data scope', render_services_error(values))
        values = services_values([entry], dataApprovals={})
        self.assertIn('Missing approved data scope',
                      render_services_error(values))

    def test_ordinary_storage_must_fit_its_fixed_budget(self):
        values = services_values([{
            'approval': service_approval(), 'publication': 'ready',
            'definition': service_definition(persistence={
                'enabled': True, 'size': '5Gi', 'mountPath': '/data',
                'retention': 'retain'})}])
        self.assertIn('approved storage budget', render_services_error(values))
        values['catalog'][0]['definition']['persistence']['size'] = '4Gi'
        documents = render_services(values)
        quota = find(documents, 'ResourceQuota', 'budget')
        self.assertEqual(quota['spec']['hard']['requests.storage'], '4Gi')

    def test_composition_claims_must_fit_their_approved_budget(self):
        composition = {
            'chart': {'repository': 'https://github.com/example/app.git',
                      'revision': 'e' * 40, 'path': 'deploy/helm/app'},
            'imageValues': {'web': 'images.web'},
            'images': {'web': 'harbor.example/app@sha256:' + 'f' * 64},
            'workloads': [{'name': 'web', 'replicas': 1, 'podSpec': {
                'containers': [{'name': 'web', 'image': SERVICE_IMAGE}]}}],
            'claims': [{'name': 'app-postgres', 'size': '20Gi'},
                       {'name': 'app-data', 'size': '13Gi'}],
            'budget': {'requests.cpu': '2000m', 'requests.memory': '2048Mi',
                       'limits.cpu': '8000m', 'limits.memory': '8192Mi',
                       'pods': 12, 'persistentvolumeclaims': 7,
                       'requests.storage': '33Gi'},
            'backends': {},
            'secrets': [{'name': 'app-secrets', 'item': 'app-item',
                         'fields': {'token': 'token'}}]}

        def composition_values(claims):
            entry = copy.deepcopy(composition)
            entry['claims'] = claims
            approval = service_approval(
                name='taskopotamus',
                namespace='cloudlab-app-taskopotamus',
                secretReferences=['app-secrets'])
            del approval['egress']
            approval['composition'] = entry
            return services_values([{
                'approval': approval,
                'definition': service_definition(name='taskopotamus'),
                'publication': 'ready'}])

        # At-budget composition renders, matching the accepted production shape.
        documents = render_services(composition_values(composition['claims']))
        quota = find(documents, 'ResourceQuota', 'budget')
        self.assertEqual(quota['spec']['hard']['requests.storage'], '33Gi')
        over_storage = composition_values(
            [{'name': 'app-postgres', 'size': '20Gi'},
             {'name': 'app-data', 'size': '14Gi'}])
        self.assertIn('approved storage budget',
                      render_services_error(over_storage))
        over_count = composition_values(
            [{'name': 'app-claim-%d' % index, 'size': '1Gi'}
             for index in range(8)])
        self.assertIn('approved claim budget',
                      render_services_error(over_count))
        duplicate = composition_values(
            [{'name': 'app-data', 'size': '1Gi'},
             {'name': 'app-data', 'size': '2Gi'}])
        self.assertIn('must be unique', render_services_error(duplicate))


class RemovalTests(unittest.TestCase):
    def test_removed_request_withdraws_access_and_keeps_retained_data(self):
        retained = render_data(base_data_values())
        removed_values = base_data_values()
        removed_values['catalog'] = []
        removed = render_data(removed_values)
        # Lingering approvals alone provision nothing.
        self.assertEqual(find(removed, 'Database'), [])
        self.assertEqual(
            [doc for doc in removed if doc.get('kind') == 'ExternalSecret'
             and doc['metadata']['name'].startswith('prices-')], [])
        cluster = find(removed, 'Cluster', 'cloudlab-postgres')
        roles = {role['name'] for role in cluster['spec']['managed']['roles']}
        self.assertNotIn('prices_app', roles)
        self.assertNotIn('prices_migration', roles)
        hba = ' '.join(cluster['spec']['postgresql']['pg_hba'])
        self.assertNotIn('prices', hba)
        policy = find(removed, 'NetworkPolicy', 'postgres-private')
        self.assertNotIn('cloudlab-app-prices', json.dumps(policy))
        grants = find(removed, 'ConfigMap', 'data-grants')['data']
        self.assertEqual(sorted(grants), ['notes.sql'])
        settings = json.loads(find(
            removed, 'ConfigMap', 'cloudlab-data-settings')['data']['settings'])
        self.assertEqual(settings['serviceRequests'], [])
        desired = reconcile.load_desired_text(find(
            removed, 'ConfigMap', 'data-desired-state')['data']['desired.json'])
        self.assertEqual([row['name'] for row in desired['databases']],
                         ['notes'])
        self.assertEqual(desired['buckets'], ['notes'])
        calls = []

        def transport(method, path, headers):
            calls.append((method, path))
            if method == 'DELETE':
                raise AssertionError('removed buckets must never be deleted')
            return 200

        self.assertEqual(
            reconcile.ensure_buckets(desired, 'admin', 'secret', 'us-east-1',
                                     transport=transport), [])
        self.assertEqual(calls, [('HEAD', '/notes/')])
        # The provisioned render carried the retention guards throughout.
        database = find(retained, 'Database', 'prices')
        self.assertEqual(database['spec']['databaseReclaimPolicy'], 'retain')
        self.assertEqual(database['metadata']['annotations'][
            'argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')
        for name in ('prices-application', 'prices-migration'):
            secret = find(retained, 'ExternalSecret', name)
            self.assertEqual(secret['spec']['target']['deletionPolicy'],
                             'Retain')

    def test_removed_service_delivery_vanishes_with_retain_policy(self):
        entry = {'approval': service_approval(
                     secretReferences=['prices-database']),
                 'definition': service_definition(data={
                     'database': {'name': 'prices',
                                  'credentialReference': 'prices-database',
                                  'retention': 'retain'}}),
                 'publication': 'ready'}
        approvals = {'prices-database': {
            'kind': 'database', 'service': 'prices', 'name': 'prices',
            'item': 'cnpg-prices-production'}}
        delivered = render_services_data(
            services_values([entry], dataApprovals=approvals))
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0]['spec']['target']['deletionPolicy'],
                         'Retain')
        self.assertEqual(
            render_services_data_or_empty(
                services_values([], dataApprovals=approvals)),
            [])


class AlternatePathTests(unittest.TestCase):
    @staticmethod
    def root_values(**services):
        values = {'identity': {'argo': {
            'valuesRepository': 'https://github.com/example/private.git',
            'valuesRevision': 'b' * 40}},
            'services': {'acceptanceCommitment': '2' * 64}}
        values['services'].update(services)
        return values

    def test_default_catalog_path_is_unchanged(self):
        completed = render_root(self.root_values())
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        documents = [doc for doc in yaml.safe_load_all(completed.stdout) if doc]
        app = find(documents, 'Application', 'cloudlab-data-configuration')
        self.assertIn('$values/services/catalog.json',
                      app['spec']['sources'][0]['helm']['valueFiles'])

    def test_alternate_catalog_path_reaches_both_consumers(self):
        completed = render_root(self.root_values(
            catalogPath='services/catalog-lifecycle.yaml'))
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        documents = [doc for doc in yaml.safe_load_all(completed.stdout) if doc]
        app = find(documents, 'Application', 'cloudlab-data-configuration')
        self.assertIn('$values/services/catalog-lifecycle.yaml',
                      app['spec']['sources'][0]['helm']['valueFiles'])
        services = find(documents, 'ApplicationSet', 'cloudlab-services')
        sources = services['spec']['template']['spec']['sources']
        self.assertIn('$values/services/catalog-lifecycle.yaml',
                      sources[0]['helm']['valueFiles'])
        self.assertIn('services/catalog-lifecycle.yaml',
                      sources[1]['targetRevision'])

    def test_unknown_catalog_paths_are_refused(self):
        for path in ('services/evil.txt', '../services/catalog.json',
                     'services/catalog.json/evil'):
            with self.subTest(path=path):
                completed = render_root(self.root_values(catalogPath=path))
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn('bounded catalog', completed.stderr)

    def test_alternate_catalog_content_carries_the_same_contract(self):
        fragment = yaml.safe_load(FIXTURE_CATALOG.read_text())
        values = dict(fragment)
        values.update({'sharedInputs': True, 'zone': 'example.test',
                       'production': False})
        documents = render_data(values)
        database = find(documents, 'Database', 'prices')
        self.assertEqual(database['spec']['owner'], 'prices_migration')
        desired = reconcile.load_desired_text(find(
            documents, 'ConfigMap', 'data-desired-state')['data']['desired.json'])
        self.assertEqual(desired['buckets'], ['notes', 'prices-history'])
        refused = copy.deepcopy(values)
        refused['dataApprovals']['prices-db']['service'] = 'shop'
        self.assertIn('exact administrator approval',
                      render_data_error(refused))


if __name__ == '__main__':
    unittest.main()
