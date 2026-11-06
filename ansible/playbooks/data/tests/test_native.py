"""Disabled native preparation preserves storage scope and operation ownership."""
import copy
import json
from pathlib import Path
import subprocess
import unittest

import yaml
from fixtures import shared_data
from playbooks.data.files.requests import request, resolve, protect

ROOT = Path(__file__).resolve().parents[4]


class NativeDataTests(unittest.TestCase):
    def render(self, path, values, *, valid=True, final=None):
        command = ['helm', 'template', 'cloudlab-data', str(ROOT / path), '-n', 'cloudlab-data', '-f', '-']
        data = json.dumps(values)
        if final is not None:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as file:
                json.dump(final, file); file.flush()
                result = subprocess.run(command + ['-f', file.name], input=data, capture_output=True, text=True, timeout=60)
        else: result = subprocess.run(command, input=data, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode == 0, valid, result.stderr if valid else 'Unsafe native input accepted')
        return [obj for obj in yaml.safe_load_all(result.stdout) if obj] if valid else []

    def settings(self, objects): return json.loads(next(o for o in objects if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'cloudlab-data-settings')['data']['settings'])

    def test_native_catalog_matches_legacy_resolver_including_retired_scopes(self):
        shared = shared_data()
        requested = [request(e['approval']['name'], e['definition']['data'], shared['dataApprovals']) for e in shared['catalog']]
        def lookup(item, fields):
            name = 'fixture' if 'fixture' in item else 'notes'
            return {'database': name, 'username': name + ('_migration' if item.endswith('migration') else '_app'), 'BUCKET': name}
        resolved = resolve(requested, lookup)
        protect(resolved, shared)
        resolved = [row for row in resolved if row['service'] != 'notes']
        legacy = {k: v for k, v in shared.items() if k not in ('sharedInputs', 'zone', 'production', 'catalog', 'dataApprovals')}
        legacy.update(s3Host='s3.internal.example.invalid', serviceRequests=resolved, serviceConsumers=['cloudlab-app-fixture', 'cloudlab-app-notes'])
        old = self.render('platform/data/configuration', legacy)
        new = self.render('platform/data/configuration', shared)
        identities = [(o['apiVersion'], o['kind'], o['metadata'].get('namespace', '' if o['kind'] in ('Namespace', 'StorageClass') else 'cloudlab-data'), o['metadata']['name']) for o in new]
        self.assertEqual(len(identities), len(set(identities)))
        settings = self.settings(new)
        self.assertEqual(settings['serviceRequests'], resolved)
        self.assertEqual(settings['serviceConsumers'], legacy['serviceConsumers'])
        self.assertEqual([o for o in new if o['kind'] != 'ConfigMap'], old)
        self.assertEqual(settings['s3Host'], 's3.internal.example.invalid')
        self.assertFalse(settings['maintenance']); self.assertFalse(settings['hibernated'])

    def test_native_requires_complete_sources_and_scoped_role_metadata(self):
        for field in ('zone', 'production', 'catalog', 'dataApprovals'):
            values = shared_data(); values.pop(field)
            self.render('platform/data/configuration', values, valid=False)
        for change in ('roles', 'partial-role', 'reserved', 'scope', 'privileged', 'duplicate', 'protected', 'identity', 'zone', 'production', 'requests', 'consumers'):
            values = shared_data(); approval = values['dataApprovals']['fixture-database']
            if change == 'roles': approval.pop('applicationRole'); approval.pop('migrationRole')
            if change == 'partial-role': approval.pop('migrationRole')
            if change == 'reserved': approval['applicationRole'] = 'pg_bad'
            if change == 'scope': approval['service'] = 'other'
            if change == 'privileged': approval['item'] = 'cnpg-superuser'
            if change == 'duplicate': values['catalog'].append(copy.deepcopy(values['catalog'][1]))
            if change == 'protected': approval['applicationRole'] = values['backupRole']
            if change == 'identity': values['identity']['role'] = values['applicationRole']
            if change == 'zone': values['zone'] = 'https://foreign.invalid/path'
            if change == 'production': values['production'] = 'true'
            if change == 'requests': values['serviceRequests'] = [{'service': 'foreign', 'namespace': 'cloudlab-app-foreign'}]
            if change == 'consumers': values['serviceConsumers'] = ['cloudlab-app-foreign']
            with self.subTest(change=change): self.render('platform/data/configuration', values, valid=False)

    def test_native_preserves_global_scope_uniqueness_and_request_bound(self):
        for conflict in ('database', 'role', 'bucket', 'limit'):
            values = shared_data()
            count = 8 if conflict == 'limit' else 1
            for index in range(count):
                name = 'extra' + str(index)
                entry = copy.deepcopy(values['catalog'][1])
                entry['definition']['name'] = name
                entry['approval'].update(name=name, namespace='cloudlab-app-' + name)
                for kind, requested in entry['definition']['data'].items():
                    requested.update(name=name, credentialReference=name + '-' + kind)
                    source = values['dataApprovals']['fixture-' + kind]
                    scope = copy.deepcopy(source); scope.update(service=name, name=name)
                    scope['item'] = ('cnpg-' if kind == 'database' else 's3-') + name + '-production'
                    if kind == 'database':
                        scope.update(migrationItem='cnpg-' + name + '-migration', applicationRole=name + '_app', migrationRole=name + '_migration')
                        if conflict == 'database': requested['name'] = scope['name'] = 'fixture'
                        if conflict == 'role': scope['applicationRole'] = source['applicationRole']
                    elif conflict == 'bucket': requested['name'] = scope['name'] = 'fixture'
                    values['dataApprovals'][requested['credentialReference']] = scope
                values['catalog'].append(entry)
            with self.subTest(conflict=conflict): self.render('platform/data/configuration', values, valid=False)

    def test_fixed_platform_resource_and_s3_identity_collisions_are_rejected(self):
        for name, kind in (('notes', 'database'), ('notes', 'bucket'), ('keycloak', 'database'),
                           ('data-admin', 'bucket'), ('admin', 'bucket'), ('app', 'bucket')):
            values = shared_data()
            entry = values['catalog'][1]
            entry['definition']['name'] = name
            entry['approval'].update(name=name, namespace='cloudlab-app-' + name)
            entry['definition']['data'] = {kind: entry['definition']['data'][kind]}
            values['dataApprovals']['fixture-' + kind]['service'] = name
            if name == 'notes': values['catalog'].pop(0)
            with self.subTest(name=name, kind=kind): self.render('platform/data/configuration', values, valid=False)
        values = shared_data(); values['identity']['enabled'] = False
        entry = values['catalog'][1]; entry['definition']['name'] = 'keycloak'
        entry['approval'].update(name='keycloak', namespace='cloudlab-app-keycloak')
        for kind in ('database', 'bucket'): values['dataApprovals']['fixture-' + kind]['service'] = 'keycloak'
        self.render('platform/data/configuration', values)

    def test_public_value_objects_own_operations_and_native_selector(self):
        for maintenance, hibernated in ((False, False), (True, False), (True, True)):
            values = shared_data(); values.update(maintenance='untrusted', hibernated={'wrong': True}, sharedInputs=False)
            objects = self.render('platform/data/configuration', values, final={'sharedInputs': True, 'maintenance': maintenance, 'hibernated': hibernated})
            settings = self.settings(objects)
            self.assertIs(settings['maintenance'], maintenance); self.assertIs(settings['hibernated'], hibernated)
            cluster = next(o for o in objects if o['kind'] == 'Cluster')
            self.assertEqual(cluster['metadata']['annotations']['cnpg.io/hibernation'], 'on' if hibernated else 'off')
        seaweed = self.render('platform/data/seaweedfs', {})
        same = self.render('platform/data/seaweedfs', {'seaweedfs': {name: {'replicas': 1} for name in ('master', 'volume', 'filer', 's3')}})
        self.assertEqual(seaweed, same)

    def root_values(self):
        return {'identity': {'argo': {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}},
                'data': {'configuration': {'enabled': True, 'revision': 'a' * 40, 'seaweedfsRevision': 'c' * 40}}}

    def test_disabled_unbound_and_invalid_roots_fail_safely(self):
        for values in ({}, {'data': {'configuration': {'enabled': True}}}, self.root_values() | {'data': {'configuration': {'enabled': False}}}):
            objects = self.render('gitops/roots/public', values)
            self.assertFalse(any(o['kind'] == 'Application' and o['metadata']['name'] in ('cloudlab-data-configuration', 'cloudlab-seaweedfs') for o in objects))
            root = next(o for o in objects if o['kind'] == 'Application' and o['metadata']['name'] == 'cloudlab-public-root')
            self.assertNotIn('ignoreDifferences', root['spec'])
        for field in ('revision', 'seaweedfsRevision'):
            values = self.root_values(); values['data']['configuration'][field] = 'main'
            self.render('gitops/roots/public', values, valid=False)
        for binding in ({}, None, False):
            values = self.root_values(); values['identity']['argo'] = binding
            self.render('gitops/roots/public', values, valid=False)

    def test_native_root_scopes_sources_reader_and_exact_operation_delegations(self):
        objects = self.render('gitops/roots/public', self.root_values())
        apps = {o['metadata']['name']: o for o in objects if o['kind'] == 'Application'}
        config = apps['cloudlab-data-configuration']; seaweed = apps['cloudlab-seaweedfs']; root = apps['cloudlab-public-root']
        self.assertIsNone(config['spec']['source'])
        self.assertEqual(config['spec']['sources'][1], {'repoURL': 'https://github.com/example/private.git', 'targetRevision': 'b' * 40, 'ref': 'values'})
        self.assertEqual(config['spec']['sources'][0]['helm']['valueFiles'], ['$values/platform/certificates.yaml', '$values/platform/data.yaml', '$values/services/catalog.json'])
        selected = self.root_values()
        selected['services'] = {'enabled': False, 'catalogPath': 'services/catalog-v2.yaml'}
        alternate = next(o for o in self.render('gitops/roots/public', selected)
                         if o['kind'] == 'Application' and o['metadata']['name'] == 'cloudlab-data-configuration')
        self.assertEqual(alternate['spec']['sources'][0]['helm']['valueFiles'],
            ['$values/platform/certificates.yaml', '$values/platform/data.yaml', '$values/services/catalog-v2.yaml'])
        selected['services']['catalogPath'] = 'services/../identity.yaml'
        self.render('gitops/roots/public', selected, valid=False)
        self.assertEqual(config['spec']['sources'][0]['helm']['valuesObject'], {'sharedInputs': True, 'maintenance': False, 'hibernated': False})
        self.assertEqual(seaweed['spec']['source']['targetRevision'], 'c' * 40)
        rules = root['spec']['ignoreDifferences']
        self.assertEqual([(r['name'], r['namespace'], r['kind'], r['group']) for r in rules], [('cloudlab-public-root', 'argocd', 'Application', 'argoproj.io'), ('cloudlab-seaweedfs', 'argocd', 'Application', 'argoproj.io')])
        self.assertEqual(rules[0]['jsonPointers'], ['/spec/source/helm/valuesObject/data/configuration/maintenance', '/spec/source/helm/valuesObject/data/configuration/hibernated'])
        self.assertNotIn('data', root['spec']['source']['helm']['valuesObject'])
        changed = self.root_values()
        changed['identity']['argo']['valuesRevision'] = 'e' * 40
        changed['data']['configuration'].update(maintenance=True, hibernated=True)
        advanced = {o['metadata']['name']: o for o in self.render('gitops/roots/public', changed) if o['kind'] == 'Application'}
        self.assertEqual(advanced['cloudlab-public-root']['spec']['source']['helm']['valuesObject']['data'],
            {'configuration': {'maintenance': True, 'hibernated': True}})
        self.assertEqual(advanced['cloudlab-data-configuration']['spec']['sources'][1]['targetRevision'], 'e' * 40)
        self.assertEqual(advanced['cloudlab-data-configuration']['spec']['sources'][0]['helm']['valuesObject'],
            {'sharedInputs': True, 'maintenance': True, 'hibernated': True})
        changed['data']['configuration']['maintenance'] = 'true'
        self.render('gitops/roots/public', changed, valid=False)
        self.assertEqual(rules[1]['jsonPointers'], ['/spec/source/helm/valuesObject/seaweedfs/' + name + '/replicas' for name in ('master', 'volume', 'filer', 's3')])
        self.assertIn('RespectIgnoreDifferences=true', root['spec']['syncPolicy']['syncOptions'])
        self.assertNotIn('RespectIgnoreDifferences=true', apps['cloudlab-argocd']['spec']['syncPolicy']['syncOptions'])
        projects = {o['metadata']['name']: o['spec'] for o in objects if o['kind'] == 'AppProject'}
        self.assertEqual(projects['cloudlab-data-configuration']['sourceRepos'], [config['spec']['sources'][0]['repoURL'], 'https://github.com/example/private.git'])
        self.assertEqual(projects['cloudlab-seaweedfs']['sourceRepos'], [config['spec']['sources'][0]['repoURL']])
        self.assertIn({'group': '', 'kind': 'ConfigMap'}, projects['cloudlab-data-configuration']['namespaceResourceWhitelist'])
        reader = next(o for o in objects if o['metadata']['name'] == 'cloudlab-data-configuration-source')
        self.assertEqual(reader['spec']['target']['template']['data']['project'], 'cloudlab-data-configuration')
        self.assertEqual(reader['spec']['target']['deletionPolicy'], 'Retain')
        self.assertEqual(reader['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')
