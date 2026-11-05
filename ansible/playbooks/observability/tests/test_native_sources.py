"""Native telemetry sources remain inert until a guarded writer handoff."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

import yaml

from playbooks.observability.tests.fixtures import native_source_inputs
from playbooks.observability.files.chart import render
from playbooks.observability.files.writer_guard import check_parent

ROOT = Path(__file__).resolve().parents[4]


class NativeSourcesTests(unittest.TestCase):
    def helm(self, chart, values, valid=True, namespace='argocd'):
        result = subprocess.run(['helm', 'template', 'fixture', str(ROOT / chart), '-n', namespace,
            '--kube-version', '1.36.5', '-f', '-'], input=yaml.safe_dump(values),
            capture_output=True, text=True, timeout=90)
        if not valid:
            self.assertNotEqual(result.returncode, 0, 'Invalid synthetic input unexpectedly rendered')
            return []
        self.assertEqual(result.returncode, 0, result.stderr)
        return [obj for obj in yaml.safe_load_all(result.stdout) if obj]

    def root_values(self):
        source = native_source_inputs()['nativeSource']
        return {'repository': source['repository'], 'identity': {'argo': {
            'valuesRepository': source['valuesRepository'], 'valuesRevision': 'b' * 40}},
            'observability': {'configuration': {'enabled': True, 'revision': source['revision'],
                'paused': True}}}

    def parent(self, values=None, valid=True):
        return self.helm('platform/observability/gitops',
                         native_source_inputs() if values is None else values, valid)

    def test_default_root_has_no_native_parent_and_preserves_child_privileges(self):
        default = self.helm('gitops/roots/public', {})
        self.assertFalse(any(o['metadata']['name'] == 'cloudlab-observability-gitops' for o in default))
        legacy = next(o for o in default if o['metadata']['name'] == 'cloudlab-observability')
        self.assertEqual(legacy['kind'], 'AppProject')
        self.assertEqual(len(legacy['spec']['sourceRepos']), 1)
        prepared = self.helm('gitops/roots/public', self.root_values())
        project = next(o for o in prepared if o['metadata']['name'] == 'cloudlab-observability')
        expected = copy.deepcopy(legacy['spec'])
        expected['sourceRepos'] = [native_source_inputs()['nativeSource']['repository']]
        self.assertEqual(project['spec'], expected)

    def test_root_is_paused_and_only_parent_has_project_scoped_private_reader(self):
        objects = self.helm('gitops/roots/public', self.root_values())
        app = next(o for o in objects if o['kind'] == 'Application' and
                   o['metadata']['name'] == 'cloudlab-observability-gitops')
        self.assertEqual(app['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'], 'true')
        self.assertEqual(app['spec']['syncPolicy']['automated'],
                         {'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False})
        public, private = app['spec']['sources']
        self.assertEqual(public['helm']['valueFiles'],
                         ['$values/services/catalog.json', '$values/platform/observability.yaml'])
        self.assertEqual(private['targetRevision'], 'main')
        check_parent(app, native_source_inputs()['nativeSource']['repository'])
        self.assertEqual(public['helm']['valuesObject']['nativeSource'], native_source_inputs()['nativeSource'])
        project = next(o for o in objects if o['kind'] == 'AppProject' and
                       o['metadata']['name'] == 'cloudlab-observability-gitops')
        self.assertEqual(project['spec']['clusterResourceWhitelist'], [])
        self.assertEqual(project['spec']['namespaceResourceWhitelist'], [{'group': 'argoproj.io', 'kind': 'Application'}])
        self.assertFalse(any(o['kind'] == 'ExternalSecret' and o['metadata']['name'] == 'cloudlab-observability-source' for o in objects))
        for name in ('cloudlab-observability-gitops',):
            secret = next(o for o in objects if o['kind'] == 'ExternalSecret' and o['metadata']['name'] == name + '-source')
            self.assertEqual(secret['spec']['target']['template']['data']['project'], name)
            self.assertEqual(secret['spec']['target']['deletionPolicy'], 'Retain')
            self.assertEqual(secret['spec']['dataFrom'], [{'extract': {'key': 'github-argocd'}}])
            self.assertEqual(secret['spec']['target']['template']['data']['url'], private['repoURL'])

    def test_root_rejects_untyped_and_unsafe_sources(self):
        cases = []
        for key, value in [('enabled', 'true'), ('paused', 'true'), ('revision', 'main'), ('valuesRevision', 'b' * 40),
                           ('annotations', {'argocd.argoproj.io/skip-reconcile': 'false'}),
                           ('syncPolicy', {'automated': {'enabled': True}})]:
            row = self.root_values()
            row['observability']['configuration'][key] = value
            cases.append(row)
        for path, value in [('services', {'catalogPath': '../private.yaml'}),
                            ('externalSecrets', {'reconcile': False}), ('observability', {'enabled': False})]:
            row = self.root_values()
            row.setdefault(path, {}).update(value)
            cases.append(row)
        row = self.root_values()
        row['identity']['argo']['valuesRepository'] = row['repository']
        cases.append(row)
        for row in cases:
            with self.subTest(row=row):
                self.helm('gitops/roots/public', row, valid=False)

    def test_parent_renders_six_pinned_existing_children_without_arbitrary_overrides(self):
        children = self.parent()
        empty = native_source_inputs()
        empty['catalog'] = []
        self.assertEqual(len(self.parent(empty)), 6)
        self.assertEqual({o['metadata']['name'] for o in children}, {'cloudlab-observability',
            'cloudlab-prometheus', 'cloudlab-loki', 'cloudlab-tempo', 'cloudlab-alloy', 'cloudlab-kiali'})
        for child in children:
            spec = child['spec']
            self.assertNotIn('sources', spec)
            self.assertEqual(spec['project'], 'cloudlab-observability')
            self.assertEqual(spec['destination']['namespace'], 'cloudlab-observability')
            self.assertEqual(spec['source']['targetRevision'], 'a' * 40)
            self.assertFalse(spec['syncPolicy']['automated']['prune'])
            self.assertEqual(spec['source']['helm']['releaseName'], child['metadata']['name'])
        prometheus = next(o for o in children if o['metadata']['name'] == 'cloudlab-prometheus')
        self.assertEqual(prometheus['spec']['revisionHistoryLimit'], 0)
        self.assertNotIn('hostAliases', yaml.safe_dump(children))

    def test_parent_rejects_missing_foreign_and_unsupported_inputs(self):
        cases = []
        for key in ('catalog', 'observabilityInputs', 'nativeSource'):
            row = native_source_inputs()
            del row[key]
            cases.append(row)
        for key, value in [('apiPeers', ['192.0.2.1/0', '192.0.2.2/32']),
                           ('apiPeers', [':::::/128', '192.0.2.2/32']),
                           ('grafanaHost', 'grafana.internal.other.invalid'), ('monitoringEnabled', 'true'),
                           ('traces', {'enabled': True})]:
            row = native_source_inputs()
            row['observabilityInputs'][key] = value
            cases.append(row)
        for change in ('duplicate', 'namespace', 'name'):
            row = native_source_inputs()
            if change == 'duplicate': row['catalog'].append(copy.deepcopy(row['catalog'][0]))
            elif change == 'namespace': row['catalog'][0]['approval']['namespace'] = 'cloudlab-app-other'
            else: row['catalog'][0]['definition']['name'] = 'other'
            cases.append(row)
        for key in ('kube-prometheus-stack', 'serviceMonitoring', 'syncPolicy'):
            row = native_source_inputs()
            row[key] = {'enabled': True}
            cases.append(row)
        for key, value in [('revision', 'main'), ('valuesRevision', 'b' * 40),
                           ('valuesRepository', 'https://github.com/example/platform.git')]:
            row = native_source_inputs()
            row['nativeSource'][key] = value
            cases.append(row)
        for row in cases:
            with self.subTest(row=row): self.parent(row, valid=False)

    def test_typed_child_adapters_preserve_auth_routes_and_storage(self):
        children = {o['metadata']['name']: o for o in self.parent()}
        config = children['cloudlab-observability']['spec']['source']['helm']['valuesObject']
        objects = self.helm('platform/observability', config, namespace='cloudlab-observability')
        route = next(o for o in objects if o['kind'] == 'HTTPRoute' and o['metadata']['name'] == 'grafana')
        self.assertEqual(route['spec']['hostnames'], ['grafana.internal.example.invalid'])
        overrides = children['cloudlab-prometheus']['spec']['source']['helm']['valuesObject']
        objects = render('prometheus', overrides)
        ini = next(o['data']['grafana.ini'] for o in objects if o['kind'] == 'ConfigMap' and 'grafana.ini' in o.get('data', {}))
        for text in ('role_attribute_strict = true', 'use_pkce = true', 'allow_assign_grafana_admin = false',
                     'https://login.example.invalid/realms/platform/protocol/openid-connect/token'):
            self.assertIn(text, ini)
        prometheus = next(o for o in objects if o['kind'] == 'Prometheus')
        self.assertEqual(prometheus['spec']['storage']['volumeClaimTemplate']['spec']['storageClassName'], 'cloudlab-telemetry')
        kiali = children['cloudlab-kiali']['spec']['source']['helm']['valuesObject']['kiali-server']
        self.assertEqual(kiali['auth']['openid']['issuer_uri'], 'https://login.example.invalid/realms/platform')

    def test_root_three_states_and_missing_binding_preserve_foundations(self):
        values = self.root_values()
        values['observability']['configuration']['paused'] = False
        objects = self.helm('gitops/roots/public', values)
        parent = next(o for o in objects if o['kind'] == 'Application' and o['metadata']['name'] == 'cloudlab-observability-gitops')
        self.assertEqual(parent['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'], 'false')
        self.assertTrue(parent['spec']['syncPolicy']['automated']['enabled'])
        del values['identity']['argo']
        objects = self.helm('gitops/roots/public', values)
        self.assertFalse(any(o['metadata']['name'].startswith('cloudlab-observability-gitops') for o in objects))
        self.assertTrue(any(o['metadata']['name'] == 'cloudlab-observability' for o in objects))
        defaults = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
        self.assertEqual(defaults['observability']['configuration'], {'enabled': False, 'paused': True, 'revision': ''})
        self.assertTrue(defaults['data']['configuration']['enabled'])

    def test_native_digest_is_stable_sensitive_and_separate_from_legacy_revision(self):
        def digest(values):
            children = self.parent(values)
            digests = {o['metadata']['annotations']['cloudlab.io/observability-input-digest'] for o in children}
            self.assertEqual(len(digests), 1)
            value = digests.pop()
            self.assertRegex(value, r'^[a-f0-9]{64}$')
            prometheus = next(o for o in children if o['metadata']['name'] == 'cloudlab-prometheus')
            overrides = prometheus['spec']['source']['helm']['valuesObject']
            self.assertNotIn('serviceCatalogRevision', overrides)
            self.assertEqual(overrides['nativeInputDigest'], value)
            return value, overrides
        values = native_source_inputs()
        baseline, overrides = digest(values)
        merged = yaml.safe_load((ROOT / 'platform/observability/gitops/values.yaml').read_text()) | values
        consumed = {key: merged[key] for key in ('catalog', 'observabilityInputs', 'platformNotifications', 'serviceObservability', 'alertmanagerState')}
        self.assertEqual(baseline, hashlib.sha256(json.dumps(consumed, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
        self.assertEqual(digest(dict(reversed(list(values.items()))))[0], baseline)
        changed_public = copy.deepcopy(values)
        changed_public['nativeSource']['revision'] = 'c' * 40
        self.assertEqual(digest(changed_public)[0], baseline)
        for key, value in [('catalog', []), ('observabilityInputs', dict(values['observabilityInputs'], monitoringEnabled=False)),
                           ('platformNotifications', {'enabled': False, 'repeatIntervalSeconds': 3600})]:
            row = copy.deepcopy(values)
            row[key] = value
            self.assertNotEqual(digest(row)[0], baseline)
        objects = render('prometheus', dict(overrides, serviceCatalogRevision='d' * 40))
        dashboard = next(o for o in objects if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'cloudlab-dashboards')
        self.assertEqual(dashboard['metadata']['annotations'], {'cloudlab.io/observability-input-digest': baseline,
            'cloudlab.io/service-catalog-revision': 'd' * 40})


if __name__ == '__main__':
    unittest.main()
