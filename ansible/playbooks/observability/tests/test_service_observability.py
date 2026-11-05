"""Native collection isolation, trusted rule inputs and one bounded override payload."""
import copy
import json
from pathlib import Path
import subprocess
import tarfile
import unittest

import jsonschema
import yaml

from playbooks.observability.tests.fixtures import monitored_service_inputs, logged_service_inputs, native_source_inputs, helm, native_overrides
from playbooks.observability.files.chart import render
from playbooks.services.files import package

ROOT = Path(__file__).resolve().parents[4]



class ServiceObservabilityTests(unittest.TestCase):
    def test_independent_logs_contract_preserves_metrics_policy_and_scoped_reader(self):
        value = logged_service_inputs()
        definition = value['catalog'][0]['definition']
        definition['exposure'] = {'class': 'public', 'hostname': 'fixture.example.invalid',
            'access': 'public', 'port': 8080, 'path': '/'}
        def catalog():
            return helm('platform/delivery/services', {'repository': value['nativeSource']['repository'], 'catalog': value['catalog']})
        objects = catalog()
        policies = [o for o in objects if o['kind'] in ('NetworkPolicy', 'AuthorizationPolicy')]
        role = next(o for o in objects if o['kind'] == 'Role' and o['metadata']['name'] == 'cloudlab-alloy-logs')
        self.assertEqual(role['metadata']['namespace'], 'cloudlab-app-synthetic')
        self.assertEqual(role['rules'], [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list', 'watch']},
                                       {'apiGroups': [''], 'resources': ['pods/log'], 'verbs': ['get']}])
        binding = next(o for o in objects if o['kind'] == 'RoleBinding' and o['metadata']['name'] == role['metadata']['name'])
        self.assertEqual(binding['subjects'], [{'kind': 'ServiceAccount', 'name': 'cloudlab-alloy', 'namespace': 'cloudlab-observability'}])
        overrides = native_overrides(value)['cloudlab-observability']
        self.assertEqual(overrides['serviceMetrics'], {})
        self.assertEqual(set(overrides['serviceLogs']), {'synthetic'})
        rendered = helm('platform/observability', overrides)
        self.assertFalse(any(o['kind'] == 'PodMonitor' and o['metadata']['name'] == 'svc-synthetic' for o in rendered))
        workload = next(o for o in helm('charts/service', definition) if o['kind'] == 'Deployment')
        self.assertEqual(workload['spec']['template']['metadata']['labels']['cloudlab.io/log-profile'], 'cloudlab-http-json-v1')
        definition['monitoring'] = {'enabled': False}
        disabled = catalog()
        self.assertEqual(policies, [o for o in disabled if o['kind'] in ('NetworkPolicy', 'AuthorizationPolicy')])
        self.assertFalse(any(o['kind'] == 'Role' and o['metadata']['name'] == role['metadata']['name'] for o in disabled))

    def test_signal_declarations_fail_closed_and_links_require_log_coverage(self):
        for change in ('no-signal', 'disabled', 'trace', 'old-route', 'other', 'log-profile'):
            value = logged_service_inputs()
            monitor = value['catalog'][0]['definition']['monitoring']
            if change == 'no-signal': monitor['logs'] = {'enabled': False}
            if change == 'disabled': monitor['enabled'] = False
            if change == 'trace': monitor['traces'] = {'enabled': True}
            if change == 'old-route': monitor['metrics']['routes'] = monitor.pop('routes')
            if change == 'other': monitor['routes'] = ['other']
            if change == 'log-profile': monitor['logs']['profile'] = 'raw'
            for chart in ('charts/service', 'platform/delivery/services', 'platform/observability/gitops'):
                candidate = value if chart.endswith('gitops') else (value['catalog'][0]['definition'] if chart == 'charts/service' else {
                    'repository': value['nativeSource']['repository'], 'catalog': value['catalog']})
                with self.subTest(change=change, chart=chart), self.assertRaises(ValueError): helm(chart, candidate)
        for logs in (False, True):
            value = logged_service_inputs(metrics=True) if logs else monitored_service_inputs()
            overrides = native_overrides(value)['cloudlab-observability']
            self.assertEqual(bool(overrides['serviceMetrics']), True)
            rule = overrides['serviceRules']['svc-synthetic-availability']['groups'][0]['rules'][0]
            self.assertEqual('logs_url' in rule['annotations'], logs)
            if logs:
                self.assertIn('service%3D', rule['annotations']['logs_url'])
                self.assertNotIn('namespace', rule['annotations']['logs_url'])

    def test_generated_logs_keep_trusted_targets_and_enter_aggregate_budget(self):
        value = logged_service_inputs()
        overrides = native_overrides(value)['cloudlab-observability']
        config = next(o['data']['config.alloy'] for o in helm('platform/observability', overrides)
                      if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'cloudlab-alloy')
        legacy = (ROOT / 'platform/observability/config.alloy').read_text()
        self.assertTrue(config.startswith(legacy))
        self.assertIn('app.kubernetes.io/name=synthetic,cloudlab.io/owner=', config)
        self.assertIn('cloudlab.io/log-profile=cloudlab-http-json-v1,!cloudlab.io/release-analysis', config)
        self.assertIn('regex = "application"', config)
        self.assertIn('values = ["service", "kind"]', config)
        self.assertIn('generic_oversize', config)
        value['serviceObservability']['synthetic']['dashboard']['description'] = 'a' * 90000
        for n in range(15):
            entry = copy.deepcopy(value['catalog'][0])
            name = 'service' + str(n)
            entry['approval'].update(name=name, namespace='cloudlab-app-' + name)
            entry['definition'].update(name=name, monitoring={'enabled': False})
            value['catalog'].append(entry)
        value['serviceObservability']['service0'] = {'dashboard': {
            'uid': 'svc-service0', 'title': 'Service 0', 'editable': False, 'panels': [], 'description': 'b' * 90000}}
        native_overrides(value)
        for entry in value['catalog'][1:]:
            entry['definition']['monitoring'] = {'enabled': True,
                'routes': ['/r' + str(n) + 'x' * 93 for n in range(8)],
                'logs': {'enabled': True, 'profile': 'cloudlab-http-json-v1'}}
        with self.assertRaises(ValueError): native_overrides(value)

    def test_canonical_schema_and_independent_consumer_validation(self):
        package.check()
        schema = json.loads((ROOT / 'charts/service/values.schema.json').read_text())
        native = json.loads((ROOT / 'platform/observability/gitops/values.schema.json').read_text())
        value = monitored_service_inputs()
        definition = value['catalog'][0]['definition']
        jsonschema.validate(definition, schema)
        jsonschema.validate(value, native)
        for change in ('unknown', 'profile', 'query-route', 'duplicate-route', 'endpoint', 'many-routes'):
            row = copy.deepcopy(value)
            monitoring = row['catalog'][0]['definition']['monitoring']
            metrics = monitoring['metrics']
            if change == 'unknown': monitoring['receiver'] = 'unexpected'
            if change == 'profile': metrics['profile'] = 'arbitrary'
            if change == 'query-route': monitoring['routes'] = ['/api/items?token=secret']
            if change == 'duplicate-route': monitoring['routes'] *= 2
            if change == 'endpoint': metrics['endpoints'] *= 2
            if change == 'many-routes': monitoring['routes'] = ['/route' + str(n) for n in range(9)]
            with self.subTest(change=change):
                for candidate, contract in ((row['catalog'][0]['definition'], schema), (row, native)):
                    with self.assertRaises(jsonschema.ValidationError): jsonschema.validate(candidate, contract)

    def test_cross_fields_rejected_by_both_catalog_and_native_owner(self):
        cases = []
        for change in ('missing-port', 'aliased-port', 'duplicate-name', 'udp', 'probe', 'public', 'private',
                       'additional', 'implicit-exposure', 'rollout', 'notes', 'composition', 'targets'):
            row = monitored_service_inputs()
            entry = row['catalog'][0]
            definition = entry['definition']
            if change == 'missing-port': definition['ports'].pop()
            if change == 'aliased-port': definition['ports'].append({'name': 'alias', 'port': 9191})
            if change == 'duplicate-name': definition['ports'].append({'name': 'http-metrics', 'port': 9292})
            if change == 'udp': definition['ports'][-1]['protocol'] = 'UDP'
            if change == 'probe': definition['health']['readiness']['port'] = 'http-metrics'
            if change in ('public', 'private', 'implicit-exposure', 'additional'):
                definition['exposure'] = {'class': 'public', 'hostname': 'fixture.example.invalid',
                    'access': 'public', 'port': 8080, 'path': '/'}
                if change in ('public', 'private'): definition['exposure'].update({'class': change, 'port': 9191})
                if change == 'additional': definition['additionalExposures'] = [dict(definition['exposure'], **{'class': 'private', 'port': 9191})]
                if change == 'implicit-exposure': definition['exposure'].pop('port')
            if change == 'rollout': definition['rollouts']['enabled'] = True
            if change == 'notes': entry['approval']['chartPath'] = 'apps/notes'
            if change == 'composition': entry['approval']['composition'] = {}
            if change == 'targets': definition['replicas'] = 5
            cases.append((change, row))
        for change, value in cases:
            with self.subTest(change=change):
                for chart in ('platform/delivery/services', 'platform/observability/gitops'):
                    with self.assertRaises(ValueError): helm(chart, value if chart.endswith('gitops') else {
                        'repository': value['nativeSource']['repository'], 'catalog': value['catalog']})

    def test_combined_application_allow_rules_isolate_metrics_and_preserve_ports_order(self):
        value = monitored_service_inputs()
        definition = value['catalog'][0]['definition']
        definition['exposure'] = {'class': 'public', 'hostname': 'fixture.example.invalid', 'access': 'public', 'port': 8080, 'path': '/'}
        definition['ports'].append({'name': 'private', 'port': 8443})
        definition['additionalExposures'] = [dict(definition['exposure'], **{'class': 'private', 'port': 8443})]
        def policies():
            return helm('platform/delivery/services', {'repository': value['nativeSource']['repository'], 'catalog': value['catalog']})
        objects = policies()
        policy = next(o for o in objects if o['kind'] == 'AuthorizationPolicy' and o['metadata']['name'] == 'platform-workloads')
        def allowed(principal, port):
            for rule in policy['spec']['rules']:
                identities = [p for origin in rule.get('from', []) for p in origin['source'].get('principals', [])]
                if principal not in identities: continue
                for target in rule.get('to', [{'operation': {}}]):
                    operation = target['operation']
                    if ('ports' not in operation or str(port) in operation['ports']) and str(port) not in operation.get('notPorts', []):
                        return True
            return False
        prefixes = 'cluster.local/ns/'
        callers = {'prometheus': prefixes + 'cloudlab-observability/sa/cloudlab-prometheus',
            'app': prefixes + 'cloudlab-app-synthetic/sa/synthetic',
            'same-namespace': prefixes + 'cloudlab-app-synthetic/sa/other',
            'observability-peer': prefixes + 'cloudlab-observability/sa/cloudlab-alloy',
            'public': prefixes + 'cloudlab-gateway-public/sa/cloudlab-istio',
            'private': prefixes + 'cloudlab-gateway-private/sa/cloudlab-istio', 'unauthenticated': ''}
        expected = {'prometheus': {9191}, 'app': {8080, 8443}, 'public': {8080}, 'private': {8443}}
        for caller, principal in callers.items():
            for port in (8080, 8443, 9191):
                self.assertEqual(allowed(principal, port), port in expected.get(caller, set()), (caller, port))
        definition['ports'].reverse()
        self.assertEqual(next(o for o in policies() if o['kind'] == 'AuthorizationPolicy' and o['metadata']['name'] == 'platform-workloads'), policy)
        workload = helm('charts/service', definition)
        self.assertFalse(any(o['kind'] in ('PodMonitor', 'AuthorizationPolicy', 'NetworkPolicy') for o in workload))
        service = next(o for o in workload if o['kind'] == 'Service')
        self.assertEqual({p['port']: p['targetPort'] for p in service['spec']['ports']}, {9191: 'http-metrics', 8080: 'http', 8443: 'private'})

    def test_native_limits_match_pinned_crd_and_rules_and_dashboards_reach_native_owners(self):
        value = monitored_service_inputs()
        overrides = native_overrides(value)
        configuration = helm('platform/observability', overrides['cloudlab-observability'])
        monitor = next(o for o in configuration if o['kind'] == 'PodMonitor' and o['metadata']['name'] == 'svc-synthetic')
        archive = ROOT / 'platform/observability/prometheus/charts/kube-prometheus-stack-92.3.1.tgz'
        with tarfile.open(archive) as source:
            name = next(n for n in source.getnames() if n.endswith('/crd-podmonitors.yaml'))
            crd = yaml.safe_load(source.extractfile(name))
        schema = next(v for v in crd['spec']['versions'] if v['name'] == 'v1')['schema']['openAPIV3Schema']
        jsonschema.validate(monitor, schema)
        spec = monitor['spec']
        self.assertEqual((spec['bodySizeLimit'], spec['sampleLimit'], spec['targetLimit'], spec['labelLimit']), ('1MB', 1000, 8, 20))
        endpoint = spec['podMetricsEndpoints'][0]
        self.assertFalse(endpoint['honorLabels'])
        self.assertFalse(endpoint['honorTimestamps'])
        self.assertEqual(spec['selector']['matchExpressions'], [{'key': 'cloudlab.io/release-analysis', 'operator': 'DoesNotExist'}])
        rules = next(o for o in configuration if o['kind'] == 'PrometheusRule' and o['metadata']['name'] == 'svc-synthetic-availability')
        alert = rules['spec']['groups'][0]['rules'][0]
        self.assertEqual(alert['labels']['service'], 'synthetic')
        self.assertIn('/d/svc-synthetic', alert['annotations']['dashboard_url'])
        prometheus = render('prometheus', overrides['cloudlab-prometheus'])
        dashboards = next(o['data'] for o in prometheus if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'cloudlab-dashboards')
        self.assertEqual(json.loads(dashboards['svc-synthetic.json'])['uid'], 'svc-synthetic')
        self.assertIn('ALERTS{', dashboards['active-alerts.json'])
        links = json.loads(dashboards['active-alerts.json'])['links']
        self.assertEqual(links, [{'title': 'synthetic', 'type': 'link', 'url': '/d/svc-synthetic'}])
        empty = native_overrides(native_source_inputs())
        self.assertEqual(empty['cloudlab-observability']['serviceMetrics'], {})

    def test_target_limit_reserves_default_pod_quota_for_surge_and_terminating_overlap(self):
        value = monitored_service_inputs()
        definition = value['catalog'][0]['definition']
        definition['replicas'] = 3
        overrides = native_overrides(value)
        configuration = helm('platform/observability', overrides['cloudlab-observability'])
        monitor = next(o for o in configuration if o['kind'] == 'PodMonitor' and o['metadata']['name'] == 'svc-synthetic')
        workload = next(o for o in helm('charts/service', definition) if o['kind'] == 'Deployment')
        catalog = helm('platform/delivery/services', {
            'repository': value['nativeSource']['repository'], 'catalog': value['catalog']})
        quota = next(o for o in catalog if o['kind'] == 'ResourceQuota')
        replicas = workload['spec']['replicas']
        surge = workload['spec']['strategy']['rollingUpdate']['maxSurge']
        targets = monitor['spec']['targetLimit']
        self.assertEqual((replicas, surge), (3, 1))
        self.assertEqual((int(quota['spec']['hard']['pods']), targets), (8, 8))
        # Reserve the default pod quota, including overlap beyond one surge pod.
        self.assertGreater(targets, replicas + surge)
        definition['replicas'] = 4
        with self.assertRaises(ValueError): native_overrides(value)
        with self.assertRaises(ValueError): helm('charts/service', definition)
        with self.assertRaises(ValueError):
            helm('platform/delivery/services', {
                'repository': value['nativeSource']['repository'], 'catalog': value['catalog']})

    def test_rules_only_links_use_existing_active_alerts_fallback(self):
        value = monitored_service_inputs()
        value['serviceObservability']['synthetic'].pop('dashboard')
        overrides = native_overrides(value)
        rule = overrides['cloudlab-observability']['serviceRules']['svc-synthetic-availability']['groups'][0]['rules'][0]
        self.assertTrue(rule['annotations']['dashboard_url'].endswith('/d/active-alerts'))
        self.assertEqual(overrides['cloudlab-prometheus']['serviceDashboardLinks'], [])

    def test_rule_dashboard_binding_and_total_payload_fail_closed(self):
        for change in ('foreign', 'retired', 'label', 'record-name-label', 'record-state-label', 'duplicate', 'group', 'record', 'uid', 'datasource', 'editable', 'overflow'):
            value = monitored_service_inputs()
            entry = value['serviceObservability']['synthetic']
            rule = entry['rules']['availability']['groups'][0]['rules'][0]
            if change == 'foreign': value['catalog'] = []
            if change == 'retired': value['catalog'][0]['publication'] = 'retired'
            if change == 'label': rule['labels'] = {'service': 'forged'}
            if change in ('record-name-label', 'record-state-label'):
                entry['rules']['availability']['groups'][0]['rules'][1]['labels'] = {
                    '__name__' if change == 'record-name-label' else 'alertstate': 'forged'}
            if change == 'duplicate': entry['rules']['availability']['groups'][0]['rules'].append(copy.deepcopy(rule))
            if change == 'group': entry['rules']['availability']['groups'] *= 2
            if change == 'record': entry['rules']['availability']['groups'][0]['rules'][1]['record'] = 'svc_foreign:requests:sum'
            if change == 'uid': entry['dashboard']['uid'] = 'foreign'
            if change == 'datasource': entry['dashboard']['panels'][0]['datasource']['uid'] = 'foreign'
            if change == 'editable': entry['dashboard']['editable'] = True
            if change == 'overflow':
                # Each board fits its cap, their total JSON-encoded inline values do not.
                for n in range(5):
                    name = 'service' + str(n)
                    value['catalog'].append({'approval': {'name': name, 'namespace': 'cloudlab-app-' + name}, 'definition': {'name': name}, 'publication': 'published'})
                    value['serviceObservability'][name] = {'dashboard': {'uid': 'svc-' + name, 'title': name, 'editable': False, 'panels': [], 'description': 'a' * 80000}}
            with self.subTest(change=change), self.assertRaises(ValueError): native_overrides(value)
