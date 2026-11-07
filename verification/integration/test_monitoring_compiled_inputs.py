"""Per-service monitoring derives from catalog and reviewed observability inputs.

Renders platform/observability/gitops with a prices catalog entry plus
serviceObservability rules/dashboard, and checks the derived scrape
bindings, native rules, dashboards and notification annotation on the six
child Applications. Retired services are excluded; unbound declarations
fail rendering.
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]

INPUTS = {'loginHost': 'login.example.test',
          'grafanaHost': 'grafana.internal.example.test',
          'kialiHost': 'kiali.internal.example.test',
          'apiPeers': ['10.0.0.11/32', '10.0.0.12/32'],
          'monitoringEnabled': True}


def prices(publication='ready'):
    return {
        'approval': {'name': 'prices', 'namespace': 'cloudlab-app-prices'},
        'definition': {
            'name': 'prices', 'owner': 'service-platform',
            'replicas': 1,
            'exposure': {'class': 'none'},
            'rollouts': {'enabled': False},
            'ports': [{'name': 'http', 'port': 8080},
                      {'name': 'http-metrics', 'port': 9091}],
            'health': {'readiness': {'port': 'http', 'path': '/healthz'},
                       'liveness': {'port': 'http', 'path': '/healthz'}},
            'monitoring': {
                'enabled': True,
                'routes': ['/api/prices', '/api/prices/:id'],
                'metrics': {'enabled': True, 'profile': 'cloudlab-http',
                            'endpoints': [{'port': 'http-metrics',
                                           'path': '/metrics'}]},
                'logs': {'enabled': True,
                         'profile': 'cloudlab-http-json-v1'}}},
        'publication': publication}


def merged_values(*catalog):
    return {
        'nativeSource': {
            'repository': 'https://github.com/example/platform.git',
            'revision': 'a' * 40,
            'valuesRepository': 'https://github.com/example/private.git'},
        'catalog': list(catalog),
        'observabilityInputs': dict(INPUTS),
        'serviceObservability': {
            'prices': {
                'rules': {'availability': {'groups': [{
                    'name': 'prices-metrics',
                    'rules': [{
                        'alert': 'Svc_prices_MetricsUnavailable',
                        'expr': 'absent_over_time(up{service="prices"}[5m])',
                        'for': '2m',
                        'labels': {'severity': 'warning'},
                        'annotations': {'summary': 'Prices metrics unavailable'}}]}]}},
                'dashboard': {
                    'uid': 'svc-prices', 'title': 'Prices', 'editable': False,
                    'panels': [{'title': 'Requests', 'targets': []}]}}},
    }


def render(values):
    if shutil.which('helm') is None:
        raise unittest.SkipTest('helm renders the observability parent')
    with tempfile.TemporaryDirectory() as workspace:
        work = Path(workspace)
        (work / 'values.yaml').write_text(yaml.safe_dump(values))
        rendered = subprocess.check_output(
            ['helm', 'template', '--kube-version', '1.36',
             '-f', str(work / 'values.yaml'),
             str(ROOT / 'platform/observability/gitops')],
            text=True, timeout=120, stderr=subprocess.STDOUT)
    return [doc for doc in yaml.safe_load_all(rendered) if doc]


def application(documents, name):
    return next(doc for doc in documents
                if doc.get('kind') == 'Application'
                and doc['metadata']['name'] == name)


class MonitoringCompiledInputsTests(unittest.TestCase):
    def test_prices_bindings_rules_and_dashboard_derive(self):
        documents = render(merged_values(prices()))
        names = sorted(doc['metadata']['name'] for doc in documents
                       if doc.get('kind') == 'Application')
        self.assertEqual(names, ['cloudlab-alloy', 'cloudlab-kiali',
                                 'cloudlab-loki', 'cloudlab-observability',
                                 'cloudlab-prometheus', 'cloudlab-tempo'])
        digest = {doc['metadata']['annotations'][
            'cloudlab.io/observability-input-digest'] for doc in documents
            if doc.get('kind') == 'Application'}
        self.assertEqual(len(digest), 1)
        prometheus = application(documents, 'cloudlab-prometheus')
        values = prometheus['spec']['source']['helm']['valuesObject']
        lifecycle = values['nativeLifecycle']
        self.assertEqual(lifecycle['serviceMetrics']['prices'], {
            'namespace': 'cloudlab-app-prices', 'port': 9091,
            'routes': ['/api/prices', '/api/prices/:id'],
            'owner': 'service-platform'})
        rules = lifecycle['serviceRules']['svc-prices-availability']['groups']
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]['name'],
                         'svc-prices-availability-prices-metrics')
        alert = rules[0]['rules'][0]
        self.assertEqual(alert['alert'], 'Svc_prices_MetricsUnavailable')
        self.assertEqual(alert['labels']['service'], 'prices')
        self.assertEqual(alert['labels']['namespace'], 'cloudlab-app-prices')
        self.assertEqual(alert['labels']['severity'], 'warning')
        self.assertEqual(
            alert['annotations']['dashboard_url'],
            'https://grafana.internal.example.test/d/svc-prices')
        self.assertIn('logs_url', alert['annotations'])
        board = yaml.safe_load(
            values['serviceDashboards']['svc-prices.json'])
        self.assertEqual((board['uid'], board['title'], board['editable']),
                         ('svc-prices', 'Prices', False))
        self.assertIn({'title': 'prices', 'type': 'link', 'url': '/d/svc-prices'},
                      values['serviceDashboardLinks'])
        self.assertEqual(
            prometheus['metadata']['annotations'][
                'cloudlab.io/notification-delivery'],
            'unconfigured')
        configuration = application(documents, 'cloudlab-observability')
        configuration_values = (
            configuration['spec']['source']['helm']['valuesObject'])
        self.assertEqual(configuration_values['serviceMetrics']['prices'],
                         lifecycle['serviceMetrics']['prices'])
        self.assertEqual(configuration_values['serviceLogs']['prices'], {
            'namespace': 'cloudlab-app-prices',
            'routes': ['/api/prices', '/api/prices/:id'],
            'owner': 'service-platform', 'profile': 'cloudlab-http-json-v1'})

    def test_retired_prices_is_excluded_from_collection(self):
        documents = render(merged_values(prices('retired')) | {
            'serviceObservability': {}})
        prometheus = application(documents, 'cloudlab-prometheus')
        values = prometheus['spec']['source']['helm']['valuesObject']
        lifecycle = values['nativeLifecycle']
        self.assertEqual(lifecycle['serviceMetrics'], {})
        self.assertEqual(lifecycle['serviceRules'], {})
        self.assertEqual(values['serviceDashboards'], {})

    def test_unbound_or_retired_declarations_fail_closed(self):
        if shutil.which('helm') is None:
            raise unittest.SkipTest('helm renders the observability parent')
        retired = merged_values(prices('retired'))
        unknown = merged_values(prices())
        unknown['serviceObservability'] = {'unknown': {'rules': {}}}
        for values in (retired, unknown):
            with self.subTest(values=values['serviceObservability']):
                with tempfile.TemporaryDirectory() as workspace:
                    work = Path(workspace)
                    (work / 'values.yaml').write_text(yaml.safe_dump(values))
                    with self.assertRaises(subprocess.CalledProcessError):
                        subprocess.check_output(
                            ['helm', 'template', '--kube-version', '1.36',
                             '-f', str(work / 'values.yaml'),
                             str(ROOT / 'platform/observability/gitops')],
                            text=True, timeout=120, stderr=subprocess.STDOUT)


if __name__ == '__main__':
    unittest.main()
