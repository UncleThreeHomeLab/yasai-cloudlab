import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from automation.observability.chart import render
from automation.observability.configuration import grafana
from automation.observability.values import values
from automation.observability.verify import dashboards_ready


ROOT = Path(__file__).resolve().parents[3]


class DashboardTests(unittest.TestCase):
    def test_chart_provisions_only_nodes_with_resolvable_sources_and_home(self):
        config = next(obj for obj in render('prometheus') if obj['kind'] == 'ConfigMap'
                      and obj['metadata']['name'] == 'cloudlab-dashboards')
        files = {path.name: path.read_text() for path in
                 (ROOT / 'platform/observability/prometheus/dashboards').glob('*.json')}
        self.assertEqual(config['data'], files)
        dashboards = [json.loads(raw) for raw in files.values()]
        self.assertEqual({d['uid'] for d in dashboards}, {'cloudlab-nodes'})
        settings = values('prometheus')['grafana']
        sources = {d['uid'] for d in settings['datasources']['datasources.yaml']['datasources']}
        for dashboard in dashboards:
            self.assertFalse(dashboard['editable'])
            self.assertLessEqual(len(dashboard['panels']), 8)
            self.assertEqual(len({p['id'] for p in dashboard['panels']}), len(dashboard['panels']))
            for panel in dashboard['panels']:
                self.assertIn(panel['datasource']['uid'], sources)
                self.assertTrue(panel['targets'])
                self.assertEqual(panel['fieldConfig']['defaults']['noValue'], 'UNKNOWN')
                if panel['type'] == 'table':
                    fields = panel['transformations'][0]['options']['include']['names']
                    self.assertLessEqual(len(fields), 4)
                    self.assertFalse(set(fields) & {'Time', '__name__', 'instance', 'job', 'endpoint', 'container'})
                if panel['type'] == 'stat':
                    mappings = panel['fieldConfig']['defaults']['mappings']
                    self.assertEqual({mapping['options']['match'] for mapping in mappings}, {'null', 'nan'})
                    self.assertTrue(all(mapping['options']['result']['color'] == 'gray' for mapping in mappings))
        provider = settings['dashboardProviders']['providers.yaml']['providers'][0]
        self.assertFalse(provider['disableDeletion'])
        self.assertFalse(provider['allowUiUpdates'])
        home = grafana('https://login.example.invalid/realms/platform',
                       'https://grafana.internal.example.invalid')['ini']['dashboards']['default_home_dashboard_path']
        self.assertEqual(Path(home).name, 'nodes.json')
        self.assertIn(Path(home).name, files)
        nodes = next(d for d in dashboards if d['uid'] == 'cloudlab-nodes')
        self.assertFalse(any(p['type'] == 'table' for p in nodes['panels']))

    def test_runtime_rejects_stale_unmanaged_or_retained_dashboards_and_query_failures(self):
        expected = json.loads((ROOT / 'platform/observability/prometheus/dashboards/nodes.json').read_text())
        actual = {'meta': {'provisioned': True}, 'dashboard': copy.deepcopy(expected)}
        responses = [(200, json.dumps(actual).encode())] + [(404, b'{}')] * 4
        with patch('automation.observability.verify.direct_https', side_effect=responses), \
                patch('automation.observability.verify.proxy', return_value={'status': 'success'}) as query:
            self.assertTrue(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {'nodes': expected}))
            self.assertTrue(query.called)
            self.assertTrue(all('$' not in call.args[-1] for call in query.call_args_list))
        for status, altered in ((404, actual), (200, dict(actual, meta={})),
                                (200, dict(actual, dashboard=dict(expected, panels=[])))):
            with patch('automation.observability.verify.direct_https', return_value=(status, json.dumps(altered).encode())):
                self.assertFalse(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {'nodes': expected}))
        with patch('automation.observability.verify.direct_https', return_value=(200, json.dumps(actual).encode())), \
                patch('automation.observability.verify.proxy', return_value={'status': 'error'}):
            with self.assertRaises(RuntimeError):
                dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {'nodes': expected})
        for index in range(4):
            retained = [(404, b'{}')] * 4
            retained[index] = (200, b'{}')
            with self.subTest(retained=index), \
                    patch('automation.observability.verify.direct_https', side_effect=retained):
                self.assertFalse(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {}))
        with patch('automation.observability.verify.direct_https', return_value=(200, b'{}')):
            self.assertFalse(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {}))
