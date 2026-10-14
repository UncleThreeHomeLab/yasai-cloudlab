import json
import unittest

from automation.observability.slo import ROOT, dashboard, definition, expressions, rules


class SLOTests(unittest.TestCase):
    def test_rules_and_dashboards_have_one_native_owner_and_definition(self):
        path = ROOT / 'platform/observability/prometheus/templates'
        self.assertEqual(json.loads((path / 'notes-slo.json').read_text())['spec'], rules())
        provisioned = json.loads((path / 'dashboards.json').read_text())['data']['notes-slo.json']
        self.assertEqual(json.loads(provisioned), dashboard())
        self.assertFalse(dashboard()['editable'])
        from automation.observability.values import values
        identifiers = {row['uid'] for row in values('prometheus')['grafana']['datasources']['datasources.yaml']['datasources']}
        self.assertTrue(all(panel['datasource']['uid'] in identifiers for panel in dashboard()['panels']))

    def test_window_budget_math_and_evidence_are_explicit(self):
        policy = definition()
        self.assertEqual(policy['window_seconds'], 7 * 86400)
        self.assertEqual(len(rules()['groups'][0]['rules']), 7)
        for window in policy['burn_windows']:
            threshold = window['budget_fraction'] * policy['window_seconds'] / window['seconds']
            self.assertGreater(threshold, 1)
        for indicator in ('availability', 'latency'):
            count, bad = expressions(indicator, '1h')
            self.assertIn('traffic="user"', count)
            self.assertIn('status=~"2..|5.."', count)
            self.assertNotIn('release', count)
            self.assertIn('or vector(0)', bad)
        self.assertIn('absent(', rules()['groups'][0]['rules'][-2]['expr'])
        self.assertIn('absent_over_time(', rules()['groups'][0]['rules'][-1]['expr'])
        self.assertIn('20159', rules()['groups'][0]['rules'][-2]['expr'])
        for panel in dashboard()['panels']:
            if panel['type'] == 'stat':
                self.assertIn('sum_over_time(notes:slo_evidence:present[7d])', panel['targets'][0]['expr'])
