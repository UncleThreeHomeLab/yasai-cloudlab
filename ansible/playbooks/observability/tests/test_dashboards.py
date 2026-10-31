import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from playbooks.observability.files.chart import render
from playbooks.observability.files.configuration import grafana
from playbooks.observability.files.values import values
from playbooks.observability.files.verify import dashboards_ready, release_state_matches


ROOT = Path(__file__).resolve().parents[4]


class DashboardTests(unittest.TestCase):
    def test_release_view_compares_live_weights_and_roles_without_treating_absence_as_zero(self):
        rollout = {'status': {'stableRS': 'old', 'currentPodHash': 'new'}}
        route = {'spec': {'rules': [{'backendRefs': [{'name': 'app', 'weight': 50}, {'name': 'app-canary', 'weight': 50}]}]}}
        info = [{'metric': {'stable_revision': 'old', 'canary_revision': 'new'}}]
        weights = [{'metric': {'backend': name}, 'value': [0, '50']} for name in ('app', 'app-canary')]
        roles = [{'metric': {'role': role, 'revision': revision}, 'value': [0, '1']}
                 for role, revision in [('stable', 'old'), ('canary', 'new')]]
        self.assertTrue(release_state_matches(rollout, route, info, weights, roles))
        self.assertFalse(release_state_matches(rollout, route, info, weights, roles + roles[:1]))
        for inputs in (([], weights, roles), (info, [], roles), (info, weights, roles[:1])):
            self.assertFalse(release_state_matches(rollout, route, *inputs))
        stale = copy.deepcopy(weights)
        stale[0]['value'][1] = '100'
        self.assertFalse(release_state_matches(rollout, route, info, stale, roles))
        rollout['status']['currentPodHash'] = 'old'
        info[0]['metric']['canary_revision'] = 'old'
        self.assertFalse(release_state_matches(rollout, route, info, weights, roles))
        self.assertTrue(release_state_matches(rollout, route, info, weights, roles[:1]))

    def test_chart_provisions_nodes_and_releases_with_resolvable_sources_and_home(self):
        config = next(obj for obj in render('prometheus') if obj['kind'] == 'ConfigMap'
                      and obj['metadata']['name'] == 'cloudlab-dashboards')
        files = {path.name: path.read_text() for path in
                 (ROOT / 'platform/observability/prometheus/dashboards').glob('*.json')}
        self.assertEqual(config['data'], files)
        dashboards = [json.loads(raw) for raw in files.values()]
        self.assertEqual({d['uid'] for d in dashboards}, {'cloudlab-nodes', 'cloudlab-rollouts', 'cloudlab-services'})
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
        self.assertTrue(any(link.get('url') == '/d/cloudlab-rollouts' for link in nodes['links']))

    def test_service_view_uses_collected_workload_metrics_without_masking_missing_data(self):
        dashboard = json.loads((ROOT / 'platform/observability/prometheus/dashboards/services.json').read_text())
        namespace, = dashboard['templating']['list']
        self.assertEqual(namespace['name'], 'namespace')
        self.assertEqual(namespace['query'], 'label_values(kube_deployment_spec_replicas, namespace)')
        self.assertEqual(namespace['current'], {'text': 'All', 'value': '$__all'})
        self.assertIn('without readiness probes', dashboard['description'])
        expressions = [target['expr'] for panel in dashboard['panels'] for target in panel['targets']]
        self.assertEqual(len(expressions), 6)
        for expression in expressions:
            self.assertIn('namespace=~"$namespace"', expression)
            self.assertNotIn('or vector(0)', expression)
        for metric in ('kube_deployment_spec_replicas', 'kube_deployment_status_replicas_available',
                       'kube_pod_status_ready', 'kube_pod_container_status_restarts_total',
                       'container_cpu_usage_seconds_total', 'container_memory_working_set_bytes'):
            self.assertTrue(any(metric in expression for expression in expressions))

    def test_release_dashboard_distinguishes_configured_measured_idle_and_missing_data(self):
        dashboard = json.loads((ROOT / 'platform/observability/prometheus/dashboards/releases.json').read_text())
        panels = {panel['title']: panel for panel in dashboard['panels']}
        configured = panels['Configured traffic split']
        self.assertTrue(all('cloudlab_httproute_backend_weight' in target['expr'] for target in configured['targets']))
        observed = panels['Observed traffic split — last 2m']
        self.assertTrue(all('cloudlab:rollout_requests:rate2m' in target['expr'] for target in observed['targets']))
        self.assertTrue(all('or vector(0)' not in target['expr'] for panel in dashboard['panels'] for target in panel['targets']))
        mapping = observed['fieldConfig']['defaults']['mappings'][2]['options']
        self.assertEqual(mapping['-1']['text'], 'No traffic')
        self.assertTrue(all('> 0' in target['expr'] and '== 0' in target['expr'] for target in observed['targets']))
        self.assertIn('== 0', observed['targets'][1]['expr'])
        self.assertEqual(panels['Canary share over time']['targets'][1]['expr'], observed['targets'][1]['expr'])
        roles = panels['Stable and candidate revisions']['transformations'][0]['options']['include']['names']
        self.assertEqual(roles, ['role', 'revision'])

    def test_custom_state_uses_pinned_existing_exporter_with_only_read_access_and_config_rollout(self):
        objects = render('prometheus')
        deployment = next(obj for obj in objects if obj['kind'] == 'Deployment' and 'kube-state' in obj['metadata']['name'])
        self.assertIn('checksum/release-metrics', deployment['spec']['template']['metadata']['annotations'])
        role = next(obj for obj in objects if obj['kind'] == 'ClusterRole' and 'kube-state' in obj['metadata']['name'])
        custom = [rule for rule in role['rules'] if set(rule['resources']) & {'rollouts', 'httproutes', 'customresourcedefinitions'}]
        self.assertEqual({resource for rule in custom for resource in rule['resources']}, {'rollouts', 'httproutes', 'customresourcedefinitions'})
        self.assertTrue(all(set(rule['verbs']) == {'list', 'watch'} for rule in custom))
        config = values('prometheus')['kube-state-metrics']['customResourceState']['config']
        self.assertEqual({resource['groupVersionKind']['kind'] for resource in config['spec']['resources']}, {'Rollout', 'HTTPRoute'})
        route = config['spec']['resources'][1]['metrics'][0]['each']['gauge']
        self.assertEqual(route['path'], ['spec', 'rules', '0', 'backendRefs'])
        self.assertFalse(any(resource['groupVersionKind']['version'] == '*' for resource in config['spec']['resources']))

    def test_runtime_rejects_stale_unmanaged_or_retained_dashboards_and_query_failures(self):
        expected = json.loads((ROOT / 'platform/observability/prometheus/dashboards/nodes.json').read_text())
        actual = {'meta': {'provisioned': True}, 'dashboard': copy.deepcopy(expected)}
        responses = [(200, json.dumps(actual).encode())] + [(404, b'{}')] * 4
        with patch('playbooks.observability.files.verify.direct_https', side_effect=responses), \
                patch('playbooks.observability.files.verify.proxy', return_value={'status': 'success'}) as query:
            self.assertTrue(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {'nodes': expected}))
            self.assertTrue(query.called)
            self.assertTrue(all('$' not in call.args[-1] for call in query.call_args_list))
        for status, altered in ((404, actual), (200, dict(actual, meta={})),
                                (200, dict(actual, dashboard=dict(expected, panels=[])))):
            with patch('playbooks.observability.files.verify.direct_https', return_value=(status, json.dumps(altered).encode())):
                self.assertFalse(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {'nodes': expected}))
        with patch('playbooks.observability.files.verify.direct_https', return_value=(200, json.dumps(actual).encode())), \
                patch('playbooks.observability.files.verify.proxy', return_value={'status': 'error'}):
            with self.assertRaises(RuntimeError):
                dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {'nodes': expected})
        for index in range(4):
            retained = [(404, b'{}')] * 4
            retained[index] = (200, b'{}')
            with self.subTest(retained=index), \
                    patch('playbooks.observability.files.verify.direct_https', side_effect=retained):
                self.assertFalse(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {}))
        with patch('playbooks.observability.files.verify.direct_https', return_value=(200, b'{}')):
            self.assertFalse(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {}))
