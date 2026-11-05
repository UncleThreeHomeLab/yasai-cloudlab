import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from playbooks.observability.files.chart import render
from playbooks.observability.files.configuration import grafana
from playbooks.observability.files.values import values
from playbooks.observability.files.verify import dashboards_ready, release_state_matches
from playbooks.observability.files.dashboards import build, projection, generated, inventory, substitute, query_rules, overview
from playbooks.observability.tests.fixtures import service_bindings, service_visibility_tests


ROOT = Path(__file__).resolve().parents[4]


class DashboardTests(unittest.TestCase):
    def test_runtime_queries_both_levels_and_unsaved_component_variables(self):
        expected = {'overview': overview(service_bindings()), 'detail': build(service_bindings()[1])}
        responses = [(200, json.dumps({'meta': {'provisioned': True}, 'dashboard': board}).encode())
                     for board in expected.values()] + [(404, b'{}')] * 5
        with patch('playbooks.observability.files.verify.direct_https', side_effect=responses), \
                patch('playbooks.observability.files.verify.proxy', return_value={'status': 'success'}) as query:
            self.assertTrue(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, expected))
        from urllib.parse import parse_qs, urlsplit
        expressions = [parse_qs(urlsplit(call.args[-1]).query)['query'][0] for call in query.call_args_list]
        self.assertTrue(any('sort(' in expression for expression in expressions))
        self.assertTrue(all('${' not in expression for expression in expressions))
        self.assertTrue(all('namespace="fixture"' in expression for expression in expressions))

    def test_overview_height_is_bounded_and_empty_catalog_has_no_fake_service(self):
        self.assertEqual(overview([])['panels'][0]['gridPos']['h'], 5)
        services = [{'name': 'service-' + str(index), 'namespace': 'fixture',
                     'workloads': [{'name': 'workload-' + str(index), 'kind': 'Deployment'}]} for index in range(20)]
        self.assertEqual(overview(services)['panels'][0]['gridPos']['h'], 16)
        self.assertEqual(overview([])['templating'], {'list': []})

    def test_runtime_service_views_render_owned_rollouts_and_deployments_without_changing_static_boards(self):
        services = service_bindings()
        dynamic = generated(services)
        config = next(obj for obj in render('prometheus', {'serviceDashboards': dynamic, 'serviceCatalogRevision': 'a' * 40})
                      if obj['kind'] == 'ConfigMap' and obj['metadata']['name'] == 'cloudlab-dashboards')
        self.assertEqual(config['data'], inventory(services))
        self.assertEqual(config['metadata']['annotations']['cloudlab.io/service-catalog-revision'], 'a' * 40)
        for name, raw in dynamic.items():
            board = json.loads(raw)
            self.assertFalse(board['editable'])
            if name == 'service-overview.json':
                self.assertEqual(board['uid'], 'cloudlab-service-overview')
                self.assertEqual(len(board['panels']), 1)
                table, = board['panels']
                self.assertEqual(table['type'], 'table')
                self.assertEqual(table['gridPos']['w'], 24)
                self.assertEqual(table['gridPos']['h'], 5)
                for target in table['targets']:
                    self.assertTrue(target['instant'])
                    self.assertFalse(target['range'])
                    self.assertNotIn('container_', target['expr'])
                    self.assertNotIn('kube_pod_', target['expr'])
                    self.assertNotIn('ALERTS', target['expr'])
                self.assertIn('/d/svc-${__value.raw}', json.dumps(table['fieldConfig']['overrides']))
                self.assertEqual(table['transformations'][2]['options']['sort'], [{'field': 'Value #A', 'desc': False}])
                continue
            self.assertTrue(board['uid'].startswith('svc-'))
            self.assertLessEqual(len(board['panels']), 12)
            self.assertTrue(all(target['instant'] and target['range'] is False for panel in board['panels']
                                if panel['type'] == 'stat' for target in panel['targets']))
            self.assertFalse(any(panel['type'] == 'table' for panel in board['panels']))
            component = board['templating']['list'][0]
            self.assertEqual(component['sort'], 0)
            self.assertEqual(component['current'], {})
            self.assertTrue(component['query'].startswith('query_result(sort('))
            self.assertTrue(any(link['url'] == '/d/cloudlab-service-overview' for link in board['links']))
            for variable in board['templating']['list']:
                self.assertFalse(variable['multi'])
                self.assertFalse(variable['includeAll'])
            for panel in board['panels']:
                self.assertEqual(panel['fieldConfig']['defaults']['noValue'], 'UNKNOWN')
                if panel['type'] == 'table':
                    fields = next(t for t in panel['transformations'] if t['id'] == 'filterFieldsByName')['options']['include']['names']
                    self.assertLessEqual(len(fields), 4)
                for target in panel['targets']:
                    self.assertNotIn('kube_pod_labels', target['expr'])
                    self.assertNotIn('or vector(0)', target['expr'])
                    if panel['id'] == 1:
                        self.assertNotIn('${component', target['expr'])
            self.assertTrue(query_rules([board])['groups'][0]['rules'])
        worker = json.loads(dynamic['svc-example-worker.json'])
        self.assertEqual(len(worker['panels']), 8)
        self.assertEqual(worker['panels'][0]['gridPos'], {'x': 0, 'y': 0, 'w': 8, 'h': 4})
        self.assertNotIn('cloudlab_http_', json.dumps(worker))
        notes = json.loads(dynamic['svc-example-notes.json'])
        panels = {panel['id']: panel for panel in notes['panels']}
        self.assertIn('owner_kind="Rollout"', panels[5]['targets'][0]['expr'])
        self.assertIn('owner_name=~"notes-api"', panels[5]['targets'][0]['expr'])
        self.assertIn('traffic="user"', panels[10]['targets'][0]['expr'])
        self.assertTrue(service_visibility_tests())

    def test_catalog_projection_includes_ready_without_ingress_and_rejects_ambiguous_or_injected_scope(self):
        def entry(name, publication='ready', **approval):
            return {'publication': publication, 'definition': {'name': name, 'exposure': {'class': 'none'}, 'rollouts': {'enabled': False}},
                    'approval': dict(name=name, namespace='shared', **approval)}
        catalog = {'catalog': [entry('first'), entry('second', 'published'), entry('retired', 'retired')]}
        result = projection(catalog)
        self.assertEqual([s['name'] for s in result], ['first', 'second'])
        self.assertEqual(set(result[0]), {'name', 'namespace', 'workloads'})
        composed = entry('composed', composition={'workloads': [{'name': 'worker'}]})
        self.assertEqual(projection({'catalog': [composed]})[0]['workloads'], [{'name': 'worker', 'kind': 'Deployment'}])
        notes = entry('notes', chartPath='apps/notes')
        notes['definition']['rollouts']['enabled'] = True
        self.assertEqual(projection({'catalog': [notes]})[0]['workloads'], [
            {'name': 'notes-web', 'kind': 'Rollout'}, {'name': 'notes-api', 'kind': 'Deployment'}])
        for field in ('name', 'namespace'):
            invalid = copy.deepcopy(result[0]); invalid[field] = 'escape"} or vector(1)'
            with self.assertRaises(ValueError): build(invalid)
        with self.assertRaises(ValueError): generated([result[0], result[0]])
        with self.assertRaises(ValueError): substitute('metric{scope="$unsupported"}')
        query = substitute(next(panel for panel in build(result[0])['panels'] if panel['id'] == 5)['targets'][0]['expr'])
        self.assertIn('namespace="shared"', query)
        self.assertIn('owner_name=~"first"', query)

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
        self.assertEqual({d['uid'] for d in dashboards}, {'cloudlab-nodes', 'cloudlab-rollouts', 'active-alerts'})
        settings = values('prometheus')['grafana']
        sources = {d['uid'] for d in settings['datasources']['datasources.yaml']['datasources']}
        for dashboard in dashboards:
            self.assertFalse(dashboard['editable'])
            self.assertLessEqual(len(dashboard['panels']), 8)
            self.assertEqual(len({p['id'] for p in dashboard['panels']}), len(dashboard['panels']))
            if dashboard['uid'] == 'active-alerts':
                self.assertIn('ALERTS{', dashboard['panels'][1]['targets'][0]['expr'])
                self.assertIn('do not prove health', dashboard['panels'][0]['options']['content'])
                continue
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

    def test_shared_services_view_is_retired_while_per_service_boards_remain(self):
        self.assertFalse((ROOT / 'platform/observability/prometheus/dashboards/services.json').exists())
        files = inventory(service_bindings())
        self.assertEqual(set(files), {'nodes.json', 'releases.json', 'active-alerts.json', 'service-overview.json', 'svc-example-notes.json', 'svc-example-worker.json'})
        self.assertNotIn('cloudlab-services', {json.loads(raw)['uid'] for raw in files.values()})

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
        responses = [(200, json.dumps(actual).encode())] + [(404, b'{}')] * 5
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
        for index in range(5):
            retained = [(404, b'{}')] * 5
            retained[index] = (200, b'{}')
            with self.subTest(retained=index), \
                    patch('playbooks.observability.files.verify.direct_https', side_effect=retained):
                self.assertFalse(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {}))
        with patch('playbooks.observability.files.verify.direct_https', return_value=(200, b'{}')):
            self.assertFalse(dashboards_ready('https://grafana.example.invalid', 'fixture', {}, {}))
