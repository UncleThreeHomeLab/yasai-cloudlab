"""Per-service monitoring derives from catalog and reviewed observability inputs.

Renders platform/observability/gitops with a prices catalog entry plus
serviceObservability rules/dashboard, and checks the derived scrape
bindings, native rules, dashboards and notification annotation on the six
child Applications. Retired services are excluded; unbound declarations
fail rendering.

Paused skip-reconcile and live convergence belong to the ArgoCD stage
only (private_verify telemetry); this file stays offline helm rendering
with no ansible directory or runner branch.
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
        'approval': {'name': 'prices', 'namespace': 'cloudlab-app-prices',
                     'chartPath': 'charts/service'},
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


def render_fails(values):
    """Render expecting failure; return the combined helm output."""
    if shutil.which('helm') is None:
        raise unittest.SkipTest('helm renders the observability parent')
    with tempfile.TemporaryDirectory() as workspace:
        work = Path(workspace)
        (work / 'values.yaml').write_text(yaml.safe_dump(values))
        try:
            subprocess.check_output(
                ['helm', 'template', '--kube-version', '1.36',
                 '-f', str(work / 'values.yaml'),
                 str(ROOT / 'platform/observability/gitops')],
                text=True, timeout=120, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as error:
            return error.output
    raise AssertionError('helm render unexpectedly succeeded')


def notifications(**overrides):
    """Enabled platformNotifications with email fallback by default."""
    base = {
        'enabled': True,
        'fallbackReceiver': 'mail',
        'receivers': [{'name': 'mail', 'email': {
            'host': 'smtp.example.test', 'port': 587,
            'from': 'alerts@example.test', 'to': 'ops@example.test',
            'username': 'alerts',
            'passwordSecretRef': {'name': 'alertmanager-notification-mail',
                                  'key': 'password'}}}],
        'subscriptions': [{'service': 'prices', 'severities': ['warning'],
                           'receivers': ['mail']}],
        'groupWaitSeconds': 10, 'groupIntervalSeconds': 60,
        'repeatIntervalSeconds': 14400,
        'timeIntervals': [{'name': 'maint', 'weekdays': ['sunday'],
                           'times': [{'start': '02:00', 'end': '03:00'}]}],
        'muteWindows': ['maint'],
        'inhibitRules': [{'sourceMatchers': ['severity="critical"'],
                          'targetMatchers': ['severity="warning"'],
                          'equal': ['alertname']}]}
    base.update(overrides)
    return base


def mesh_webhook(name='hooks', service='prices', port='http', path='/hooks'):
    return {'name': name, 'webhook': {
        'target': {'service': service, 'port': port, 'path': path},
        'authentication': {'mode': 'mesh'}}}


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

    def test_children_share_single_pinned_source_and_digest_is_content_bound(self):
        documents = render(merged_values(prices()))
        children = [doc for doc in documents
                    if doc.get('kind') == 'Application']
        self.assertEqual(len(children), 6)
        sources = {(child['spec']['source']['repoURL'],
                    child['spec']['source']['targetRevision'])
                   for child in children}
        self.assertEqual(sources, {(
            'https://github.com/example/platform.git', 'a' * 40)})
        digest = {child['metadata']['annotations'][
            'cloudlab.io/observability-input-digest'] for child in children}
        self.assertEqual(len(digest), 1)
        stale, = digest
        changed = merged_values(prices())
        changed['observabilityInputs']['monitoringEnabled'] = False
        other = {child['metadata']['annotations'][
            'cloudlab.io/observability-input-digest']
            for child in render(changed)
            if child.get('kind') == 'Application'}
        self.assertEqual(len(other), 1)
        self.assertNotEqual(stale, other.pop())

    def test_service_dashboard_identity_and_size_fail_closed(self):
        base = merged_values(prices())['serviceObservability']['prices']
        board = base['dashboard']
        variants = {
            'uid': dict(board, uid='wrong'),
            'editable': dict(board, editable=True),
            'size': dict(board, description='x' * 100000)}
        for case, dashboard in variants.items():
            with self.subTest(case=case):
                values = merged_values(prices())
                values['serviceObservability']['prices']['dashboard'] = (
                    dashboard)
                render_fails(values)

    def test_notes_pinned_expressions_and_release_callers_preserved(self):
        import json
        pinned = json.loads(
            (ROOT / 'platform/observability/prometheus'
             '/notes-slo.json').read_text())
        groups = pinned['spec']['groups']
        self.assertEqual([group['name'] for group in groups],
                         ['notes-user-slo'])
        alerts = {rule.get('alert') for rule in groups[0]['rules']}
        self.assertEqual(alerts, {
            None, 'NotesAvailabilityBurn1h', 'NotesAvailabilityBurn6h',
            'NotesLatencyBurn1h', 'NotesLatencyBurn6h',
            'NotesSLOEvidenceUnavailable', 'NotesMetricsStale'})
        for rule in groups[0]['rules']:
            self.assertTrue(rule['expr'])
            self.assertTrue('cloudlab_http' in rule['expr']
                            or rule['expr'].startswith('(min(up{'))
        source = pinned['metadata']['annotations']['cloudlab.io/slo-source']
        self.assertIn('apps/notes/slo.json@', source)
        self.assertIn('charts/service/release-policy.json@', source)
        callers = (ROOT / 'docs/service-onboarding.md').read_text(
            encoding='utf-8')
        self.assertIn('platform/observability/prometheus'
                      '/notes-slo.json', callers)

    def test_notification_renders_mute_inhibit_continuation_and_recovery(self):
        values = merged_values(prices())
        values['platformNotifications'] = notifications()
        prometheus = application(render(values), 'cloudlab-prometheus')
        stack = prometheus['spec']['source']['helm']['valuesObject'][
            'kube-prometheus-stack']
        config = stack['alertmanager']['config']
        route = config['route']
        self.assertEqual(
            (route['receiver'], route['group_wait'], route['group_interval'],
             route['repeat_interval']),
            ('mail', '10s', '60s', '14400s'))
        self.assertEqual(route['mute_time_intervals'], ['maint'])
        self.assertEqual(config['inhibit_rules'], [{
            'source_matchers': ['severity="critical"'],
            'target_matchers': ['severity="warning"'],
            'equal': ['alertname']}])
        self.assertEqual(config['time_intervals'][0]['name'], 'maint')
        mail = next(item for item in config['receivers']
                    if item['name'] == 'mail')
        delivery = mail['email_configs'][0]
        self.assertEqual(
            (delivery['require_tls'], delivery['send_resolved'],
             delivery['auth_username'], delivery['auth_password_file']),
            (True, True, 'alerts',
             '/etc/alertmanager/secrets/alertmanager-notification-mail'
             '/password'))
        self.assertEqual(route['routes'], [{
            'receiver': 'mail', 'continue': True,
            'matchers': ['service="prices"', 'severity=~"warning"']}])
        self.assertEqual(
            prometheus['metadata']['annotations'][
                'cloudlab.io/notification-delivery'],
            'candidate')
        rejections = {
            'disabled_with_destinations': notifications(
                enabled=False, fallbackReceiver='mail',
                receivers=[{'name': 'mail', 'email': {
                    'host': 'smtp.example.test', 'port': 587,
                    'from': 'a@example.test', 'to': 'b@example.test'}}]),
            'unknown_fallback': notifications(fallbackReceiver='unknown'),
            'mute_without_interval': notifications(muteWindows=['missing']),
            'unknown_subscription_receiver': notifications(subscriptions=[{
                'service': 'prices', 'severities': ['warning'],
                'receivers': ['unknown']}]),
            'short_repeat_interval': notifications(
                repeatIntervalSeconds=30, groupIntervalSeconds=60)}
        for case, platform in rejections.items():
            with self.subTest(case=case):
                values = merged_values(prices())
                values['platformNotifications'] = platform
                render_fails(values)

    def test_parent_bounds_and_bindings_fail_closed(self):
        same = merged_values(prices())
        same['nativeSource']['valuesRepository'] = same['nativeSource'][
            'repository']
        render_fails(same)
        zone = merged_values(prices())
        zone['observabilityInputs']['grafanaHost'] = 'grafana.example.test'
        render_fails(zone)
        collision = merged_values(prices(), prices())
        collision['serviceObservability'] = {}
        render_fails(collision)
        bulk = merged_values(prices())
        rules = {}
        for resource in range(4):
            groups = []
            for group in range(4):
                members = [{
                    'alert': 'Svc_prices_bulk%02d%02d%04d' % (
                        resource, group, index),
                    'expr': 'vector(1) # ' + 'x' * 2000,
                    'for': '2m',
                    'labels': {'severity': 'warning'},
                    'annotations': {'summary': 'bulk'}} for index in range(16)]
                groups.append({'name': 'bulk-%d-%d' % (resource, group),
                               'rules': members})
            rules['bulk-%d' % resource] = {'groups': groups}
        bulk['serviceObservability']['prices'] = {'rules': rules}
        output = render_fails(bulk)
        self.assertIn('192KiB', output)

    def test_alertmanager_state_claim_is_retained_singleton(self):
        values = merged_values(prices())
        values['platformNotifications'] = notifications()
        prometheus = application(render(values), 'cloudlab-prometheus')
        stack = prometheus['spec']['source']['helm']['valuesObject'][
            'kube-prometheus-stack']
        spec = stack['alertmanager']['alertmanagerSpec']
        self.assertNotIn('replicas', spec)
        self.assertEqual(spec['persistentVolumeClaimRetentionPolicy'],
                         {'whenDeleted': 'Retain', 'whenScaled': 'Retain'})
        self.assertEqual(spec['secrets'], ['alertmanager-notification-mail'])
        claim = spec['storage']['volumeClaimTemplate']
        self.assertEqual(claim['metadata']['annotations'], {
            'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'})
        self.assertEqual(
            (claim['spec']['storageClassName'],
             claim['spec']['accessModes'],
             claim['spec']['resources']['requests']['storage']),
            ('cloudlab-telemetry', ['ReadWriteOnce'], '1Gi'))

    def test_webhook_receiver_permissions_fail_closed(self):
        values = merged_values(prices())
        values['platformNotifications'] = notifications(
            fallbackReceiver='hooks',
            receivers=[mesh_webhook()], subscriptions=[])
        prometheus = application(render(values), 'cloudlab-prometheus')
        config = prometheus['spec']['source']['helm']['valuesObject'][
            'kube-prometheus-stack']['alertmanager']['config']
        hooks = next(item for item in config['receivers']
                     if item['name'] == 'hooks')
        delivery = hooks['webhook_configs'][0]
        self.assertEqual(
            delivery['url'],
            'http://prices.cloudlab-app-prices.svc:8080/hooks')
        self.assertEqual(delivery['http_config'],
                         {'follow_redirects': False})
        self.assertEqual(delivery['send_resolved'], True)
        for case, receiver in (
                ('unknown_service', mesh_webhook(service='unknown')),
                ('unknown_port', mesh_webhook(port='missing')),
                ('retired_service', mesh_webhook(service='prices'))):
            with self.subTest(case=case):
                if case == 'retired_service':
                    candidate = merged_values(prices('retired'))
                    candidate['serviceObservability'] = {}
                else:
                    candidate = merged_values(prices())
                candidate['platformNotifications'] = notifications(
                    fallbackReceiver='hooks', receivers=[receiver],
                    subscriptions=[])
                render_fails(candidate)
        composed = prices()
        composed['approval']['composition'] = {'profile': 'custom'}
        candidate = merged_values(composed)
        candidate['platformNotifications'] = notifications(
            fallbackReceiver='hooks', receivers=[mesh_webhook()],
            subscriptions=[])
        render_fails(candidate)

    def test_grafana_stays_git_owned_with_proxies(self):
        import json
        boards = {}
        for path in sorted((ROOT / 'platform/observability/prometheus'
                            '/dashboards').glob('*.json')):
            boards[path.name] = json.loads(path.read_text())
        self.assertEqual(
            {board['uid'] for board in boards.values()},
            {'active-alerts', 'cloudlab-nodes', 'cloudlab-rollouts'})
        for name, board in boards.items():
            with self.subTest(board=name):
                self.assertIs(board['editable'], False)
                self.assertNotIn('alertmanager', json.dumps(board).lower())
        stack = json.loads(
            (ROOT / 'platform/observability/prometheus/values.json')
            .read_text())['kube-prometheus-stack']['grafana']
        provider = stack['dashboardProviders']['providers.yaml']['providers']
        self.assertEqual(
            [(entry['type'], entry['allowUiUpdates']) for entry in provider],
            [('file', False)])
        self.assertEqual(stack['dashboardsConfigMaps'],
                         {'cloudlab': 'cloudlab-dashboards'})
        sources = stack['datasources']['datasources.yaml']['datasources']
        self.assertEqual(
            {(entry['uid'], entry['access'], entry['editable'])
             for entry in sources},
            {('metrics', 'proxy', False), ('logs', 'proxy', False),
             ('traces', 'proxy', False)})


if __name__ == '__main__':
    unittest.main()
