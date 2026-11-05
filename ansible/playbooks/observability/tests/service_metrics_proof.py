"""Isolated proof of rendered native HTTP filters, rules, notifications and file boards."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml

from playbooks.observability.tests import notifications_proof as notifications

FIXTURE = Path('/fixture')
PROMETHEUS = 'http://prometheus:9090'
MODE = 'good'


def prepare():
    from playbooks.observability.tests.fixtures import monitored_service_inputs, notification_inputs
    from playbooks.observability.tests.fixtures import native_overrides, helm
    from playbooks.observability.files.chart import render
    notifications.prepare()
    value = monitored_service_inputs()
    delivery = notification_inputs()
    value['catalog'].append(delivery['catalog'][1])
    value['platformNotifications'] = delivery['platformNotifications']
    subscription = value['platformNotifications']['subscriptions'][0]
    subscription.update(service='synthetic', severities=['warning'], receivers=['operator-email', 'primary'])
    overrides = native_overrides(value)
    objects = render('prometheus', overrides['cloudlab-prometheus'])
    spec = next(o['spec'] for o in objects if o['kind'] == 'PodMonitor' and o['metadata']['name'] == 'svc-synthetic')
    endpoint = spec['podMetricsEndpoints'][0]
    def relabel(rule):
        keys = {'sourceLabels': 'source_labels', 'targetLabel': 'target_label'}
        return {keys.get(key, key): item for key, item in rule.items()}
    scrape = {'job_name': 'native-http', 'scrape_interval': '1s', 'scrape_timeout': '1s',
        'metrics_path': endpoint['path'], 'honor_labels': endpoint['honorLabels'],
        'honor_timestamps': endpoint['honorTimestamps'],
        'static_configs': [{'targets': ['exporter:9191'], 'labels': {
            'namespace': 'cloudlab-app-synthetic', 'service': 'synthetic', 'pod': 'synthetic-fixture'}}],
        'relabel_configs': [relabel(rule) for rule in endpoint['relabelings']],
        'metric_relabel_configs': [relabel(rule) for rule in endpoint['metricRelabelings']]}
    for field, key in {'bodySizeLimit': 'body_size_limit', 'sampleLimit': 'sample_limit',
                       'targetLimit': 'target_limit', 'labelLimit': 'label_limit',
                       'labelNameLengthLimit': 'label_name_length_limit',
                       'labelValueLengthLimit': 'label_value_length_limit'}.items():
        scrape[key] = spec[field]
    rules = next(o['spec'] for o in objects if o['kind'] == 'PrometheusRule' and o['metadata']['name'] == 'svc-synthetic-availability')
    (FIXTURE / 'rules.yaml').write_text(yaml.safe_dump(rules))
    invalid = json.loads(json.dumps(rules))
    invalid['groups'][0]['rules'][0]['expr'] = 'sum('
    (FIXTURE / 'invalid-rules.yaml').write_text(yaml.safe_dump(invalid))
    (FIXTURE / 'prometheus.yaml').write_text(yaml.safe_dump({
        'global': {'evaluation_interval': '1s'}, 'rule_files': ['/fixture/rules.yaml'],
        'alerting': {'alertmanagers': [{'static_configs': [{'targets': ['alertmanager:9093']}]}]},
        'scrape_configs': [scrape]}))
    rendered = render('prometheus', overrides['cloudlab-prometheus'])
    secret = next(o for o in rendered if o['kind'] == 'Secret' and o['metadata']['name'] == 'alertmanager-cloudlab')
    (FIXTURE / 'alertmanager.yaml').write_bytes(base64.b64decode(secret['data']['alertmanager.yaml']))
    dashboards = next(o['data'] for o in rendered if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'cloudlab-dashboards')
    boards = FIXTURE / 'dashboards'
    boards.mkdir(exist_ok=True)
    for name, raw in dashboards.items(): (boards / name).write_text(raw)
    # Same native file provider/datasource models; only fixture paths and backend address change.
    values = json.loads((notifications.ROOT / 'platform/observability/prometheus/values.json').read_text())['kube-prometheus-stack']['grafana']
    providers = values['dashboardProviders']['providers.yaml']
    for provider in providers['providers']: provider['options']['path'] = '/fixture/dashboards'
    (FIXTURE / 'grafana-provisioning/dashboards').mkdir(parents=True, exist_ok=True)
    (FIXTURE / 'grafana-provisioning/dashboards/providers.yaml').write_text(yaml.safe_dump(providers))
    datasource = values['datasources']['datasources.yaml']
    for source in datasource['datasources']:
        if source['uid'] == 'metrics': source['url'] = PROMETHEUS
    (FIXTURE / 'grafana-provisioning/datasources').mkdir(parents=True, exist_ok=True)
    (FIXTURE / 'grafana-provisioning/datasources/datasources.yaml').write_text(yaml.safe_dump(datasource))
    for name in ('plugins', 'alerting'):
        (FIXTURE / 'grafana-provisioning' / name).mkdir(exist_ok=True)
    ini = values['grafana.ini']
    assert not ini['unified_alerting']['enabled'] and not ini['alerting']['enabled']
    (FIXTURE / 'grafana.ini').write_text('[unified_alerting]\nenabled=false\n[alerting]\nenabled=false\n')
    (FIXTURE / 'grafana_password').write_text(secrets.token_urlsafe(32))
    # Files are disposable fixture inputs, never production credentials.
    FIXTURE.chmod(0o755)
    for path in FIXTURE.rglob('*'):
        if path.is_dir(): path.chmod(0o755)
        elif path.name not in ('token', 'password', 'server.key'): path.chmod(0o644)
    print(json.dumps({'native_collection_prepared': True, 'only_timing_and_transport_adapted': True}))


def exposition(mode):
    base = 'route="/api/items",method="GET",status="200",traffic="user"'
    good = 'cloudlab_http_requests_total{' + base + ',service="forged",namespace="forged",pod="forged",user="private-canary",token="token-canary",revision="raw-revision",exported_service="spoof"} 5 1\n'
    if mode == 'missing': return '# No HTTP coverage\n'
    if mode == 'body': return '# ' + 'a' * (1024 * 1024 + 1) + '\n'
    if mode == 'samples':
        return ''.join('cloudlab_http_requests_total{route="/api/items",method="' + ('GET' if n < 500 else 'POST' if n < 1000 else 'PUT') + '",status="' + str(100 + n % 500) + '",traffic="user"} 1\n' for n in range(1001))
    rows = [good]
    for bucket in ('0.005', '0.01', '0.025', '0.05', '0.1', '0.25', '0.5', '1', '2', '5', '10', '+Inf'):
        rows.append('cloudlab_http_duration_seconds_bucket{' + base + ',le="' + bucket + '"} 5\n')
    for suffix in ('sum', 'count', 'max'):
        rows.append('cloudlab_http_duration_seconds_' + suffix + '{' + base + '} 5\n')
    rows.append('cloudlab_http_requests_total{route="/api/items/:id",method="GET",status="200",traffic="user"} 2\n')
    rows.append('cloudlab_http_requests_total{route="other",method="GET",status="200",traffic="user"} 1\n')
    for before, after in [('route="/api/items"', 'route="/api/items?token=raw-query-canary"'),
                          ('method="GET"', 'method="UNREVIEWED"'), ('status="200"', 'status="999"'),
                          ('traffic="user"', 'traffic="secret-canary"')]:
        rows.append('cloudlab_http_requests_total{' + base.replace(before, after) + '} 99\n')
    rows.append('cloudlab_http_duration_seconds_bucket{' + base + ',le="123.456"} 99\n')
    rows.append('private_unapproved_metric{token="family-canary"} 99\n')
    if mode == 'error': rows.append('cloudlab_http_requests_total{' + base.replace('status="200"', 'status="500"') + '} 1\n')
    return ''.join(rows)


class Exporter(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_POST(self):
        global MODE
        mode = self.path.removeprefix('/control/')
        if mode not in ('good', 'error', 'missing', 'body', 'samples'):
            self.send_error(400)
            return
        MODE = mode
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if self.path != '/metrics':
            self.send_error(404)
            return
        raw = exposition(MODE).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def query(expression, grafana=False):
    url = ('http://grafana:3000/api/datasources/proxy/uid/metrics' if grafana else PROMETHEUS)
    return json.loads(request(url + '/api/v1/query?' + urllib.parse.urlencode({'query': expression}), grafana=grafana))['data']['result']


def request(url, grafana=False, method=None):
    headers = {}
    if grafana:
        credentials = 'fixture-admin:' + (FIXTURE / 'grafana_password').read_text()
        headers['Authorization'] = 'Basic ' + base64.b64encode(credentials.encode()).decode()
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers, method=method), timeout=5) as response:
        return response.read(2 * 1024 * 1024)


def mode(value):
    request('http://exporter:9191/control/' + value, method='POST')


def verify():
    wait = notifications.wait
    wait(lambda: request(PROMETHEUS + '/-/ready'), label='native Prometheus readiness')
    wait(lambda: request('http://grafana:3000/api/health'), label='Grafana readiness')
    wait(lambda: query('cloudlab_http_requests_total'), label='retained compatible HTTP data')
    rows = query('{__name__=~"cloudlab_http_.*"}')
    if len(rows) != 18: raise RuntimeError('Unexpected stored HTTP family/dimension coverage: ' + str(len(rows)))
    for row in rows:
        labels = row['metric']
        if labels.get('namespace') != 'cloudlab-app-synthetic' or labels.get('service') != 'synthetic':
            raise RuntimeError('Exporter spoofed trusted identity')
        if set(labels) - {'__name__', 'namespace', 'service', 'job', 'instance', 'pod', 'container', 'endpoint', 'route', 'method', 'status', 'traffic', 'le'}:
            raise RuntimeError('Unapproved HTTP dimension survived')
    encoded = json.dumps(rows)
    if any(canary in encoded for canary in ('canary', 'forged', 'raw-revision', '123.456')):
        raise RuntimeError('A forbidden stored-series canary survived')
    if any(row['metric'].get('status') == '999' for row in rows): raise RuntimeError('Unapproved status survived')
    if query('private_unapproved_metric'): raise RuntimeError('Unapproved family survived')
    age = query('time() - timestamp(cloudlab_http_requests_total{route="/api/items"})')
    if not age or float(age[0]['value'][1]) > 10: raise RuntimeError('Exporter timestamp was trusted')
    boards = {}
    for uid in ('svc-synthetic', 'active-alerts'):
        boards[uid] = json.loads(wait(lambda: request('http://grafana:3000/api/dashboards/uid/' + uid, grafana=True), label='native dashboard file provisioning'))
        if not boards[uid]['meta']['provisioned'] or boards[uid]['dashboard']['editable']:
            raise RuntimeError('Dashboard file ownership differs')
    expression = boards['active-alerts']['dashboard']['panels'][1]['targets'][0]['expr']
    if query(expression, grafana=True): raise RuntimeError('Good fixture unexpectedly alerted')
    mode('error')
    wait(lambda: query('ALERTS{alertname="Svc_synthetic_Errors",alertstate="pending"}'), label='pending native alert')
    wait(lambda: query(expression, grafana=True), label='active alert visible through Grafana datasource')
    wait(lambda: notifications.delivered('Svc_synthetic_Errors', 'firing', ['email', '/alerts/primary']), label='native alert fanout')
    mode('good')
    wait(lambda: not query('ALERTS{alertname="Svc_synthetic_Errors"}'), label='resolved native alert')
    wait(lambda: notifications.delivered('Svc_synthetic_Errors', 'resolved', ['email', '/alerts/primary']), label='native resolved delivery')
    mode('missing')
    wait(lambda: not query('cloudlab_http_requests_total'), label='missing series are absent')
    if float(query('up')[0]['value'][1]) != 1: raise RuntimeError('Missing-series fixture should still scrape')
    for value in ('samples', 'body'):
        mode(value)
        wait(lambda: query('up') and float(query('up')[0]['value'][1]) == 0, label=value + ' limit rejection')
        targets = json.loads(request(PROMETHEUS + '/api/v1/targets'))['data']['activeTargets']
        error = targets[0]['lastError'].lower()
        if value == 'samples' and 'sample limit' not in error: raise RuntimeError('Wrong sample rejection: ' + error)
        if value == 'body' and 'body size' not in error: raise RuntimeError('Wrong body rejection: ' + error)
        mode('good')
        wait(lambda: query('cloudlab_http_requests_total') and float(query('up')[0]['value'][1]) == 1, label='HTTP recovery')
    # This exercises Prometheus server reload only, not operator revision handling.
    accepted = json.loads(request(PROMETHEUS + '/api/v1/rules'))['data']['groups'][0]
    expressions = {rule['name']: rule['query'] for rule in accepted['rules']}
    original = (FIXTURE / 'rules.yaml').read_text()
    candidate = FIXTURE / 'rules.pending'
    candidate.write_text((FIXTURE / 'invalid-rules.yaml').read_text())
    candidate.replace(FIXTURE / 'rules.yaml')
    try:
        request(PROMETHEUS + '/-/reload', method='POST')
    except urllib.error.HTTPError as error:
        if error.code != 500: raise
    else:
        raise RuntimeError('Prometheus server accepted invalid PromQL')
    def still_evaluating():
        group = json.loads(request(PROMETHEUS + '/api/v1/rules'))['data']['groups'][0]
        return ({rule['name']: rule['query'] for rule in group['rules']} == expressions and
                group['lastEvaluation'] != accepted['lastEvaluation'] and
                all(rule['health'] == 'ok' for rule in group['rules']))
    wait(still_evaluating, label='accepted rules continue evaluating after rejected server reload')
    candidate.write_text(original)
    candidate.replace(FIXTURE / 'rules.yaml')
    request(PROMETHEUS + '/-/reload', method='POST')
    print(json.dumps({'stored_series_privacy': True, 'spoofed_identity_rejected': True,
        'native_limits_reject_and_recover': True, 'native_pending_firing_resolved': True,
        'native_email_webhook_fanout': True, 'grafana_file_provisioned_queries': True,
        'invalid_server_reload_rejected': True,
        'accepted_rules_continue_evaluating': True,
        'missing_http_is_absent_despite_up': True, 'kubernetes_adoption_proven': False}))


if __name__ == '__main__':
    if sys.argv[1:] == ['prepare']: prepare()
    elif sys.argv[1:] == ['exporter']: ThreadingHTTPServer(('0.0.0.0', 9191), Exporter).serve_forever()
    elif sys.argv[1:] == ['verify']: verify()
    else: raise SystemExit('Expected prepare, exporter or verify')
