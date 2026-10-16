"""Exercise the pinned collector/backends on disposable isolated local storage."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import time
import secrets
import os
import threading
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path('/fixture')


def prepare():
    import yaml
    from automation.observability.chart import render
    FIXTURE.mkdir(parents=True, exist_ok=True)
    password = FIXTURE / 'grafana_password'
    if not password.exists():
        password.write_text(secrets.token_urlsafe(48))
        password.chmod(0o444)
    for component in ('loki', 'tempo'):
        configs = [o for o in render(component) if o['kind'] == 'ConfigMap']
        filename = 'config.yaml' if component == 'loki' else 'tempo.yaml'
        raw = next(o['data'][filename] for o in configs if filename in o.get('data', {}))
        if component == 'loki':
            raw = raw.replace('/etc/loki/runtime-config/runtime-config.yaml', '/fixture/runtime-config.yaml')
            runtime = next(o['data']['runtime-config.yaml'] for o in configs if 'runtime-config.yaml' in o.get('data', {}))
            (FIXTURE / 'runtime-config.yaml').write_text(runtime)
        if component == 'tempo':
            raw = raw.replace('/conf/overrides.yaml', '/fixture/overrides.yaml')
            overrides = next(o['data']['overrides.yaml'] for o in configs if 'overrides.yaml' in o.get('data', {}))
            (FIXTURE / 'overrides.yaml').write_text(overrides)
        (FIXTURE / (component + '.yaml')).write_text(raw)
        (FIXTURE / (component + '.yaml')).chmod(0o644)
    loki = yaml.safe_load((FIXTURE / 'loki.yaml').read_text())
    tempo = yaml.safe_load((FIXTURE / 'tempo.yaml').read_text())
    receipt = {'loki_retention': loki['limits_config']['retention_period'],
               'loki_audit_retention': loki['limits_config']['retention_stream'][0]['period'],
               'loki_retention_enabled': loki['compactor']['retention_enabled'],
               'tempo_storage': tempo['storage']['trace']['backend'],
               'tempo_retention': tempo['backend_scheduler']['provider']['compaction']['compaction']['block_retention']}
    (FIXTURE / 'retention.json').write_text(json.dumps(receipt))
    config = (ROOT / 'platform/observability/config.alloy').read_text()
    # Only input transport differs. The redaction and OTLP pipelines are identical.
    pipeline = config[config.index('loki.process "redacted"'):]
    (FIXTURE / 'config.alloy').write_text('logging { level = "warn" }\n'
        'loki.source.api "fixture" {\n  http { listen_address = "0.0.0.0"\n    listen_port = 1300 }\n'
        '  forward_to = [loki.process.redacted.receiver]\n}\n' + pipeline)
    (FIXTURE / 'config.alloy').chmod(0o644)
    from automation.observability.slo import rules
    from automation.observability.configuration import audit_rules
    compiled = rules()
    compiled['groups'].extend(audit_rules()['groups'])
    (FIXTURE / 'slo-rules.json').write_text(json.dumps(compiled))
    (FIXTURE / 'prometheus.yaml').write_text(yaml.safe_dump({
        'global': {'scrape_interval': '2s', 'evaluation_interval': '30s'},
        'rule_files': ['/fixture/slo-rules.json'],
        'alerting': {'alertmanagers': [{'static_configs': [{'targets': ['alertmanager:9093']}]}]},
        'scrape_configs': [{'job_name': 'notes-api', 'static_configs': [{
            'targets': ['alert-fixture:8085'], 'labels': {'namespace': 'cloudlab-app-notes'}}]}]}))
    secret = next(o for o in render('prometheus') if o['kind'] == 'Secret' and
                  o['metadata']['name'] == 'alertmanager-cloudlab')
    alertmanager = yaml.safe_load(base64.b64decode(secret['data']['alertmanager.yaml'], validate=True))
    # Keep rendered routing; only fixture timing and notification transport differ.
    alertmanager['route'].update(group_wait='1s', group_interval='5s', repeat_interval='1h')
    alertmanager['receivers'][0]['webhook_configs'] = [
        {'url': 'http://alert-fixture:8085/alerts', 'send_resolved': True}]
    (FIXTURE / 'alertmanager.yaml').write_text(yaml.safe_dump(alertmanager))
    base = '{service="notes-api",route="/api/notes",traffic="user",status="'
    series = [
        {'series': 'cloudlab_http_requests_total' + base + '200"}', 'values': '0+90x69 6310+100x140'},
        {'series': 'cloudlab_http_requests_total' + base + '500"}', 'values': '0+10x69 690+0x140'},
        {'series': 'cloudlab_http_duration_seconds_bucket' + base + '200",le="0.5"}', 'values': '0+80x69 5620+100x140'},
        {'series': 'cloudlab_http_requests_total{service="notes-api",route="/api/release/notes",traffic="release",status="500"}',
         'values': '0+1000x210'}]
    cases = []
    for rule in compiled['groups'][0]['rules']:
        if 'Burn' not in rule.get('alert', ''):
            continue
        cases.extend([{'eval_time': '20m', 'alertname': rule['alert'],
                       'exp_alerts': [{'exp_labels': rule['labels'], 'exp_annotations': rule['annotations']}]},
                      {'eval_time': '140m', 'alertname': rule['alert'], 'exp_alerts': []}])
    audit = {rule['alert']: rule['expr'] for rule in audit_rules()['groups'][0]['rules']}
    audit_cases = []
    for newest, incomplete in ((1190, 0), (1190, 1), (100, 0)):
        observations = [{'series': metric + '{realm="platform",instance="' + instance + '"}',
                         'values': str(value) + '+0x20'}
                        for instance, observed, truncated in (('old', 100, 1), ('current', newest, incomplete))
                        for metric, value in (('cloudlab_keycloak_health_last_success_seconds', observed),
                                              ('cloudlab_keycloak_audit_incomplete', truncated))]
        audit_cases.append({'interval': '1m', 'input_series': observations, 'promql_expr_test': [
            {'expr': 'count(' + audit['KeycloakAuditIncomplete'] + ') or vector(0)', 'eval_time': '20m',
             'exp_samples': [{'labels': '{}', 'value': 1 if newest == 100 else incomplete}]},
            {'expr': 'count(' + audit['KeycloakEvidenceStalePlatform'] + ') or vector(0)', 'eval_time': '20m',
             'exp_samples': [{'labels': '{}', 'value': int(newest == 100)}]}]})
    audit_cases.append({'interval': '1m', 'promql_expr_test': [
        {'expr': audit['KeycloakEvidenceStalePlatform'], 'eval_time': '20m',
         'exp_samples': [{'labels': '{realm="platform"}', 'value': 1}]}]})
    (FIXTURE / 'slo-test.json').write_text(json.dumps({'rule_files': ['/fixture/slo-rules.json'],
        'evaluation_interval': '30s', 'tests': [{'interval': '1m', 'input_series': series, 'alert_rule_test': cases}] + audit_cases}))
    dashboards = [json.loads(path.read_text()) for path in
                  sorted((ROOT / 'platform/observability/prometheus/dashboards').glob('*.json'))]
    expressions = []
    for dashboard in dashboards:
        for panel in dashboard['panels']:
            if panel['datasource']['uid'] != 'metrics':
                continue
            for target in panel['targets']:
                expression = target['expr']
                for key, value in (('$__rate_interval', '2m'), ('$__range', '6h'), ('$namespace', '.*'),
                                   ('$pod', '.*'), ('$instance', '.*'), ('$service', '.*'),
                                   ('$route', '.*'), ('$traffic', 'user')):
                    expression = expression.replace(key, value)
                expressions.append({'record': 'dashboard:query_' + str(len(expressions)), 'expr': expression})
    (FIXTURE / 'dashboard-rules.json').write_text(json.dumps({'groups': [
        {'name': 'dashboard-syntax', 'rules': expressions}]}))
    tests = json.loads((FIXTURE / 'slo-test.json').read_text())
    tests['rule_files'].append('/fixture/dashboard-rules.json')
    (FIXTURE / 'slo-test.json').write_text(json.dumps(tests))
    print(json.dumps({'fixture_prepared': True, 'production_credentials': False}))


def http(url, value=None):
    request = urllib.request.Request(url, data=json.dumps(value).encode() if value is not None else None,
                                     headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024: raise RuntimeError('Fixture response exceeded limit')
    return raw


def wait(check, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = check()
            if value: return value
        except (urllib.error.URLError, ValueError, TimeoutError): pass
        time.sleep(2)
    raise RuntimeError('Pinned telemetry fixture did not converge')


def verify():
    wait(lambda: http('http://loki:3100/ready'))
    wait(lambda: http('http://tempo:3200/ready'))
    wait(lambda: http('http://alloy:12345/-/ready'))
    # Exercise the actual SDK through the actual Alloy OTLP pipeline.
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.trace import Link, SpanContext, TraceFlags, TraceState
    provider = TracerProvider(resource=Resource({'service.name': 'notes-web', 'secret': 'fixture-secret-do-not-export'}))
    provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint='http://alloy:4318/v1/traces', timeout=5)))
    tracer = provider.get_tracer('fixture-secret-do-not-export', attributes={'secret': 'fixture-secret-do-not-export'})
    api_provider = TracerProvider(resource=Resource({'service.name': 'notes-api'}))
    api_provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint='http://alloy:4318/v1/traces', timeout=5)))
    api_tracer = api_provider.get_tracer('cloudlab.fixture')
    link = Link(SpanContext(1, 1, False, TraceFlags(1), TraceState()), {'secret': 'fixture-secret-do-not-export'})
    with tracer.start_as_current_span('notes.web', record_exception=False, links=[link]) as parent:
        trace_id = format(parent.get_span_context().trace_id, '032x')
        parent.set_attribute('authorization', 'fixture-secret-do-not-export')
        parent.set_attribute('http.route', '/health')
        parent.set_attribute('cloudlab.traffic', 'fixture-secret-do-not-export')
        parent.add_event('fixture-secret-do-not-export', {'secret': 'fixture-secret-do-not-export'})
        carrier = {}
        TraceContextTextMapPropagator().inject(carrier)
        with api_tracer.start_as_current_span('notes.api', context=TraceContextTextMapPropagator().extract(carrier), record_exception=False):
            with api_tracer.start_as_current_span('notes.database', record_exception=False): pass
    provider.force_flush()
    result = wait(lambda: json.loads(http('http://tempo:3200/api/traces/' + trace_id)))
    raw = json.dumps(result)
    if ('fixture-secret-do-not-export' in raw or any(name not in raw for name in
            ('notes.web', 'notes.api', 'notes.database', 'notes-web', 'notes-api'))):
        raise RuntimeError('Pinned OTLP trace propagation or redaction failed')
    now = str(time.time_ns())
    line = json.dumps({'kind': 'request', 'service': 'notes-web', 'route': '/health', 'status': 200,
                       'realm': 'fixture-secret-do-not-export', 'operationType': 'fixture-secret-do-not-export',
                       'duration_ms': 1.0, 'trace_id': trace_id, 'password': 'fixture-secret-do-not-export'}, separators=(',', ':'))
    http('http://alloy:1300/loki/api/v1/push', {'streams': [{'stream': {'service': 'notes-web',
         'secret': 'fixture-secret-do-not-export'}, 'values': [[now, line]]}]})
    query = urllib.parse.urlencode({'query': '{kind="request"}', 'limit': 10})
    logs = wait(lambda: (lambda value: value if value.get('data', {}).get('result') else None)(
        json.loads(http('http://loki:3100/loki/api/v1/query_range?' + query))))
    if 'fixture-secret-do-not-export' in json.dumps(logs) or trace_id not in json.dumps(logs):
        raise RuntimeError('Pinned log correlation or redaction failed')
    events = [
        {'kind': 'identity-audit', 'realm': 'platform', 'type': 'LOGIN_ERROR', 'password': 'fixture-secret-do-not-export'},
        {'kind': 'identity-audit', 'realm': 'platform', 'type': 'fixture-secret-do-not-export',
         'operationType': 'UPDATE', 'resourceType': 'fixture-secret-do-not-export'},
        {'kind': 'identity-health', 'realm': 'platform', 'healthy': 1, 'incomplete': 1, 'observed': str(int(time.time()))},
    ]
    http('http://alloy:1300/loki/api/v1/push', {'streams': [{'stream': {'secret': 'fixture-secret-do-not-export'},
         'values': [[str(time.time_ns() + i), json.dumps(event)] for i, event in enumerate(events)]}]})
    query = urllib.parse.urlencode({'query': '{service="identity-audit"}', 'limit': 10})
    audit = wait(lambda: (lambda value: value if len(value.get('data', {}).get('result', [])) >= 3 else None)(
        json.loads(http('http://loki:3100/loki/api/v1/query_range?' + query))))
    if 'fixture-secret-do-not-export' in json.dumps(audit):
        raise RuntimeError('Pinned audit body or label redaction failed')
    metrics = http('http://alloy:12345/metrics').decode()
    if any(name not in metrics for name in ('cloudlab_keycloak_login_failures_total',
            'cloudlab_keycloak_admin_events_total', 'cloudlab_keycloak_health_last_success_seconds',
            'cloudlab_keycloak_audit_incomplete')):
        raise RuntimeError('Pinned bounded audit metrics unavailable')
    # Exercise the actual app middleware, rather than only hand-created SDK spans.
    sys.path.insert(0, str(ROOT / 'apps/notes'))
    import telemetry
    import web
    from http.server import ThreadingHTTPServer
    os.environ.update(OTEL_ENABLED='1', SOURCE_SHA256='0' * 64,
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT='http://cloudlab-alloy.cloudlab-observability.svc:4318/v1/traces')
    telemetry.start('notes-web')
    telemetry.instrument(web.Handler, 'notes-web')
    server = ThreadingHTTPServer(('127.0.0.1', 0), web.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        request = urllib.request.Request('http://127.0.0.1:' + str(server.server_port) + '/ready?password=fixture-secret-do-not-export',
            headers={'traceparent': carrier['traceparent'], 'Authorization': 'Bearer fixture-secret-do-not-export'})
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status != 200: raise RuntimeError('Real app fixture readiness failed')
        request_metrics = urllib.request.Request('http://127.0.0.1:9091/metrics',
            headers={'Accept': 'application/openmetrics-text;version=1.0.0'})
        with urllib.request.urlopen(request_metrics, timeout=5) as response: exported = response.read().decode()
        if ('fixture-secret-do-not-export' in exported or 'traffic="synthetic"' not in exported or
                'revision="' + '0' * 64 + '"' not in exported or trace_id not in exported):
            raise RuntimeError('Real app metrics, source revision, propagation or redaction failed')
    finally:
        server.shutdown()
        server.server_close()
    receipt = json.loads((FIXTURE / 'retention.json').read_text())
    if (receipt != {'loki_retention': '72h', 'loki_audit_retention': '168h', 'loki_retention_enabled': True,
                   'tempo_storage': 'local', 'tempo_retention': '24h'}):
        raise RuntimeError('Pinned local retention settings differ')
    print(json.dumps({'otlp_sdk_to_alloy_to_tempo': True, 'parent_child_trace': True,
                      'redacted_logs_to_loki': True, 'trace_log_correlation': True,
                      'configured_local_retention': True, 'real_app_middleware_and_metrics': True,
                      'audit_projection_and_metrics': True, 'b2_connections': 0}))
    from automation.observability.alert_fixture import verify as verify_alerts
    print(json.dumps(verify_alerts()))


if __name__ == '__main__':
    try:
        {'prepare': prepare, 'verify': verify}[sys.argv[1]]()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Native telemetry fixture failed; private diagnostics withheld') from None
