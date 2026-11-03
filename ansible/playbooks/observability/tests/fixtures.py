"""Synthetic independent account and monitor responses."""
import copy

from playbooks.observability.files.uptimerobot import desired


def service_bindings():
    return [{'name': 'example-notes', 'namespace': 'fixture', 'workloads': [
        {'name': 'notes-api', 'kind': 'Deployment'}, {'name': 'notes-web', 'kind': 'Rollout'}]},
        {'name': 'example-worker', 'namespace': 'fixture', 'workloads': [{'name': 'worker', 'kind': 'Deployment'}]}]


def service_visibility_tests():
    """Run generated expressions against ownership, missing evidence and counter resets."""
    from playbooks.observability.files.dashboards import build, substitute
    board = build(service_bindings()[0])
    def expression(panel, target=0):
        return substitute(board['panels'][panel - 1]['targets'][target]['expr'], board)
    def series(metric, labels, values='1+0x32'):
        return {'series': metric + '{namespace="fixture",' + labels + '}', 'values': values}
    def check(expr, value, labels='{}', when='4m'):
        return {'expr': 'round((' + expr + '), 0.000001)', 'eval_time': when,
                'exp_samples': [] if value is None else [{'labels': labels, 'value': round(value, 6)}]}
    inputs = []
    for kind, name, count, available in [('Deployment', 'notes-api', 2, 1), ('Rollout', 'notes-web', 1, 1), ('Deployment', 'worker', 9, 9)]:
        if kind == 'Deployment':
            metrics = [('kube_deployment_spec_replicas', count), ('kube_deployment_status_replicas_available', available)]
            label = 'deployment'
        else:
            metrics = [('cloudlab_rollout_replicas_desired', count), ('cloudlab_rollout_replicas_available', available)]
            label = 'rollout'
        inputs.extend(series(metric, label + '="' + name + '"', str(value) + '+0x32') for metric, value in metrics)
        inputs.append(series('kube_replicaset_owner', 'replicaset="' + name + '-rs",owner_name="' + name + '",owner_kind="' + kind + '",owner_is_controller="true"'))
    for pod, name, ready in [('api-a', 'notes-api', 1), ('api-b', 'notes-api', 0), ('web-a', 'notes-web', 1), ('other', 'worker', 1)]:
        inputs.append(series('kube_pod_owner', 'pod="' + pod + '",owner_name="' + name + '-rs",owner_kind="ReplicaSet",owner_is_controller="true"'))
        inputs.append(series('kube_pod_status_ready', 'pod="' + pod + '",condition="true"', str(ready) + '+0x32'))
        for metric, values in [('container_cpu_usage_seconds_total', '0+15x32'), ('container_memory_working_set_bytes', '100+0x32'),
                               ('kube_pod_container_status_restarts_total', '0+0x32')]:
            inputs.append(series(metric, 'pod="' + pod + '",container="app",image="fixture"', values))
    cases = [{'name': 'service-ownership-and-failing-replica', 'input_series': inputs, 'promql_expr_test': [
        check(expression(1), 0.5),
        {'expr': expression(2), 'eval_time': '4m', 'exp_samples': [
            {'labels': '{component="notes-api"}', 'value': 2}, {'labels': '{component="notes-web"}', 'value': 1}]},
        {'expr': expression(3), 'eval_time': '4m', 'exp_samples': [
            {'labels': '{component="notes-api"}', 'value': 1}, {'labels': '{component="notes-web"}', 'value': 1}]},
        check(expression(5), 2, '{component="notes-api"}'), check(expression(6), 200, '{component="notes-api"}')]}]
    cases.append({'name': 'missing-is-unknown-not-zero', 'input_series': [], 'promql_expr_test': [
        check(expression(1), None), check(expression(5), None), check(expression(10), None),
        {'expr': expression(2), 'eval_time': '4m', 'exp_samples': [
            {'labels': '{component="notes-api"}', 'value': -1}, {'labels': '{component="notes-web"}', 'value': -1}]}]})
    stale = copy.deepcopy(inputs)
    for row in stale:
        row['values'] = row['values'].replace('x32', 'x8')
    cases.append({'name': 'stale-controller-and-resources', 'input_series': stale, 'promql_expr_test': [
        check(expression(1), None), check(expression(5), None), {'expr': expression(2), 'eval_time': '4m', 'exp_samples': [
            {'labels': '{component="notes-api"}', 'value': -2}, {'labels': '{component="notes-web"}', 'value': -2}]}]})
    reset = copy.deepcopy(inputs)
    for row in reset:
        if row['series'].startswith('container_cpu_usage_seconds_total'):
            row['values'] = '0+15x8 0+15x24'
    cases.append({'name': 'counter-reset-keeps-positive-component-rate', 'input_series': reset,
        'promql_expr_test': [check('count(' + expression(5) + ' > 0)', 1)]})
    tampered = board['panels'][6]['targets'][0]['expr'].replace('${pod:regex}', 'other').replace('${container:regex}', 'app')
    cases.append({'name': 'same-namespace-unowned-pod-selection-stays-empty', 'input_series': inputs,
                  'promql_expr_test': [check(substitute(tampered, board), None)]})
    wildcard = substitute(board['panels'][4]['targets'][0]['expr'].replace('${component:regex}', '.*'), board)
    cases.append({'name': 'url-component-wildcard-cannot-include-other-service', 'input_series': inputs,
                  'promql_expr_test': [check('count(' + wildcard + ')', 2), check('sum(' + wildcard + ')', 3)]})
    for label, values, rate, state in [('zero', '0+0x32', 0, -1), ('low', '0+0.1x32', 0.1 / 15, -2), ('busy', '0+15x32', 1, 0)]:
        counters = [series('cloudlab_http_requests_total', 'pod="api-a",service="notes-api",route="/api/notes",traffic="user",status="200"', values),
                    series('cloudlab_http_requests_total', 'pod="other",service="notes-api",route="/api/notes",traffic="user",status="500"', '0+1500x32'),
                    series('cloudlab_http_requests_total', 'pod="api-a",service="notes-api",route="/api/notes",traffic="release",status="500"', '0+1500x32')]
        cases.append({'name': 'user-traffic-' + label, 'input_series': inputs + counters, 'promql_expr_test': [
            check(expression(10), rate), check(expression(11), state)]})
    histogram = []
    for pod in ('api-a', 'api-b'):
        labels = 'pod="' + pod + '",service="notes-api",route="/api/notes",traffic="user",status="200"'
        histogram.append(series('cloudlab_http_requests_total', labels, '0+15x32'))
        for le, step in [('0.5', 15 if pod == 'api-a' else 0), ('1', 15), ('+Inf', 15)]:
            histogram.append(series('cloudlab_http_duration_seconds_bucket', labels + ',le="' + le + '"', '0+' + str(step) + 'x32'))
    cases.append({'name': 'histograms-combine-replica-buckets-before-percentile', 'input_series': inputs + histogram,
                  'promql_expr_test': [check(expression(12), 0.95)]})
    stale_http = [dict(row, values=row['values'].replace('x32', 'x8')) for row in histogram]
    cases.append({'name': 'stale-http-is-explicit-not-idle', 'input_series': inputs + stale_http,
                  'promql_expr_test': [check(expression(10), -3), check(expression(11), -3)]})
    return [dict(case, interval='15s') for case in cases]


class FakeAPI:
    def __init__(self):
        self.user = {'email': 'operator@example.com', 'monitorLimit': 50,
                     'activeSubscription': {'plan': 'FREE'}}
        self.contacts = [{'id': 7, 'type': 'Email', 'value': 'operator@example.com', 'status': 'Active'}]
        self.rows = []
        self.writes = []
        self.next_link = None
        self.next_id = 12

    def request(self, method, path, value=None):
        if method == 'GET':
            if path == 'user/me': return copy.deepcopy(self.user)
            if path == 'user/alert-contacts': return copy.deepcopy(self.contacts)
            if path == 'monitors?limit=50': return {'data': copy.deepcopy(self.rows), 'nextLink': self.next_link}
            raise AssertionError('Unexpected fixture read')
        self.writes.append((method, path, copy.deepcopy(value)))
        if method == 'POST':
            while any(row.get('id') == self.next_id for row in self.rows): self.next_id += 1
            self.rows.append(dict(value, id=self.next_id, status='STARTED'))
        elif method == 'PATCH':
            identifier = int(path.split('/')[-1])
            next(row for row in self.rows if row['id'] == identifier).update(value)
        elif method == 'DELETE':
            identifier = int(path.split('/')[-1])
            self.rows = [row for row in self.rows if row['id'] != identifier]
        else: raise AssertionError('Unexpected fixture mutation')


def existing(key='notes-health', url='https://notes.example.com/health', **overrides):
    return dict(desired(key, url, 7), id=12, status='UP', **overrides)


def rollout_visibility_tests():
    """Exercise actual dashboard expressions against active, idle and missing metrics."""
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[4]
    dashboard = json.loads((root / 'platform/observability/prometheus/dashboards/releases.json').read_text())
    panels = {panel['id']: panel for panel in dashboard['panels']}
    def expression(panel, target=0):
        value = panels[panel]['targets'][target]['expr']
        for key, replacement in (('$namespace', 'fixture'), ('$rollout', 'app'), ('$traffic', 'release')):
            value = value.replace(key, replacement)
        return value
    def info(candidate):
        return {'series': 'cloudlab_rollout_info{namespace="fixture",rollout="app",service="app",stable_revision="old",canary_revision="' + candidate + '"}',
                'values': '1+0x32'}
    def counter(revision, step=15, job='cloudlab-observability/release-canaries'):
        return {'series': 'cloudlab_http_requests_total{namespace="fixture",service="app",revision="' + revision + '",traffic="release",job="' + job + '"}',
                'values': '0+' + str(step) + 'x32'}
    def check(expr, value, labels='{namespace="fixture",rollout="app"}'):
        return {'expr': expr, 'eval_time': '4m', 'exp_samples': [] if value is None else [
            {'labels': labels, 'value': value}]}
    active = [info('new'), counter('old'), counter('new'), counter('old', 1500, job='duplicate-exporter')]
    cases = [
        ('balanced-active', active, [check(expression(3), 50), check(expression(3, 1), 50),
                                    check(expression(4), 120), check(expression(4, 1), 120)]),
        ('completed', [info('old'), counter('old')], [check(expression(3), 100), check(expression(3, 1), 0), check(expression(4, 1), 0)]),
        ('idle-with-valid-zero-counters', [info('old'), counter('old', 0)],
            [check(expression(3), -1), check(expression(3, 1), -1), check(expression(4), 0), check(expression(4, 1), 0)]),
        ('active-candidate-metrics-missing', [info('new'), counter('old')], [check(expression(3), None), check(expression(3, 1), None), check(expression(4, 1), None)]),
        ('all-request-metrics-missing', [info('old')], [check(expression(3), None), check(expression(3, 1), None), check(expression(4), None)]),
        ('routing-state-missing', [counter('old')], [check(expression(3), None), check(expression(3, 1), None), check(expression(4, 1), None)]),
        ('configured-split-ignores-other-routes', [
            {'series': 'cloudlab_httproute_backend_weight{namespace="fixture",route="app",backend="app"}', 'values': '50+0x32'},
            {'series': 'cloudlab_httproute_backend_weight{namespace="fixture",route="app",backend="app-canary"}', 'values': '50+0x32'},
            {'series': 'cloudlab_httproute_backend_weight{namespace="fixture",route="other",backend="app-canary"}', 'values': '100+0x32'}],
            [check(expression(2), 50, '{}'), check(expression(2, 1), 50, '{}')]),
        ('every-panel-is-unknown-without-telemetry', [], [check(expression(panel['id'], index), None)
            for panel in dashboard['panels'] for index, _ in enumerate(panel['targets'])]),
    ]
    return {'rule_files': ['/workspace/platform/observability/prometheus/rollout-rules.yaml'],
            'evaluation_interval': '15s', 'tests': [{'name': name, 'interval': '15s', 'input_series': series,
                'promql_expr_test': expectations} for name, series, expectations in cases]}
