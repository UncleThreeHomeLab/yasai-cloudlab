"""Synthetic independent account and monitor responses."""
import copy

from playbooks.observability.files.uptimerobot import desired


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
