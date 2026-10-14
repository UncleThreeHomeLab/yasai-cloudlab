"""One service definition owns user SLO alerts, panels and release thresholds."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def definition():
    return json.loads((ROOT / 'apps/notes/slo.json').read_text())


def expressions(indicator, window):
    policy = definition()
    selector = ','.join(key + '="' + policy[key] + '"' for key in ('service', 'route', 'traffic'))
    total = 'sum(increase(cloudlab_http_requests_total{' + selector + ',status=~"2..|5.."}[' + window + ']))'
    if indicator == 'availability':
        good = 'sum(increase(cloudlab_http_requests_total{' + selector + ',status=~"2.."}[' + window + ']))'
    else:
        good = ('sum(increase(cloudlab_http_duration_seconds_bucket{' + selector + ',status=~"2..",le="' +
                str(policy['latency_seconds']) + '"}[' + window + ']))')
    # A missing good series means zero good events; missing total is unavailable evidence.
    bad = '(1 - ((' + good + ' or vector(0)) / ' + total + '))'
    return total, bad


def rules():
    policy = definition()
    result = [{'record': 'notes:slo_evidence:present',
               'expr': '(min(up{namespace="cloudlab-app-notes",job="notes-api"}) or vector(0)) == bool 1'}]
    for indicator in ('availability', 'latency'):
        budget = 1 - policy[indicator + '_target']
        for windows in policy['burn_windows']:
            threshold = windows['budget_fraction'] * policy['window_seconds'] / windows['seconds']
            count, long = expressions(indicator, windows['long'])
            short_count, short = expressions(indicator, windows['short'])
            expression = (f'({long} / {budget:.9f} > {threshold:g}) and '
                          f'({short} / {budget:.9f} > {threshold:g}) and '
                          f'({count} >= {windows["minimum_samples"]}) and ({short_count} >= 10)')
            result.append({'alert': 'Notes' + indicator.title() + 'Burn' + windows['long'],
                'expr': expression, 'for': '2m', 'labels': {'service': policy['service'],
                'severity': windows['severity'], 'indicator': indicator},
                'annotations': {'summary': indicator.title() + ' error budget burns in both ' +
                    windows['long'] + ' and ' + windows['short'],
                    'description': 'Inspect private Notes request dashboard and correlated trace. Release and synthetic traffic are excluded.'}})
    count, _ = expressions('availability', policy['window'])
    result.append({'alert': 'NotesSLOEvidenceUnavailable',
        'expr': '(' + count + ' < ' + str(policy['minimum_window_samples']) + ') or absent(' + count +
                ') or (' + coverage() + ' < ' + str(policy['window_seconds'] // 30 - 1) + ')',
        'for': policy['evaluation_duration'], 'labels': {'service': policy['service'], 'severity': 'warning'},
        'annotations': {'summary': 'Notes SLO lacks complete window evidence',
                        'description': 'Compliance requires sufficient user samples and a complete retained scrape window. Missing, stale or truncated evidence is unavailable.'}})
    result.append({'alert': 'NotesMetricsStale', 'expr': 'absent_over_time(cloudlab_http_requests_total{service="notes-api"}[5m])',
        'for': '5m', 'labels': {'service': policy['service'], 'severity': 'warning'},
        'annotations': {'summary': 'Notes request metrics unavailable',
                        'description': 'Missing metrics are unknown availability, never success. Check app and Prometheus scrape targets.'}})
    return {'groups': [{'name': 'notes-user-slo', 'interval': '30s', 'rules': result}]}


def coverage():
    return '(sum_over_time(notes:slo_evidence:present[' + definition()['window'] + ']) or vector(0))'


def dashboard():
    policy = definition()
    panels = []
    for indicator in ('availability', 'latency'):
        count, bad = expressions(indicator, policy['window'])
        expression = ('(1 - ' + bad + ') and (' + count + ' >= ' + str(policy['minimum_window_samples']) +
                      ') and (' + coverage() + ' >= ' + str(policy['window_seconds'] // 30 - 1) + ')')
        panels.append({'id': len(panels) + 1, 'title': indicator.title() + ' (' + policy['window'] + ')',
            'type': 'stat', 'datasource': {'type': 'prometheus', 'uid': 'metrics'},
            'gridPos': {'x': 12 * (len(panels) % 2), 'y': 0, 'w': 12, 'h': 6},
            'targets': [{'refId': 'A', 'expr': expression, 'instant': True}],
            'fieldConfig': {'defaults': {'unit': 'percentunit', 'min': 0, 'max': 1, 'noValue': 'UNAVAILABLE',
                'thresholds': {'mode': 'absolute', 'steps': [{'color': 'red', 'value': None},
                    {'color': 'green', 'value': policy[indicator + '_target']}]}}}})
        for windows in policy['burn_windows']:
            _, burn = expressions(indicator, windows['long'])
            panels.append({'id': len(panels) + 1, 'title': indicator.title() + ' burn ' + windows['long'],
                'type': 'timeseries', 'datasource': {'type': 'prometheus', 'uid': 'metrics'},
                'gridPos': {'x': 0, 'y': 6 * len(panels), 'w': 24, 'h': 6},
                'targets': [{'refId': 'A', 'expr': burn + ' / ' + str(1 - policy[indicator + '_target'])}]})
    panels.append({'id': len(panels) + 1, 'title': 'Evidence and burn alerts', 'type': 'table',
        'datasource': {'type': 'prometheus', 'uid': 'metrics'},
        'gridPos': {'x': 0, 'y': 6 * len(panels), 'w': 24, 'h': 6},
        'targets': [{'refId': 'A', 'expr': 'ALERTS{service="notes-api"}', 'instant': True, 'format': 'table'}]})
    return {'uid': 'notes-user-slo', 'title': 'Notes user SLO', 'schemaVersion': 41, 'version': 1,
        'editable': False, 'refresh': '30s', 'time': {'from': 'now-6h', 'to': 'now'},
        'description': 'User reads only. Complete 7d scrape window and 10000 samples required. Missing or truncated evidence is UNAVAILABLE. Release traffic is separate.',
        'panels': panels}


def build():
    path = ROOT / 'platform/observability/prometheus/templates'
    path.mkdir(exist_ok=True)
    resource = {'apiVersion': 'monitoring.coreos.com/v1', 'kind': 'PrometheusRule',
                'metadata': {'name': 'notes-user-slo', 'namespace': 'cloudlab-observability'}, 'spec': rules()}
    (path / 'notes-slo.json').write_text(json.dumps(resource, indent=2) + '\n')
    config = {'apiVersion': 'v1', 'kind': 'ConfigMap',
              'metadata': {'name': 'cloudlab-dashboards', 'namespace': 'cloudlab-observability'},
              'data': {'notes-slo.json': json.dumps(dashboard(), separators=(',', ':'))}}
    (path / 'dashboards.json').write_text(json.dumps(config, indent=2) + '\n')


if __name__ == '__main__':
    build()
