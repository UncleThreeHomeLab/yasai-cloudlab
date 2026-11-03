"""Compile private, bounded service views from approved workload identities."""
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[4]
SOURCE = {'type': 'prometheus', 'uid': 'metrics'}
NAME = r'[a-z][a-z0-9-]{0,62}'


def projection(catalog):
    from playbooks.services.files.remote import bindings
    result = []
    for entry in catalog['catalog']:
        if entry['publication'] != 'retired':
            result.append({'name': entry['approval']['name'], 'namespace': entry['approval']['namespace'],
                           'workloads': bindings(entry)})
    validate(result)
    return sorted(result, key=lambda row: row['name'])


def validate(services):
    if not isinstance(services, list) or len(services) > 20:
        raise ValueError('Service dashboard bindings exceed their scope')
    names, owners = set(), set()
    for service in services:
        if (set(service) != {'name', 'namespace', 'workloads'} or
                not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', service['name']) or
                not re.fullmatch(NAME, service['namespace']) or service['name'] in names or
                not isinstance(service['workloads'], list) or not 1 <= len(service['workloads']) <= 12):
            raise ValueError('Service dashboard requires distinct bounded identities')
        names.add(service['name'])
        for row in service['workloads']:
            if (set(row) != {'name', 'kind'} or not re.fullmatch(NAME, row['name']) or
                    row['kind'] not in ('Deployment', 'Rollout') or
                    (service['namespace'], row['name']) in owners):
                raise ValueError('Dashboard workload binding is ambiguous or unsupported')
            owners.add((service['namespace'], row['name']))


def substitute(expression, dashboard=None):
    """Use the same bounded substitutions for native and live query verification."""
    replacements = {'__rate_interval': '2m', '__range': '6h', 'namespace': '.*', 'pod': '.*',
                    'instance': '.*', 'service': '.*', 'rollout': '.*', 'route': '.*', 'traffic': 'user|release',
                    'component': '.*', 'container': '.*'}
    if dashboard:
        for variable in dashboard.get('templating', {}).get('list', []):
            if variable['name'] == 'component':
                replacements['component'] = json.dumps(re.escape(variable['current']['value']))[1:-1]
    for name, value in replacements.items():
        expression = expression.replace('${' + name + ':regex}', value).replace('$' + name, value)
    if re.search(r'\$(?:\{|[A-Za-z_])', expression):
        raise ValueError('Dashboard query contains an unsupported variable')
    return expression


def ownership(service, selected=False):
    namespace = json.dumps(service['namespace'])
    controllers = []
    for kind in ('Deployment', 'Rollout'):
        names = [row['name'] for row in service['workloads'] if row['kind'] == kind]
        if not names:
            continue
        scope = 'namespace=' + namespace + ',owner_is_controller="true",owner_kind="' + kind + '",owner_name=~"' + '|'.join(names) + '"'
        if selected:
            scope += ',owner_name=~"${component:regex}"'
        metric = 'kube_replicaset_owner{' + scope + '}'
        controllers.append('label_replace((' + metric + ' and (time() - timestamp(' + metric + ') < 120)), "component", "$1", "owner_name", "(.+)")')
    rs = 'max by(namespace,replicaset,component) (' + ' or '.join(controllers) + ')'
    pod = 'kube_pod_owner{namespace=' + namespace + ',owner_is_controller="true",owner_kind="ReplicaSet"}'
    pod = 'max by(namespace,pod,replicaset) (label_replace((' + pod + ' and (time() - timestamp(' + pod + ') < 120)), "replicaset", "$1", "owner_name", "(.+)"))'
    return '(' + pod + ' * on(namespace,replicaset) group_left(component) ' + rs + ')'


def replicas(service, available=False):
    rows = []
    for row in service['workloads']:
        if row['kind'] == 'Deployment':
            metric = 'kube_deployment_' + ('status_replicas_available' if available else 'spec_replicas')
            selector = 'deployment'
        else:
            metric = 'cloudlab_rollout_replicas_' + ('available' if available else 'desired')
            selector = 'rollout'
        raw = metric + '{namespace=' + json.dumps(service['namespace']) + ',' + selector + '=' + json.dumps(row['name']) + '}'
        fresh = '(' + raw + ' and (time() - timestamp(' + raw + ') < 120))'
        stale = '(0 * last_over_time(' + raw + '[10m]) - 2)'
        # Keep every approved component visible; negative values are explicitly unknown/stale.
        observed = 'max by(component) (label_replace((' + fresh + ' or ' + stale + '), "component", ' + json.dumps(row['name']) + ', "' + selector + '", ".*"))'
        missing = 'label_replace(vector(-1), "component", ' + json.dumps(row['name']) + ', "", "")'
        rows.append('(' + observed + ' or on(component) ' + missing + ')')
    return '(' + ' or '.join(rows) + ')'


def measured(service, metric, selected=False, detail=False, rate=False):
    selector = 'namespace=' + json.dumps(service['namespace'])
    if metric.startswith('container_'):
        selector += ',container!="",container!="POD",image!=""'
    if metric == 'kube_pod_status_ready':
        selector += ',condition="true"'
    if detail:
        selector += ',pod=~"${pod:regex}",container=~"${container:regex}"'
    raw = metric + '{' + selector + '}'
    value = ('rate(' + raw + '[$__rate_interval])' if rate else raw)
    value = '(' + value + ' and (time() - timestamp(' + raw + ') < 120))'
    labels = 'namespace,pod,container' if metric != 'kube_pod_status_ready' else 'namespace,pod'
    joined = 'max by(' + labels + ') (' + value + ') * on(namespace,pod) group_left(component) ' + ownership(service, selected)
    return 'sum by(' + ('container' if detail else 'component') + ') (' + joined + ')'


def panel(identifier, title, expressions, unit, kind='timeseries', fields=None, description=''):
    mappings = [{'type': 'special', 'options': {'match': match, 'result': {'text': 'UNKNOWN', 'color': 'gray'}}}
                for match in ('null', 'nan')]
    mappings.append({'type': 'value', 'options': {'-1': {'text': 'UNKNOWN', 'color': 'gray'},
        '-2': {'text': 'STALE', 'color': 'gray'}}})
    result = {'id': identifier, 'title': title, 'type': kind, 'datasource': SOURCE,
        'gridPos': {'x': 0 if identifier % 2 else 12, 'y': ((identifier - 1) // 2) * 8, 'w': 12, 'h': 8},
        'fieldConfig': {'defaults': {'unit': unit, 'noValue': 'UNKNOWN', 'mappings': mappings}, 'overrides': []},
        'options': {'legend': {'displayMode': 'table', 'placement': 'bottom'}},
        'description': description or 'Only approved owned workloads. Missing or stale telemetry is not healthy zero.',
        'targets': [{'refId': chr(65 + index), 'expr': expression, 'legendFormat': '{{component}}' if not title.startswith('Selected pod') else '{{container}}',
                     **({'format': 'table', 'instant': True} if kind == 'table' else
                        {'instant': True, 'range': False} if kind == 'stat' else {})}
                    for index, expression in enumerate(expressions)]}
    if kind == 'table':
        labels = {'All component replicas': ('Desired', 'Available'),
                  'All component readiness and restarts': ('Ready pods', 'Restarts / second'),
                  'All component CPU and memory': ('CPU cores', 'Memory bytes')}[title]
        result['transformations'] = [{'id': 'merge', 'options': {}},
            {'id': 'filterFieldsByName', 'options': {'include': {'names': fields}}},
            {'id': 'sortBy', 'options': {'sort': [{'field': 'Value #C' if title == 'All component replicas' else 'Value #B', 'desc': False}]}},
            {'id': 'organize', 'options': {'renameByName': {'Value #A': labels[0], 'Value #B': labels[1], 'Value #C': 'Replica gap'}}}]
        if title == 'All component CPU and memory':
            result['fieldConfig']['overrides'] = [
                {'matcher': {'id': 'byName', 'options': name}, 'properties': [{'id': 'unit', 'value': unit}]}
                for name, unit in zip(labels, ('cores', 'bytes'))]
    return result


def build(service):
    validate([service])
    desired, available = replicas(service), replicas(service, True)
    ready = measured(service, 'kube_pod_status_ready')
    restarts = measured(service, 'kube_pod_container_status_restarts_total', rate=True)
    cpu = measured(service, 'container_cpu_usage_seconds_total', rate=True)
    memory = measured(service, 'container_memory_working_set_bytes')
    panels = [panel(1, 'Replica availability (readiness only)',
        ['min((' + available + ' >= 0) / on(component) (' + desired + ' > 0)) and (min(' + available + ') >= 0) and (min(' + desired + ') >= 0)'], 'percentunit', 'stat',
        description='Readiness is not functional health. Components without probes need application-specific evidence.'),
        panel(2, 'All component replicas', [desired, available, '(' + available + ' >= 0) - on(component) (' + desired + ' >= 0)'],
              'short', 'table', ['component', 'Value #A', 'Value #B', 'Value #C']),
        panel(3, 'All component readiness and restarts', [ready, restarts], 'short', 'table', ['component', 'Value #A', 'Value #B']),
        panel(4, 'All component CPU and memory', [cpu, memory], 'short', 'table', ['component', 'Value #A', 'Value #B']),
        panel(5, 'Component CPU', [measured(service, 'container_cpu_usage_seconds_total', True, rate=True)], 'cores'),
        panel(6, 'Component memory', [measured(service, 'container_memory_working_set_bytes', True)], 'bytes'),
        panel(7, 'Selected pod CPU', [measured(service, 'container_cpu_usage_seconds_total', True, True, True)], 'cores'),
        panel(8, 'Selected pod memory', [measured(service, 'container_memory_working_set_bytes', True, True)], 'bytes'),
        panel(9, 'Selected pod restarts per second', [measured(service, 'kube_pod_container_status_restarts_total', True, True, True)], 'ops')]
    from playbooks.observability.files.slo import definition
    policy = definition()
    if policy['service'] in {w['name'] for w in service['workloads']}:
        panels.extend(performance(service, policy))
    component = policy['service'] if policy['service'] in {w['name'] for w in service['workloads']} else service['workloads'][0]['name']
    if len(panels) == 12:
        positions = {1: (0, 0, 12), 10: (12, 0, 12), 11: (0, 8, 12), 12: (12, 8, 12),
                     2: (0, 16, 24), 3: (0, 24, 12), 4: (12, 24, 12), 5: (0, 32, 12),
                     6: (12, 32, 12), 7: (0, 40, 12), 8: (12, 40, 12), 9: (0, 48, 12)}
        for item in panels:
            x, y, width = positions[item['id']]
            item['gridPos'].update(x=x, y=y, w=width)
    variables = [{'name': 'component', 'label': 'Component', 'type': 'custom',
        'query': ','.join(row['name'] for row in service['workloads']), 'current': {'text': component, 'value': component},
        'includeAll': False, 'multi': False}]
    pod_query = 'query_result(count by(pod) (' + ownership(service, True) + '))'
    container_query = 'query_result(' + measured(service, 'kube_pod_container_info', True, True) + ')'
    # Container options must not depend on their own current selection.
    container_query = container_query.replace(',container=~"${container:regex}"', '')
    for name, query in (('pod', pod_query), ('container', container_query)):
        variables.append({'name': name, 'label': name.title(), 'type': 'query', 'datasource': SOURCE,
            'query': query, 'regex': '/' + name + '="([^\"]+)"/', 'refresh': 2, 'sort': 1,
            'includeAll': False, 'multi': False, 'current': {}})
    return {'schemaVersion': 41, 'uid': 'svc-' + service['name'], 'title': service['name'],
        'editable': False, 'version': 1, 'tags': ['cloudlab', 'service'], 'timezone': 'browser', 'refresh': '30s',
        'time': {'from': 'now-6h', 'to': 'now'}, 'description':
        'Approved service workloads only. Readiness and resources do not prove application behavior. '
        'UNKNOWN means missing evidence; STALE means last controller evidence is older than 120s. '
        'No application performance panels means accepted HTTP/worker instrumentation is unavailable.',
        'templating': {'list': variables}, 'links': [{'type': 'link', 'title': 'Nodes', 'url': '/d/cloudlab-nodes'}], 'panels': panels}


def performance(service, policy):
    scope = 'namespace=' + json.dumps(service['namespace']) + ',' + ','.join(
        key + '=' + json.dumps(policy[key]) for key in ('service', 'route', 'traffic'))
    def rate(metric, extra=''):
        raw = metric + '{' + scope + extra + '}'
        return '(rate(' + raw + '[$__rate_interval]) and (time() - timestamp(' + raw + ') < 120)) * on(namespace,pod) group_left(component) ' + ownership(service)
    total = 'sum(' + rate('cloudlab_http_requests_total', ',status=~"2..|5.."') + ')'
    errors = 'sum(' + rate('cloudlab_http_requests_total', ',status=~"5.."') + ')'
    error_ratio = '((' + errors + ' or (0 * ' + total + ')) / (' + total + ' > 0))'
    buckets = 'sum by(le) (' + rate('cloudlab_http_duration_seconds_bucket', ',status=~"2.."') + ')'
    raw = 'cloudlab_http_requests_total{' + scope + ',status=~"2..|5.."}'
    count = 'sum((increase(' + raw + '[2m]) and (time() - timestamp(' + raw + ') < 120)) * on(namespace,pod) group_left(component) ' + ownership(service) + ')'
    sufficient = '(' + count + ' >= 10)'
    latency = '(histogram_quantile(0.95, ' + buckets + ') and ' + sufficient + ')'
    stale = '((-3 + 0 * sum(last_over_time(' + raw + '[10m]) * on(namespace,pod) group_left(component) ' + ownership(service) + ')) unless ' + total + ')'
    no_traffic = '(-1 + 0 * (' + total + ' == 0))'
    insufficient = '(-2 + 0 * ((' + count + ' > 0) < 10))'
    result = [panel(10, 'User requests per second', ['(' + total + ') or ' + stale], 'reqps'),
              panel(11, 'User error fraction', ['(' + error_ratio + ' and ' + sufficient + ') or ' + no_traffic + ' or ' + insufficient + ' or ' + stale], 'percentunit'),
              panel(12, 'User p95 latency', [latency + ' or ' + no_traffic + ' or ' + insufficient + ' or ' + stale], 's')]
    for item in result:
        item['description'] = ('Approved user route only; release/probe/synthetic traffic excluded. '
            'Percentiles combine replica buckets. Error/latency needs >=10 requests in 2m; '
            'lower evidence is unavailable, not compliance. Full SLO compliance still requires the owning definition\'s complete window and minimum counts.')
        item['fieldConfig']['defaults']['mappings'][-1] = {'type': 'value', 'options': {
            '-1': {'text': 'No traffic', 'color': 'gray'}, '-2': {'text': 'Insufficient evidence', 'color': 'gray'},
            '-3': {'text': 'STALE', 'color': 'gray'}, **({'0': {'text': 'No traffic', 'color': 'gray'}} if item['id'] == 10 else {})}}
    return result


def generated(services):
    validate(services)
    result = {'svc-' + row['name'] + '.json': json.dumps(build(row), sort_keys=True, indent=2) + '\n'
              for row in services}
    if sum(len(raw.encode()) for raw in result.values()) > 768 * 1024:
        raise ValueError('Generated service dashboards exceed their ConfigMap budget')
    return result


def query_rules(dashboards):
    result = []
    for dashboard in dashboards:
        expressions = [target['expr'] for panel in dashboard['panels']
                       if panel['datasource']['uid'] == 'metrics' for target in panel['targets']]
        expressions.extend(variable_queries(dashboard))
        for expression in expressions:
            result.append({'record': 'dashboard:query_' + str(len(result)), 'expr': substitute(expression, dashboard)})
    return {'groups': [{'name': 'dashboard-syntax', 'rules': result}]}


def variable_queries(dashboard):
    return [variable['query'][len('query_result('):-1] for variable in dashboard['templating']['list']
            if variable.get('query', '').startswith('query_result(')]


def inventory(services=()):
    result = {path.name: path.read_text() for path in
              sorted((ROOT / 'platform/observability/prometheus/dashboards').glob('*.json'))}
    result.update(generated(list(services)))
    uids = [json.loads(raw)['uid'] for raw in result.values()]
    if len(uids) != len(set(uids)):
        raise ValueError('Dashboard UIDs must be unique')
    return result
