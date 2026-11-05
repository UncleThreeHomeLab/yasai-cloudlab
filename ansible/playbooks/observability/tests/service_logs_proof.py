"""Exercise rendered sanitizers and the native mounted-directory reload watcher."""
import copy
import json
from pathlib import Path
import shutil
import sys
import time
import urllib.error
import urllib.parse

from playbooks.observability.tests import native_proof as native

FIXTURE = Path('/fixture')
CONFIG = FIXTURE / 'alloy'


def publish(name):
    revision = CONFIG / ('revision-' + str(time.time_ns()))
    revision.mkdir()
    shutil.copyfile(FIXTURE / (name + '.alloy'), revision / 'config.alloy')
    link = CONFIG / '..next'
    link.symlink_to(revision.name, target_is_directory=True)
    link.replace(CONFIG / '..data')


def prepare():
    native.prepare()
    from playbooks.observability.tests.fixtures import logged_service_inputs, native_overrides, helm
    value = logged_service_inputs()
    second = copy.deepcopy(value['catalog'][0])
    second['approval'].update(name='secondary', namespace='cloudlab-app-secondary')
    second['definition']['name'] = 'secondary'
    value['catalog'].append(copy.deepcopy(second))
    legacy = (FIXTURE / 'config.alloy').read_text()
    # Only replace Kubernetes input transport. The rendered process blocks remain exact.
    def config(inputs):
        overrides = native_overrides(inputs)['cloudlab-observability']
        rendered = next(o['data']['config.alloy'] for o in helm('platform/observability', overrides)
                        if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'cloudlab-alloy')
        if len(overrides['serviceLogs']) == 2:
            (FIXTURE / 'production.alloy').write_text(rendered)
        result = legacy
        for name, port in (('synthetic', 1301), ('secondary', 1302)):
            marker = 'loki.process "svc_' + name + '"'
            if marker not in rendered: continue
            process = rendered[rendered.index(marker):]
            process = process[:process.index('\ndiscovery.kubernetes ')] if '\ndiscovery.kubernetes ' in process else process
            result += '\nloki.source.api "fixture_' + name + '" {\n  http { listen_address = "0.0.0.0"\n    listen_port = ' + str(port) + ' }\n'
            result += '  forward_to = [loki.process.svc_' + name + '.receiver]\n}\n' + process + '\n'
        return result
    both = config(value)
    (FIXTURE / 'both.alloy').write_text(both)
    value['catalog'][1]['definition']['monitoring'] = {'enabled': False}
    (FIXTURE / 'initial.alloy').write_text(config(value))
    value['catalog'][1] = second
    value['catalog'][0]['definition']['monitoring']['routes'] = ['/v2/items']
    updated = config(value)
    (FIXTURE / 'updated.alloy').write_text(updated)
    value['catalog'][1]['definition']['monitoring'] = {'enabled': False}
    removed = config(value)
    (FIXTURE / 'removed.alloy').write_text(removed)
    (FIXTURE / 'invalid.alloy').write_text('this is not valid Alloy {{{')
    (FIXTURE / 'backend-failure.alloy').write_text(removed.replace('http://cloudlab-loki:3100/loki/api/v1/push', 'http://127.0.0.1:9/loki/api/v1/push'))
    CONFIG.mkdir(exist_ok=True)
    if not (CONFIG / 'config.alloy').is_symlink():
        (CONFIG / 'config.alloy').symlink_to('..data/config.alloy')
    publish('initial')
    print(json.dumps({'rendered_service_logs': True, 'native_watcher': True}))


def metrics():
    return native.http('http://alloy:12345/metrics').decode()


def metric(name, optional=False):
    values = [float(line.rsplit(' ', 1)[1]) for line in metrics().splitlines()
              if line.startswith(name + ' ') or line.startswith(name + '{')]
    if not values and not optional: raise RuntimeError('Native metric is unavailable: ' + name)
    return sum(values)


def push(service, record):
    port = {'synthetic': 1301, 'secondary': 1302}[service]
    line = record if isinstance(record, str) else json.dumps(record)
    native.http('http://alloy:' + str(port) + '/loki/api/v1/push', {'streams': [{
        'stream': {'service': 'forged', 'service_name': 'forged', 'namespace': 'forged', 'secret': 'private-canary'},
        'values': [[str(time.time_ns()), line]]}]})


def logs(service):
    query = urllib.parse.urlencode({'query': '{service="' + service + '"}', 'limit': 1000})
    return json.loads(native.http('http://loki:3100/loki/api/v1/query_range?' + query))['data']['result']


def contains(service, marker):
    return marker in json.dumps(logs(service))


def request(marker, route='/api/items'):
    return {'kind': 'request', 'method': 'GET', 'route': route, 'status': 200, 'duration_ms': 1,
        'trace_id': marker, 'service': 'forged', 'service_name': 'forged', 'password': 'private-canary'}


def verify():
    native.wait(lambda: native.http('http://alloy:12345/-/ready'))
    native.wait(lambda: native.http('http://loki:3100/ready'))
    start = metric('process_start_time_seconds')
    native.verify(alerts=False)
    dropped = metric('loki_process_dropped_lines_total', optional=True)
    native.http('http://alloy:1300/loki/api/v1/push', {'streams': [{'stream': {'probe': 'legacy-kind'},
        'values': [[str(time.time_ns()), json.dumps({'kind': {'token': 'legacy-kind-canary'}, 'password': 'legacy-kind-canary'})]]}]})
    native.wait(lambda: metric('loki_process_dropped_lines_total', optional=True) > dropped)
    legacy_query = urllib.parse.urlencode({'query': '{pipeline="redacted"}'})
    if 'legacy-kind-canary' in native.http('http://loki:3100/loki/api/v1/query_range?' + legacy_query).decode():
        raise RuntimeError('Malformed legacy kind leaked raw content')
    first = '1' * 32
    push('synthetic', request(first))
    native.wait(lambda: contains('synthetic', first))
    publish('both')
    second = '2' * 32
    native.wait(lambda: push('secondary', request(second)) or True)
    native.wait(lambda: contains('secondary', second))
    time.sleep(1)
    push('synthetic', {'kind': 'request', 'method': 'POST', 'route': 'other', 'status': 201, 'duration_ms': 2})
    time.sleep(1)
    push('synthetic', {'kind': 'error', 'code': 'timeout'})
    native.wait(lambda: any('"code":"timeout"' in line for row in logs('synthetic') for _, line in row['values']))
    time.sleep(1)
    push('synthetic', dict(request(None), duration_ms=3))
    native.wait(lambda: any(json.loads(line).get('duration_ms') == 3 and 'trace_id' not in json.loads(line)
                           for row in logs('synthetic') for _, line in row['values']))
    time.sleep(1)
    before = metric('loki_process_dropped_lines_total', optional=True)
    bad = ['not-json', 'x' * 5000, request('invalid'), dict(request(first), route='/api/items?token=private-canary'),
           dict(request(first), duration_ms=1000000), {'kind': 'error', 'code': 'private-canary'},
           *[dict(request(first), kind=kind) for kind in ({'token': 'private-canary'}, ['private-canary'], 4, None)],
           *[dict(request(first), **{field: {'secret': 'private-canary'}}) for field in ('method', 'status', 'duration_ms', 'trace_id')],
           dict(request(first), trace_id=0), dict(request(first), trace_id='0' * 32),
           dict(request('<nil>'), duration_ms=17), {'kind': 'error', 'code': 'internal_error', 'trace_id': '<nil>'}]
    for record in bad:
        push('synthetic', record)
        time.sleep(0.6)
    native.wait(lambda: metric('loki_process_dropped_lines_total') >= before + len(bad))
    for service in ('synthetic', 'secondary'):
        rows = logs(service)
        if any(set(row['stream']) - {'service', 'kind', 'service_name'} for row in rows):
            raise RuntimeError('Unapproved stored log index label')
        if any(row['stream'].get('service') != service or row['stream'].get('service_name', service) != service for row in rows):
            raise RuntimeError('Producer spoofed service identity')
        if any(json.loads(line).get('duration_ms') == 17 for row in rows for _, line in row['values']):
            raise RuntimeError('Literal nil trace marker was accepted')
        for row in rows:
            for _, line in row['values']:
                trace = json.loads(line).get('trace_id')
                if trace is not None and (len(trace) != 32 or any(c not in '0123456789abcdef' for c in trace) or trace == '0' * 32):
                    raise RuntimeError('Invalid trace ID reached stored logs')
        if any(word in json.dumps(rows) for word in ('canary', 'forged', '1000000', '?token=', '<nil>')):
            raise RuntimeError('Unsafe log body or label survived')
    publish('updated')
    updated = '3' * 32
    native.wait(lambda: (push('synthetic', request(updated, '/v2/items')) or contains('synthetic', updated)))
    native.wait(lambda: contains('synthetic', updated))
    dropped = metric('loki_process_dropped_lines_total')
    push('synthetic', request('a' * 32))
    native.wait(lambda: metric('loki_process_dropped_lines_total') > dropped)
    if contains('synthetic', 'a' * 32): raise RuntimeError('Removed route remained accepted')
    publish('invalid')
    native.wait(lambda: metric('alloy_config_last_load_successful') == 0)
    retained = '4' * 32
    push('synthetic', request(retained, '/v2/items'))
    native.wait(lambda: contains('synthetic', retained))
    if metric('process_start_time_seconds') != start: raise RuntimeError('Alloy restarted instead of reloading')
    publish('removed')
    native.wait(lambda: metric('alloy_config_last_load_successful') == 1)
    def removed():
        try: push('secondary', request('5' * 32))
        except urllib.error.URLError: return True
        return False
    native.wait(removed)
    if not contains('secondary', second): raise RuntimeError('Removal deleted retained historical logs')
    retries = metric('loki_write_batch_retries_total', optional=True)
    publish('backend-failure')
    time.sleep(3)
    recovery = '6' * 32
    push('synthetic', request(recovery, '/v2/items'))
    native.wait(lambda: metric('loki_write_batch_retries_total', optional=True) > retries)
    publish('removed')
    native.wait(lambda: metric('alloy_config_last_load_successful') == 1)
    # Endpoint replacement can discard its bounded queue; prove new ingestion resumes.
    resumed = '7' * 32
    native.wait(lambda: push('synthetic', request(resumed, '/v2/items')) or contains('synthetic', resumed))
    if metric('process_start_time_seconds') != start: raise RuntimeError('Watcher lifecycle restarted Alloy')
    print(json.dumps({'generic_log_privacy': True, 'constant_service_identity': True,
        'legacy_malformed_kind_dropped': True,
        'optional_trace_ids': True, 'native_drop_and_export_failure_evidence': True,
        'automatic_add_update_remove': True, 'invalid_reload_preserves_running_config': True,
        'automatic_recovery': True, 'historical_logs_retained': True, 'process_not_restarted': True,
        'kubernetes_discovery_proven': False}))


if __name__ == '__main__':
    {'prepare': prepare, 'verify': verify}[sys.argv[1]]()
