"""Disposable metric source and bounded notification receiver for native alert proof."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
COUNTERS = {'good': 0, 'bad': 0, 'fast': 0, 'release': 0}
NOTIFICATIONS = set()
RECOVERED = False
UPDATED = time.monotonic()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def respond(self, value, content_type='application/json'):
        body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global UPDATED
        with LOCK:
            if self.path == '/notifications':
                return self.respond(sorted(NOTIFICATIONS))
            if self.path != '/metrics':
                self.send_error(404)
                return
            elapsed = time.monotonic() - UPDATED
            UPDATED = time.monotonic()
            for key, rate in {'good': 100000 if RECOVERED else 90,
                              'bad': 0 if RECOVERED else 10,
                              'fast': 100000 if RECOVERED else 80, 'release': 1000}.items():
                COUNTERS[key] += elapsed * rate
            labels = 'service="notes-api",route="/api/notes",traffic="user"'
            metrics = [
                f'cloudlab_http_requests_total{{{labels},status="200"}} {COUNTERS["good"]}',
                f'cloudlab_http_requests_total{{{labels},status="500"}} {COUNTERS["bad"]}',
                f'cloudlab_http_duration_seconds_bucket{{{labels},status="200",le="0.5"}} {COUNTERS["fast"]}',
                'cloudlab_http_requests_total{service="notes-api",route="/api/release/notes",traffic="release",status="500"} ' + str(COUNTERS['release'])]
            self.respond('\n'.join(metrics) + '\n', 'text/plain; version=0.0.4')

    def do_POST(self):
        global RECOVERED
        if self.path == '/recover':
            with LOCK: RECOVERED = True
            return self.respond({'recovered': True})
        size = int(self.headers.get('Content-Length', '0'))
        if self.path != '/alerts' or not 0 < size <= 65536:
            self.send_error(400)
            return
        document = json.loads(self.rfile.read(size))
        with LOCK:
            for alert in document.get('alerts', [])[:16]:
                name, status = alert.get('labels', {}).get('alertname', ''), alert.get('status')
                if name in ('NotesAvailabilityBurn1h', 'NotesAvailabilityBurn6h',
                            'NotesLatencyBurn1h', 'NotesLatencyBurn6h') and status in ('firing', 'resolved'):
                    NOTIFICATIONS.add((name, status))
        self.respond({'accepted': True})


def verify():
    from playbooks.observability.tests.native_proof import http, wait
    names = {'NotesAvailabilityBurn1h', 'NotesAvailabilityBurn6h', 'NotesLatencyBurn1h', 'NotesLatencyBurn6h'}
    def delivered(status):
        received = json.loads(http('http://alert-fixture:8085/notifications'))
        return {name for name, state in received if state == status} == names
    wait(lambda: delivered('firing'), seconds=300)
    http('http://alert-fixture:8085/recover', {})
    wait(lambda: delivered('resolved'), seconds=180)
    alerts = json.loads(http('http://prometheus:9090/api/v1/alerts'))['data']['alerts']
    if any(alert['labels'].get('alertname') in names and alert['state'] == 'firing' for alert in alerts):
        raise RuntimeError('Recovered user SLO still burns; release exclusion failed')
    from playbooks.observability.files.slo import expressions, rules
    from urllib.parse import urlencode
    def query(expression):
        return json.loads(http('http://prometheus:9090/api/v1/query?' + urlencode({'query': expression})))['data']['result']
    samples = query(expressions('availability', '7d')[0])
    if not samples or float(samples[0]['value'][1]) < 10000:
        raise RuntimeError('Fixture lacks enough samples to qualify missing-window behavior')
    unavailable = next(row['expr'] for group in rules()['groups'] for row in group['rules']
                       if row.get('alert') == 'NotesSLOEvidenceUnavailable')
    if not query(unavailable):
        raise RuntimeError('Incomplete retained window incorrectly reports SLO compliance')
    return {'native_burn_firing_and_resolved': True, 'webhook_delivery': True,
            'release_failures_excluded': True, 'incomplete_window_unavailable': True, 'production_traffic': False}


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8085), Handler).serve_forever()
