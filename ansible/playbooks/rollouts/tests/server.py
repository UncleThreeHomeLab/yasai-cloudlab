"""Disposable release exporter; no application, database or vault credentials."""
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import time

REVISION = os.environ['CLOUDLAB_REVISION']
MODE = os.environ.get('RELEASE_MODE', 'healthy')
COUNTS = Counter({'200': 0, '503': 0})
BUCKETS = Counter({value: 0 for value in (0.01, 0.05, 0.1, 0.25, 0.5, 1, float('inf'))})
MAXIMUM = 0
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        global MAXIMUM
        if self.path == '/metrics':
            body = metrics().encode()
            status = 200
        elif self.path == '/ready':
            body, status = b'ready', 200
        elif self.path == '/canary-proof':
            started = time.monotonic()
            status = 503 if MODE == 'faulty' else 200
            body = json.dumps({'revision': REVISION}).encode()
            if self.headers.get('User-Agent') == 'CloudLab-Release-Proof/1.0' and MODE != 'low-samples':
                elapsed = time.monotonic() - started
                with LOCK:
                    COUNTS[str(status)] += 1
                    MAXIMUM = max(MAXIMUM, elapsed)
                    for bound in BUCKETS:
                        if elapsed <= bound:
                            BUCKETS[bound] += 1
        else:
            body, status = b'not found', 404
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-CloudLab-Revision', REVISION)
        self.end_headers()
        self.wfile.write(body)


def metrics():
    if MODE == 'missing':
        return ''
    labels = 'service="release-proof",traffic="release",revision="' + REVISION + '"'
    with LOCK:
        lines = ['cloudlab_http_requests_total{' + labels + ',status="' + status + '"} ' + str(count)
                 for status, count in COUNTS.items()]
        for bound, count in BUCKETS.items():
            lines.append('cloudlab_http_duration_seconds_bucket{' + labels + ',le="' +
                         ('+Inf' if bound == float('inf') else str(bound)) + '"} ' + str(count))
        lines.append('cloudlab_http_duration_seconds_max{' + labels + '} ' + str(MAXIMUM))
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    threading.Thread(target=ThreadingHTTPServer(('0.0.0.0', 9091), Handler).serve_forever, daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
