"""Notes static frontend; credentials and tokens never reach web-server logs."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import urllib.request
import telemetry

ROOT = Path(__file__).resolve().parent


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def dependency_ready():
    try:
        # Fixed in-cluster peer; user input cannot select the dependency.
        request = urllib.request.Request('http://notes-api:8080/ready', headers=telemetry.headers())
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=8) as response:
            raw = response.read(1025)
            return response.status == 200 and len(raw) <= 1024 and json.loads(raw) == {'ready': True}
    except Exception:
        return False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path == '/operations' and self.headers.get('Host') != os.environ.get('OPERATIONS_HOST'):
            self.send_error(404)
            return
        if path == '/monitoring-proof/failed':
            body = b'{"ready":false}'
            self.send_response(503)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return
        if path == '/health':
            healthy = dependency_ready()
            body = b'{"ready":true}' if healthy else b'{"ready":false}'
            self.send_response(200 if healthy else 503)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return
        if path in ('/live', '/ready', '/monitoring-proof/ready'):
            body, kind = b'{"ready":true}', 'application/json'
        elif path == '/settings.json':
            body = json.dumps({'issuer': os.environ['OIDC_ISSUER'], 'client': os.environ['OIDC_CLIENT'],
                               'audience': os.environ['OIDC_AUDIENCE'],
                               'scopes': os.environ.get('OIDC_SCOPES', 'openid profile').split(),
                               'operations': self.headers.get('Host') == os.environ.get('OPERATIONS_HOST')}).encode()
            kind = 'application/json'
        elif path in ('/', '/callback', '/operations'):
            body, kind = (ROOT / 'index.html').read_bytes(), 'text/html; charset=utf-8'
        elif path == '/app.js':
            body, kind = (ROOT / 'app.js').read_bytes(), 'text/javascript'
        elif path == '/style.css':
            body, kind = (ROOT / 'style.css').read_bytes(), 'text/css'
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; connect-src 'self' https:; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    telemetry.start('notes-web')
    telemetry.instrument(Handler, 'notes-web')
    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
