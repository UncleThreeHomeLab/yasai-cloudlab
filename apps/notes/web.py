"""Notes static frontend; credentials and tokens never reach web-server logs."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent


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
        if path in ('/live', '/ready'):
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
    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
