"""Private isolated TLS gateway for master issuer compatibility, not production policy."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import socket
import urllib.error
import urllib.request

HOST = 'admin.fixture.test'
CONTEXT = ssl.create_default_context(cafile='/fixture/ca.crt')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


OPENER = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=CONTEXT))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def forward(self):
        if self.headers.get('Host') not in (HOST, HOST + ':443') or not self.path.startswith(('/admin/', '/realms/', '/resources/')):
            self.send_error(403)
            return
        size = int(self.headers.get('Content-Length', 0))
        if size > 131072:
            self.send_error(413)
            return
        headers = {key: value for key, value in self.headers.items() if key.lower() not in (
            'host', 'forwarded', 'connection', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-proto', 'x-forwarded-for')}
        headers.update({'Host': HOST, 'X-Forwarded-Host': HOST, 'X-Forwarded-Port': '443', 'X-Forwarded-Proto': 'https'})
        request = urllib.request.Request('https://localhost:8443' + self.path, headers=headers,
            method=self.command, data=self.rfile.read(size) if size else None)
        try:
            response = OPENER.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(8 * 1024 * 1024 + 1)
            if len(body) > 8 * 1024 * 1024:
                self.send_error(502)
                return
            self.send_response(response.status)
            for key, value in response.headers.items():
                if key.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    do_GET = forward
    do_POST = forward
    do_PUT = forward
    do_DELETE = forward


if __name__ == '__main__':
    server = HTTPServer((socket.gethostbyname('server'), 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain('/fixture/tls.crt', '/fixture/tls.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
