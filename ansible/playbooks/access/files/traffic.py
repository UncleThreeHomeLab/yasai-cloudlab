"""Direct, verified HTTPS probes without environment proxies or redirect following."""
import http.client
import ipaddress
import socket
import ssl


def https(hostname, *, address=None, headers=None, path='/', stream=None, timeout=12):
    values = {'Host': hostname, 'Connection': 'close', 'Cache-Control': 'no-cache'}
    values.update(headers or {})
    if any('\r' in str(x) or '\n' in str(x) for pair in values.items() for x in pair):
        raise ValueError('HTTP probe header contains a line break')
    connection = stream or socket.create_connection((address or hostname, 443), timeout=timeout)
    try:
        connection.settimeout(timeout)
        with ssl.create_default_context().wrap_socket(connection, server_hostname=hostname) as secure:
            peer = secure.getpeername()[0] if not stream else None
            request = 'GET ' + path + ' HTTP/1.1\r\n' + ''.join(k + ': ' + v + '\r\n' for k, v in values.items()) + '\r\n'
            secure.sendall(request.encode('ascii'))
            response = http.client.HTTPResponse(secure)
            response.begin()
            return {'status': response.status, 'body': response.read(65536),
                    'headers': dict((k.lower(), v) for k, v in response.getheaders()),
                    'public_peer': bool(peer and ipaddress.ip_address(peer).is_global)}
    finally:
        connection.close()


def success(response):
    return response['status'] == 200 and response['body'].strip() == b'mesh-ok'


def denied(response):
    return response['status'] in (301, 302, 303, 401, 403, 404) and not success(response)
