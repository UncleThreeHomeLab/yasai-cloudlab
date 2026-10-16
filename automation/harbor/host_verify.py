"""Check the actual host resolver, TLS trust and registry challenge on each node."""
import http.client
import json
import socket
import ssl
import sys


def run(payload):
    host = payload['configuration']['harborHost']
    if not socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
        raise RuntimeError('Node host cannot resolve private Harbor')
    connection = http.client.HTTPSConnection(host, timeout=20, context=ssl.create_default_context())
    try:
        connection.request('GET', '/v2/')
        response = connection.getresponse()
        response.read()
        challenge = response.getheader('WWW-Authenticate') or ''
        if response.status != 401 or 'realm="https://' + host + '/service/token"' not in challenge:
            raise RuntimeError('Node host did not reach the authenticated private TLS registry')
    finally:
        connection.close()
    return {'host_dns': True, 'trusted_tls': True, 'registry_challenge': True}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Node Harbor DNS/TLS verification failed; private endpoint withheld') from None
