"""Fixed in-Pod HTTP checks; bearer credentials exist only in transient stdin."""
import errno
import http.client
import ipaddress
import json
import resource
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


def refused():
    raise ValueError('Probe refused')


def request(target, bearer=None):
    headers = {'Host': target['host'], 'Cache-Control': 'no-cache', 'Connection': 'close'}
    if bearer: headers['Authorization'] = 'Bearer ' + bearer
    try:
        if target['tls']:
            from traffic import https
            result = https(target['host'], address=target['address'], headers=headers, path=target['path'], timeout=2)
            status, body = result['status'], result['body']
        else:
            connection = http.client.HTTPConnection(target['address'], 8080, timeout=2)
            try:
                try:
                    connection.connect()
                except socket.timeout:
                    return 'timeout'
                except ConnectionRefusedError as error:
                    return 'refused' if error.errno == errno.ECONNREFUSED else 'unproved'
                connection.request('GET', target['path'], headers=headers)
                response = connection.getresponse()
                status, body = response.status, response.read(65537)
            finally:
                connection.close()
        expected = json.dumps(target['expected'], sort_keys=True, separators=(',', ':'))
        try:
            decoded = json.loads(body)
            matched = len(body) <= 65536 and json.dumps(decoded, sort_keys=True, separators=(',', ':')) == expected
            exposed = isinstance(decoded, dict) and all(decoded.get(key) == value for key, value in target['expected'].items())
        except (ValueError, UnicodeError): matched = exposed = False
        return 'allowed' if status == 200 and matched else 'denied' if status in (401, 403) and not exposed else 'unexpected'
    except socket.timeout:
        return 'unproved'
    except Exception:
        return 'unproved'


def classify(control, gateway, service, pod):
    if control != 'allowed' or gateway != 'allowed': refused()
    if len(service) != 3 or len(pod) != 3: refused()
    if any(value not in ('denied', 'timeout', 'refused') for value in pod): refused()
    if service not in (['allowed', 'denied', 'denied'], ['denied'] * 3, ['timeout'] * 3, ['refused'] * 3): refused()
    return {'control': True, 'gateway': True, 'podProtected': True,
            'serviceProtected': True, 'serviceMode': 'waypoint' if service[0] == 'allowed' else 'blocked'}


def run(frame):
    if (not isinstance(frame, dict) or set(frame) != {'control', 'targets', 'tokens', 'deadline', 'phase'} or
            frame['phase'] not in ('preflight', 'probe') or
            type(frame['deadline']) is not int or not time.time() < frame['deadline'] <= time.time() + 60 or
            not isinstance(frame['targets'], list) or len(frame['targets']) != 2 or
            not isinstance(frame['tokens'], list) or len(frame['tokens']) != (0 if frame['phase'] == 'preflight' else 2) or
            any(not isinstance(token, str) or not 1 <= len(token) <= 8192 or any(c.isspace() for c in token) for token in frame['tokens'])):
        refused()
    for target in [frame['control'], *(value for group in frame['targets'] for value in group.values())]:
        if (set(target) != {'host', 'address', 'path', 'tls', 'expected'} or type(target['tls']) is not bool or
                not isinstance(target['expected'], dict) or not target['path'].startswith('/') or
                any(c in target['path'] + target['host'] for c in ('\r', '\n', ' ', '#'))): refused()
        ipaddress.ip_address(target['address'])
    control = request(frame['control'])
    if frame['phase'] == 'preflight':
        if control != 'allowed' or any(request(group['gateway']) != 'denied' for group in frame['targets']): refused()
        return {'preflight': True}
    result = []
    for index, group in enumerate(frame['targets']):
        if set(group) != {'gateway', 'service', 'pod'}: refused()
        if time.time() + 16 > frame['deadline']: refused()
        gateway = request(group['gateway'], frame['tokens'][index])
        statuses = {}
        for mode in ('service', 'pod'):
            statuses[mode] = [request(group[mode], bearer) for bearer in (frame['tokens'][index], None, frame['tokens'][1-index])]
        if request(group['gateway'], frame['tokens'][index]) != 'allowed': refused()
        result.append(classify(control, gateway, statuses['service'], statuses['pod']))
    if time.time() >= frame['deadline'] or request(frame['control']) != 'allowed': refused()
    return {'targets': result}


class Control(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        body = b'{"synthetic":"probe-control"}'
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.argv == [sys.argv[0], 'serve']:
        HTTPServer(('0.0.0.0', 8080), Control).serve_forever()
    else:
        try:
            raw = sys.stdin.buffer.read(32769)
            if len(raw) > 32768: refused()
            print(json.dumps(run(json.loads(raw))))
        except Exception:
            print('{"refused":true}')
            raise SystemExit(1)
