"""Bounded OIDC health and a strict redacted audit projection."""
import json
import http.client
import re
import ssl
import socket
import sys
import time
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request


def redact(events, admin=False):
    if not isinstance(events, list) or len(events) > 1000:
        raise ValueError('Audit batch exceeds the bounded projection')
    result = []
    for event in events:
        row = {}
        timestamp = event.get('time')
        if type(timestamp) is int and timestamp >= 0:
            row['time'] = timestamp
        for key in (('operationType', 'resourceType') if admin else ('type', 'error')):
            value = event.get(key)
            if isinstance(value, str) and re.fullmatch('[A-Za-z_]{1,64}', value):
                row[key] = value
        # Drop IPs, IDs, usernames, paths, client metadata and event representations.
        result.append(row)
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def direct_https(url, address, headers, data=None):
    """Keep HTTPS SNI/Host validation while selecting an explicit gateway peer."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.port not in (None, 443):
        raise ValueError('Explicit gateway health requires canonical HTTPS')
    connection = http.client.HTTPSConnection(parsed.hostname, timeout=15)
    try:
        connection.sock = ssl.create_default_context().wrap_socket(
            socket.create_connection((address, 443), timeout=15), server_hostname=parsed.hostname)
        path = parsed.path + ('?' + parsed.query if parsed.query else '')
        connection.request('POST' if data is not None else 'GET', path, body=data, headers=headers)
        response = connection.getresponse()
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise RuntimeError('Identity health response exceeded its limit')
        return response.status, raw
    finally:
        connection.close()


def json_get(url, token=None, form=None, headers=None, address=None):
    headers = dict(headers or {}, Accept='application/json', **{'User-Agent': 'CloudLab-Identity-Health/1.0'})
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = None
    if form is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(form).encode()
    if address is not None:
        status, raw = direct_https(url, address, headers, data)
        if status != 200:
            raise urllib.error.HTTPError(url, status, 'Identity health HTTP status rejected', {}, None)
        return json.loads(raw)
    request = urllib.request.Request(url, headers=headers, data=data)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=15) as response:
        if response.geturl() != url:
            raise RuntimeError('Identity health must not redirect through Access or another issuer')
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise RuntimeError('Identity health response exceeded its limit')
    return json.loads(data)


def check(issuer, address=None):
    parsed = urllib.parse.urlsplit(issuer)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.port not in (None, 443)
            or parsed.path not in ('/realms/platform', '/realms/applications')):
        raise ValueError('Health requires an exact managed HTTPS realm issuer')
    document = json_get(issuer + '/.well-known/openid-configuration', address=address)
    if document.get('issuer') != issuer:
        raise RuntimeError('Stable issuer health failed')
    suffixes = {'authorization_endpoint': '/auth', 'token_endpoint': '/token',
                'jwks_uri': '/certs', 'userinfo_endpoint': '/userinfo'}
    for key, suffix in suffixes.items():
        if document.get(key) != issuer + '/protocol/openid-connect' + suffix:
            raise RuntimeError('OIDC discovery exposes an unexpected host or path')
    jwks = json_get(document['jwks_uri'], address=address)
    if not any(k.get('kty') == 'RSA' and k.get('alg') == 'RS256' and k.get('use') == 'sig' for k in jwks.get('keys', [])):
        raise RuntimeError('No supported realm signing key')
    return {'discovery': True, 'jwks': True, 'stable_https_issuer': True}


def proxy_privacy(login_host, address=None):
    if not re.fullmatch('[a-z0-9.-]+', login_host):
        raise ValueError('Identity privacy requires its exact login hostname')
    origin = 'https://' + login_host
    spoof = {'User-Agent': 'CloudLab-Identity-Health/1.0',
             'Forwarded': 'for=198.51.100.23;proto=http;host=forbidden.invalid',
             'X-Forwarded-Host': 'forbidden.invalid', 'X-Forwarded-Proto': 'http', 'X-Forwarded-Port': '80'}
    for realm in ('platform', 'applications'):
        issuer = origin + '/realms/' + realm
        document = json_get(issuer + '/.well-known/openid-configuration', headers=spoof, address=address)
        if document.get('issuer') != issuer or document.get('token_endpoint') != issuer + '/protocol/openid-connect/token':
            raise RuntimeError('Gateway proxy headers changed the stable identity issuer')
    paths = ['/admin/realms', '/admin/master/console/', '/realms/master/.well-known/openid-configuration',
             '/realms/platform/account/', '/realms/platform/account/credentials',
             '/realms/applications/account/', '/realms/applications/account/credentials',
             '/health/ready', '/metrics', '/realms/platform/clients-registrations',
             '/realms/applications/clients-registrations', '/realms/platform/../../admin/realms',
             '/realms/platform/%2e%2e/%2e%2e/admin/realms',
             '/realms/platform/%2e%2e%2f%2e%2e%2fadmin/realms']
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    for path in paths:
        try:
            if address is not None:
                status, _ = direct_https(origin + path, address, spoof)
            else:
                with opener.open(urllib.request.Request(origin + path, headers=spoof), timeout=15) as response:
                    status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        except Exception:
            raise RuntimeError('Identity gateway privacy probe unavailable') from None
        if status not in (403, 404):
            raise RuntimeError('Public identity management or traversal path is not denied at the gateway')
    return {'canonical_proxy_headers': True, 'public_management_paths_denied': len(paths)}


def run(login_host, admin_host):
    for host in (login_host, admin_host):
        if not re.fullmatch(r'[a-z0-9.-]+', host):
            raise ValueError('Health host must be a DNS name')
    ready = json_get('http://cloudlab-keycloak-service:9000/health/ready')
    if ready.get('status') != 'UP':
        raise RuntimeError('Private identity readiness failed')
    for realm in ('platform', 'applications'):
        status = check('https://' + login_host + '/realms/' + realm)
        secret = Path('/credentials/' + realm + '_client_secret').read_text()
        token = json_get('https://' + admin_host + '/realms/' + realm + '/protocol/openid-connect/token',
                         form={'grant_type': 'client_credentials', 'client_id': 'realm-health', 'client_secret': secret})
        root = 'https://' + admin_host + '/admin/realms/' + realm
        cutoff = int((time.time() - 300) * 1000)
        projected = {}
        for path, admin in (('/events?max=100', False), ('/admin-events?max=100', True)):
            events = json_get(root + path, token=token['access_token'])
            projected['admin' if admin else 'login'] = [e for e in redact(events, admin) if e.get('time', 0) >= cutoff]
        print(json.dumps({'realm': realm, 'health': status, 'audit': projected,
                          'audit_limit': 'Latest 100 events per category; full audit pipeline belongs to milestone 05'}, sort_keys=True))


if __name__ == '__main__':
    try:
        run(*sys.argv[1:])
    except Exception:
        raise SystemExit('Identity health/audit check failed; private diagnostics withheld') from None
