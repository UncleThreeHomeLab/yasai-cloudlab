"""Cloudflare desired state. TLS verification and explicit Access classification are mandatory."""
import json
import re
import urllib.error
import urllib.request

from automation.connectivity.contract import policy, runtime_rule
from automation.connectivity.provider_http import open_request


class API:
    def __init__(self, token):
        if not token or token != token.strip():
            raise ValueError('Cloudflare token is missing or has surrounding whitespace')
        self.token = token

    def request(self, method, path, document=None, *, with_info=False):
        if not re.fullmatch(r'[a-zA-Z0-9_/?=&.%-]+', path) or path.startswith('/') or '..' in path:
            raise ValueError('Invalid Cloudflare API path')
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json'}
        if document is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request('https://api.cloudflare.com/client/v4/' + path,
            headers=headers, method=method, data=json.dumps(document).encode() if document is not None else None)
        try:
            with open_request(request, timeout=30) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError('Cloudflare API ' + method + ' failed: HTTP ' + str(error.code)) from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            raise RuntimeError('Cloudflare API unavailable or returned invalid JSON') from None
        if not isinstance(result, dict) or not result.get('success') or 'result' not in result:
            raise RuntimeError('Cloudflare API rejected the operation; private diagnostics withheld')
        return (result['result'], result.get('result_info', {})) if with_info else result['result']

    def collection(self, path):
        """Read every page; truncated inventories cannot establish unique ownership."""
        result = []
        for page in range(1, 1001):
            separator = '&' if '?' in path else '?'
            values, info = self.request('GET', path + separator + 'per_page=100&page=' + str(page), with_info=True)
            if not isinstance(values, list):
                raise RuntimeError('Cloudflare inventory response is not a collection')
            if any(obj.get('id') == old.get('id') for obj in values for old in result):
                raise RuntimeError('Cloudflare inventory repeated identities across pages')
            result.extend(values)
            if not values or (info.get('total_pages') and page >= info['total_pages']):
                return result
        raise RuntimeError('Cloudflare inventory exceeded its bounded page limit')


def tunnel_config(rules, audiences, team):
    ingress = []
    settings = policy()
    if not rules or len({rule.get('hostname') for rule in rules if isinstance(rule, dict)}) != len(rules):
        raise ValueError('Tunnel configuration requires unique explicit hostname rules')
    for rule in rules:
        runtime_rule(rule)
        hostname = rule['hostname']
        origin = {'originServerName': hostname, 'httpHostHeader': hostname, 'noTLSVerify': False,
                  'connectTimeout': 10, 'tlsTimeout': 10}
        if rule['access'] != 'public':
            if not audiences.get(hostname) or not team:
                raise ValueError('Protected hostname requires its Access audience and organization')
            # Enforce Access again at the connector; the tunnel token is never user authentication.
            origin['access'] = {'required': True, 'teamName': team, 'audTag': [audiences[hostname]]}
        ingress.append({'hostname': hostname, 'service': settings['cloudflareOrigin'], 'originRequest': origin})
    ingress.append({'service': 'http_status:404'})
    return {'config': {'ingress': ingress, 'warp-routing': {'enabled': False}}}


def access_application(rule, *, human_email=None, identity_provider=None, service_token_id=None, identity_group=None):
    runtime_rule(rule)
    kind = rule['access']
    if kind not in ('human', 'machine'):
        raise ValueError('Only explicitly protected hostnames receive Access applications')
    if kind == 'human':
        if not human_email or '@' not in human_email or not identity_provider:
            raise ValueError('Human Access requires an approved email and identity provider')
        rules = [{'email': {'email': human_email}}]
        decision = 'allow'
    else:
        if not service_token_id:
            raise ValueError('Machine Access requires a pre-provisioned service token')
        rules = [{'service_token': {'token_id': service_token_id}}]
        decision = 'non_identity'
    result = {'name': 'cloudlab-' + rule['hostname'].split('.')[0], 'type': 'self_hosted',
              'domain': rule['hostname'], 'session_duration': policy()['sessionDuration'],
              'app_launcher_visible': False, 'auto_redirect_to_identity': kind == 'human',
              'policies': [{'name': 'cloudlab-' + kind, 'decision': decision, 'precedence': 1,
                            'include': rules, 'exclude': [], 'require': []}]}
    if kind == 'human':
        result['allowed_idps'] = [identity_provider]
        if identity_group is not None:
            if identity_group != '/platform-admin':
                raise ValueError('Central Access requires the exact privileged group path')
            result['policies'][0]['require'] = [
                {'login_method': {'id': identity_provider}},
                {'oidc': {'claim_name': 'groups', 'claim_value': identity_group,
                          'identity_provider_id': identity_provider}}]
    return result


def dns_record(hostname, tunnel):
    return {'type': 'CNAME', 'name': hostname, 'content': tunnel + '.cfargotunnel.com',
            'proxied': True, 'ttl': 1, 'comment': 'cloudlab connectivity API owner'}


def permission_probe(admin, account, zone):
    """Create and remove one unpublished deny-all fixture; never alter an existing app."""
    from automation.connectivity.contract import zone_name
    hostname = 'access-permission-probe.' + zone_name(zone)
    path = 'accounts/' + account + '/access/apps'
    existing = admin.request('GET', path)
    if any(app.get('domain') == hostname or app.get('name') == 'cloudlab-access-permission-probe' for app in existing):
        raise RuntimeError('Access permission fixture already exists; review it before retrying')
    created = admin.request('POST', path, {
        'name': 'cloudlab-access-permission-probe', 'type': 'self_hosted', 'domain': hostname,
        'app_launcher_visible': False, 'session_duration': '1h',
        'policies': [{'name': 'deny-all', 'decision': 'deny', 'precedence': 1,
                      'include': [{'everyone': {}}], 'exclude': [], 'require': []}]})
    identity = created.get('id')
    if not identity:
        raise RuntimeError('Access permission fixture response lacks an identity; inspect account before retrying')
    try:
        actual = admin.request('GET', path + '/' + identity)
        if actual.get('domain') != hostname:
            raise RuntimeError('Access permission fixture identity changed')
    finally:
        admin.request('DELETE', path + '/' + identity)
    if any(app.get('id') == identity for app in admin.request('GET', path)):
        raise RuntimeError('Access permission fixture cleanup failed')
    return {'access_app_write': True, 'deny_all_fixture_removed': True, 'dns_published': False}
