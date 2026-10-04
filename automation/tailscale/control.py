"""Scoped policy and one-use enrollment keys, independent of Kubernetes."""
import copy
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'credentials'))
from vault import fields

HOST_TAG = 'tag:cloudlab-host'
TEST_TAG = 'tag:cloudlab-denied'


class API:
    def __init__(self, item):
        values = fields(item, ('CLIENT_ID', 'CLIENT_SECRET'))
        payload = urllib.parse.urlencode(dict(client_id=values['CLIENT_ID'],
                                             client_secret=values['CLIENT_SECRET'],
                                             grant_type='client_credentials')).encode()
        request = urllib.request.Request('https://api.tailscale.com/api/v2/oauth/token', data=payload)
        try:
            self.token = json.load(urllib.request.urlopen(request, timeout=30))['access_token']
        except (urllib.error.URLError, KeyError):
            raise RuntimeError('Tailscale OAuth authentication failed') from None

    def request(self, method, path, body=None, etag=None):
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        if etag:
            headers['If-Match'] = etag
        request = urllib.request.Request('https://api.tailscale.com/api/v2/' + path,
                  data=json.dumps(body).encode() if body is not None else None,
                  headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read()
                return (json.loads(data) if data else {}), response.headers.get('ETag')
        except urllib.error.HTTPError as error:
            raise RuntimeError('Tailscale API ' + method + ' failed: HTTP ' + str(error.code)) from None
        except urllib.error.URLError:
            raise RuntimeError('Tailscale API unavailable') from None


def candidate(current, login, ports, devices=()):
    """Own only two tags, one grant and their tests; preserve unrelated policy."""
    if not login or '@' not in login:
        raise ValueError('TAILSCALE_ADMIN_LOGIN must identify the approved administrator.')
    result = copy.deepcopy(current)
    if 'acls' not in current and 'grants' not in current:
        # An omitted policy is implicit allow-all. Preserve existing non-lab
        # destinations explicitly before restricting newly introduced host tags.
        destinations = set(current.get('tagOwners', {})) - {HOST_TAG, TEST_TAG}
        for device in devices:
            if not device.get('tags') and device.get('user'):
                destinations.add(device['user'])
            destinations.update(device.get('enabledRoutes', []))
        if not destinations:
            raise RuntimeError('Cannot preserve implicit policy without a device inventory.')
        result['acls'] = []
        result['grants'] = [{'src': ['*'], 'dst': sorted(destinations), 'ip': ['*']}]
    owners = result.setdefault('tagOwners', {})
    for tag in (HOST_TAG, TEST_TAG):
        if tag in owners and owners[tag] != [login]:
            raise RuntimeError('Lab tag already has different owners; review before adoption.')
        owners[tag] = [login]
    grant = {'src': [login], 'dst': [HOST_TAG], 'ip': ['tcp:' + str(p) for p in sorted(set(ports))]}
    grants = result.setdefault('grants', [])
    existing = [g for g in grants if g.get('dst') == [HOST_TAG]]
    if existing and existing != [grant]:
        raise RuntimeError('Existing host grant differs; review its owner before replacing.')
    if grant not in grants:
        grants.append(grant)
    tests = result.setdefault('tests', [])
    for test in ({'src': login, 'accept': [HOST_TAG + ':' + str(p) for p in sorted(set(ports))]},
                 {'src': TEST_TAG, 'deny': [HOST_TAG + ':' + str(p) for p in sorted(set(ports) | {6443, 10250})]}):
        if test not in tests:
            tests.append(test)
    return result


def policy(apply=False):
    api = API('tailscale-policy')
    current, etag = api.request('GET', 'tailnet/-/acl')
    devices, _ = api.request('GET', 'tailnet/-/devices')
    login = os.environ.get('TAILSCALE_ADMIN_LOGIN', '')
    ports = [int(os.environ.get(p + '_PORT', '22')) for p in ('VM', 'VM2')]
    desired = candidate(current, login, ports, devices.get('devices', []))
    # Negative tests include every other human owner without touching their devices.
    for owner in sorted({d.get('user') for d in devices.get('devices', []) if d.get('user')} - {login}):
        test = {'src': owner, 'deny': [HOST_TAG + ':' + str(p) for p in sorted(set(ports) | {6443, 10250})]}
        if test not in desired['tests']:
            desired['tests'].append(test)
    validation, _ = api.request('POST', 'tailnet/-/acl/validate', desired)
    if validation:
        raise RuntimeError('Policy validation failed; existing grants may allow lab hosts. Review private policy.')
    if not apply and desired != current:
        raise RuntimeError('Live tailnet policy differs from the declared host contract; apply policy before access proof.')
    if apply and desired != current:
        if not etag:
            raise RuntimeError('Policy API supplied no ETag; refusing an unguarded policy write.')
        api.request('POST', 'tailnet/-/acl', desired, etag)
    print(json.dumps({'changed': bool(apply and desired != current), 'policy_validated': True,
                      'devices': len(devices.get('devices', []))}))


def key(test=False):
    api = API('tailscale-test-enrollment' if test else 'tailscale-host-enrollment')
    value, _ = api.request('POST', 'tailnet/-/keys', {
        'capabilities': {'devices': {'create': {'reusable': False, 'ephemeral': test,
            'preauthorized': True, 'tags': [TEST_TAG if test else HOST_TAG]}}},
        'expirySeconds': 300,
        'description': 'cloudlab disposable test' if test else 'cloudlab host enrollment'})
    # Only consumed through Ansible no_log or a private subprocess pipe.
    print(value['key'])


if __name__ == '__main__':
    try:
        if sys.argv[1] in ('policy', 'policy-check'):
            policy(sys.argv[1] == 'policy')
        elif sys.argv[1] in ('key', 'test-key'):
            key(sys.argv[1] == 'test-key')
        else:
            raise ValueError('Unknown Tailscale action')
    except (RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from None
