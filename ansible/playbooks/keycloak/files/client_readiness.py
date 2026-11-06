"""Observe compiler-owned client fields; never change clients, roles or grants."""
import base64
import hmac
import re
import time
from urllib.parse import quote, urlencode

from playbooks.istio.files.kube import get, condition
from playbooks.keycloak.files.configuration import MANAGED_CLIENT_FIELDS, exact_url, name, private_request
from playbooks.keycloak.files.maintenance import NAMESPACE


def matches(actual, desired):
    """Compare only explicitly owned fields; provider metadata remains unverified."""
    if not isinstance(actual, dict): return False
    sets = {'redirectUris', 'webOrigins', 'defaultClientScopes', 'optionalClientScopes'}
    for field in MANAGED_CLIENT_FIELDS:
        if field in sets:
            values = [actual.get(field), desired[field]]
            if any(not isinstance(value, list) or any(not isinstance(item, str) for item in value)
                   or len(value) != len(set(value)) for value in values): return False
            if set(values[0]) != set(values[1]): return False
        elif field not in ('attributes', 'protocolMappers'):
            if type(actual.get(field)) is not type(desired[field]) or actual[field] != desired[field]: return False
    attributes = actual.get('attributes')
    if not isinstance(attributes, dict): return False
    if any(type(attributes.get(key)) is not type(value) or attributes[key] != value
           for key, value in desired['attributes'].items()): return False
    if 'post.logout.redirect.uris' not in desired['attributes'] and attributes.get('post.logout.redirect.uris') not in (None, ''):
        return False
    rows = actual.get('protocolMappers')
    if (not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get('name'), str) for row in rows)
            or len({row['name'] for row in rows}) != len(rows)): return False
    mappers = {row['name']: row for row in rows}
    if set(mappers) != {row['name'] for row in desired['protocolMappers']}: return False
    for expected in desired['protocolMappers']:
        row = mappers[expected['name']]
        if any(type(row.get(key)) is not type(expected[key]) or row[key] != expected[key]
               for key in ('protocol', 'protocolMapper')): return False
        config = row.get('config')
        if not isinstance(config, dict) or any(type(config.get(key)) is not type(value) or config[key] != value
                                              for key, value in expected['config'].items()): return False
    return True


def verify(realm, desired, admin_host):
    """Use existing realm-writer custody for at most four bounded provider requests."""
    try:
        if realm != 'applications': raise ValueError()
        identifier = name(desired['clientId'])
        if not isinstance(admin_host, str) or not re.fullmatch('[a-z0-9.-]+', admin_host): raise ValueError()
        origin = exact_url('https://' + admin_host + '/').removesuffix('/')
        deadline = time.monotonic() + 90
        writers = get('secret', 'keycloak-realm-writers', NAMESPACE)
        external = get('externalsecret.external-secrets.io', 'keycloak-realm-writers', NAMESPACE)
        if not condition(external, 'Ready') or not any(
                owner.get('uid') == external['metadata']['uid'] for owner in writers.get('metadata', {}).get('ownerReferences', [])):
            raise ValueError()
        secret = base64.b64decode(writers['data'][realm + '_client_secret'], validate=True).decode()
        if not secret: raise ValueError()
        def request(path, **kwargs):
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise RuntimeError()
            value = private_request(origin + path, timeout=min(20, remaining), **kwargs)
            if time.monotonic() >= deadline: raise RuntimeError()
            return value
        token = request('/realms/' + realm + '/protocol/openid-connect/token', form={
            'grant_type': 'client_credentials', 'client_id': 'realm-writer', 'client_secret': secret})['access_token']
        if not isinstance(token, str) or not token: raise ValueError()
        path = '/admin/realms/' + realm + '/clients'
        rows = request(path + '?' + urlencode({'clientId': identifier}), token=token)
        if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
                or rows[0].get('clientId') != identifier or not isinstance(rows[0].get('id'), str)
                or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', rows[0]['id'])):
            raise ValueError()
        path += '/' + quote(rows[0]['id'], safe='')
        actual = request(path, token=token)
        if actual.get('id') != rows[0]['id'] or not matches(actual, desired): raise ValueError()
        if not desired['publicClient']:
            actual_secret = request(path + '/client-secret', token=token).get('value')
            if (not isinstance(actual_secret, str) or not isinstance(desired.get('secret'), str)
                    or not hmac.compare_digest(actual_secret.encode(), desired['secret'].encode())):
                raise ValueError()
    except Exception:
        raise RuntimeError('Referenced identity client is not converged; values withheld') from None
