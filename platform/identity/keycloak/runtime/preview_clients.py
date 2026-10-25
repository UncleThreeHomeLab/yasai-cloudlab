"""Transient clients belong to the existing leased writer, never the preview pod."""
import copy
import json
from pathlib import Path
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import quote

try:
    from playbooks.previews.files.contract import (OWNER, APPROVALS, STATE, IDENTITY_STATE,
        approval, stored_approval, obsolete, runtime_catalog, canonical, digest, client, names, MAX_ACTIVE, ORIGIN_VERSION)
    from playbooks.keycloak.files.configuration import client as compile_client
except ImportError:
    from preview_contract import (OWNER, APPROVALS, STATE, IDENTITY_STATE,
        approval, stored_approval, obsolete, runtime_catalog, canonical, digest, client, names, MAX_ACTIVE, ORIGIN_VERSION)
    from configuration import client as compile_client

IDENTITY_OWNER = 'cloudlab-preview-identity'
GRACE = 600


def representation(row, settings):
    approval(row)
    value = compile_client(client(row, settings), {})
    value['attributes'].update({'cloudlab.preview.instance': row['instance'],
                                'cloudlab.preview.approval': digest(canonical(row))})
    return value


def matching(observed, record):
    attrs = observed.get('attributes', {})
    return (observed.get('clientId') == record['clientId'] and
            attrs.get('cloudlab.preview.instance') == record['approval']['instance'] and
            attrs.get('cloudlab.preview.approval') == record['approvalDigest'] and
            isinstance(observed.get('id'), str) and observed['id'] and
            (not record.get('uuid') or observed['id'] == record['uuid']))


def reconcile(settings, intent, state, api, save, now, persistent, *, input_available=True):
    """Called only after acquiring the existing identity Lease. Never waits for grace."""
    if settings is not None:
        runtime_catalog(settings)
    if (not isinstance(state, dict) or set(state) != {'format', 'entries'} or state['format'] != 1 or
            not isinstance(state['entries'], dict) or len(state['entries']) > 256):
        raise ValueError('Preview identity inventory is invalid')
    desired = {row['instance']: row for row in settings['approvals']} if settings else {}
    if intent is not None and (intent.get('format') != 1 or not isinstance(intent.get('entries'), dict)):
        raise ValueError('Preview lifecycle intent is invalid')
    records = state['entries']
    for instance, row in desired.items():
        existing = records.get(instance)
        if existing and existing['approvalDigest'] != digest(canonical(row)):
            raise ValueError('Preview identity instance cannot be reused')
        if obsolete(row):
            continue
        approval(row)
        lifecycle = (intent or {}).get('entries', {}).get(instance)
        if existing or not lifecycle or lifecycle.get('originVersion') != ORIGIN_VERSION or lifecycle.get('phase') not in ('pending', 'active'):
            continue
        if lifecycle.get('approvalDigest') != digest(canonical(row)) or not row['createdAt'] <= now < row['expiresAt']:
            continue
        identifier = names(row)['client']
        if identifier in persistent or len(records) >= 256:
            raise ValueError('Preview client collides with persistent inventory or capacity')
        if sum(r['phase'] != 'retired' for r in records.values()) >= MAX_ACTIVE:
            raise ValueError('Preview identity capacity includes retiring clients')
        if api('find', identifier):
            raise ValueError('Preview client exists without creation inventory; adoption refused')
        records[instance] = {'approval': row, 'approvalDigest': digest(canonical(row)), 'clientId': identifier,
                             'settings': {key: settings[key] for key in ('hostname', 'issuer')},
                             'phase': 'creating', 'uuid': None, 'originVersion': ORIGIN_VERSION}
        save(state)
    for instance, record in records.items():
        if record['phase'] == 'retired':
            continue
        row = stored_approval(record['approval'])
        if (instance != row['instance'] or record['clientId'] != names(row)['client'] or record['clientId'] in persistent or
                record['approvalDigest'] != digest(canonical(row)) or record['phase'] not in ('creating', 'active', 'retiring', 'disabled')):
            raise ValueError('Preview client runtime inventory identity differs')
        if (obsolete(row) or record.get('originVersion') != ORIGIN_VERSION) and record['phase'] in ('creating', 'active'):
            record['phase'] = 'retiring'
            save(state)
        current = desired.get(instance)
        lifecycle = (intent or {}).get('entries', {}).get(instance)
        if not input_available and record['phase'] in ('creating', 'active'):
            if record['phase'] == 'creating' and now < row['expiresAt'] and (not lifecycle or lifecycle.get('phase') in ('pending', 'active')):
                continue
            current = row
            if lifecycle is None:
                lifecycle = {'approvalDigest': record['approvalDigest'], 'phase': 'active', 'originVersion': ORIGIN_VERSION}
        wants_active = (record.get('originVersion') == ORIGIN_VERSION and not obsolete(row) and current is not None and lifecycle is not None and
            lifecycle.get('originVersion') == ORIGIN_VERSION and
            lifecycle.get('approvalDigest') == record['approvalDigest'] and
            lifecycle.get('phase') in ('pending', 'active') and row['createdAt'] <= now < row['expiresAt'])
        if record['phase'] in ('retiring', 'disabled'):
            wants_active = False
        if wants_active and settings and record['settings'] != {key: settings[key] for key in ('hostname', 'issuer')}:
            raise ValueError('Preview identity callback contract changed')
        rows = api('find', record['clientId'])
        if not isinstance(rows, list) or len(rows) > 1 or any(not matching(item, record) for item in rows):
            raise ValueError('Preview client UUID or ownership changed')
        if wants_active:
            local_settings = dict(record['settings'], approvals=[row], privateDiscovery=False)
            value = representation(row, local_settings)
            if not rows:
                if record['phase'] != 'creating':
                    raise ValueError('Active preview client disappeared; implicit recreation refused')
                api('create', value)
                rows = api('find', record['clientId'])
                if len(rows) != 1 or not matching(rows[0], record):
                    raise ValueError('Preview client creation did not converge')
            record['uuid'] = rows[0]['id']
            # The existing writer repairs only the fully bounded preview representation.
            api('update', dict(value, id=record['uuid']))
            record.update(phase='active', verifiedAt=now)
            save(state)
            continue
        if not rows:
            record.clear()
            record.update(phase='retired', approvalDigest=digest(canonical(row)))
            save(state)
            continue
        record['uuid'] = rows[0]['id']
        record['phase'] = 'retiring'
        save(state)
        if rows[0].get('enabled') is not False or 'disabledAt' not in record:
            api('update', dict(rows[0], enabled=False))
            confirmed = api('find', record['clientId'])
            if len(confirmed) != 1 or not matching(confirmed[0], record) or confirmed[0].get('enabled') is not False:
                raise ValueError('Preview client disable did not converge')
            record.update(phase='disabled', disabledAt=now)
            save(state)
            continue
        if now < record['disabledAt'] + GRACE:
            continue
        api('delete', record['uuid'])
        if api('find', record['clientId']):
            raise ValueError('Preview client removal did not converge')
        record.clear()
        record.update(phase='retired', approvalDigest=digest(canonical(row)))
        save(state)
    return state


def run(admin_host):
    """Runtime adapter; invoked inside validate-and-lock after Lease acquisition."""
    from lease import api_request
    from configuration import private_request
    from urllib.parse import urlencode
    deadline = time.monotonic() + 45
    def bounded_api(method, route, body=None):
        if time.monotonic() + 10 > deadline:
            raise RuntimeError('Preview identity time budget exhausted')
        return api_request(method, route, body)
    origin = 'https://kubernetes.default.svc'
    def get(namespace, name):
        try:
            return bounded_api('GET', origin + '/api/v1/namespaces/' + namespace + '/configmaps/' + name)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            return None
    document = get('argocd', APPROVALS)
    lifecycle = get('argocd', STATE)
    current = get('cloudlab-identity', IDENTITY_STATE)
    if document is None and current is None:
        return
    for obj, owner in ((lifecycle, OWNER), (current, IDENTITY_OWNER)):
        if obj is not None and (obj.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != owner or
                obj['metadata'].get('ownerReferences') or obj['metadata'].get('finalizers')):
            raise ValueError('Preview identity input has conflicting ownership')
    settings, input_available = None, False
    try:
        if document and document.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') == OWNER:
            settings = runtime_catalog(json.loads(document['data']['catalog.json']))
            if admin_host != 'identity-admin.internal.' + settings['hostname'].split('.internal.', 1)[1]:
                raise ValueError('Preview issuer differs from the accepted identity owner')
            input_available = True
    except (ValueError, TypeError, KeyError):
        settings = None
    intent = json.loads(lifecycle['data']['state.json']) if lifecycle else None
    state = json.loads(current['data']['state.json']) if current else {'format': 1, 'entries': {}}
    for record in state.get('entries', {}).values():
        if record.get('phase') != 'retired' and admin_host != 'identity-admin.internal.' + record['settings']['hostname'].split('.internal.', 1)[1]:
            raise ValueError('Stored preview issuer differs from the accepted identity owner')
    source = json.loads(Path('/private/desired_state').read_text())
    persistent = {row['id'] for row in source.get('realms', {}).get('applications', {}).get('clients', [])}
    endpoint = origin + '/api/v1/namespaces/cloudlab-identity/configmaps'
    def save(value):
        nonlocal current
        obj = copy.deepcopy(current) if current else {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': IDENTITY_STATE, 'namespace': 'cloudlab-identity', 'labels': {'cloudlab.io/owner': IDENTITY_OWNER}}}
        obj['data'] = {'state.json': json.dumps(value, sort_keys=True)}
        current = bounded_api('PUT' if current else 'POST', endpoint + ('/' + IDENTITY_STATE if current else ''), obj)
    secret = Path('/credentials/applications_client_secret').read_text()
    admin = 'https://' + admin_host
    if time.monotonic() + 20 > deadline:
        raise RuntimeError('Preview identity time budget exhausted')
    token = private_request(admin + '/realms/applications/protocol/openid-connect/token', form={
        'grant_type': 'client_credentials', 'client_id': 'realm-writer', 'client_secret': secret})['access_token']
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    def api(action, value):
        if time.monotonic() + 10 > deadline:
            raise RuntimeError('Preview identity time budget exhausted')
        route = '/admin/realms/applications/clients'
        method = {'find': 'GET', 'create': 'POST', 'update': 'PUT', 'delete': 'DELETE'}[action]
        if action == 'find': route += '?' + urlencode({'clientId': value, 'max': 2})
        if action in ('update', 'delete'):
            uid = value['id'] if action == 'update' else value
            if not isinstance(uid, str) or len(uid) > 100 or '/' in uid or '?' in uid:
                raise ValueError('Invalid preview client UUID')
            route += '/' + quote(uid, safe='')
        body = json.dumps(value).encode() if action in ('create', 'update') else None
        request = urllib.request.Request(admin + route, data=body, method=method,
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        try:
            opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
            with opener.open(request, timeout=10) as response:
                raw = response.read(262145)
                if len(raw) > 262144:
                    raise ValueError('Preview identity response exceeds its bound')
                return json.loads(raw) if raw else None
        except Exception:
            raise RuntimeError('Preview identity operation failed; diagnostics withheld') from None
    reconcile(settings, intent, state, api, save, int(time.time()), persistent, input_available=input_available)
    if not input_available:
        raise RuntimeError('Preview approval input unavailable; stored expiry reconciliation completed')


def attempt(admin_host, directory='/imports'):
    """Preview failure remains visible after ordinary realm repair finishes."""
    try:
        run(admin_host)
        return True
    except Exception:
        Path(directory, 'preview-error').write_text('Preview identity reconciliation failed; diagnostics withheld\n')
        return False
