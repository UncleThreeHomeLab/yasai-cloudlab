"""Read-only live protocol, privacy and least-privilege audit verification."""
import base64
import fcntl
import json

from automation.identity.bootstrap import private_inputs, reconciled
from automation.identity.configuration import private_request
from automation.identity.health import check, proxy_privacy, redact
from automation.identity.maintenance import APP, BASE, NAMESPACE, OWNER
from automation.mesh.kube import condition, get


def credentials():
    external = get('externalsecret.external-secrets.io', 'keycloak-realm-health', NAMESPACE)
    secret = get('secret', 'keycloak-realm-health', NAMESPACE)
    if not condition(external, 'Ready') or not secret or not any(
            ref.get('kind') == 'ExternalSecret' and ref.get('uid') == external['metadata']['uid']
            for ref in secret['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Live health requires ready ESO-owned audit credentials')
    values = {realm: base64.b64decode(secret['data'][realm + '_client_secret'], validate=True).decode()
              for realm in ('platform', 'applications')}
    if any(len(value) < 32 for value in values.values()):
        raise RuntimeError('Live audit credentials are incomplete')
    return values


def protocols(values, secrets):
    origin = 'https://' + values['loginHost']
    admin = 'https://' + values['adminHost']
    result = {}
    for realm in ('platform', 'applications'):
        issuer = origin + '/realms/' + realm
        status = check(issuer)
        token = private_request(issuer + '/protocol/openid-connect/token', form={
            'grant_type': 'client_credentials', 'client_id': 'realm-health',
            'client_secret': secrets[realm]})
        if (not isinstance(token.get('access_token'), str) or token.get('token_type', '').lower() != 'bearer'
                or type(token.get('expires_in')) is not int or not 0 < token['expires_in'] <= 300):
            raise RuntimeError('Live public token endpoint violates its bounded credential contract')
        root = admin + '/admin/realms/' + realm
        audit = {}
        for endpoint, is_admin in (('/events?max=100', False), ('/admin-events?max=100', True)):
            events = private_request(root + endpoint, token=token['access_token'])
            if not isinstance(events, list) or len(events) > 100:
                raise RuntimeError('Live audit response exceeds its requested bound')
            audit['admin' if is_admin else 'login'] = redact(events, is_admin)
        denied = private_request(root + '/users?max=1', token=token['access_token'], accepted_statuses=(403,))
        if not isinstance(denied, dict) or 'error' not in denied:
            raise RuntimeError('Audit client must be denied user administration')
        result[realm] = dict(status, public_client_credentials_token=True,
                             private_audit_read=True, user_administration_denied=True, audit=audit)
    return dict(realms=result, privacy=proxy_privacy(values['loginHost']))


def run(payload):
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = json.loads((BASE / 'ownership.json').read_text())
        app = get('application.argoproj.io', APP, 'argocd') or {}
        if (receipt.get('phase') != 'scoped' or receipt.get('revision') != payload['revision']
                or app.get('metadata', {}).get('uid') != receipt.get('uid')
                or app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER
                or not reconciled(payload['revision'], receipt['uid'])
                or not condition(get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE), 'Ready')):
            raise RuntimeError('Live health requires the current converged scoped identity owner')
        values = app['spec']['source']['helm']['valuesObject']
        if values.get('maintenance') or values.get('operation') or values.get('bootstrapMode'):
            raise RuntimeError('Live health cannot run during another identity operation')
        private_inputs(dict(payload, values=values))
        result = protocols(values, credentials())
        if not reconciled(payload['revision'], receipt['uid']):
            raise RuntimeError('Identity source changed during live health verification')
        return dict(result, changed=False, real_browser_enrollment_proven=False,
                    integrated_sessions_proven=False, independent_repair_preserved=True)
