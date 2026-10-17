"""Verify installation prerequisites before registry API ownership or human onboarding."""
import base64
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from automation.harbor import recovery, deployments
from automation.harbor.values import POLICY
from automation.identity.health import direct_https
from playbooks.istio.files.kube import get, contains, application_ready


def oidc_discovery(login_host):
    issuer = 'https://' + login_host + '/realms/platform'
    raw = recovery.execute('core', ['curl', '--fail', '--silent', '--show-error', '--connect-timeout', '5',
                                   '--max-time', '20', issuer + '/.well-known/openid-configuration'])
    document = json.loads(raw)
    expected = {'issuer': issuer, 'authorization_endpoint': issuer + '/protocol/openid-connect/auth',
                'token_endpoint': issuer + '/protocol/openid-connect/token',
                'jwks_uri': issuer + '/protocol/openid-connect/certs'}
    if any(document.get(key) != value for key, value in expected.items()):
        raise RuntimeError('Harbor core must discover the exact trusted platform issuer before human onboarding')
    return {'core_oidc_discovery': True, 'trusted_tls': True}


def run(payload):
    for name in recovery.APPS:
        app = recovery.application(name)
        if (app['spec']['source']['repoURL'] != payload['repository'] or
                not application_ready(name, payload['revision'])):
            raise RuntimeError('Harbor Applications must converge at the published revision')
    volumes = recovery.sources()
    claims = get('pvc', namespace=recovery.NAMESPACE)['items']
    if {claim['metadata']['name'] for claim in claims} != set(recovery.CLAIMS.values()):
        raise RuntimeError('Harbor must retain exactly its three independent claims')
    storage = get('storageclass', recovery.NAMESPACE)
    if storage['reclaimPolicy'] != 'Retain' or json.loads(storage['parameters']['recurringJobSelector']) != [
            {'name': 'harbor-coordinated', 'isGroup': True}]:
        raise RuntimeError('Harbor storage inherited an uncoordinated export policy')
    route = get('httproute.gateway.networking.k8s.io', 'harbor', recovery.NAMESPACE)
    if route['spec']['hostnames'] != [payload['configuration']['harborHost']] or not contains(route['spec'], {
            'parentRefs': [{'name': 'cloudlab', 'namespace': 'cloudlab-gateway-private', 'sectionName': 'https'}]}):
        raise RuntimeError('Harbor escaped its private TLS route')
    gateway = get('service', 'cloudlab-istio', 'cloudlab-gateway-private')['spec']['clusterIP']
    origin = 'https://' + payload['configuration']['harborHost']
    credentials = recovery.secret('harbor-emergency')
    username = base64.b64decode(credentials['username']).decode()
    password = base64.b64decode(credentials['password']).decode()
    headers = {'Authorization': 'Basic ' + base64.b64encode((username + ':' + password).encode()).decode()}
    status, raw = direct_https(origin + '/api/v2.0/configurations', gateway, headers)
    if status != 200:
        raise RuntimeError('Independent Harbor emergency API access failed')
    settings = json.loads(raw)
    expected = {'auth_mode': 'oidc_auth', 'oidc_endpoint': 'https://' + payload['configuration']['loginHost'] + '/realms/platform',
                'oidc_client_id': 'harbor', 'oidc_verify_cert': True, 'self_registration': False,
                'project_creation_restriction': 'adminonly', 'oidc_user_claim': 'sub', 'oidc_groups_claim': 'groups'}
    expected.update(oidc_auto_onboard=True, token_expiration=POLICY['registry_token_minutes'])
    if any(settings.get(key, {}).get('value') != value for key, value in expected.items()):
        raise RuntimeError('Harbor OIDC prerequisites differ; do not create human accounts')
    oidc_discovery(payload['configuration']['loginHost'])
    for path, authorization in (('/api/v2.0/users/current', {}),
            ('/api/v2.0/users/current', {'Authorization': 'Basic aW52YWxpZDppbnZhbGlk'}), ('/v2/', {})):
        status, _ = direct_https(origin + path, gateway, authorization)
        if status not in (302, 401, 403) or (path == '/v2/' and status != 401):
            raise RuntimeError('Unauthenticated Harbor access was not rejected')
    public = get('service', 'cloudlab-istio', 'cloudlab-gateway-public')['spec']['clusterIP']
    public_origin = 'https://' + payload['configuration']['loginHost']
    if direct_https(public_origin + '/v2/', public, {'Host': payload['configuration']['harborHost']})[0] != 404:
        raise RuntimeError('Harbor registry is exposed by the public gateway')
    before = recovery.fingerprints()
    deployed = deployments.verify()
    restored = recovery.run('check-local')
    after_deployed = deployments.verify(repull=deployed['active'])
    if deployed['active'] != after_deployed['active']:
        raise RuntimeError('Harbor Deployment fixture disappeared during recovery')
    if recovery.fingerprints() != before or recovery.sources() != volumes:
        # Allocation counters change during normal operation; source identities must not.
        current = recovery.sources()
        if recovery.fingerprints() != before or any(
                {key: value for key, value in row.items() if key != 'actual_bytes'} !=
                {key: value for key, value in current[component].items() if key != 'actual_bytes'}
                for component, row in volumes.items()):
            raise RuntimeError('Harbor recovery changed production credential or volume identities')
    return {'argo_converged': True, 'independent_retained_claims': 3, 'oidc_prerequisites': True,
            'independent_emergency_api': True, 'unauthenticated_access_denied': True,
            'public_gateway_denied': True, 'recovery': restored, 'deployed_rollback': after_deployed}


if __name__ == '__main__':
    os.umask(0o077)
    try:
        print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
    except Exception as error:
        recovery.BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
        recovery.atomic(recovery.BASE / 'verification-failure.json', {
            'type': type(error).__name__, 'frames': [
                {'file': Path(frame.filename).name, 'line': frame.lineno}
                for frame in traceback.extract_tb(error.__traceback__)]})
        raise SystemExit('Harbor installation verification incomplete; private values withheld') from None
