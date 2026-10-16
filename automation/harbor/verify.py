"""Verify installation prerequisites before registry API ownership or human onboarding."""
import base64
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from automation.harbor import recovery
from automation.identity.health import direct_https
from automation.mesh.kube import get, contains, application_ready


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
    if any(settings.get(key, {}).get('value') != value for key, value in expected.items()):
        raise RuntimeError('Harbor OIDC prerequisites differ; do not create human accounts')
    for path, authorization in (('/api/v2.0/users/current', {}),
            ('/api/v2.0/users/current', {'Authorization': 'Basic aW52YWxpZDppbnZhbGlk'}), ('/v2/', {})):
        status, _ = direct_https(origin + path, gateway, authorization)
        if status not in (302, 401, 403) or (path == '/v2/' and status != 401):
            raise RuntimeError('Unauthenticated Harbor access was not rejected')
    public = get('service', 'cloudlab-istio', 'cloudlab-gateway-public')['spec']['clusterIP']
    if direct_https(origin + '/v2/', public, {})[0] != 404:
        raise RuntimeError('Harbor registry is exposed by the public gateway')
    before = recovery.fingerprints()
    restored = recovery.run('check-local')
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
            'public_gateway_denied': True, 'recovery': restored}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Harbor installation verification incomplete; private values withheld') from None
