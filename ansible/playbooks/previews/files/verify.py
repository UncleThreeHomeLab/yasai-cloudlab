"""Scoped live checks; positive OIDC and PR lifecycle proof are separate fixtures."""
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, '/opt/cloudlab')
from playbooks.istio.files.kube import get, kube, wait
from playbooks.previews.files.contract import OWNER, STATE, ORIGIN_VERSION, runtime_catalog, names, hostname
from playbooks.previews.files.admission import CONTROLLER, native


def collection(kind, namespace):
    value = get(kind, namespace=namespace)
    if value is None:
        return []
    if not isinstance(value, dict) or not isinstance(value.get('items'), list):
        raise ValueError('Preview resource collection has an unexpected response shape')
    return value['items']


def verify(payload):
    settings = runtime_catalog(payload['catalog'])
    native(lambda kind, name: get(kind, name), settings)
    controller = get('deployment', 'argocd-applicationset-controller', 'argocd')
    args = controller['spec']['template']['spec']['containers'][0].get('args', [])
    if '--policy=create-update' not in args or any('enable-policy-override' in arg and not arg.endswith('=false') for arg in args):
        raise ValueError('Effective ApplicationSet retention policy differs')
    pilot = get('deployment', 'istiod', 'istio-system')
    env = {entry['name']: entry.get('value') for entry in pilot['spec']['template']['spec']['containers'][0].get('env', [])}
    if env.get('ENABLE_INGRESS_WAYPOINT_ROUTING') != 'true' or env.get('PILOT_JWT_ENABLE_REMOTE_JWKS') != 'false':
        raise ValueError('Effective waypoint ingress or control-plane JWKS ownership differs')
    for verb, resource, namespace in (('get', 'secrets', 'cloudlab-app-notes'),
            ('list', 'secrets', 'cloudlab-identity'), ('update', 'namespaces', None)):
        result = kube('auth', 'can-i', verb, resource, *(['-n', namespace] if namespace else []), '--as=' + CONTROLLER, allow_failure=True)
        if result.returncode != 1 or result.stdout.strip() != 'no':
            raise ValueError('Preview controller has an unexpected persistent credential or namespace write permission')
    cron = get('cronjob', OWNER, 'argocd')
    if not cron or cron['spec'].get('suspend') or cron['spec']['concurrencyPolicy'] != 'Forbid':
        raise ValueError('Preview lifecycle scheduler is unavailable')
    state = get('configmap', STATE, 'argocd')
    if not state or state['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
        raise ValueError('Preview controller has not initialized its durable state')
    entries = json.loads(state['data']['state.json'])['entries']
    expected = {receipt['uid'] for record in entries.values() for receipt in record.get('resources', [])
                if receipt['key'][1] == 'Namespace'}
    if any(obj['metadata'].get('labels', {}).get('cloudlab.io/owner') == OWNER and obj['metadata']['uid'] not in expected
           for obj in get('namespaces')['items']):
        raise ValueError('Uninventoried preview namespace requires administrator review; adoption and deletion refused')
    negatives = 0
    for instance, record in entries.items():
        if record['phase'] != 'active':
            continue
        if record.get('originVersion') != ORIGIN_VERSION:
            raise ValueError('Historical shared-origin preview remains active')
        row = record['approval']
        n = names(row)
        namespace = get('namespace', n['namespace'])
        if (not namespace or namespace['metadata']['labels'].get('pod-security.kubernetes.io/enforce') != 'restricted' or
                namespace['metadata']['labels'].get('cloudlab.io/gateway') != 'private' or
                collection('persistentvolumeclaims', n['namespace']) or
                collection('secrets', n['namespace'])):
            raise ValueError('Preview namespace privacy or data boundary differs')
        appset = get('applicationset.argoproj.io', n['name'], 'argocd')
        spec = appset['spec']
        selector = spec['generators'][0]['selector']['matchLabels']
        app = spec['template']['spec']
        if (selector != {'number': str(row['pullRequest']), 'head_sha': row['sourceSha']} or
                app['source']['targetRevision'] != row['platformRevision'] or app['source']['path'] != 'charts/service' or
                app['project'] != n['name'] or app['destination']['namespace'] != n['namespace'] or
                spec['syncPolicy'] != {'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True}):
            raise ValueError('Preview ApplicationSet execution boundary differs')
        route = get('httproute', 'preview', n['namespace'])
        if (route['spec']['parentRefs'][0]['namespace'] != 'cloudlab-gateway-private' or
                route['spec']['hostnames'] != [hostname(row, settings)]):
            raise ValueError('Preview route is not private')
        try:
            with urllib.request.urlopen('https://' + hostname(row, settings) + n['path'], timeout=10):
                raise ValueError('Unauthenticated preview application data is reachable')
        except urllib.error.HTTPError as error:
            if error.code not in (401, 403):
                raise ValueError('Preview negative identity check failed') from None
        negatives += 1
    return {'configured': True, 'active': sum(r['phase'] == 'active' for r in entries.values()),
            'private_unauthenticated_denials': negatives, 'persistent_secret_rbac_denied': True,
            'positive_identity_fixture_required': True, 'close_expiry_fixture_required': True}


if __name__ == '__main__':
    try:
        print(json.dumps(verify(json.load(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Preview verification failed; private diagnostics withheld') from None
