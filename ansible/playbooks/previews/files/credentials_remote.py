"""Host-side custody of the bounded operational preview discovery token."""
import base64
import copy
import json
import sys

sys.path.insert(0, '/opt/cloudlab')
from playbooks.istio.files.kube import get, kube

NAME = 'github-preview-discovery'
OWNER = 'cloudlab-preview-discovery'


def owned(value):
    meta = value.get('metadata', {})
    if (meta.get('name') != NAME or meta.get('namespace') != 'argocd' or
            meta.get('labels', {}).get('cloudlab.io/owner') != OWNER or
            meta.get('labels', {}).get('argocd.argoproj.io/secret-type') != 'scm-creds' or
            not meta.get('uid') or not meta.get('resourceVersion') or
            meta.get('ownerReferences') or meta.get('finalizers') or meta.get('deletionTimestamp') or
            value.get('type') != 'Opaque' or set(value.get('data', {})) != {'TOKEN', 'lease.json'}):
        raise ValueError('Preview discovery Secret has conflicting ownership')
    return value


def current():
    value = get('secret', NAME, 'argocd')
    return owned(value) if value else None


def unchanged(value, expected):
    actual = {key: value['metadata'][key] for key in ('uid', 'resourceVersion')} if value else None
    if actual != expected:
        raise ValueError('Preview discovery Secret changed during the operation')


def dispatch(request):
    action = request.get('action')
    value = current()
    if action == 'inspect' and set(request) == {'action'}:
        return value
    if action in ('retirement-inspect', 'remove'):
        if set(request) != ({'action'} if action == 'retirement-inspect' else {'action', 'expected'}):
            raise ValueError('Invalid discovery credential retirement')
        approvals = get('configmap', 'cloudlab-preview-approvals', 'argocd')
        settings = json.loads(approvals['data']['catalog.json']) if approvals else None
        if settings and settings['privateDiscovery'] and settings['approvals']:
            raise ValueError('Withdraw preview approvals before retiring discovery credentials')
        def references(obj):
            if isinstance(obj, dict):
                return (obj.get('secretName') == NAME or obj.get('appSecretName') == NAME or
                        any(references(item) for item in obj.values()))
            return isinstance(obj, list) and any(references(item) for item in obj)
        if any(references(row['spec']) for row in get('applicationsets.argoproj.io', namespace='argocd')['items']):
            raise ValueError('Preview discovery consumers remain; cleanup credentials retained')
        if action == 'retirement-inspect':
            return value
        unchanged(value, request['expected'])
        if value:
            kube('delete', '--raw=/api/v1/namespaces/argocd/secrets/' + NAME, '-f', '-',
                 document={'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': request['expected']})
        return {'changed': value is not None}
    if action != 'deliver' or set(request) != {'action', 'expected', 'lease'}:
        raise ValueError('Unsupported preview discovery credential operation')
    unchanged(value, request['expected'])
    lease = request['lease']
    from playbooks.previews.files.contract import discovery_lease
    discovery_lease(lease)
    obj = copy.deepcopy(value) if value else {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
        'metadata': {'name': NAME, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER,
            'argocd.argoproj.io/secret-type': 'scm-creds'}}}
    obj['data'] = {'TOKEN': base64.b64encode(lease['token'].encode()).decode(),
        'lease.json': base64.b64encode(json.dumps({key: item for key, item in lease.items() if key != 'token'}, sort_keys=True).encode()).decode()}
    kube('replace' if value else 'create', '-f', '-', document=obj)
    return {'changed': True}


if __name__ == '__main__':
    try:
        print(json.dumps(dispatch(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Preview discovery custody failed; private diagnostics retained') from None
