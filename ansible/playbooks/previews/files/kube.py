"""Bounded Kubernetes API operations with optimistic state and delete guards."""
import json
from pathlib import Path
import re
import ssl
import urllib.error
import urllib.request

RESOURCES = {
    ('v1', 'Namespace'): 'namespaces', ('v1', 'ConfigMap'): 'configmaps',
    ('v1', 'Secret'): 'secrets', ('v1', 'Service'): 'services',
    ('v1', 'ServiceAccount'): 'serviceaccounts', ('v1', 'ResourceQuota'): 'resourcequotas',
    ('v1', 'LimitRange'): 'limitranges', ('v1', 'Pod'): 'pods',
    ('v1', 'PersistentVolumeClaim'): 'persistentvolumeclaims',
    ('apps/v1', 'Deployment'): 'deployments', ('apps/v1', 'ReplicaSet'): 'replicasets',
    ('argoproj.io/v1alpha1', 'Application'): 'applications',
    ('argoproj.io/v1alpha1', 'ApplicationSet'): 'applicationsets',
    ('argoproj.io/v1alpha1', 'AppProject'): 'appprojects',
    ('networking.k8s.io/v1', 'NetworkPolicy'): 'networkpolicies',
    ('gateway.networking.k8s.io/v1', 'HTTPRoute'): 'httproutes',
    ('gateway.networking.k8s.io/v1', 'Gateway'): 'gateways',
    ('security.istio.io/v1', 'AuthorizationPolicy'): 'authorizationpolicies',
    ('security.istio.io/v1', 'PeerAuthentication'): 'peerauthentications',
    ('security.istio.io/v1', 'RequestAuthentication'): 'requestauthentications',
    ('kyverno.io/v1', 'Policy'): 'policies',
    ('rbac.authorization.k8s.io/v1', 'RoleBinding'): 'rolebindings',
}

POD_METRICS = ('metrics.k8s.io/v1beta1', 'PodMetrics')


class NamespaceInventory(list):
    """Keep discovery eligibility outside API-controlled object fields."""
    def __init__(self):
        super().__init__()
        self.pod_metrics = set()


class APIError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__('Preview Kubernetes operation failed: HTTP ' + str(code))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def identity(obj):
    meta = obj['metadata']
    return (obj['apiVersion'], obj['kind'], meta.get('namespace', ''), meta['name'])


def path(key):
    version, kind, namespace, name = key
    if (version, kind) not in RESOURCES or any(
            not isinstance(part, str) or not re.fullmatch('[a-z0-9][a-z0-9.-]*', part)
            for part in (namespace, name) if part):
        raise ValueError('Unsupported preview resource coordinate')
    prefix = '/api/v1' if version == 'v1' else '/apis/' + version
    if namespace:
        prefix += '/namespaces/' + namespace
    return prefix + '/' + RESOURCES[(version, kind)] + ('/' + name if name else '')


class Kubernetes:
    def __init__(self):
        self.account = Path('/var/run/secrets/kubernetes.io/serviceaccount')
        self.context = ssl.create_default_context(cafile=str(self.account / 'ca.crt'))

    def request(self, method, route, value=None):
        if (route != '/apis' and not route.startswith(('/api/', '/apis/'))) or '?' in route or '..' in route:
            raise ValueError('Unsupported preview API path')
        headers = {'Authorization': 'Bearer ' + self.account.joinpath('token').read_text().strip(),
                   'Content-Type': 'application/json'}
        request = urllib.request.Request('https://kubernetes.default.svc' + route,
            data=json.dumps(value).encode() if value is not None else None, headers=headers, method=method)
        try:
            opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=self.context))
            with opener.open(request, timeout=10) as response:
                raw = response.read(2097153)
                if len(raw) > 2097152:
                    raise ValueError('Preview Kubernetes response exceeds its bound')
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raise APIError(error.code) from None
        except (OSError, ValueError):
            raise RuntimeError('Preview Kubernetes operation unavailable') from None

    def get(self, key):
        try:
            obj = self.request('GET', path(key))
            if obj is None:
                raise RuntimeError('Preview Kubernetes object observation unavailable')
            return obj
        except APIError as error:
            if error.code != 404:
                raise
            return None

    def list(self, version, kind, namespace=''):
        result = self.request('GET', path((version, kind, namespace, '')))
        if result.get('metadata', {}).get('continue') or len(result.get('items', [])) > 500:
            raise RuntimeError('Incomplete preview resource inventory')
        return result['items']

    def create(self, obj):
        key = identity(obj)
        return self.request('POST', path((*key[:3], '')), obj)

    def replace(self, obj):
        if not obj.get('metadata', {}).get('resourceVersion'):
            raise ValueError('Preview state writes require a resource version')
        return self.request('PUT', path(identity(obj)), obj)

    def delete(self, key, uid, version, *, orphan=False):
        if not uid or not version:
            raise ValueError('Preview deletion requires exact UID and resource version')
        return self.request('DELETE', path(key), {'apiVersion': 'v1', 'kind': 'DeleteOptions',
            'propagationPolicy': 'Orphan' if orphan else 'Foreground', 'preconditions': {'uid': uid, 'resourceVersion': version}})

    def namespace_inventory(self, namespace):
        result = self.request('GET', '/api/v1')['resources']
        endpoints = [('v1', result)]
        groups = self.request('GET', '/apis')['groups']
        if len(groups) > 100:
            raise RuntimeError('Preview API discovery exceeds its bound')
        discovered = set()
        for group in groups:
            for served in group['versions']:
                version = served['groupVersion']
                if version in discovered:
                    continue
                discovered.add(version)
                if len(discovered) > 200:
                    raise RuntimeError('Preview API discovery exceeds its bound')
                endpoints.append((version, self.request('GET', '/apis/' + version)['resources']))
        objects = NamespaceInventory()
        collections = set()
        for version, resources in endpoints:
            if len(resources) > 1000:
                raise RuntimeError('Preview API discovery exceeds its bound')
            for item in resources:
                metrics = version == POD_METRICS[0] and item['name'] == 'pods'
                if metrics and (item.get('kind') != POD_METRICS[1] or item.get('namespaced') is not True or
                                set(item.get('verbs', [])) != {'get', 'list'}):
                    raise RuntimeError('Preview metrics discovery is not the accepted read-only projection')
                if item.get('namespaced') and '/' not in item['name'] and 'list' in item.get('verbs', []):
                    collection = (version.split('/')[0] if '/' in version else '', item['name'])
                    if collection in collections:
                        continue
                    collections.add(collection)
                    if len(collections) > 1000:
                        raise RuntimeError('Preview API discovery exceeds its bound')
                    prefix = '/api/v1' if version == 'v1' else '/apis/' + version
                    value = self.request('GET', prefix + '/namespaces/' + namespace + '/' + item['name'])
                    if value.get('metadata', {}).get('continue') or len(value.get('items', [])) > 500:
                        raise RuntimeError('Incomplete preview namespace inventory')
                    for obj in value.get('items', []):
                        if (not isinstance(obj, dict) or obj.get('apiVersion', version) != version or
                                obj.get('kind', item['kind']) != item['kind']):
                            raise RuntimeError('Preview inventory object differs from its discovered collection')
                        if version == 'v1' and item['kind'] == 'Endpoints' and item['name'] != 'endpoints':
                            raise RuntimeError('Native Endpoints require their exact core collection')
                        obj.setdefault('apiVersion', version)
                        obj.setdefault('kind', item['kind'])
                        if metrics:
                            meta = obj.get('metadata', {})
                            if ((obj['apiVersion'], obj['kind']) != POD_METRICS or
                                    not isinstance(meta, dict) or meta.get('namespace') != namespace or
                                    not isinstance(meta.get('name'), str) or not meta['name']):
                                raise RuntimeError('Preview metrics projection differs from its discovery')
                            objects.pod_metrics.add(id(obj))
                        objects.append(obj)
        return objects
