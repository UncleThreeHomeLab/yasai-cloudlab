"""Read-only mesh ownership and retained identities."""
import hashlib
import json
from pathlib import Path
from kube import application_ready, condition, contains, get, wait

BASE = Path('/var/lib/cloudlab/mesh')
APP = 'cloudlab-gateways'
OWNER = 'cloudlab-gateways-bootstrap'


def gateway_api(expected):
    identities = {}
    for obj in expected:
        name = obj['metadata']['name']
        actual = get('customresourcedefinition', name)
        if not actual or actual['metadata'].get('deletionTimestamp') or not contains(actual['spec'], obj['spec']):
            raise RuntimeError('Existing Gateway API differs from its pinned standard contract')
        annotations = actual['metadata'].get('annotations', {})
        legacy_owner = annotations.get('meta.helm.sh/release-name')
        if not (legacy_owner == 'traefik-crd' or
                (legacy_owner is None and annotations.get('cloudlab.io/owner') == 'cloudlab-gateway-api')):
            raise RuntimeError('Gateway API owner changed outside the declared handoff')
        if annotations.get('gateway.networking.k8s.io/bundle-version') != 'v1.6.1':
            raise RuntimeError('Gateway API version changed')
        identities[name] = actual['metadata']['uid']
    return identities


def selected_zone():
    # Certificate resources are the public interface; no private receipt coupling.
    public = get('certificate.cert-manager.io', 'cloudlab-gateway', 'cloudlab-gateway-public')
    private = get('certificate.cert-manager.io', 'cloudlab-gateway', 'cloudlab-gateway-private')
    def ready(obj):
        return (bool(obj) and not obj['metadata'].get('deletionTimestamp')
                and obj['metadata'].get('generation') is not None
                and any(c.get('type') == 'Ready' and c.get('status') == 'True'
                        and c.get('observedGeneration') == obj['metadata']['generation']
                        for c in obj.get('status', {}).get('conditions', []))
                and not any(c.get('type') == 'Issuing' and c.get('status') == 'True'
                            and c.get('observedGeneration') == obj['metadata']['generation']
                            for c in obj.get('status', {}).get('conditions', [])))
    if not ready(public) or not ready(private):
        raise RuntimeError('Both gateway certificates must be ready before mesh configuration')
    names = public['spec'].get('dnsNames', [])
    if len(names) != 1 or not names[0].startswith('*.'):
        raise RuntimeError('Public certificate wildcard contract changed')
    zone = names[0][2:]
    if private['spec'].get('dnsNames') != ['*.internal.' + zone, 'login.' + zone]:
        raise RuntimeError('Private certificate wildcard contract changed')
    return zone


def argo_owned(obj, actual, app):
    metadata = (actual or {}).get('metadata', {})
    if obj['kind'] == 'CustomResourceDefinition':
        # Argo 3.5 intentionally does not annotate CRDs for resource tracking.
        # Require its actual SSA spec ownership, plus revision and UID checks.
        return any(field.get('manager') == 'argocd-controller' and field.get('operation') == 'Apply'
                   and 'f:spec' in field.get('fieldsV1', {}) for field in metadata.get('managedFields', []))
    return metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(app + ':')


def component_identities(payload):
    result = {}
    for component, objects in payload['mesh_objects'].items():
        app = 'cloudlab-istio-' + component
        wait(lambda: application_ready(app, payload['revision']), 'Istio Application convergence')
        for obj in objects:
            group = obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
            kind = obj['kind'] + ('.' + group if group else '')
            meta = obj['metadata']
            actual = get(kind, meta['name'], meta.get('namespace'))
            if not actual or actual['metadata'].get('deletionTimestamp') or not argo_owned(obj, actual, app):
                raise RuntimeError('Istio declaration lacks its sole Argo owner')
            result['/'.join((kind, meta.get('namespace', ''), meta['name']))] = actual['metadata']['uid']
    return result


def retained(payload, state):
    if (state.get('phase') != 'accepted' or not state.get('application_uid')
            or set(state.get('gateways', {})) != {'public', 'private'}
            or not state.get('components') or not state.get('gateway_api')):
        raise RuntimeError('Accepted mesh ownership receipt is incomplete')
    if gateway_api(payload['gateway_api']) != state['gateway_api'] or component_identities(payload) != state['components']:
        raise RuntimeError('Retained mesh declaration identities changed')
    zone = selected_zone()
    if hashlib.sha256(zone.encode()).hexdigest() != state['zone_hash']:
        raise RuntimeError('Retained gateway zone changed')
    ca = get('secret', 'istio-ca-secret', 'istio-system') or {}
    identity = {'uid': ca.get('metadata', {}).get('uid'),
                'content': hashlib.sha256(json.dumps(ca.get('data', {}), sort_keys=True).encode()).hexdigest()}
    if ca.get('metadata', {}).get('deletionTimestamp') or identity != state['workload_ca']:
        raise RuntimeError('Retained Istio CA identity or content changed')
    tls = {}
    for exposure, expected in state['gateways'].items():
        namespace = 'cloudlab-gateway-' + exposure
        for kind, name in [('gateway.gateway.networking.k8s.io', 'cloudlab'),
                           *[(kind, 'cloudlab-istio') for kind in ('deployment', 'service', 'serviceaccount')]]:
            obj = get(kind, name, namespace) or {}
            key = 'gateway' if kind.startswith('gateway.') else kind
            if obj.get('metadata', {}).get('deletionTimestamp') or obj.get('metadata', {}).get('uid') != expected[key]:
                raise RuntimeError('Retained gateway stack identity changed')
            if kind == 'service':
                spec = obj.get('spec', {})
                if (spec.get('type') != 'ClusterIP' or spec.get('externalIPs')
                        or any(port.get('nodePort') for port in spec.get('ports', []))):
                    raise RuntimeError('Retained gateway service has external exposure')
        secret = get('secret', 'cloudlab-gateway-tls', namespace) or {}
        if (secret.get('metadata', {}).get('deletionTimestamp') or secret.get('type') != 'kubernetes.io/tls'
                or not {'tls.crt', 'tls.key'} <= secret.get('data', {}).keys()
                or secret.get('metadata', {}).get('annotations', {}).get('cert-manager.io/certificate-name') != 'cloudlab-gateway'):
            raise RuntimeError('Gateway TLS credential ownership changed')
        tls[exposure] = {'uid': secret['metadata']['uid'],
            'content': hashlib.sha256(json.dumps(secret['data'], sort_keys=True).encode()).hexdigest()}
    return tls
