"""Retain existing Gateway APIs and configure private gateway Applications."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys

from kube import application_ready, condition, contains, get, kube, wait

BASE = Path('/var/lib/cloudlab/mesh')
APP = 'cloudlab-gateways'
OWNER = 'cloudlab-gateways-bootstrap'


def record(state):
    temporary = BASE / 'ownership.tmp'
    with temporary.open('w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(BASE / 'ownership.json')
    directory = os.open(BASE, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def gateway_api(expected):
    identities = {}
    for obj in expected:
        name = obj['metadata']['name']
        actual = get('customresourcedefinition', name)
        if not actual or not contains(actual['spec'], obj['spec']):
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
    if not condition(public, 'Ready') or not condition(private, 'Ready'):
        raise RuntimeError('Both gateway certificates must be ready before mesh configuration')
    names = public['spec'].get('dnsNames', [])
    if len(names) != 1 or not names[0].startswith('*.'):
        raise RuntimeError('Public certificate wildcard contract changed')
    zone = names[0][2:]
    if private['spec'].get('dnsNames') != ['*.internal.' + zone]:
        raise RuntimeError('Private certificate wildcard contract changed')
    return zone


def application(payload, zone):
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': APP, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': APP, 'source': {'repoURL': payload['repository'],
            'targetRevision': payload['branch'], 'path': 'platform/connectivity/gateways',
            'helm': {'releaseName': APP, 'valueFiles': ['values.json'], 'valuesObject': {'zone': zone}}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-gateway-public'},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}}}


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
            if not argo_owned(obj, actual, app):
                raise RuntimeError('Istio declaration lacks its sole Argo owner')
            result['/'.join((kind, meta.get('namespace', ''), meta['name']))] = actual['metadata']['uid']
    return result


def run(payload):
    os.umask(0o077)
    if BASE.resolve() != BASE.absolute():
        raise RuntimeError('Mesh state directory cannot be a symlink')
    with (BASE / 'ownership.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        crds = gateway_api(payload['gateway_api'])
        zone = selected_zone()
        digest = hashlib.sha256(zone.encode()).hexdigest()
        path = BASE / 'ownership.json'
        before = get('application.argoproj.io', APP, 'argocd')
        if not path.exists():
            if before or any(get('gateway.gateway.networking.k8s.io', 'cloudlab', 'cloudlab-gateway-' + k)
                             for k in ('public', 'private')):
                raise RuntimeError('Gateway configuration exists without its ownership checkpoint')
            state = {'phase': 'preparing', 'gateway_api': crds, 'zone_hash': digest}
            record(state)
        else:
            state = json.loads(path.read_text())
        if state['gateway_api'] != crds or state['zone_hash'] != digest:
            raise RuntimeError('Gateway API identities or selected zone changed')
        components = component_identities(payload)
        if 'components' in state and state['components'] != components:
            raise RuntimeError('Istio declaration identities changed')
        for kind, name in [('deployment', 'istiod'), ('daemonset', 'istio-cni-node'), ('daemonset', 'ztunnel')]:
            kube('rollout', 'status', kind + '/' + name, '-n', 'istio-system', '--timeout=300s', timeout=330)
        ca = get('secret', 'istio-ca-secret', 'istio-system')
        if not ca or not {'ca-cert.pem', 'ca-key.pem'} <= ca.get('data', {}).keys():
            raise RuntimeError('Istio workload CA credential is missing')
        ca_identity = {'uid': ca['metadata']['uid'],
                       'content': hashlib.sha256(json.dumps(ca['data'], sort_keys=True).encode()).hexdigest()}
        if 'workload_ca' in state and state['workload_ca'] != ca_identity:
            raise RuntimeError('Istio workload CA identity changed; explicit trust migration required')
        if 'components' not in state or 'workload_ca' not in state:
            state.update(components=components, workload_ca=ca_identity)
            record(state)
        desired = application(payload, zone)
        if state.get('application_uid') and not before:
            raise RuntimeError('Gateway Application missing; retain checkpoint and review recovery')
        if before and (before['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                       or before['metadata'].get('finalizers') or before['metadata'].get('ownerReferences')
                       or state.get('application_uid', before['metadata']['uid']) != before['metadata']['uid']):
            raise RuntimeError('Gateway Application has a conflicting owner or replaced identity')
        changed = not before or not contains(before, desired)
        if changed:
            wait(lambda: not (get('application.argoproj.io', APP, 'argocd') or {}).get('operation'),
                 'previous gateway operation', timeout=300)
            kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
        current = get('application.argoproj.io', APP, 'argocd')
        if before and current['metadata']['uid'] != before['metadata']['uid']:
            raise RuntimeError('Gateway Application identity changed')
        if state.get('application_uid') != current['metadata']['uid']:
            state['application_uid'] = current['metadata']['uid']
            record(state)
        wait(lambda: application_ready(APP, payload['revision']), 'gateway configuration convergence')
        identities = {}
        for exposure in ('public', 'private'):
            namespace = 'cloudlab-gateway-' + exposure
            gateway = wait(lambda: (obj if condition(obj := get('gateway.gateway.networking.k8s.io', 'cloudlab', namespace), 'Programmed') else None),
                           'gateway programming')
            kube('rollout', 'status', 'deployment/cloudlab-istio', '-n', namespace, '--timeout=300s', timeout=330)
            identities[exposure] = {'gateway': gateway['metadata']['uid'], **{
                kind: get(kind, 'cloudlab-istio', namespace)['metadata']['uid']
                for kind in ('deployment', 'service', 'serviceaccount')}}
            if get('service', 'cloudlab-istio', namespace)['spec']['type'] != 'ClusterIP':
                raise RuntimeError('Gateway service is not internal')
            retained = state.setdefault('gateways', {})
            if exposure in retained and retained[exposure] != identities[exposure]:
                raise RuntimeError('Gateway generated object identities changed')
            if exposure not in retained:
                retained[exposure] = identities[exposure]
                record(state)
        if 'gateways' in state and state['gateways'] != identities:
            raise RuntimeError('Gateway generated object identities changed')
        if state['phase'] != 'accepted':
            state.update(phase='accepted', components=components, gateways=identities, workload_ca=ca_identity)
            record(state)
            changed = True
        return {'changed': changed, 'phase': 'accepted', 'mesh_objects': len(components),
                'existing_gateway_api_objects': len(crds), 'internal_gateways': 2}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Mesh configuration failed; checkpoint retained, private diagnostics withheld') from None
