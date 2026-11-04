"""Retain existing Gateway APIs and configure private gateway Applications."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

from kube import application_ready, condition, contains, get, kube, wait

from ownership import BASE, APP, OWNER, gateway_api, selected_zone, component_identities


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


def application(payload, zone, argo=None):
    values = {'zone': zone}
    if argo:
        values['argo'] = argo
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': APP, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': APP, 'source': {'repoURL': payload['repository'],
            'targetRevision': payload['branch'], 'path': 'platform/connectivity/gateways',
            'helm': {'releaseName': APP, 'valueFiles': ['values.json'], 'valuesObject': values}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-gateway-public'},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}}}



def argo_routes(zone, previous=None):
    """Use the consumer's verified ConfigMap interface; never infer an empty removal."""
    current = get('configmap', 'argocd-cm', 'argocd') or {}
    data = current.get('data', {})
    expected = (previous or {}).get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {}).get('argo')
    if not data.get('oidc.config'):
        if expected:
            raise RuntimeError('Existing Argo routes require their available OIDC configuration')
        return {}
    if not current.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-argocd:'):
        raise RuntimeError('Argo OIDC routing requires the existing consumer owner')
    import yaml
    oidc = yaml.safe_load(data['oidc.config'])
    if not isinstance(oidc, dict) or oidc.get('issuer') != 'https://login.' + zone + '/realms/platform' or oidc.get('clientID') != 'argocd':
        raise RuntimeError('Argo routing requires the scoped platform identity client')
    additional = yaml.safe_load(data.get('additionalUrls', '[]'))
    if not isinstance(additional, list) or len(additional) != 1:
        raise RuntimeError('Argo requires exact public and private origins')
    hosts = {}
    for origin in [data.get('url'), *additional]:
        if not isinstance(origin, str) or any(char.isspace() or ord(char) < 32 for char in origin):
            raise RuntimeError('Argo origin must be an exact HTTPS authority')
        parsed = urlsplit(origin)
        if parsed.scheme != 'https' or parsed.port not in (None, 443) or parsed.path or parsed.query or parsed.fragment or parsed.username is not None:
            raise RuntimeError('Argo origin must be an exact HTTPS authority')
        host = parsed.hostname or ''
        if host == 'cd.internal.' + zone:
            exposure = 'private'
        elif host.endswith('.' + zone) and len(host.split('.')) == len(zone.split('.')) + 1 and host.split('.')[0] != 'internal':
            exposure = 'public'
        else:
            raise RuntimeError('Argo origin must stay within its approved gateway zone')
        if exposure in hosts:
            raise RuntimeError('Argo origins require distinct public/private exposures')
        hosts[exposure] = host
    if set(hosts) != {'public', 'private'}:
        raise RuntimeError('Argo requires both independent gateway origins')
    return hosts


def run(payload):
    os.umask(0o077)
    if BASE.resolve() != BASE.absolute():
        raise RuntimeError('Mesh state directory cannot be a symlink')
    with (BASE / 'ownership.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = BASE / 'ownership.json'
        if path.exists():
            accepted = json.loads(path.read_text())
            if accepted.get('phase') == 'accepted':
                from native import guard, observe_legacy
                if payload.get('native') is None:
                    observe_legacy(payload, accepted)
                else:
                    guard(payload['native'], accepted, payload)
                return {'changed': False, 'phase': 'accepted', 'mesh_objects': len(accepted['components']),
                        'existing_gateway_api_objects': len(accepted['gateway_api']), 'internal_gateways': 2}
        crds = gateway_api(payload['gateway_api'])
        zone = selected_zone()
        digest = hashlib.sha256(zone.encode()).hexdigest()
        path = BASE / 'ownership.json'
        before = get('application.argoproj.io', APP, 'argocd')
        if not path.exists():
            if before or any(get(kind, name, 'cloudlab-gateway-' + exposure)
                             for exposure in ('public', 'private') for kind, name in (
                                 ('gateway.gateway.networking.k8s.io', 'cloudlab'),
                                 ('configmap', 'cloudlab-gateway-options'),
                                 ('httproute.gateway.networking.k8s.io', 'argocd'),
                                 *[(kind, 'cloudlab-istio') for kind in ('deployment', 'service', 'serviceaccount')])):
                raise RuntimeError('Gateway configuration exists without its ownership checkpoint')
            state = {'phase': 'preparing', 'gateway_api': crds, 'zone_hash': digest}
            record(state)
        else:
            state = json.loads(path.read_text())
        if state.get('phase') != 'preparing':
            raise RuntimeError('Initial mesh receipt phase is invalid')
        if state['gateway_api'] != crds or state['zone_hash'] != digest:
            raise RuntimeError('Gateway API identities or selected zone changed')
        components = component_identities(payload)
        if 'components' in state and state['components'] != components:
            raise RuntimeError('Istio declaration identities changed')
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
        desired = application(payload, zone, argo_routes(zone, before))
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
