"""Resumable legacy ingress handoff; loaded on the server by Ansible only."""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, '/var/lib/cloudlab/mesh')
from kube import application_ready, contains, get, kube, wait

BASE = Path('/var/lib/cloudlab/connectivity')
RECEIPT = BASE / 'cutover.json'
APP = 'cloudlab-gateway-api'


def record(state):
    temporary = RECEIPT.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(RECEIPT)
    descriptor = os.open(BASE, os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def release():
    secrets = json.loads(kube('get', 'secrets', '-n', 'kube-system', '-l', 'owner=helm,name=traefik-crd', '-o', 'json'))['items']
    found = []
    for secret in secrets:
        data = json.loads(gzip.decompress(base64.b64decode(base64.b64decode(secret['data']['release']))))
        if data['info']['status'] == 'deployed':
            found.append({'uid': secret['metadata']['uid'], 'manifest': data['manifest']})
    if len(found) != 1:
        raise RuntimeError('Expected one active legacy CRD release')
    return found[0]


def dependencies():
    crds = get('customresourcedefinitions')['items']
    for crd in crds:
        if crd['spec']['group'] in ('traefik.io', 'traefik.containo.us'):
            if json.loads(kube('get', crd['metadata']['name'], '-A', '-o', 'json'))['items']:
                raise RuntimeError('A Traefik custom resource still depends on the legacy controller')
    if json.loads(kube('get', 'ingresses', '-A', '-o', 'json'))['items']:
        raise RuntimeError('Ingress dependencies require an explicit migration')
    for service in json.loads(kube('get', 'services', '-A', '-o', 'json'))['items']:
        if service['spec'].get('type') == 'LoadBalancer' and service['spec'].get('loadBalancerClass') != 'tailscale':
            if (service['metadata']['namespace'], service['metadata']['name']) != ('kube-system', 'traefik'):
                raise RuntimeError('ServiceLB still has an unrelated consumer')
    for kind in ('httproutes', 'grpcroutes', 'tcproutes', 'tlsroutes', 'udproutes'):
        for route in json.loads(kube('get', kind + '.gateway.networking.k8s.io', '-A', '-o', 'json'))['items']:
            if any(p.get('name') != 'cloudlab' for p in route['spec'].get('parentRefs', [])):
                raise RuntimeError('An unreviewed Gateway API route still exists')


def identities(expected):
    result = {}
    for obj in expected:
        actual = get('customresourcedefinition', obj['metadata']['name'])
        if not actual or not contains(actual['spec'], obj['spec']):
            raise RuntimeError('Gateway API definition changed or disappeared')
        result[obj['metadata']['name']] = actual['metadata']['uid']
    if len(result) != 10:
        raise RuntimeError('Gateway API inventory differs from the pinned baseline')
    return result


def prepare(payload):
    current = json.loads(RECEIPT.read_text()) if RECEIPT.exists() else None
    observed = identities(payload['gateway_api'])
    if current:
        if current['crds'] != observed:
            raise RuntimeError('Gateway API identity changed during cutover')
        return {'changed': False, 'phase': current['phase']}
    evidence = json.loads((BASE / 'receipts/acceptance.json').read_text())
    external = json.loads((BASE / 'receipts/external.json').read_text())
    if (not evidence['evidence'].get('acceptance_passed') or time.time() - evidence['verified_at'] > 86400
            or evidence['external_binding'] != external['binding']):
        raise RuntimeError('Recent complete replacement acceptance is required before legacy removal')
    from cluster_fixture import identities as proxy_identities, snapshot
    snapshot()
    if proxy_identities() != evidence['identities']:
        raise RuntimeError('Proxy identities changed since replacement acceptance')
    dependencies()
    retained = release()
    if (retained['uid'] != payload['release_uid'] or hashlib.sha256(retained['manifest'].encode()).hexdigest() != payload['release_hash']):
        raise RuntimeError('Legacy release changed after retention audit')
    config = Path('/etc/rancher/k3s/config.yaml')
    backup = BASE / 'k3s-before-cutover.yaml'
    if not backup.exists():
        backup.write_bytes(config.read_bytes())
        backup.chmod(0o600)
    record({'phase': 'prepared', 'crds': observed, 'release_uid': retained['uid'],
            'acceptance_at': evidence['verified_at']})
    return {'changed': True, 'phase': 'prepared'}


def legacy_removed():
    # kubectl --ignore-not-found may produce no JSON for an empty collection.
    charts = (get('helmcharts.helm.cattle.io', namespace='kube-system') or {}).get('items', [])
    if any(c['metadata']['name'] in ('traefik', 'traefik-crd') for c in charts):
        return False
    if get('deployment', 'traefik', 'kube-system') or get('service', 'traefik', 'kube-system'):
        return False
    workloads = (get('daemonsets', namespace='kube-system') or {}).get('items', [])
    return not any(d['metadata']['name'].startswith('svclb-') for d in workloads)


def finish(payload):
    state = json.loads(RECEIPT.read_text())
    if identities(payload['gateway_api']) != state['crds']:
        raise RuntimeError('Gateway API identities were not retained')
    wait(legacy_removed, 'bundled Traefik and unused ServiceLB workload removal', timeout=600)
    dependencies()
    # The old Helm reconciler is gone. Retained CRDs can now acquire one new owner.
    changed = state['phase'] not in ('adopted', 'accepted')
    for name in state['crds']:
        obj = get('customresourcedefinition', name)
        annotations = obj['metadata'].get('annotations', {})
        if annotations.get('meta.helm.sh/release-name'):
            if annotations['meta.helm.sh/release-name'] != 'traefik-crd':
                raise RuntimeError('Gateway API has an unexpected Helm owner')
            kube('patch', 'customresourcedefinition', name, '--type=json', '-p', json.dumps([
                {'op': 'test', 'path': '/metadata/uid', 'value': state['crds'][name]},
                {'op': 'remove', 'path': '/metadata/annotations/meta.helm.sh~1release-name'},
                {'op': 'remove', 'path': '/metadata/annotations/meta.helm.sh~1release-namespace'},
                {'op': 'add', 'path': '/metadata/annotations/cloudlab.io~1owner', 'value': APP}]))
            changed = True
    desired = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': APP, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': APP + '-bootstrap'}},
        'spec': {'project': APP, 'source': {'repoURL': payload['repository'], 'targetRevision': payload['branch'],
            'path': 'platform/connectivity/gateway-api', 'helm': {'releaseName': APP}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['ServerSideApply=true', 'FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}
    before = get('application.argoproj.io', APP, 'argocd')
    if before and (before['metadata'].get('labels', {}).get('cloudlab.io/owner') != APP + '-bootstrap'
                   or before['metadata'].get('finalizers') or before['metadata'].get('ownerReferences')
                   or state.get('application_uid', before['metadata']['uid']) != before['metadata']['uid']):
        raise RuntimeError('Gateway API Application has conflicting ownership')
    if not before and state.get('application_uid'):
        raise RuntimeError('Gateway API Application disappeared; explicit recovery required')
    if not before or not contains(before, desired):
        kube('apply', '--server-side', '--field-manager=' + APP + '-bootstrap', '-f', '-', document=desired)
        changed = True
    uid = get('application.argoproj.io', APP, 'argocd')['metadata']['uid']
    if state.get('application_uid') != uid:
        state['application_uid'] = uid
        record(state)
    wait(lambda: application_ready(APP, payload['revision']), 'Gateway API GitOps handoff')
    if identities(payload['gateway_api']) != state['crds']:
        raise RuntimeError('Gateway API identities changed during adoption')
    for name in state['crds']:
        actual = get('customresourcedefinition', name)
        if (not actual['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(APP + ':')
                or not any(field.get('manager') == 'argocd-controller' and field.get('operation') == 'Apply'
                           and 'f:spec' in field.get('fieldsV1', {}) for field in actual['metadata'].get('managedFields', []))):
            raise RuntimeError('Gateway API spec is not owned by the declared GitOps reconciler')
    if state['phase'] == 'prepared':
        state['phase'] = 'adopted'
        record(state)
    return {'changed': changed, 'phase': state['phase'], 'retained_gateway_crds': 10,
            'traefik_removed': True, 'servicelb_workloads_removed': True, 'control_plane_ha': False}


def accept(payload):
    state = json.loads(RECEIPT.read_text())
    if state['phase'] not in ('adopted', 'accepted') or sorted(payload.get('disabled', [])) != ['servicelb', 'traefik']:
        raise RuntimeError('Both packaged components must be disabled after CRD adoption')
    # Recheck the retained owner and absence of consumers after the final restart.
    result = finish(payload)
    if state['phase'] != 'accepted':
        state['phase'] = 'accepted'
        record(state)
        result['changed'] = True
    return dict(result, phase='accepted', servicelb_removed=True)


if __name__ == '__main__':
    try:
        payload = json.load(sys.stdin)
        action = payload.pop('action')
        result = ({'state': json.loads(RECEIPT.read_text()) if RECEIPT.exists() else None} if action == 'status'
                  else release() if action == 'release' else prepare(payload) if action == 'prepare'
                  else finish(payload) if action == 'finish' else accept(payload) if action == 'accept' else None)
        if result is None: raise ValueError('Invalid legacy handoff action')
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Legacy handoff failed; retained CRDs and private checkpoint require inspection.') from None
