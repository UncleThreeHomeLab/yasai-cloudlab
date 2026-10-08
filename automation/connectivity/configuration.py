"""Bounded owner of the access Application; Argo owns every rendered declaration."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys

# Public Kubernetes I/O interface, installed by the prerequisite mesh module.
sys.path.insert(0, '/var/lib/cloudlab/mesh')
from kube import application_ready, condition, contains, get, kube, wait

BASE = Path('/var/lib/cloudlab/connectivity')
OWNER = 'cloudlab-access-bootstrap'
APP = 'cloudlab-access'


def application(payload):
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': APP, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': APP, 'source': {'repoURL': payload['repository'],
            'targetRevision': payload['branch'], 'path': 'platform/connectivity/access',
            'helm': {'releaseName': APP, 'valuesObject': {'administrator': payload['administrator']}}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'tailscale'},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}}}


def record(state):
    temporary = BASE / 'ownership.tmp'
    with temporary.open('w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(BASE / 'ownership.json')
    descriptor = os.open(BASE, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run(payload):
    os.umask(0o077)
    with (BASE / 'ownership.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        wait(lambda: application_ready('cloudlab-tailscale-operator', payload['revision']), 'operator GitOps convergence')
        for name in ('proxyclasses', 'proxygroups'):
            wait(lambda: condition(get('customresourcedefinition', name + '.tailscale.com'), 'Established'), 'operator CRDs')
        for namespace, name in [('tailscale', 'operator-oauth'), ('cloudlab-connectors', 'cloudflared-runtime')]:
            wait(lambda: condition(get('externalsecret', name, namespace), 'Ready'), 'access credential delivery')
        kube('rollout', 'status', 'deployment/operator', '-n', 'tailscale', '--timeout=300s', timeout=330)
        path = BASE / 'ownership.json'
        before = get('application.argoproj.io', APP, 'argocd')
        binding = hashlib.sha256(payload['administrator'].encode()).hexdigest()
        if not path.exists():
            if before:
                raise RuntimeError('Access Application exists without its ownership checkpoint')
            state = {'phase': 'preparing', 'administrator': binding}
            record(state)
        else:
            state = json.loads(path.read_text())
        if state['administrator'] != binding:
            raise RuntimeError('Administrator changed; explicit RBAC migration required')
        if state.get('application_uid') and not before:
            raise RuntimeError('Access Application disappeared; explicit recovery required')
        if before and (before['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                       or before['metadata'].get('finalizers') or before['metadata'].get('ownerReferences')
                       or state.get('application_uid', before['metadata']['uid']) != before['metadata']['uid']):
            raise RuntimeError('Access Application has conflicting ownership')
        desired = application(payload)
        changed = not before or not contains(before, desired)
        if changed:
            kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
        current = get('application.argoproj.io', APP, 'argocd')
        if state.get('application_uid') != current['metadata']['uid']:
            state['application_uid'] = current['metadata']['uid']
            record(state)
        wait(lambda: application_ready(APP, payload['revision']), 'access GitOps convergence')
        for name in ('cloudlab-ingress', 'cloudlab-api'):
            wait(lambda: condition(get('proxygroup', name), 'ProxyGroupReady'), 'proxy group readiness', timeout=900)
            kube('rollout', 'status', 'statefulset/' + name, '-n', 'tailscale', '--timeout=300s', timeout=330)
        kube('rollout', 'status', 'deployment/cloudflared', '-n', 'cloudlab-connectors', '--timeout=300s', timeout=330)
        identities = {}
        for kind, name, ns in [('proxygroup', 'cloudlab-ingress', None), ('proxygroup', 'cloudlab-api', None),
                               ('service', 'cloudlab-tailnet', 'cloudlab-gateway-private'),
                               ('secret', 'operator-oauth', 'tailscale'), ('secret', 'cloudflared-runtime', 'cloudlab-connectors')]:
            identities[kind + '/' + name] = get(kind, name, ns)['metadata']['uid']
        if 'identities' in state and state['identities'] != identities:
            raise RuntimeError('Access object identities changed')
        if state['phase'] != 'configured':
            state.update(phase='configured', identities=identities)
            record(state)
            changed = True
        return {'changed': changed, 'phase': state['phase'], 'acceptance_passed': False}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Access configuration failed; private checkpoint retained.') from None
