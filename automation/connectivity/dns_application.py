"""Bounded bootstrap of only the custom DNS Application after host resolver proof."""
import json
from pathlib import Path
import sys
sys.path.insert(0, '/var/lib/cloudlab/mesh')
from kube import application_ready, contains, get, kube, wait
from dns_inputs import read

NAME = 'cloudlab-private-dns'
OWNER = 'cloudlab-private-dns-bootstrap'


def run(payload):
    zone = read()['zone']
    core = get('configmap', 'coredns', 'kube-system')
    if 'import /etc/coredns/custom/*.server' not in core.get('data', {}).get('Corefile', ''):
        raise RuntimeError('Cluster DNS does not expose the expected custom forwarding interface')
    actual = get('application.argoproj.io', NAME, 'argocd')
    custom = get('configmap', 'coredns-custom', 'kube-system')
    path = Path('/var/lib/cloudlab/connectivity/dns-identities.json')
    if path.exists():
        retained = json.loads(path.read_text())
        if not actual or not custom or retained != {
                'application.argoproj.io': actual['metadata']['uid'], 'configmap': custom['metadata']['uid']}:
            raise RuntimeError('Private DNS identities changed or disappeared; explicit recovery required')
    if not actual and custom:
        raise RuntimeError('Custom cluster DNS already has an owner; refusing takeover')
    if actual and (actual['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                   or actual['metadata'].get('finalizers') or actual['metadata'].get('ownerReferences')):
        raise RuntimeError('Private DNS Application ownership conflict')
    desired = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
               'metadata': {'name': NAME, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
               'spec': {'project': NAME, 'source': {'repoURL': payload['repository'],
                   'targetRevision': payload['branch'], 'path': 'platform/connectivity/private-dns',
                   'helm': {'releaseName': NAME, 'valuesObject': {'zone': zone}}},
                   'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'kube-system'},
                   'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                      'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}
    changed = not actual or not contains(actual, desired)
    if changed:
        kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
    wait(lambda: application_ready(NAME, payload['revision']), 'private DNS Application convergence')
    custom = get('configmap', 'coredns-custom', 'kube-system')
    if not custom['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(NAME + ':'):
        raise RuntimeError('Custom DNS lacks its declared Argo owner')
    # Argo does not own the existing K3s CoreDNS Deployment or its main ConfigMap.
    identities = {kind: get(kind, name, ns)['metadata']['uid'] for kind, name, ns in (
        ('application.argoproj.io', NAME, 'argocd'), ('configmap', 'coredns-custom', 'kube-system'))}
    if path.exists() and json.loads(path.read_text()) != identities:
        raise RuntimeError('Private DNS object identities changed')
    if not path.exists():
        # Independent receipt; never modify the access Application ownership checkpoint.
        import os
        temporary = path.with_suffix('.tmp')
        with temporary.open('w') as stream:
            json.dump(identities, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
    print(json.dumps({'changed': changed, 'cluster_dns_configured': True}))


if __name__ == '__main__':
    try:
        run(json.load(sys.stdin))
    except Exception:
        raise SystemExit('Private DNS Application reconciliation failed; existing cluster DNS retained.') from None
