"""Check actual service convergence and project denial without exposing private inputs."""
import json
from pathlib import Path
import sys
import subprocess
import uuid

sys.path.insert(0, '/opt/cloudlab')
from playbooks.istio.files.kube import get, kube, wait
from playbooks.services.files.remote import inspect


def unauthorized_destination(entry, payload, *, unauthorized_source=False):
    nonce = uuid.uuid4().hex[:12]
    name = 'cloudlab-service-denial-' + nonce
    namespace = 'argocd'
    obj = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
           'metadata': {'name': name, 'namespace': namespace, 'labels': {'cloudlab.io/fixture': nonce}},
           'spec': {'project': entry['approval']['name'], 'source': {
               'repoURL': payload['repository'], 'targetRevision': payload['revision'], 'path': 'charts/service'},
               'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}}}
    if unauthorized_source:
        obj['spec']['destination']['namespace'] = entry['approval']['namespace']
        obj['spec']['source']['repoURL'] = 'https://github.com/example/unapproved.git'
    if get('application.argoproj.io', name, namespace): raise RuntimeError('Denial fixture name already exists')
    kube('create', '-f', '-', document=obj)
    created = get('application.argoproj.io', name, namespace)['metadata']['uid']
    try:
        wait(lambda: any(row.get('type') == 'InvalidSpecError' for row in
                         get('application.argoproj.io', name, namespace).get('status', {}).get('conditions', [])),
             'unauthorized service destination rejection', timeout=90)
        actual = get('application.argoproj.io', name, namespace)
        if actual.get('operation') or actual.get('status', {}).get('resources'):
            raise RuntimeError('Unauthorized fixture attempted workload reconciliation')
    finally:
        actual = get('application.argoproj.io', name, namespace)
        if actual and (actual['metadata']['uid'] != created or actual['metadata'].get('labels', {}).get('cloudlab.io/fixture') != nonce or actual['metadata'].get('finalizers')):
            raise RuntimeError('Denial fixture ownership changed; cleanup refused')
        if actual: kube('delete', 'application.argoproj.io', name, '-n', namespace, '--cascade=orphan')


def run(payload):
    from playbooks.services.files.bootstrap import converged
    if not converged(payload):
        raise RuntimeError('Direct Git catalog has not converged at both reviewed revisions')
    checked = 0
    for entry in payload['values']['catalog']:
        request = {'definition': entry['definition'], 'approval': entry['approval']}
        if entry['publication'] == 'retired':
            inspect(dict(request, action='route-absent'))
        else:
            for action in ('backend', 'identity', 'data', 'tls'):
                inspect(dict(request, action=action))
            if entry['approval'].get('chartPath') == 'apps/notes': inspect(dict(request, action='api-protection'))
            unauthorized_destination(entry, payload)
            unauthorized_destination(entry, payload, unauthorized_source=True)
            from playbooks.services.files.transport import run as transport_proof
            transport_proof(entry, payload['proof_image'])
        checked += 1
    active = [entry for entry in payload['values']['catalog'] if entry['publication'] != 'retired']
    stability = {'tested': False, 'active_namespaces': 0}
    if active:
        check = subprocess.run(['python3', '/opt/cloudlab/gitops/controller_stability.py',
                                *sorted({entry['approval']['namespace'] for entry in active})],
                               capture_output=True, text=True, timeout=180)
        if check.returncode: raise RuntimeError('Service controllers did not remain stable')
        stability = json.loads(check.stdout)
        for entry in active:
            inspect({'definition': entry['definition'], 'approval': entry['approval'], 'action': 'backend'})
    return {'services_checked': checked, 'owner_convergence': True, 'unauthorized_destinations_denied': True,
            'controller_stability': stability, 'data_removal': False}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Service behavior check failed; private inputs and retained data preserved') from None
