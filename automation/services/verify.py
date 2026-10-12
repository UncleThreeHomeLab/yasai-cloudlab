"""Check actual service convergence and project denial without exposing private inputs."""
import json
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from automation.mesh.kube import get, kube, wait
from automation.services.remote import inspect


def unauthorized_destination(entry, payload):
    nonce = uuid.uuid4().hex[:12]
    name = 'cloudlab-service-denial-' + nonce
    namespace = 'argocd'
    obj = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
           'metadata': {'name': name, 'namespace': namespace, 'labels': {'cloudlab.io/fixture': nonce}},
           'spec': {'project': entry['approval']['name'], 'source': {
               'repoURL': payload['repository'], 'targetRevision': payload['revision'], 'path': 'charts/service'},
               'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}}}
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
        checked += 1
    return {'services_checked': checked, 'owner_convergence': True, 'unauthorized_destinations_denied': True,
            'data_removal': False}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Service behavior check failed; private inputs and retained data preserved') from None
