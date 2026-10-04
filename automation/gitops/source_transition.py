"""Checkpointed source recovery for an already adopted public Argo root."""
import fcntl
import json
import os
import sys
import time

from bootstrap import BASE, get, kube, wait_application

ROOT_APP = 'cloudlab-public-root'
CONTROLLER = 'argocd-application-controller'


def record(path, state):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(BASE, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def patch(kind, name, document):
    kube('patch', kind, name, '-n', 'argocd', '--type=merge', '-p', json.dumps(document))


def pause():
    kube('scale', 'statefulset/' + CONTROLLER, '-n', 'argocd', '--replicas=0')
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        pods = json.loads(kube('get', 'pods', '-n', 'argocd', '-o', 'json'))['items']
        if not any(any(owner.get('kind') == 'StatefulSet' and owner.get('name') == CONTROLLER
                       for owner in pod['metadata'].get('ownerReferences', [])) for pod in pods):
            return
        time.sleep(2)
    raise RuntimeError('Argo controller did not stop before source migration deadline')


def validate(root, project, controller, target):
    source = root['spec']['source']
    if (root['spec']['project'] != 'cloudlab-root' or source['path'] != 'gitops/roots/public' or
            root['spec'].get('syncPolicy', {}).get('automated', {}).get('prune', False) or
            root['metadata'].get('finalizers') or
            project['spec']['sourceRepos'] != [source['repoURL']] or
            controller['spec']['replicas'] != 1):
        raise RuntimeError('Public source migration requires the known single-controller ownership boundary')
    if root.get('operation') or root.get('status', {}).get('operationState', {}).get('phase') == 'Running':
        raise RuntimeError('Wait for the current Argo root operation before source migration')
    return source['repoURL'] != target


def run(payload):
    os.umask(0o077)
    state = json.loads((BASE / 'checkpoint.json').read_text())
    if state.get('phase') != 'accepted':
        raise RuntimeError('Public source migration requires accepted Argo ownership')
    with (BASE / 'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = BASE / 'source-transition.json'
        root = get('application.argoproj.io', ROOT_APP)
        controller = get('statefulset', CONTROLLER)
        project = get('appproject.argoproj.io', 'cloudlab-root')
        if not all((root, controller, project)):
            raise RuntimeError('Public source migration resources are missing')
        if not path.exists():
            if not validate(root, project, controller, payload['repository']):
                return {'changed': False, 'source_transition': 'already-current'}
            record(path, {'phase': 'prepared', 'target': payload['repository'],
                          'previous': root['spec']['source']['repoURL'],
                          'root_uid': root['metadata']['uid'], 'controller_uid': controller['metadata']['uid'],
                          'project_uid': project['metadata']['uid'], 'replicas': controller['spec']['replicas']})
        transition = json.loads(path.read_text())
        if (transition['target'] != payload['repository'] or
                transition['root_uid'] != root['metadata']['uid'] or
                transition['controller_uid'] != controller['metadata']['uid'] or
                transition['project_uid'] != project['metadata']['uid']):
            raise RuntimeError('Public source migration checkpoint identity mismatch')
        if transition['phase'] == 'accepted':
            return {'changed': False, 'source_transition': 'accepted'}
        if transition['phase'] not in ('prepared', 'paused', 'source-updated', 'resumed'):
            raise RuntimeError('Unknown source migration checkpoint')
        try:
            pause()
            transition['phase'] = 'paused'
            record(path, transition)
            # The sole reconciler is stopped. Only root source and its source
            # allowlist change; Argo reconciles all child resources after resume.
            patch('appproject.argoproj.io', 'cloudlab-root',
                  {'spec': {'sourceRepos': [transition['previous'], transition['target']]}})
            patch('application.argoproj.io', ROOT_APP,
                  {'spec': {'source': {'repoURL': transition['target'], 'targetRevision': payload['branch']}},
                   'metadata': {'annotations': {'argocd.argoproj.io/refresh': 'hard'}}})
            transition['phase'] = 'source-updated'
            record(path, transition)
        finally:
            # Even failed migrations must restart reconciliation. A killed
            # process resumes from the durable checkpoint on its next run.
            kube('scale', 'statefulset/' + CONTROLLER, '-n', 'argocd',
                 '--replicas=' + str(transition['replicas']))
        transition['phase'] = 'resumed'
        record(path, transition)
        kube('rollout', 'status', 'statefulset/' + CONTROLLER, '-n', 'argocd', '--timeout=300s')
        wait_application(ROOT_APP, payload['revision'])
        wait_application('cloudlab-argocd', payload['revision'])
        if get('appproject.argoproj.io', 'cloudlab-root')['spec']['sourceRepos'] != [payload['repository']]:
            raise RuntimeError('Argo has not retired the former public source allowlist')
        transition['phase'] = 'accepted'
        record(path, transition)
        return {'changed': True, 'source_transition': 'accepted'}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin))))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Public source migration failed; checkpoint retained') from None
