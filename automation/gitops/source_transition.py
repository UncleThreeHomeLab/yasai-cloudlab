"""Checkpointed source recovery for an already adopted public Argo root."""
import fcntl
import json
import os
import sys
import time

try:
    from .bootstrap import BASE, get, kube, wait_application, resume_identity_binding
except ImportError:
    from bootstrap import BASE, get, kube, wait_application, resume_identity_binding

ROOT_APP = 'cloudlab-public-root'
CONTROLLER = 'argocd-application-controller'


def record(path, state):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_DIRECTORY)
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


def bind_identity(payload, target):
    """Bind prevalidated immutable OIDC values while the sole reconciler is stopped."""
    import copy
    import re
    if (set(target) != {'valuesRepository', 'valuesRevision'} or
            target['valuesRepository'] != payload['private_repository'] or
            not re.fullmatch('[a-f0-9]{40}', target['valuesRevision'])):
        raise ValueError('Identity binding requires its designated immutable private source')
    state = json.loads((BASE / 'checkpoint.json').read_text())
    if state.get('phase') != 'accepted':
        raise RuntimeError('Native identity binding requires accepted independent GitOps ownership')
    with (BASE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        resume_identity_binding()
        root = get('application.argoproj.io', ROOT_APP)
        controller = get('statefulset', CONTROLLER)
        project = get('appproject.argoproj.io', 'cloudlab-root')
        if not all((root, controller, project)):
            raise RuntimeError('Native identity binding requires existing GitOps resources')
        if validate(root, project, controller, payload['repository']):
            raise RuntimeError('Native identity binding cannot migrate the public source')
        if root['spec']['source']['targetRevision'] != payload['branch']:
            raise RuntimeError('Native identity binding cannot change the public revision contract')
        values = copy.deepcopy(root['spec']['source'].get('helm', {}).get('valuesObject', {}))
        path = BASE / 'identity-values-binding.json'
        checkpoint = json.loads(path.read_text()) if path.exists() else None
        identities = {'root_uid': root['metadata']['uid'], 'controller_uid': controller['metadata']['uid'],
                      'project_uid': project['metadata']['uid']}
        if checkpoint and any(checkpoint[key] != value for key, value in identities.items()):
            raise RuntimeError('Native identity binding resource identity changed')
        if checkpoint and checkpoint['phase'] != 'accepted' and checkpoint['target'] != target:
            raise RuntimeError('Complete the pending native identity binding before another change')
        if values.get('identity', {}).get('argo') == target and checkpoint and checkpoint['phase'] == 'accepted':
            wait_application(ROOT_APP, payload['revision'])
            wait_application('cloudlab-argocd', payload['revision'])
            return {'changed': False, 'native_argo_values_bound': True}
        values.setdefault('identity', {}).update(enabled=True, argo=target)
        checkpoint = dict(identities, target=target, phase='prepared')
        record(path, checkpoint)
        try:
            pause()
            checkpoint['phase'] = 'paused'
            record(path, checkpoint)
            latest = get('application.argoproj.io', ROOT_APP)
            if (not latest or latest['metadata']['uid'] != root['metadata']['uid'] or
                    latest['spec']['source'] != root['spec']['source']):
                raise RuntimeError('Public root source changed during native identity handoff')
            annotations = dict(latest['metadata'].get('annotations', {}), **{'argocd.argoproj.io/refresh': 'hard'})
            kube('patch', 'application.argoproj.io', ROOT_APP, '-n', 'argocd', '--type=json', '-p', json.dumps([
                {'op': 'test', 'path': '/metadata/uid', 'value': root['metadata']['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': latest['metadata']['resourceVersion']},
                {'op': 'add', 'path': '/spec/source/helm/valuesObject', 'value': values},
                {'op': 'add', 'path': '/metadata/annotations', 'value': annotations}]))
            checkpoint['phase'] = 'source-updated'
            record(path, checkpoint)
        finally:
            kube('scale', 'statefulset/' + CONTROLLER, '-n', 'argocd', '--replicas=1')
        checkpoint['phase'] = 'resumed'
        record(path, checkpoint)
        kube('rollout', 'status', 'statefulset/' + CONTROLLER, '-n', 'argocd', '--timeout=300s')
        wait_application(ROOT_APP, payload['revision'])
        wait_application('cloudlab-argocd', payload['revision'])
        checkpoint['phase'] = 'accepted'
        record(path, checkpoint)
        return {'changed': True, 'native_argo_values_bound': True}


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
