"""Checkpointed source recovery for an already adopted public Argo root."""
import fcntl
import json
import os
import re
import sys
import time

try:
    from .bootstrap import BASE, get, kube, wait_application, resume_identity_binding, identity_project_rules, grant_identity_source
    from .source_revision import matches_revision
except ImportError:
    from bootstrap import BASE, get, kube, wait_application, resume_identity_binding, identity_project_rules, grant_identity_source
    from source_revision import matches_revision

ROOT_APP = 'cloudlab-public-root'
CONTROLLER = 'argocd-application-controller'


def accepted_identity_binding(*, repository, branch, revision, private_repository):
    """Read the accepted native handoff without repairing or mutating its owner."""
    pattern = r'https://github[.]com/([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9][A-Za-z0-9_.-]*)[.]git'
    public = re.fullmatch(pattern, repository) if isinstance(repository, str) else None
    private = re.fullmatch(pattern, private_repository) if isinstance(private_repository, str) else None
    if (not public or not private or repository.lower() == private_repository.lower() or
            public[1].lower() != private[1].lower() or
            not isinstance(branch, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_-]*', branch) or
            not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision)):
        raise ValueError('Accepted identity binding requires exact expected source coordinates')
    try:
        receipt = json.loads((BASE / 'identity-values-binding.json').read_text())
    except (OSError, ValueError):
        raise RuntimeError('Accepted native identity receipt is unavailable') from None
    if (not isinstance(receipt, dict) or set(receipt) != {'phase', 'target', 'root_uid', 'controller_uid', 'project_uid'} or
            receipt['phase'] != 'accepted' or not isinstance(receipt['target'], dict) or
            set(receipt['target']) != {'valuesRepository', 'valuesRevision'} or
            receipt['target']['valuesRepository'] != private_repository or
            any(not isinstance(receipt[key], str) or not receipt[key] for key in ('root_uid', 'controller_uid', 'project_uid')) or
            not isinstance(receipt['target']['valuesRevision'], str) or not re.fullmatch('[a-f0-9]{40}', receipt['target']['valuesRevision'])):
        raise RuntimeError('Native identity binding is not accepted')
    objects = {key: get(kind, name) for key, kind, name in (
        ('root_uid', 'application.argoproj.io', ROOT_APP), ('controller_uid', 'statefulset', CONTROLLER),
        ('project_uid', 'appproject.argoproj.io', 'cloudlab-root'))}
    if any(not obj or obj.get('metadata', {}).get('uid') != receipt[key] or
           obj.get('metadata', {}).get('deletionTimestamp') for key, obj in objects.items()):
        raise RuntimeError('Accepted native identity resource identity changed')
    root, project, controller = objects['root_uid'], objects['project_uid'], objects['controller_uid']
    if validate(root, project, controller, repository):
        raise RuntimeError('Accepted native identity uses another public source')
    if project['spec'].get('namespaceResourceWhitelist') != identity_project_rules(project):
        raise RuntimeError('Accepted root identity source grant is incomplete')
    source = root['spec']['source']
    values = source.get('helm', {}).get('valuesObject', {}).get('identity', {})
    status = root.get('status', {})
    if (root['spec'].get('sources') or source.get('targetRevision') != branch or values.get('enabled') is not True or
            values.get('argo') != receipt['target'] or status.get('sync', {}).get('status') != 'Synced' or
            not matches_revision(root, revision) or status.get('health', {}).get('status') != 'Healthy' or
            status.get('operationState', {}).get('phase') != 'Succeeded' or
            status.get('sync', {}).get('comparedTo', {}).get('source') != source or
            any(condition.get('type', '').endswith('Error') for condition in status.get('conditions', []))):
        raise RuntimeError('Accepted native identity root has not converged at the expected source')
    return dict(receipt['target'])


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
        identity_project_rules(project)
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
        if values.get('identity', {}).get('argo') == target and checkpoint and checkpoint['phase'] in ('source-updated', 'resumed', 'accepted'):
            wait_application(ROOT_APP, payload['revision'])
            wait_application('cloudlab-argocd', payload['revision'])
            changed = checkpoint['phase'] != 'accepted'
            checkpoint['phase'] = 'accepted'
            record(path, checkpoint)
            return {'changed': changed, 'native_argo_values_bound': True}
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
            latest_project = get('appproject.argoproj.io', 'cloudlab-root')
            if (not latest_project or latest_project['metadata']['uid'] != project['metadata']['uid']
                    or latest_project['spec'] != project['spec']):
                raise RuntimeError('Root project changed during identity source handoff')
            # Argo validates all resources before applying earlier permission waves.
            # Bootstrap grants only the ESO kind already declared by the new root.
            grant_identity_source(latest_project)
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
