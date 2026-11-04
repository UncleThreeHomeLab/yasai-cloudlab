"""Checkpointed source recovery for an already adopted public Argo root."""
import fcntl
import json
import os
import re
import sys
import time

try:
    from .bootstrap import BASE, get, kube, wait_application, resume_identity_binding, identity_project_rules, grant_identity_source
    from .data_activation import validate as validate_data, guard as data_guard, exclusion as data_exclusion
    from .source_revision import matches_revision
    from .service_activation import validate as validate_activation, guard as activation_guard
    from .access_activation import validate as validate_access, guard as access_guard
    from .private_activation import validate as validate_private, guard as private_guard, server_probe as private_server_probe
except ImportError:
    from bootstrap import BASE, get, kube, wait_application, resume_identity_binding, identity_project_rules, grant_identity_source
    from data_activation import validate as validate_data, guard as data_guard, exclusion as data_exclusion
    from source_revision import matches_revision
    from service_activation import validate as validate_activation, guard as activation_guard
    from access_activation import validate as validate_access, guard as access_guard
    from private_activation import validate as validate_private, guard as private_guard, server_probe as private_server_probe

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
        os.fchmod(stream.fileno(), 0o600)
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


def binding_source(state, root):
    """Classify an observed source, including a PATCH that committed before failing."""
    if not root or root.get('metadata', {}).get('uid') != state['root_uid'] or root['metadata'].get('deletionTimestamp'):
        raise RuntimeError('Identity handoff root identity changed; controller remains paused')
    source = root.get('spec', {}).get('source')
    if not isinstance(source, dict) or not source.get('repoURL'):
        raise RuntimeError('Identity handoff source unavailable; controller remains paused')
    if source == state.get('originalSource'):
        return 'original'
    if source == state.get('patchedSource'):
        return 'patched'
    # Legacy checkpoints recorded only the intended private binding.
    binding = source.get('helm', {}).get('valuesObject', {}).get('identity', {}).get('argo')
    if 'patchedSource' not in state and state.get('target') and binding == state['target']:
        return 'patched'
    if ('originalSource' not in state and not binding and state.get('phase') in ('prepared', 'paused')):
        return 'original'
    raise RuntimeError('Identity handoff source is ambiguous; controller remains paused')


def check_activation(state, root, read, *, data_held=False):
    evidence = state.get('serviceActivation')
    if evidence is None:
        raise RuntimeError('Pending service activation inputs unavailable; retry identity binding at its recorded private revision')
    state['serviceActivation'] = activation_guard(evidence, state['target'], read, root)
    evidence = state.get('privateActivation')
    if evidence is None:
        raise RuntimeError('Pending private activation inputs unavailable; retry identity binding at its recorded private revision')
    state['privateActivation'] = private_guard(evidence, state['target'], read, root, probe=private_server_probe)
    state['accessActivation'] = access_guard(state.get('accessActivation'), state['target'], read, root)
    state['dataActivation'] = data_guard(state.get('dataActivation'), state['target'], read, root,
        patched=binding_source(state, root) == 'patched', held=data_held)


def safe_identity_resume(state, read, *, data_held=False):
    objects = {key: read(kind, name) for key, kind, name in (
        ('root_uid', 'application.argoproj.io', ROOT_APP), ('controller_uid', 'statefulset', CONTROLLER),
        ('project_uid', 'appproject.argoproj.io', 'cloudlab-root'))}
    if any(not obj or obj.get('metadata', {}).get('uid') != state[key] or
           obj['metadata'].get('deletionTimestamp') for key, obj in objects.items()):
        raise RuntimeError('Identity handoff resource identity changed; controller remains paused')
    root = objects['root_uid']
    project = objects['project_uid']
    spec = root.get('spec', {})
    if (objects['controller_uid'].get('spec', {}).get('replicas') not in (0, 1)
            or spec.get('project') != 'cloudlab-root' or spec.get('sources')
            or spec.get('source', {}).get('path') != 'gitops/roots/public'
            or spec.get('syncPolicy', {}).get('automated', {}).get('prune', False)
            or root['metadata'].get('finalizers')):
        raise RuntimeError('Identity handoff ownership boundary changed; controller remains paused')
    identity_project_rules(project)
    if project['spec'].get('sourceRepos') != [root.get('spec', {}).get('source', {}).get('repoURL')]:
        raise RuntimeError('Identity handoff project source changed; controller remains paused')
    if binding_source(state, root) == 'patched':
        check_activation(state, root, read, data_held=data_held)
    return True


def accept_binding(path, checkpoint):
    accepted = {key: checkpoint[key] for key in ('target', 'root_uid', 'controller_uid', 'project_uid')}
    accepted['phase'] = 'accepted'
    record(path, accepted)


def hydrate_binding(path, checkpoint, payload, target, *, data_held=False):
    """An explicit retry may supply missing legacy evidence, never retarget it."""
    if checkpoint['target'] != target:
        raise RuntimeError('Complete the pending native identity binding at its recorded private revision')
    for key, kind, name in (('root_uid', 'application.argoproj.io', ROOT_APP),
                           ('controller_uid', 'statefulset', CONTROLLER),
                           ('project_uid', 'appproject.argoproj.io', 'cloudlab-root')):
        obj = get(kind, name)
        if not obj or obj['metadata'].get('uid') != checkpoint[key] or obj['metadata'].get('deletionTimestamp'):
            raise RuntimeError('Pending identity handoff resource identity changed')
    current_root = get('application.argoproj.io', ROOT_APP)
    if 'dataActivation' not in checkpoint and binding_source(checkpoint, current_root) == 'patched':
        raise RuntimeError('Patched data binding lost its durable pre-effect evidence')
    supplied_data = validate_data(payload.get('argo', {}).get('dataActivation'), target)
    supplied_data.pop('authority', None)
    if 'dataActivation' in checkpoint:
        recorded_data = validate_data(checkpoint['dataActivation'], target)
        recorded_authority = recorded_data.pop('authority', None)
        if supplied_data != recorded_data:
            raise RuntimeError('Data activation retry cannot change its immutable projection')
        if recorded_authority is not None:
            supplied_data['authority'] = recorded_authority
    current_data = data_guard(supplied_data, target, get, current_root,
        patched=binding_source(checkpoint, current_root) == 'patched', held=data_held)
    changed = False
    if 'dataActivation' not in checkpoint:
        checkpoint['dataActivation'] = current_data
        changed = True
    elif validate_data(checkpoint['dataActivation'], target) != current_data:
        raise RuntimeError('Data activation retry cannot replace its captured authority')
    for key, validator in (('serviceActivation', validate_activation), ('privateActivation', validate_private)):
        if key not in checkpoint:
            checkpoint[key] = validator(payload.get('argo', {}).get(key), target)
            changed = True
    current_access = access_guard(payload.get('argo', {}).get('accessActivation'), target, get, get('application.argoproj.io', ROOT_APP))
    if 'accessActivation' not in checkpoint:
        checkpoint['accessActivation'] = current_access
        changed = True
    elif validate_access(checkpoint['accessActivation'], target) != current_access:
        raise RuntimeError('Access activation retry cannot replace its captured authority')
    current = validate_private(payload.get('argo', {}).get('privateActivation'), target)
    previous = checkpoint['privateActivation']
    if any(current[key] != previous[key] for key in
           ('required', 'repository', 'revision', 'private_repository', 'private_revision', 'registry')):
        raise RuntimeError('Private activation retry cannot change its recorded registry or sources')
    if current['policies'] != previous['policies']:
        previous['policies'] = current['policies']
        changed = True
    if changed:
        record(path, checkpoint)


def pending_identity_checkpoint(target):
    """Authorize an exact recovery target from the durable pending handoff only."""
    path = BASE / 'identity-values-binding.json'
    state = json.loads(path.read_text()) if path.exists() else {}
    if (state.get('phase') not in ('prepared', 'paused', 'source-updated', 'resumed')
            or state.get('target') != target):
        raise RuntimeError('Identity recovery requires its exact pending private binding')
    for key, kind, name in (('root_uid', 'application.argoproj.io', ROOT_APP),
                           ('controller_uid', 'statefulset', CONTROLLER),
                           ('project_uid', 'appproject.argoproj.io', 'cloudlab-root')):
        obj = get(kind, name)
        if not obj or obj.get('metadata', {}).get('uid') != state.get(key) or obj['metadata'].get('deletionTimestamp'):
            raise RuntimeError('Pending identity recovery resource identity changed')
    return state


def pending_identity_target(target):
    return pending_identity_checkpoint(target)['target']['valuesRevision']


def bind_identity(payload, target):
    """Bind prevalidated immutable OIDC values while the sole reconciler is stopped."""
    import copy
    if (set(target) != {'valuesRepository', 'valuesRevision'} or
            target['valuesRepository'] != payload['private_repository'] or
            not re.fullmatch('[a-f0-9]{40}', target['valuesRevision'])):
        raise ValueError('Identity binding requires its designated immutable private source')
    state = json.loads((BASE / 'checkpoint.json').read_text())
    if state.get('phase') != 'accepted':
        raise RuntimeError('Native identity binding requires accepted independent GitOps ownership')
    with (BASE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with data_exclusion():
            return bind_identity_locked(payload, target)


def bind_identity_locked(payload, target):
    import copy
    path = BASE / 'identity-values-binding.json'
    checkpoint = json.loads(path.read_text()) if path.exists() else None
    access_evidence = access_guard(payload.get('argo', {}).get('accessActivation'), target, get, get('application.argoproj.io', ROOT_APP))
    if checkpoint and checkpoint.get('phase') != 'accepted':
        hydrate_binding(path, checkpoint, payload, target, data_held=True)
    resume_identity_binding(data_held=True)
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
    checkpoint = json.loads(path.read_text()) if path.exists() else None
    identities = {'root_uid': root['metadata']['uid'], 'controller_uid': controller['metadata']['uid'],
                  'project_uid': project['metadata']['uid']}
    if checkpoint and any(checkpoint[key] != value for key, value in identities.items()):
        raise RuntimeError('Native identity binding resource identity changed')
    access_evidence = access_guard(access_evidence, target, get, root)
    data_evidence = data_guard(payload.get('argo', {}).get('dataActivation'), target, get, root, held=True)
    if values.get('identity', {}).get('argo') == target and checkpoint and checkpoint['phase'] in ('source-updated', 'resumed', 'accepted'):
        wait_application(ROOT_APP, payload['revision'])
        wait_application('cloudlab-argocd', payload['revision'])
        changed = checkpoint['phase'] != 'accepted'
        accept_binding(path, checkpoint)
        return {'changed': changed, 'native_argo_values_bound': True}
    evidence = validate_activation(payload.get('argo', {}).get('serviceActivation'), target, root)
    private_evidence = validate_private(payload.get('argo', {}).get('privateActivation'), target, root)
    original = copy.deepcopy(root['spec']['source'])
    values.setdefault('identity', {}).update(enabled=True, argo=target)
    patched = copy.deepcopy(original)
    patched.setdefault('helm', {})['valuesObject'] = values
    checkpoint = dict(identities, target=target, phase='prepared', originalSource=original,
                      patchedSource=patched, serviceActivation=evidence, privateActivation=private_evidence, accessActivation=access_evidence, dataActivation=data_evidence)
    record(path, checkpoint)
    try:
        pause()
        checkpoint['phase'] = 'paused'
        record(path, checkpoint)
        latest = get('application.argoproj.io', ROOT_APP)
        if (not latest or latest['metadata']['uid'] != root['metadata']['uid'] or
                latest['spec']['source'] != original):
            raise RuntimeError('Public root source changed during native identity handoff')
        check_activation(checkpoint, latest, get, data_held=True)
        record(path, checkpoint)
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
        grant_identity_source(latest_project)
    finally:
        if safe_identity_resume(checkpoint, get, data_held=True):
            kube('scale', 'statefulset/' + CONTROLLER, '-n', 'argocd', '--replicas=1')
    checkpoint['phase'] = 'resumed'
    record(path, checkpoint)
    kube('rollout', 'status', 'statefulset/' + CONTROLLER, '-n', 'argocd', '--timeout=300s')
    wait_application(ROOT_APP, payload['revision'])
    wait_application('cloudlab-argocd', payload['revision'])
    accept_binding(path, checkpoint)
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
