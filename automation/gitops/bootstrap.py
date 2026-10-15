"""Bounded Argo seed, then a one-way handoff to the public GitOps root."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
try:
    from automation.gitops.source_revision import matches_revision
    from automation.gitops.sync_recovery import recovered_secret_sync
except ModuleNotFoundError:
    from source_revision import matches_revision
    from sync_recovery import recovered_secret_sync

BASE = Path('/var/lib/cloudlab/gitops')
MANAGER = 'cloudlab-bootstrap'


def kube(*args, document=None):
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', *args],
        input=json.dumps(document) if document is not None else None,
        capture_output=True, text=True, timeout=660 if args[0] == 'rollout' else 180)
    if result.returncode:
        raise RuntimeError('GitOps Kubernetes operation failed; private output withheld')
    return result.stdout


def get(kind, name):
    text = kube('get', kind, name, '-n', 'argocd', '--ignore-not-found', '-o', 'json')
    return json.loads(text) if text.strip() else None


def apply(objects):
    if objects:
        kube('apply', '--server-side', '--field-manager=' + MANAGER, '-f', '-',
             document={'apiVersion': 'v1', 'kind': 'List', 'items': objects})


def atomic(state):
    temporary = BASE / 'checkpoint.tmp'
    with temporary.open('w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(BASE / 'checkpoint.json')
    descriptor = os.open(BASE, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def identity(objects):
    result = {}
    for obj in objects:
        if obj['metadata'].get('annotations', {}).get('helm.sh/hook'):
            continue  # The upstream Redis initializer is an idempotent ephemeral job.
        group = obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
        resource = obj['kind'].lower() + ('.' + group if group else '')
        current = get(resource, obj['metadata']['name'])
        if not current:
            raise RuntimeError('Declared Argo resource disappeared during handoff')
        result[resource + '/' + obj['metadata']['name']] = current['metadata']['uid']
    for name in ('argocd-secret', 'argocd-redis'):
        current = get('secret', name)
        if not current:
            raise RuntimeError('Argo generated credential is missing')
        result['secret/' + name] = current['metadata']['uid']
    return result


def wait_application(name, revision, timeout=600):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app = get('application.argoproj.io', name)
        status = (app or {}).get('status', {})
        if any(c['type'] == 'InvalidSpecError' for c in status.get('conditions', [])):
            raise RuntimeError('Public GitOps application violates its declared project')
        patches = recovered_secret_sync(app or {}, revision,
                                       lambda name, namespace: get('externalsecret.external-secrets.io', name))
        if patches:
            kube('patch', 'application.argoproj.io', name, '-n', 'argocd', '--type=json',
                 '-p', json.dumps(patches))
        if (status.get('sync', {}).get('status') == 'Synced' and
                matches_revision(app, revision) and
                status.get('health', {}).get('status') == 'Healthy' and
                status.get('operationState', {}).get('phase') == 'Succeeded'):
            return revision
        time.sleep(5)
    raise RuntimeError('Public GitOps convergence timed out; retained checkpoint and resources')


def identity_project_rules(project):
    spec = project.get('spec', {})
    baseline = [{'group': 'argoproj.io', 'kind': kind} for kind in ('Application', 'AppProject')]
    desired = baseline + [{'group': 'external-secrets.io', 'kind': 'ExternalSecret'}]
    if (spec.get('destinations') != [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}]
            or spec.get('clusterResourceWhitelist') != [{'group': '', 'kind': 'Namespace'}]
            or spec.get('namespaceResourceWhitelist') not in (baseline, desired)
            or spec.get('namespaceResourceBlacklist')):
        raise RuntimeError('Identity source grant requires the exact bounded root project')
    return desired


def grant_identity_source(project):
    desired = identity_project_rules(project)
    if project['spec']['namespaceResourceWhitelist'] == desired:
        return False
    metadata = project['metadata']
    kube('patch', 'appproject.argoproj.io', 'cloudlab-root', '-n', 'argocd', '--type=json',
         '-p', json.dumps([
             {'op': 'test', 'path': '/metadata/uid', 'value': metadata['uid']},
             {'op': 'test', 'path': '/metadata/resourceVersion', 'value': metadata['resourceVersion']},
             {'op': 'add', 'path': '/spec/namespaceResourceWhitelist', 'value': desired}]))
    return True


def resume_identity_binding():
    """Repair an interrupted bounded root handoff without contacting the IdP."""
    path = BASE / 'identity-values-binding.json'
    if not path.exists():
        return False
    state = json.loads(path.read_text())
    if state.get('phase') == 'accepted':
        return False
    if state.get('phase') not in ('prepared', 'paused', 'source-updated', 'resumed'):
        raise RuntimeError('Unknown identity root handoff checkpoint')
    objects = {key: get(kind, name) for key, kind, name in (
        ('root_uid', 'application.argoproj.io', 'cloudlab-public-root'),
        ('controller_uid', 'statefulset', 'argocd-application-controller'),
        ('project_uid', 'appproject.argoproj.io', 'cloudlab-root'))}
    if any(not obj or obj['metadata']['uid'] != state[key] for key, obj in objects.items()):
        raise RuntimeError('Interrupted identity root handoff resource identity changed')
    controller = objects['controller_uid']
    if controller['spec']['replicas'] not in (0, 1):
        raise RuntimeError('Interrupted identity root handoff has an unexpected topology')
    if state['phase'] in ('source-updated', 'resumed'):
        root, project = objects['root_uid'], objects['project_uid']
        source = root['spec']['source']
        if (source.get('helm', {}).get('valuesObject', {}).get('identity', {}).get('argo') != state.get('target')
                or not state.get('target') or project['spec'].get('sourceRepos') != [source['repoURL']]):
            raise RuntimeError('Interrupted identity root handoff source changed')
        if project['spec'].get('namespaceResourceWhitelist') != identity_project_rules(project):
            try:
                try:
                    from .source_transition import pause
                except ImportError:
                    from source_transition import pause
                pause()
                latest = get('appproject.argoproj.io', 'cloudlab-root')
                current = get('application.argoproj.io', 'cloudlab-public-root')
                if (not latest or latest['metadata']['uid'] != state['project_uid'] or latest['spec'] != project['spec']
                        or not current or current['metadata']['uid'] != state['root_uid']
                        or current['spec']['source'] != source):
                    raise RuntimeError('Identity source grant changed during controller handoff')
                grant_identity_source(latest)
            finally:
                kube('scale', 'statefulset/argocd-application-controller', '-n', 'argocd', '--replicas=1')
            return True
    if controller['spec']['replicas'] == 0:
        kube('scale', 'statefulset/argocd-application-controller', '-n', 'argocd', '--replicas=1')
        return True
    return False


def require_controller_oom_pod(current, pod):
    if (pod.get('metadata', {}).get('name') != 'argocd-application-controller-0' or
            pod.get('metadata', {}).get('namespace') != 'argocd' or
            not any(o.get('kind') == 'StatefulSet' and o.get('controller') is True and
                    o.get('uid') == current['metadata']['uid'] for o in pod.get('metadata', {}).get('ownerReferences', [])) or
            any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod.get('status', {}).get('conditions', [])) or
            not any(c.get('name') == 'application-controller' and
                    c.get('lastState', {}).get('terminated', {}).get('reason') == 'OOMKilled'
                    for c in pod.get('status', {}).get('containerStatuses', []))):
        raise RuntimeError('Controller recovery requires an unready retained pod after OOMKilled')


def controller_memory_patch(state, current, pod, desired):
    name = 'argocd-application-controller'
    if (state.get('phase') != 'accepted' or current['metadata']['name'] != name or
            current['metadata'].get('namespace') != 'argocd' or
            state.get('identities', {}).get('statefulset.apps/' + name) != current['metadata']['uid'] or
            current['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
            'cloudlab-argocd:apps/StatefulSet:argocd/' + name):
        raise RuntimeError('Controller recovery requires its accepted owner and retained UID')
    actual = current['spec']['template']['spec']['containers']
    target = desired['spec']['template']['spec']['containers']
    if (len(actual) != 1 or len(target) != 1 or actual[0]['name'] != 'application-controller' or
            target[0]['name'] != actual[0]['name'] or actual[0]['image'] != target[0]['image'] or
            current['spec'].get('replicas') != 1 or desired['spec'].get('replicas') != 1):
        raise RuntimeError('Controller recovery cannot change topology or image')
    requested = target[0]['resources']['requests']['memory']
    limit = target[0]['resources']['limits']['memory']
    memory_env = [e for e in target[0].get('env', []) if e['name'] == 'GOMEMLIMIT']
    if (requested, limit, memory_env) != ('512Mi', '2Gi', [{'name': 'GOMEMLIMIT', 'value': '1600MiB'}]):
        raise RuntimeError('Controller recovery requires the reviewed bounded memory settings')
    existing_env = actual[0].get('env', [])
    indices = [i for i, e in enumerate(existing_env) if e['name'] == 'GOMEMLIMIT']
    if len(indices) > 1:
        raise RuntimeError('Controller memory environment is ambiguous')
    desired_env = memory_env[0]
    if (actual[0]['resources']['requests']['memory'] == requested and
            actual[0]['resources']['limits']['memory'] == limit and indices and
            existing_env[indices[0]] == desired_env):
        return []
    require_controller_oom_pod(current, pod)
    base = '/spec/template/spec/containers/0'
    changes = [{'op': 'test', 'path': '/metadata/' + key, 'value': current['metadata'][key]}
               for key in ('uid', 'resourceVersion')]
    changes += [{'op': 'replace', 'path': base + '/resources/requests/memory', 'value': requested},
                {'op': 'replace', 'path': base + '/resources/limits/memory', 'value': limit}]
    if indices:
        changes.append({'op': 'replace', 'path': base + '/env/' + str(indices[0]), 'value': desired_env})
    elif 'env' in actual[0]:
        changes.append({'op': 'add', 'path': base + '/env/-', 'value': desired_env})
    else:
        changes.append({'op': 'add', 'path': base + '/env', 'value': [desired_env]})
    return changes


def controller_pod_replacement(state, current, pod, desired):
    if controller_memory_patch(state, current, pod, desired):
        raise RuntimeError('Controller template changed before failed-pod replacement')
    if not pod or any(c.get('type') == 'Ready' and c.get('status') == 'True'
                      for c in pod.get('status', {}).get('conditions', [])):
        return None
    actual = pod['spec']['containers'][0]
    target = desired['spec']['template']['spec']['containers'][0]
    if actual['name'] != target['name'] or actual['image'] != target['image']:
        raise RuntimeError('Controller recovery cannot replace another container image')
    if (all(actual['resources'][key]['memory'] == target['resources'][key]['memory']
            for key in ('requests', 'limits')) and
            [e for e in actual.get('env', []) if e['name'] == 'GOMEMLIMIT'] ==
            [e for e in target.get('env', []) if e['name'] == 'GOMEMLIMIT']):
        return None
    require_controller_oom_pod(current, pod)
    return {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {
        key: pod['metadata'][key] for key in ('uid', 'resourceVersion')}}


def recover_controller(payload):
    if BASE.resolve() != BASE.absolute():
        raise RuntimeError('Unexpected GitOps checkpoint symlink')
    with (BASE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads((BASE / 'checkpoint.json').read_text())
        desired = next(o for o in payload['operator'] if o['kind'] == 'StatefulSet' and
                       o['metadata']['name'] == 'argocd-application-controller')
        current = get('statefulset', desired['metadata']['name'])
        pod = get('pod', desired['metadata']['name'] + '-0') or {}
        app = get('application.argoproj.io', 'cloudlab-argocd') or {}
        spec = app.get('spec', {})
        source = spec.get('source') or (spec.get('sources') or [{}])[0]
        if (spec.get('project') != 'cloudlab-platform' or source.get('repoURL') != payload['repository'] or
                source.get('path') != 'platform/delivery/argocd' or source.get('targetRevision') != payload['branch'] or
                state.get('version') != payload['version']):
            raise RuntimeError('Controller recovery cannot change its accepted version or source')
        changes = controller_memory_patch(state, current, pod, desired)
        retained = identity([desired])
        if any(state.get('identities', {}).get(key) != value for key, value in retained.items()):
            raise RuntimeError('Controller recovery requires retained controller and credential identities')
        if changes:
            # Force a fresh Git comparison when the unavailable controller resumes.
            kube('annotate', 'application.argoproj.io', 'cloudlab-argocd', '-n', 'argocd',
                 'argocd.argoproj.io/refresh=hard', '--overwrite')
            kube('patch', 'statefulset', desired['metadata']['name'], '-n', 'argocd', '--type=json',
                 '-p', json.dumps(changes))
        replacement = controller_pod_replacement(state, get('statefulset', desired['metadata']['name']),
                                                get('pod', desired['metadata']['name'] + '-0') or {}, desired)
        if replacement:
            # OrderedReady cannot roll forward while the previous ordinal is unhealthy.
            kube('delete', '--raw=/api/v1/namespaces/argocd/pods/argocd-application-controller-0',
                 '-f', '-', document=replacement)
        kube('rollout', 'status', 'statefulset/' + desired['metadata']['name'], '-n', 'argocd', '--timeout=600s')
        wait_application('cloudlab-argocd', payload['revision'])
        if identity([desired]) != retained:
            raise RuntimeError('Controller recovery changed a retained identity')
        result = subprocess.run(['python3', str(Path(__file__).with_name('controller_stability.py')), 'argocd'],
                                capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise RuntimeError('Argo controllers are not stable after memory recovery')
        return {'changed': bool(changes or replacement), 'pod_replaced': bool(replacement),
                'owner': 'argocd', 'operator_synced': True,
                'identities_preserved': True, 'controller_stability': json.loads(result.stdout)}


def run(payload):
    os.umask(0o077)
    if BASE.resolve() != BASE.absolute():
        raise RuntimeError('Unexpected GitOps checkpoint symlink')
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    BASE.chmod(0o700)
    with (BASE / 'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = BASE / 'checkpoint.json'
        operator, roots = payload['operator'], payload['roots']
        crds = [x for x in operator if x['kind'] == 'CustomResourceDefinition']
        if not path.exists():
            if get('namespace', 'argocd') or any(get('crd', x['metadata']['name']) for x in crds):
                raise RuntimeError('Unowned Argo installation exists; automatic adoption refused')
            atomic({'phase': 'seeding', 'version': payload['version']})
        state = json.loads(path.read_text())
        repair_changed = resume_identity_binding() if state.get('phase') == 'accepted' else False
        if state.get('phase') not in ('seeding', 'seeded', 'argo-requested', 'accepted'):
            raise RuntimeError('Unknown GitOps checkpoint phase')
        if payload.get('stop_after_seed') and state['phase'] == 'accepted' and not state.get('interruption_test_completed'):
            raise RuntimeError('Initial interruption proof cannot be injected after adoption')
        if state['phase'] == 'seeding':
            if state['version'] != payload['version']:
                raise RuntimeError('Finish the checkpointed bootstrap before changing versions')
            apply([{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'argocd'}}])
            apply(crds)
            for obj in crds:
                kube('wait', '--for=condition=Established', '--timeout=120s', 'crd/' + obj['metadata']['name'])
            # Close the default project before the API server starts.
            apply([x for x in roots if x['kind'] == 'AppProject' and x['metadata']['name'] in ('default', 'cloudlab-root')])
            apply([x for x in operator if x['kind'] != 'CustomResourceDefinition'])
            kube('wait', '-n', 'argocd', '--for=condition=complete', '--timeout=180s', 'job/argocd-redis-secret-init')
            kube('rollout', 'status', 'deployment', '-n', 'argocd', '--timeout=600s')
            kube('rollout', 'status', 'statefulset/argocd-application-controller', '-n', 'argocd', '--timeout=600s')
            state.update(phase='seeded', identities=identity(operator))
            atomic(state)
        if state['phase'] == 'seeded':
            if payload.get('stop_after_seed') and not state.get('interruption_test_completed'):
                state['interruption_test_completed'] = True
                atomic(state)
                print(json.dumps({'changed': True, 'owner': 'cloudlab-bootstrap',
                                  'bootstrap_phase': 'seeded', 'interrupted_fixture': True}))
                return
            # After this boundary bootstrap never reapplies operator resources.
            if not get('application.argoproj.io', 'cloudlab-public-root'):
                apply([x for x in roots if x['kind'] == 'Application' and x['metadata']['name'] == 'cloudlab-public-root'])
            state['phase'] = 'argo-requested'
            atomic(state)
        root_revision = wait_application('cloudlab-public-root', payload['revision'])
        operator_revision = wait_application('cloudlab-argocd', payload['revision'])
        if state['phase'] == 'argo-requested':
            if identity(operator) != state['identities']:
                raise RuntimeError('Argo handoff replaced a declared object or generated credential')
            state.update(phase='accepted', root_revision=root_revision, operator_revision=operator_revision)
            atomic(state)
            changed = True
        elif state['phase'] == 'accepted':
            changed = repair_changed
        else:
            raise RuntimeError('Unknown GitOps checkpoint phase')
        print(json.dumps({'changed': changed, 'owner': 'argocd', 'public_root_synced': True,
                          'operator_synced': True, 'bootstrap_phase': state['phase']}))


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--recover-controller']:
            print(json.dumps(recover_controller(json.load(sys.stdin)), sort_keys=True))
        else:
            run(json.load(sys.stdin))
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'GitOps bootstrap failed; checkpoint retained') from None
