"""Repair only the accepted retained Argo controller after its recorded OOM failure."""
import fcntl
import json
from pathlib import Path
import subprocess

try:
    from .bootstrap import BASE, get, identity, kube, wait_application
except ImportError:
    from bootstrap import BASE, get, identity, kube, wait_application

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
