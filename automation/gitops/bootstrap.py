"""Bounded Argo seed, then a one-way handoff to the public GitOps root."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

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
        if (status.get('sync', {}).get('status') == 'Synced' and
                status.get('sync', {}).get('revision') == revision and
                status.get('health', {}).get('status') == 'Healthy' and
                status.get('operationState', {}).get('phase') == 'Succeeded'):
            return status['sync'].get('revision')
        time.sleep(5)
    raise RuntimeError('Public GitOps convergence timed out; retained checkpoint and resources')


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
            changed = False
        else:
            raise RuntimeError('Unknown GitOps checkpoint phase')
        print(json.dumps({'changed': changed, 'owner': 'argocd', 'public_root_synced': True,
                          'operator_synced': True, 'bootstrap_phase': state['phase']}))


if __name__ == '__main__':
    try:
        run(json.load(sys.stdin))
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'GitOps bootstrap failed; checkpoint retained') from None
