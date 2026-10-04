"""Bounded ESO seed and durable release of the operator/store writer."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

BASE = Path('/var/lib/cloudlab/external-secrets')
CHECKPOINT = 'ownership.json'


def kube(*args, objects=None):
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', *args],
        input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}) if objects is not None else None,
        capture_output=True, text=True, timeout=360)
    if result.returncode:
        raise RuntimeError('ESO bootstrap Kubernetes operation failed; checkpoint retained, diagnostics withheld')
    return result.stdout


def key(obj):
    metadata = obj['metadata']
    group = '.' + obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
    return obj['kind'].lower() + group, metadata['name'], metadata.get('namespace')


def get(obj):
    kind, name, namespace = key(obj)
    if kind == 'application.argoproj.io' and not kube('get', 'crd', 'applications.argoproj.io',
                                                    '--ignore-not-found', '-o', 'name').strip():
        return None
    args = ['get', kind, name, '--ignore-not-found', '--show-managed-fields=true', '-o', 'json']
    if namespace:
        args += ['-n', namespace]
    raw = kube(*args)
    return json.loads(raw) if raw.strip() else None


def record(state):
    path = BASE / CHECKPOINT
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


def identities(objects):
    result = {}
    for obj in objects:
        current = get(obj)
        if current:
            result['/'.join(x or '' for x in key(obj))] = current['metadata']['uid']
    return result


def preserved(before, after):
    if any(after.get(name) != uid for name, uid in before.items()):
        raise RuntimeError('ESO transition changed an existing object identity')


def apply(objects):
    if objects:
        # The previous writer used this manager. Continue it only while seeding;
        # never force ownership away from another field manager.
        kube('apply', '--server-side', '--field-manager=cloudlab', '-f', '-', objects=objects)


def seed_operator(operator):
    apply([x for x in operator if x['kind'] == 'Namespace'])
    crds = [x for x in operator if x['kind'] == 'CustomResourceDefinition']
    apply(crds)
    for crd in crds:
        kube('wait', '--for=condition=Established', '--timeout=120s', 'crd/' + crd['metadata']['name'])
    apply([x for x in operator if x['kind'] not in ('Namespace', 'CustomResourceDefinition')])
    kube('rollout', 'status', 'deployment', '-n', 'external-secrets', '--timeout=300s')


def suspended(app):
    return (app.get('spec', {}).get('syncPolicy', {}).get('automated', {}).get('enabled') is False
            and not app.get('operation')
            and app.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'))


def run(objects, action, revision=None):
    if action not in ('seed', 'seed-stop', 'release', 'accept', 'recover', 'notify'):
        raise RuntimeError('Unknown ESO ownership action')
    stop_after_seed = action == 'seed-stop'
    if stop_after_seed:
        action = 'seed'
    os.umask(0o077)
    BASE.mkdir(parents=True, exist_ok=True, mode=0o750)
    if BASE.resolve() != BASE.absolute():
        raise RuntimeError('ESO ownership directory must not be a symlink')
    with (BASE / 'ownership.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = BASE / CHECKPOINT
        digest = hashlib.sha256(json.dumps(objects, sort_keys=True).encode()).hexdigest()
        stores = [x for x in objects if x['kind'] == 'ClusterSecretStore']
        operator = [x for x in objects if x['kind'] != 'ClusterSecretStore']
        token = {'apiVersion': 'v1', 'kind': 'Secret',
                 'metadata': {'name': 'onepassword-token', 'namespace': 'external-secrets'}}
        app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
               'metadata': {'name': 'cloudlab-external-secrets', 'namespace': 'argocd'}}
        if len(stores) != 1 or any(key(x) == key(token) for x in objects):
            raise RuntimeError('ESO payload must include one store and exclude its bootstrap token')
        if not path.exists():
            if action != 'seed' or get(app):
                raise RuntimeError('ESO seed requires no competing Argo application')
            existing = identities(objects + [token])
            # Existing installations are migrated only when every baseline object
            # and its token exist; interrupted new installs already have a receipt.
            if existing and len(existing) != len(objects) + 1:
                raise RuntimeError('Partial ESO installation has no ownership receipt')
            # A name-only Namespace declaration has no SSA field set. Its UID is
            # still captured, while every operator/store/token object must prove
            # the previous manager before adoption.
            owned = [obj for obj in objects + [token] if key(obj) != ('namespace', 'external-secrets', None)]
            if existing and any(not any(field.get('manager') == 'cloudlab'
                    for field in (get(obj) or {}).get('metadata', {}).get('managedFields', []))
                    for obj in owned):
                raise RuntimeError('Existing ESO objects lack the expected bootstrap field owner')
            record({'phase': 'seeding', 'digest': digest, 'identities': existing,
                    'owner': 'cloudlab-bootstrap', 'bootstrap_token_owner': 'ansible'})
        state = json.loads(path.read_text())
        if state.get('phase') not in ('seeding', 'seeded', 'released', 'accepted', 'recovering'):
            raise RuntimeError('Unknown ESO ownership checkpoint')
        if (state['phase'] != 'accepted' or action == 'recover') and state['digest'] != digest:
            raise RuntimeError('Finish the checkpointed ESO transition before changing chart inputs')
        changed = False
        if action == 'notify':
            credential = get(token)
            store = get(stores[0])
            if not credential or not store:
                raise RuntimeError('ESO credential notification requires its token and store')
            import base64
            revision = hashlib.sha256(base64.b64decode(credential['data']['token'], validate=True)).hexdigest()
            annotation = 'cloudlab.io/credential-revision'
            if store['metadata'].get('annotations', {}).get(annotation) != revision:
                kube('annotate', 'clustersecretstore', stores[0]['metadata']['name'],
                     annotation + '=' + revision, '--overwrite', '--field-manager=cloudlab-bootstrap-token')
                changed = True
            return {'changed': changed, 'bootstrap_token_owner': 'ansible'}
        if state['phase'] == 'recovering' and action != 'recover':
            raise RuntimeError('Resume the explicit ESO recovery before normal apply')
        if stop_after_seed and state['phase'] not in ('seeding', 'seeded'):
            raise RuntimeError('ESO interruption proof must run before the bootstrap writer is released')
        if action == 'recover':
            current_app = get(app) or {}
            if state['phase'] not in ('released', 'accepted', 'recovering') or not suspended(current_app):
                raise RuntimeError('Suspend ESO automatic sync in Git and finish any operation before recovery')
            preserved(state['identities'], identities(objects + [token]))
            state.update(phase='recovering', owner='cloudlab-bootstrap')
            record(state)
            seed_operator(operator)
            apply(stores)
            kube('wait', '--for=condition=Ready', '--timeout=180s',
                 'clustersecretstore/' + stores[0]['metadata']['name'])
            preserved(state['identities'], identities(objects + [token]))
            state.update(phase='released', owner='awaiting-argocd')
            record(state)
            changed = True
        if state['phase'] == 'seeding':
            if action != 'seed' or get(app):
                raise RuntimeError('ESO seeding cannot run with an Argo writer')
            seed_operator(operator)
            preserved(state['identities'], identities(objects + [token]))
            state.update(phase='seeded')
            record(state)
            changed = True
        if stop_after_seed and state['phase'] == 'seeded':
            if not state.get('interruption_test_completed'):
                state['interruption_test_completed'] = True
                record(state)
                changed = True
            return {'changed': changed, 'phase': 'seeded', 'owner': 'cloudlab-bootstrap',
                    'interruption_test_completed': True}
        if action == 'release' and state['phase'] == 'seeded':
            if get(app) or not get(token):
                raise RuntimeError('ESO release requires its bootstrap token and no Argo writer')
            apply(stores)
            kube('wait', '--for=condition=Ready', '--timeout=180s',
                 'clustersecretstore/' + stores[0]['metadata']['name'])
            current = identities(objects + [token])
            preserved(state['identities'], current)
            state.update(phase='released', identities=current, owner='awaiting-argocd')
            record(state)
            changed = True
        if action == 'accept':
            if state['phase'] not in ('released', 'accepted'):
                raise RuntimeError('Release the bootstrap writer before accepting Argo ownership')
            current = get(app) or {}
            status = current.get('status', {})
            if (status.get('sync', {}).get('status') != 'Synced' or not revision
                    or status.get('sync', {}).get('revision') != revision
                    or status.get('health', {}).get('status') != 'Healthy' or current.get('operation')
                    or current.get('spec', {}).get('syncPolicy', {}).get('automated', {}).get('enabled') is not True
                    or any(c['type'].endswith('Error') for c in status.get('conditions', []))):
                raise RuntimeError('ESO Argo ownership has not converged')
            preserved(state['identities'], identities(objects + [token]))
            if any(not (get(obj) or {}).get('metadata', {}).get('annotations', {}).get(
                    'argocd.argoproj.io/tracking-id', '').startswith('cloudlab-external-secrets:') for obj in objects):
                raise RuntimeError('ESO declared resources lack their Argo ownership marker')
            if state['phase'] != 'accepted':
                state.update(phase='accepted', owner='argocd', revision=status['sync']['revision'])
                record(state)
                changed = True
        return {'changed': changed, 'phase': state['phase'], 'owner': state['owner'],
                'bootstrap_token_owner': 'ansible'}


if __name__ == '__main__':
    try:
        payload = json.load(sys.stdin)
        print(json.dumps(run(payload['items'], sys.argv[1], payload.get('revision'))))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'ESO ownership operation failed; checkpoint retained, diagnostics withheld') from None
