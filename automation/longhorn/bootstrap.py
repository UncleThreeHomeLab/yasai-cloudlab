"""Serialize storage ownership transitions and preserve attached data and identities."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import handoff_fixture

BASE = Path('/var/lib/cloudlab/longhorn')
APP = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
       'metadata': {'name': 'cloudlab-longhorn', 'namespace': 'argocd'}}


class PendingConvergence(RuntimeError):
    """Only normal Argo convergence can be retried automatically."""


def kube(*args, objects=None):
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=30s', *args],
        input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}) if objects is not None else None,
        capture_output=True, text=True, timeout=660)
    if result.returncode:
        raise RuntimeError('Storage ownership operation failed; checkpoint retained, diagnostics withheld')
    return result.stdout


def key(obj):
    return (obj['kind'].lower() + ('.' + obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''),
            obj['metadata']['name'], obj['metadata'].get('namespace'))


def get(obj):
    kind, name, namespace = key(obj)
    if kind == 'application.argoproj.io' and not kube('get', 'crd', 'applications.argoproj.io',
                                                    '--ignore-not-found', '-o', 'name').strip():
        return None
    args = ['get', kind, name, '--ignore-not-found', '--show-managed-fields=true', '-o', 'json']
    raw = kube(*(args + (['-n', namespace] if namespace else [])))
    return json.loads(raw) if raw.strip() else None


def record(state):
    temporary = BASE / 'ownership.tmp'
    with temporary.open('w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(BASE / 'ownership.json')
    directory = os.open(BASE, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def identities(objects):
    return {'/'.join(x or '' for x in key(obj)): current['metadata']['uid']
            for obj in objects if (current := get(obj))}


def preserve(before, after):
    if any(after.get(name) != value for name, value in before.items()):
        raise RuntimeError('Storage transition changed an existing identity, attachment, or credential')


def contains(actual, desired):
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(k in actual and contains(actual[k], v) for k, v in desired.items())
    return actual == desired


def prior_owner(obj, current):
    managers = {f.get('manager') for f in current['metadata'].get('managedFields', [])}
    if 'cloudlab' in managers:
        return True
    return (obj['kind'] == 'Setting' and managers == {'longhorn-manager'}
            and current.get('value') == obj['value'])


def generated_valid(objects, generated):
    for obj in generated:
        current = get(obj)
        config = next(x for x in objects if x['kind'] == 'ConfigMap'
                      and x['metadata']['name'] == 'longhorn-storageclass')
        active_config = get(config)
        if (obj['kind'] != 'StorageClass' or not current or not contains(current, obj)
                or active_config.get('data') != config['data']
                or current['metadata'].get('annotations', {}).get('longhorn.io/last-applied-configmap')
                   != config['data']['storageclass.yaml']):
            raise RuntimeError('Generated storage class differs from its preserved controller configuration')


def setting_patch(current, desired):
    if (desired['kind'] != 'Setting' or desired['apiVersion'] != 'longhorn.io/v1beta2'
            or desired['metadata'].get('namespace') != 'longhorn-system'
            or set(desired) != {'apiVersion', 'kind', 'metadata', 'value'}):
        raise RuntimeError('Setting adoption exceeds its declared field scope')
    if current.get('value') == desired['value']:
        return []
    owners = {f['manager'] for f in current['metadata'].get('managedFields', [])
              if 'f:value' in f.get('fieldsV1', {})}
    if not owners or not owners <= {'longhorn-manager', 'cloudlab', 'argocd-controller', 'kubectl-client-side-apply'}:
        raise RuntimeError('Setting value has an unrecognized writer')
    return [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
            {'op': 'replace', 'path': '/value', 'value': desired['value']}]


def storage_receipt():
    result = {}
    for resource in ('persistentvolumeclaims', 'persistentvolumes', 'volumes.longhorn.io', 'secrets'):
        scope = ['-n', 'longhorn-system'] if resource in ('volumes.longhorn.io', 'secrets') else ['--all-namespaces']
        objects = json.loads(kube('get', resource, *scope, '-o', 'json'))['items']
        for obj in objects:
            meta = obj['metadata']
            if resource == 'secrets' and meta.get('namespace') != 'longhorn-system':
                continue
            name = '/'.join((resource, meta.get('namespace', ''), meta['name']))
            value = {'uid': meta['uid']}
            if resource == 'secrets':
                value['content'] = hashlib.sha256(json.dumps(obj.get('data', {}), sort_keys=True).encode()).hexdigest()
            if resource == 'volumes.longhorn.io':
                value['attached_node'] = obj['spec'].get('nodeID', '')
            result[name] = value
    return result


def seed(objects):
    for kinds in ({'Namespace'}, {'CustomResourceDefinition'}, {'ConfigMap'},
                  {x['kind'] for x in objects} - {'Namespace', 'CustomResourceDefinition', 'ConfigMap', 'Setting'}, {'Setting'}):
        group = [x for x in objects if x['kind'] in kinds]
        if kinds == {'Setting'}:
            for obj in group:
                current = get(obj)
                patch = setting_patch(current, obj) if current else []
                if patch:
                    kube('patch', 'settings.longhorn.io', obj['metadata']['name'], '-n', 'longhorn-system',
                         '--type=json', '--field-manager=cloudlab', '-p', json.dumps(patch))
        if group:
            kube('apply', '--server-side', '--field-manager=cloudlab', '-f', '-', objects=group)
        if kinds == {'CustomResourceDefinition'}:
            for obj in group:
                kube('wait', '--for=condition=Established', '--timeout=120s', 'crd/' + obj['metadata']['name'])
        elif 'Deployment' in kinds:
            kube('rollout', 'status', 'daemonset/longhorn-manager', '-n', 'longhorn-system', '--timeout=600s')
            kube('rollout', 'status', 'deployment', '-n', 'longhorn-system', '--timeout=600s')
    kube('rollout', 'status', 'daemonset/longhorn-csi-plugin', '-n', 'longhorn-system', '--timeout=300s')


def suspended(app):
    return (app.get('spec', {}).get('syncPolicy', {}).get('automated', {}).get('enabled') is False
            and not app.get('operation')
            and app.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'))


def owned(obj, current):
    metadata = (current or {}).get('metadata', {})
    if obj['kind'] == 'CustomResourceDefinition':
        return any(f.get('manager') == 'argocd-controller' and f.get('operation') == 'Apply'
                   and 'f:spec' in f.get('fieldsV1', {}) for f in metadata.get('managedFields', []))
    return metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-longhorn:')


def run(payload, action):
    if action not in ('seed', 'seed-stop', 'accept', 'recover'):
        raise RuntimeError('Unknown storage ownership action')
    objects, config = payload['items'], payload['fixture']
    generated = payload.get('generated', [])
    inventory = objects + generated
    digest = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
    os.umask(0o077)
    BASE.mkdir(parents=True, exist_ok=True, mode=0o750)
    if BASE.resolve() != BASE.absolute():
        raise RuntimeError('Storage ownership directory must not be a symlink')
    with (BASE / 'ownership.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = BASE / 'ownership.json'
        if not path.exists():
            if action not in ('seed', 'seed-stop') or get(APP):
                raise RuntimeError('Storage seed requires no competing Argo writer')
            existing = identities(inventory)
            if existing and len(existing) != len(inventory):
                raise RuntimeError('Partial storage installation has no ownership receipt')
            if existing and any(not prior_owner(obj, get(obj)) for obj in objects):
                raise RuntimeError('Existing storage objects lack the expected bootstrap owner')
            if existing:
                generated_valid(objects, generated)
                kube('apply', '--server-side', '--dry-run=server', '--field-manager=cloudlab', '-f', '-', objects=objects)
            record({'phase': 'preparing', 'owner': 'cloudlab-bootstrap', 'digest': digest,
                    'identities': existing, 'storage': storage_receipt() if existing else {},
                    'fixture': handoff_fixture.intent() if existing else None})
        state = json.loads(path.read_text())
        if state['phase'] not in ('preparing', 'seeding', 'seeded', 'released', 'accepted', 'recovering'):
            raise RuntimeError('Unknown storage ownership checkpoint')
        if (state['phase'] != 'accepted' or action == 'recover') and state['digest'] != digest:
            raise RuntimeError('Finish the recorded storage transition before changing chart inputs')
        if state['phase'] == 'recovering' and action != 'recover':
            raise RuntimeError('Resume explicit storage recovery before normal apply')
        changed = False
        if action == 'recover':
            if state['phase'] not in ('released', 'accepted', 'recovering') or not suspended(get(APP) or {}):
                raise RuntimeError('Suspend storage automatic sync in Git and finish its operation before recovery')
            if state['phase'] != 'recovering':
                fixture = (state.get('fixture') if not state.get('fixture_removed') else None)
                state.update(phase='recovering', owner='cloudlab-bootstrap', storage=storage_receipt(),
                             fixture=fixture or handoff_fixture.intent())
                state.pop('fixture_removed', None)
                record(state)
            preserve(state['identities'], identities(inventory))
            seed(objects)
            preserve(state['identities'], identities(inventory))
            generated_valid(objects, generated)
            # Recovery must be able to repair unhealthy controllers before asking
            # them to provision a new fixture. An unfinished adoption keeps its
            # original pod identity; it is never silently replaced to pass proof.
            if 'pod_uid' not in state['fixture']:
                state['fixture'] = handoff_fixture.prepare(config, state['fixture'])
                record(state)
            handoff_fixture.verify(config, state['fixture'])
            preserve(state['storage'], storage_receipt())
            state.update(phase='released', owner='awaiting-argocd')
            record(state)
            changed = True
        if state['phase'] in ('preparing', 'seeding'):
            if action not in ('seed', 'seed-stop') or get(APP):
                raise RuntimeError('Storage seeding refuses a competing writer')
            if state['phase'] == 'preparing':
                if state['fixture']:
                    state['fixture'] = handoff_fixture.prepare(config, state['fixture'])
                state['phase'] = 'seeding'
                record(state)
            seed(objects)
            preserve(state['identities'], identities(inventory))
            generated_valid(objects, generated)
            if state['fixture']:
                handoff_fixture.verify(config, state['fixture'])
            preserve(state['storage'], storage_receipt())
            state.update(phase='seeded', identities=identities(inventory))
            record(state)
            changed = True
        if action == 'seed-stop':
            if state['phase'] != 'seeded':
                raise RuntimeError('Storage interruption proof must precede writer release')
            if not state.get('interruption_test_completed'):
                state['interruption_test_completed'] = True
                record(state)
                changed = True
        elif state['phase'] == 'seeded':
            if action != 'seed' or get(APP):
                raise RuntimeError('Storage writer release refuses a competing writer')
            # A fresh installation gets the same attached fixture before adoption.
            if not state['fixture']:
                state['fixture'] = handoff_fixture.intent()
                record(state)
                state['fixture'] = handoff_fixture.prepare(config, state['fixture'])
            elif 'pod_uid' not in state['fixture']:
                state['fixture'] = handoff_fixture.prepare(config, state['fixture'])
            state.update(phase='released', owner='awaiting-argocd')
            record(state)
            changed = True
        if action == 'accept':
            if state['phase'] not in ('released', 'accepted'):
                raise RuntimeError('Release storage bootstrap before accepting Argo ownership')
            app = get(APP) or {}
            status = app.get('status', {})
            if (status.get('sync', {}).get('status') != 'Synced'
                    or status.get('sync', {}).get('revision') != payload['revision']
                    or status.get('health', {}).get('status') != 'Healthy' or app.get('operation')
                    or app.get('spec', {}).get('syncPolicy', {}).get('automated', {}).get('enabled') is not True
                    or any(c['type'].endswith('Error') for c in status.get('conditions', []))):
                raise PendingConvergence('Longhorn Argo ownership has not converged')
            preserve(state['identities'], identities(inventory))
            generated_valid(objects, generated)
            if any(not owned(obj, get(obj)) for obj in objects):
                raise RuntimeError('Storage declarations lack their Argo ownership evidence')
            if state['phase'] != 'accepted':
                preserve(state['storage'], storage_receipt())
                handoff_fixture.verify(config, state['fixture'])
                state.update(phase='accepted', owner='argocd', revision=payload['revision'])
                record(state)
                changed = True
            if not state.get('fixture_removed'):
                handoff_fixture.cleanup(state['fixture'])
                state['fixture_removed'] = True
                record(state)
                changed = True
        return {'changed': changed, 'phase': state['phase'], 'owner': state['owner']}


if __name__ == '__main__':
    try:
        with contextlib.redirect_stdout(sys.stderr):
            result = run(json.load(sys.stdin), sys.argv[1])
        print(json.dumps(result))
    except PendingConvergence as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Storage transition failed; checkpoint retained, diagnostics withheld') from None
