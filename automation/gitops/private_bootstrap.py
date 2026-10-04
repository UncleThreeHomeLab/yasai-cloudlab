"""Admin-owned private roots; omission never deletes an existing source."""
import fcntl
import json
import os
import sys

from bootstrap import BASE, kube
from private_sources import LABEL, OWNER, resources
from source_transition import record


def current(obj):
    group = obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
    kind = obj['kind'].lower() + ('.' + group if group else '')
    metadata = obj['metadata']
    args = ['get', kind, metadata['name'], '--ignore-not-found', '-o', 'json']
    if metadata.get('namespace'):
        args += ['-n', metadata['namespace']]
    value = kube(*args)
    return json.loads(value) if value.strip() else None


def contains(actual, desired):
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(key in actual and contains(actual[key], value)
                                               for key, value in desired.items())
    return actual == desired


def run(payload):
    os.umask(0o077)
    entries = payload['sources']
    if not entries:
        return {'changed': False, 'private_sources_configured': 0, 'existing_sources_retained': True}
    if json.loads((BASE / 'checkpoint.json').read_text()).get('phase') != 'accepted':
        raise RuntimeError('Private roots require accepted public Argo ownership')
    with (BASE / 'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        changed = False
        for entry in entries:
            objects = resources(entry, payload['store'])
            existing = [current(obj) for obj in objects]
            if any(obj and (obj['metadata'].get('labels', {}).get(LABEL) != OWNER or
                            obj['metadata'].get('finalizers') and obj['kind'] == 'Application') for obj in existing):
                raise RuntimeError('Private source conflicts with an existing owner or cascading deletion policy')
            for obj, before in zip(objects, existing):
                if before and contains(before, obj):
                    continue
                kube('apply', '--server-side', '--field-manager=cloudlab-private-bootstrap', '-f', '-', document=obj)
                after = current(obj)
                if not after or (before and before['metadata']['uid'] != after['metadata']['uid']):
                    raise RuntimeError('Private root resource identity changed unexpectedly')
                changed = True
            checkpoint = BASE / ('private-' + entry['name'] + '.json')
            previous = json.loads(checkpoint.read_text()) if checkpoint.exists() else {}
            identities = {obj['kind']: current(obj)['metadata']['uid'] for obj in objects}
            if previous.get('identities') != identities or previous.get('phase') == 'removed':
                record(checkpoint, {'phase': 'configured', 'owner': 'cloudlab-private-bootstrap',
                                    'identities': identities})
        return {'changed': changed, 'private_sources_configured': len(entries), 'existing_sources_retained': True}


def remove(payload):
    os.umask(0o077)
    selector = payload.get('remove')
    if not selector or any(entry['name'] == selector for entry in payload['sources']):
        raise RuntimeError('Removal requires an explicit selector absent from configured private sources')
    path = BASE / ('private-' + selector + '.json')
    with (BASE / 'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not path.exists():
            raise RuntimeError('Private source has no ownership checkpoint; removal refused')
        state = json.loads(path.read_text())
        if state['phase'] == 'removed':
            return {'changed': False, 'private_source_removed': True, 'workloads_retained': True}
        name = 'cloudlab-private-' + selector
        targets = [('Application', 'argoproj.io/v1alpha1'), ('ExternalSecret', 'external-secrets.io/v1'),
                   ('Secret', 'v1'), ('AppProject', 'argoproj.io/v1alpha1')]
        existing = []
        for kind, version in targets:
            obj = current({'apiVersion': version, 'kind': kind, 'metadata': {'name': name, 'namespace': 'argocd'}})
            if obj and (obj['metadata'].get('labels', {}).get(LABEL) != OWNER or
                        (kind == 'Application' and obj['metadata'].get('finalizers')) or
                        (kind in state['identities'] and obj['metadata']['uid'] != state['identities'][kind])):
                raise RuntimeError('Private source removal ownership mismatch')
            existing.append((kind, version, obj))
        for kind, version, obj in existing:
            if obj:
                group = '.' + version.split('/')[0] if '/' in version else ''
                kube('delete', kind.lower() + group, name, '-n', 'argocd', '--ignore-not-found',
                     '--wait=true', '--timeout=60s')
        state['phase'] = 'removed'
        record(path, state)
        return {'changed': True, 'private_source_removed': True, 'workloads_retained': True}


if __name__ == '__main__':
    try:
        action = remove if sys.argv[1:] == ['remove'] else run
        print(json.dumps(action(json.load(sys.stdin))))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Private bootstrap failed; inputs and diagnostics withheld') from None
