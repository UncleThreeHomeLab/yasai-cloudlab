"""Scoped upgrade from checkpointed private registrations; retain all workloads/data.

Remove this upgrade interface once no supported installation has legacy checkpoints.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import time

BASE = Path('/var/lib/cloudlab/gitops')

KINDS = {'Namespace': ('namespace', '/api/v1/namespaces/'),
         'Application': ('application.argoproj.io', '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/'),
         'ExternalSecret': ('externalsecret.external-secrets.io', '/apis/external-secrets.io/v1/namespaces/argocd/externalsecrets/'),
         'Secret': ('secret', '/api/v1/namespaces/argocd/secrets/'),
         'AppProject': ('appproject.argoproj.io', '/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/')}
ORDER = ('Application', 'ExternalSecret', 'Secret', 'AppProject')
CHECKPOINT_KINDS = set(KINDS) - {'Secret'}
ESO_FINALIZER = 'externalsecrets.external-secrets.io/externalsecret-cleanup'


def kube(*args, **kwargs):
    from bootstrap import kube as request
    return request(*args, **kwargs)


def current(kind, name):
    text = kube('get', KINDS[kind][0], name,
                *([] if kind == 'Namespace' else ['-n', 'argocd']),
                '--ignore-not-found', '--show-managed-fields=true', '-o', 'json')
    return json.loads(text) if text.strip() else None


def checkpoint(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Legacy registration requires its regular ownership checkpoint')
    state = json.loads(path.read_text())
    ids = state.get('identities')
    if (state.get('phase') not in ('accepted', 'retiring', 'removed')
            or state.get('owner') != 'cloudlab-private-bootstrap'
            or not isinstance(ids, dict) or set(ids) != CHECKPOINT_KINDS
            or any(not isinstance(uid, str) or not uid for uid in ids.values())):
        raise RuntimeError('Legacy registration checkpoint is incomplete or not accepted')
    return state


def owned(kind, obj, uid):
    metadata = obj['metadata']
    finalizers = metadata.get('finalizers') or []
    target = obj.get('spec', {}).get('target', {})
    if (metadata.get('uid') != uid or not metadata.get('resourceVersion')
            or metadata.get('labels', {}).get('cloudlab.io/owner') != 'private-gitops'
            or metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id')
            or (finalizers not in ([], [ESO_FINALIZER]) if kind == 'ExternalSecret' else bool(finalizers))
            or (kind == 'ExternalSecret' and (target.get('name') != metadata.get('name')
                    or target.get('creationPolicy') != 'Owner' or target.get('deletionPolicy') != 'Retain'
                    or 'resource' in target))
            or metadata.get('deletionTimestamp')
            or (kind != 'Secret' and metadata.get('ownerReferences'))
            or (kind not in ('Secret', 'Namespace') and any(field.get('manager') != 'cloudlab-private-bootstrap'
                    and 'f:spec' in field.get('fieldsV1', {}) for field in metadata.get('managedFields', [])))
            or (kind != 'Secret' and not any(field.get('manager') == 'cloudlab-private-bootstrap'
                    for field in metadata.get('managedFields', [])))):
        raise RuntimeError('Legacy registration ownership changed; retirement refused')


def retire(name):
    from source_transition import record
    if not isinstance(name, str) or not re.fullmatch(r'[a-z](?:[a-z0-9-]{0,28}[a-z0-9])?', name):
        raise RuntimeError('Retirement requires one explicit legacy registration name')
    path = BASE / ('private-' + name + '.json')
    title = 'cloudlab-private-' + name
    state = checkpoint(path)
    namespace = current('Namespace', title)
    if not namespace:
        raise RuntimeError('Retained legacy namespace is missing')
    owned('Namespace', namespace, state['identities']['Namespace'])
    objects = {kind: current(kind, title) for kind in ORDER}
    if state['phase'] == 'removed':
        if any(objects.values()):
            raise RuntimeError('A retired registration name is occupied; no resources removed')
        return {'changed': False, 'private_registration_removed': True, 'workloads_retained': True}
    ids = state['identities']
    for kind, obj in objects.items():
        if kind != 'Secret' and obj:
            owned(kind, obj, ids[kind])
    secret = objects['Secret']
    saved = state.get('retirement')
    if saved is None:
        if state['phase'] != 'accepted' or not all(objects.values()):
            raise RuntimeError('Initial retirement requires the complete accepted registration')
        secret_uid = secret['metadata']['uid']
    else:
        if (not isinstance(saved, dict) or set(saved) != {'secret_uid'}
                or not isinstance(saved['secret_uid'], str) or not saved['secret_uid']):
            raise RuntimeError('Legacy retirement journal is incomplete')
        secret_uid = saved['secret_uid']
    if secret:
        owned('Secret', secret, secret_uid)
        owners = secret['metadata'].get('ownerReferences', [])
        if (len(owners) != 1 or owners[0].get('apiVersion') != 'external-secrets.io/v1'
                or owners[0].get('kind') != 'ExternalSecret' or owners[0].get('name') != title
                or owners[0].get('uid') != ids['ExternalSecret'] or owners[0].get('controller') is not True):
            raise RuntimeError('Legacy repository credential lacks its exact ESO owner')
    if saved is None:
        state.update(phase='retiring', retirement={'secret_uid': secret_uid})
        record(path, state)
    for kind in ORDER:
        obj = current(kind, title)
        if not obj:
            continue
        owned(kind, obj, secret_uid if kind == 'Secret' else ids[kind])
        if kind == 'Secret' and obj['metadata'].get('ownerReferences') != secret['metadata']['ownerReferences']:
            raise RuntimeError('Legacy credential owner changed during retirement')
        # Preconditions also reject changes between inspection and the DELETE request.
        kube('delete', '--raw=' + KINDS[kind][1] + title, '-f', '-', document={
            'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Background',
            'preconditions': {key: obj['metadata'][key] for key in ('uid', 'resourceVersion')}})
        deadline = time.monotonic() + 60
        while current(kind, title):
            if time.monotonic() >= deadline:
                raise RuntimeError('Legacy registration deletion remains pending; retry the scoped retirement')
            time.sleep(1)
    if any(current(kind, title) for kind in ORDER):
        raise RuntimeError('Legacy registration reappeared; retirement remains pending')
    state['phase'] = 'removed'
    record(path, state)
    return {'changed': True, 'private_registration_removed': True, 'workloads_retained': True}


def runtime_ready():
    for path in BASE.glob('private-*.json'):
        if checkpoint(path)['phase'] != 'removed':
            raise RuntimeError('Retire each legacy registration with the scoped private retirement playbook first')
    return {'changed': False, 'legacy_registrations_retired': True}


if __name__ == '__main__':
    try:
        os.umask(0o077)
        if BASE.is_symlink() or BASE.resolve() != BASE.absolute():
            raise RuntimeError('Legacy checkpoint directory is redirected')
        if not BASE.exists() and sys.argv[1:] == ['check']:
            print(json.dumps({'changed': False, 'legacy_registrations_retired': True}))
        else:
            with (BASE / 'lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                action = runtime_ready if sys.argv[1:] == ['check'] else lambda: retire(json.load(sys.stdin)['name'])
                print(json.dumps(action()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Legacy private registration retirement failed; diagnostics withheld') from None
