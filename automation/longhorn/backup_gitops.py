"""Bounded backup declaration handoff; private Argo inputs stay inside the cluster."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys

from adopt_backup_target import adoption_patch
from bootstrap import BASE, PendingConvergence, contains, get, identities, kube, preserve, suspended

CHECKPOINT = 'backup-ownership.json'
OWNER = 'ansible-longhorn-backup'


def record(state):
    temporary = BASE / 'backup-ownership.tmp'
    with temporary.open('w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(BASE / CHECKPOINT)
    directory = os.open(BASE, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def secret_receipt(payload):
    secret = get({'apiVersion': 'v1', 'kind': 'Secret',
                  'metadata': {'name': payload['secret'], 'namespace': 'longhorn-system'}})
    if not secret:
        return None
    external = get(next(obj for obj in payload['inventory'] if obj['kind'] == 'ExternalSecret'))
    if not external or not any(owner.get('kind') == 'ExternalSecret' and owner.get('uid') == external['metadata']['uid']
                               for owner in secret['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Backup credential is not owned by its declared ExternalSecret')
    return {'uid': secret['metadata']['uid'],
            'content': hashlib.sha256(json.dumps(secret.get('data', {}), sort_keys=True).encode()).hexdigest()}


def apply(objects):
    kube('apply', '--server-side', '--field-manager=cloudlab', '-f', '-', objects=objects)


def begin(payload):
    operator = json.loads((BASE / 'ownership.json').read_text())
    operator_app = get({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
                        'metadata': {'name': 'cloudlab-longhorn', 'namespace': 'argocd'}})
    if operator['phase'] not in ('released', 'accepted') or operator['phase'] != 'accepted' and operator_app:
        raise RuntimeError('Accept the storage operator handoff before migrating backup declarations')
    if get(payload['app']):
        raise RuntimeError('Backup bootstrap refuses a competing Argo application')
    existing = identities(payload['inventory'])
    credential = secret_receipt(payload)
    if operator_app and (len(existing) != len(payload['inventory']) or not credential):
        raise RuntimeError('Existing backup installation is incomplete; ownership adoption refused')
    for obj in payload['inventory']:
        current = get(obj)
        if current:
            if current['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id'):
                raise RuntimeError('Backup declaration already belongs to an Argo application')
            managers = {field['manager'] for field in current['metadata'].get('managedFields', [])}
            if 'cloudlab' not in managers and not (obj['kind'] == 'BackupTarget' and managers == {'longhorn-manager'}
                    and current['spec'].get('backupTargetURL') == '' and current['spec'].get('credentialSecret') == ''):
                raise RuntimeError('Existing backup declaration has an unexpected writer')
    state = {'phase': 'preparing', 'owner': 'cloudlab-bootstrap', 'identities': existing,
             'credential': credential, 'application_owner': OWNER, 'credential_owner': 'external-secrets'}
    record(state)
    return state


def run(payload, action):
    if action not in ('credential-seed', 'seed', 'seed-stop', 'configure', 'accept', 'recover'):
        raise RuntimeError('Unknown backup ownership action')
    os.umask(0o077)
    if BASE.resolve() != BASE.absolute():
        raise RuntimeError('Storage ownership directory must not be a symlink')
    with (BASE / 'ownership.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = BASE / CHECKPOINT
        if not path.exists() and action != 'credential-seed':
            raise RuntimeError('Initialize backup credential ownership before other transitions')
        state = json.loads(path.read_text()) if path.exists() else begin(payload)
        if state['phase'] not in ('preparing', 'seeded', 'released', 'accepted', 'recovering'):
            raise RuntimeError('Unknown backup ownership checkpoint')
        if action == 'seed-stop' and state['phase'] not in ('preparing', 'seeded'):
            raise RuntimeError('Backup interruption fixture must precede writer release')
        changed = False
        if action == 'credential-seed':
            if state['phase'] == 'preparing':
                if get(payload['app']) or len(payload['items']) != 1 or payload['items'][0]['kind'] != 'ExternalSecret':
                    raise RuntimeError('Credential seeding must precede an Argo writer and contain only its declaration')
                current = get(payload['items'][0])
                if current and not contains(current, payload['items'][0]):
                    raise RuntimeError('Existing credential declaration differs during ownership migration')
                apply(payload['items'])
                preserve(state['identities'], identities(payload['inventory']))
                changed = True
            return {'changed': changed, 'phase': state['phase'], 'owner': state['owner']}
        digest = hashlib.sha256(json.dumps(payload['items'], sort_keys=True).encode()).hexdigest()
        if state['phase'] != 'accepted' and state.get('digest', digest) != digest:
            raise RuntimeError('Finish the backup handoff before changing its destination or policy')
        if state['phase'] == 'recovering' and action != 'recover':
            raise RuntimeError('Resume explicit backup recovery before normal reconciliation')
        if action in ('seed', 'seed-stop') and state['phase'] == 'preparing':
            if get(payload['app']):
                raise RuntimeError('Backup seeding refuses a competing Argo writer')
            state['digest'] = digest
            record(state)
            external = next(x for x in payload['items'] if x['kind'] == 'ExternalSecret')
            kube('wait', '--for=condition=Ready', '--timeout=180s', '-n', 'longhorn-system',
                 'externalsecret/' + external['metadata']['name'])
            for obj in payload['items']:
                current = get(obj)
                if obj['kind'] == 'BackupTarget' and current:
                    patch = adoption_patch(current, obj)
                    if patch:
                        kube('patch', 'backuptargets.longhorn.io', 'default', '-n', 'longhorn-system',
                             '--type=json', '--field-manager=cloudlab', '-p', json.dumps(patch))
                    elif not contains(current, obj):
                        raise RuntimeError('Backup destination differs during ownership migration')
                elif current and not contains(current, obj):
                    raise RuntimeError('Backup declaration differs during ownership migration')
            apply(payload['items'])
            preserve(state['identities'], identities(payload['inventory']))
            credential = secret_receipt(payload)
            if not credential or state['credential'] and state['credential'] != credential:
                raise RuntimeError('Backup credential changed during ownership migration')
            state.update(phase='seeded', identities=identities(payload['inventory']),
                         credential=credential)
            record(state)
            changed = True
        if action == 'seed' and state['phase'] == 'seeded':
            if get(payload['app']):
                raise RuntimeError('Backup release refuses a competing Argo writer')
            preserve(state['identities'], identities(payload['inventory']))
            if state['credential'] != secret_receipt(payload):
                raise RuntimeError('Backup credential changed before writer release')
            state.update(phase='released', owner='awaiting-argocd')
            record(state)
            changed = True
        if action == 'configure':
            if state['phase'] not in ('released', 'accepted') or not payload['enabled']:
                raise RuntimeError('Release backup bootstrap and enable its reviewed project before Argo configuration')
            operator = get({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
                            'metadata': {'name': 'cloudlab-longhorn', 'namespace': 'argocd'}}) or {}
            status = operator.get('status', {})
            if status.get('health', {}).get('status') != 'Healthy' or status.get('sync', {}).get('status') != 'Synced':
                raise PendingConvergence('Storage operator must converge before its backup application')
            app = payload['app']
            current = get(app)
            if current and (current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                            or current['metadata'].get('finalizers')
                            or state.get('application_uid', current['metadata'].get('uid')) != current['metadata'].get('uid')):
                raise RuntimeError('Backup application conflicts with another owner or deletion policy')
            if not current or not contains(current, app):
                kube('apply', '--server-side', '--field-manager=cloudlab-longhorn-backup-bootstrap', '-f', '-', objects=[app])
                if current and get(app)['metadata']['uid'] != current['metadata']['uid']:
                    raise RuntimeError('Backup application identity changed')
                changed = True
            application_uid = get(app)['metadata']['uid']
            if state.get('application_uid') != application_uid:
                state['application_uid'] = application_uid
                record(state)
                changed = True
        if action == 'recover':
            current_app = get(payload['app']) or {}
            if (state['phase'] not in ('released', 'accepted', 'recovering')
                    or payload['app']['spec']['syncPolicy']['automated']['enabled'] is not False
                    or current_app.get('spec', {}).get('syncPolicy', {}).get('automated', {}).get('enabled') is not False):
                raise RuntimeError('Suspend the backup Argo writer in Git and finish its operation before recovery')
            if not suspended(current_app):
                raise PendingConvergence('Wait for the suspended backup Application operation to finish')
            if (current_app.get('metadata', {}).get('uid') != state.get('application_uid')
                    or current_app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER
                    or current_app.get('metadata', {}).get('finalizers')):
                raise RuntimeError('Backup recovery Application ownership changed')
            if state.get('digest') != digest:
                raise RuntimeError('Backup recovery requires the checkpointed destination and policy')
            preserve(state['identities'], identities(payload['inventory']))
            if state['phase'] != 'recovering':
                state['credential'] = secret_receipt(payload)
            state.update(phase='recovering', owner='cloudlab-bootstrap')
            record(state)
            apply(payload['items'])
            preserve(state['identities'], identities(payload['inventory']))
            if state['credential'] != secret_receipt(payload):
                raise RuntimeError('Backup recovery changed its generated credential')
            state.update(phase='released', owner='awaiting-argocd')
            record(state)
            changed = True
        if action == 'accept':
            if state['phase'] not in ('released', 'accepted'):
                raise RuntimeError('Release backup bootstrap before accepting Argo ownership')
            app = get(payload['app']) or {}
            status = app.get('status', {})
            if (app.get('metadata', {}).get('uid') != state.get('application_uid')
                    or app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER
                    or app.get('metadata', {}).get('finalizers')):
                raise RuntimeError('Backup acceptance Application ownership changed')
            if (status.get('sync', {}).get('status') != 'Synced'
                    or status.get('sync', {}).get('revision') != payload['revision']
                    or status.get('health', {}).get('status') != 'Healthy' or app.get('operation')
                    or status.get('operationState', {}).get('phase') not in (None, 'Succeeded')
                    or app.get('spec', {}).get('syncPolicy', {}).get('automated', {}).get('enabled') is not True
                    or any(c['type'].endswith('Error') for c in status.get('conditions', []))):
                raise PendingConvergence('Backup Argo ownership has not converged')
            preserve(state['identities'], identities(payload['inventory']))
            for obj in payload['items']:
                current = get(obj) or {}
                if (not contains(current, obj) or not current.get('metadata', {}).get('annotations', {}).get(
                        'argocd.argoproj.io/tracking-id', '').startswith('cloudlab-longhorn-backup:')):
                    raise RuntimeError('Backup declarations lack their intended Argo state and ownership')
            if state['phase'] != 'accepted':
                if secret_receipt(payload) != state['credential']:
                    raise RuntimeError('Backup credential identity or contents changed during adoption')
                state.update(phase='accepted', owner='argocd', revision=payload['revision'])
                record(state)
                changed = True
            elif state.get('digest') != digest:
                state.update(digest=digest, revision=payload['revision'])
                record(state)
                changed = True
        return {'changed': changed, 'phase': state['phase'], 'owner': state['owner'],
                'application_owner': OWNER, 'credential_owner': 'external-secrets'}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin), sys.argv[1])))
    except PendingConvergence as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Backup ownership failed; checkpoint retained, private diagnostics withheld') from None
