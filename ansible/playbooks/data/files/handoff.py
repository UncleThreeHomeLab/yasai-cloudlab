"""One prepared data-owner handoff and its conflicting-operation fence."""
import copy
import hashlib
import json
import re
import sys
import os
import fcntl
import base64
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from playbooks.data.files import control, native

PENDING = ('cold-maintenance.json', 'pending-volume.json')
ROTATION = 'rotation-reservation.json'


def state():
    path = control.BASE / 'ownership.json'
    return native.receipt(path, missing=True)


def journal(owner):
    value = owner.get('handoff')
    if value is None:
        return None
    if (not isinstance(value, dict) or set(value) != {'phase', 'target', 'pins', 'owners', 'specs', 'settings', 'resources', 'absence'}
            or value['phase'] not in ('armed', 'completed')
            or value['absence'] != [native.SETTINGS, native.APP + '-source']
            or not isinstance(value['target'], dict) or set(value['target']) != {'valuesRepository', 'valuesRevision'}
            or not re.fullmatch('[a-f0-9]{40}', value['target'].get('valuesRevision', ''))
            or set(value['pins']) != {'revision', 'seaweedfsRevision'}
            or any(not isinstance(pin, str) or not re.fullmatch('[a-f0-9]{40}', pin) for pin in value['pins'].values())
            or set(value['specs']) != {native.APP, native.SEAWEED}
            or not isinstance(value['settings'], dict) or not isinstance(value['resources'], dict)):
        raise RuntimeError('Data handoff journal is invalid; recovery evidence retained')
    if bool(owner.get('settings_uid')) != (value['phase'] == 'completed'):
        raise RuntimeError('Data handoff registration state is inconsistent')
    return value


def active(owner=None):
    value = journal(state() if owner is None else owner)
    return value if value and value['phase'] == 'armed' else None


def fence(operation):
    if active():
        raise RuntimeError('Prepared data handoff blocks new ' + operation + '; complete the handoff first')


def binding_target(target):
    value = active()
    if value and value['target'] != target:
        raise RuntimeError('Prepared data handoff forbids a different private binding target')


def legacy_scope(owner, app, seaweed):
    value = active(owner)
    if value and ({native.APP: app.get('spec'), native.SEAWEED: seaweed.get('spec')} != value['specs']
                  or owner.get('applications') != value['owners']['applications']):
        raise RuntimeError('Prepared data handoff forbids legacy scope or operation changes')


def quiescent():
    if any((control.BASE / name).exists() or (control.BASE / name).is_symlink() for name in (*PENDING, ROTATION)):
        raise RuntimeError('Complete the pending data operation before handoff')
    if control.get('namespace', control.RESTORE_NAMESPACE) or control.get('namespace', control.PROOF_NAMESPACE):
        raise RuntimeError('Complete the owned restore or SQL fixture before handoff')


def resources():
    """Capture identities and credential hashes, never credential values."""
    from playbooks.data.files.volumes import inventory
    inventory()
    control.primary()
    result = {}
    for kind in ('secret', 'pvc', 'database.postgresql.cnpg.io', 'cluster.postgresql.cnpg.io'):
        objects = control.get(kind, namespace=control.NAMESPACE) or {}
        rows = {}
        for obj in objects.get('items', []):
            meta = obj['metadata']
            if meta.get('deletionTimestamp') or not meta.get('uid') or meta['name'] in rows:
                raise RuntimeError('Data handoff resource discovery is incomplete')
            if kind == 'pvc' and obj.get('status', {}).get('phase') != 'Bound':
                raise RuntimeError('Data handoff requires bound persistent claims')
            if kind == 'database.postgresql.cnpg.io' and (obj.get('status', {}).get('applied') is not True
                    or obj['status'].get('observedGeneration') != meta.get('generation')):
                raise RuntimeError('Data handoff requires current applied database owners')
            row = {'uid': meta['uid']}
            if kind == 'secret':
                row['content'] = hashlib.sha256(json.dumps(obj.get('data', {}), sort_keys=True).encode()).hexdigest()
            else:
                row['spec'] = obj['spec']
            rows[meta['name']] = row
        if not rows:
            raise RuntimeError('Data handoff resource discovery is empty')
        result[kind] = rows
    return result


def absence(target):
    if native.get('configmap', native.SETTINGS, control.NAMESPACE):
        raise RuntimeError('Data handoff cannot adopt an existing settings ConfigMap')
    for kind in ('externalsecret.external-secrets.io', 'secret'):
        if native.get(kind, native.APP + '-source', 'argocd'):
            raise RuntimeError('Data handoff cannot adopt an existing source reader')
    for obj in (native.get('secrets', namespace='argocd') or {}).get('items', []):
        if obj.get('metadata', {}).get('labels', {}).get('argocd.argoproj.io/secret-type') != 'repository':
            continue
        scope = {key: base64.b64decode(obj.get('data', {}).get(key, ''), validate=True).decode() for key in ('url', 'project')}
        if scope == {'url': target['valuesRepository'], 'project': native.APP}:
            raise RuntimeError('Data handoff has competing repository credentials')


def legacy_projects(public, target):
    for name in (native.APP, native.SEAWEED):
        project = native.get('appproject.argoproj.io', name, 'argocd') or {}
        native.project_guard(name, project, public, target, legacy=True)


def capture(owner, target, pins, expected, owners):
    binding_target(target)
    quiescent()
    apps = {name: native.get('application.argoproj.io', name, 'argocd') or {} for name in (native.APP, native.SEAWEED)}
    native.legacy_guard(owner, apps[native.APP], apps[native.SEAWEED])
    normal = {'maintenance': False, 'hibernated': False, 'seaweedfs': {name: 1 for name in native.COMPONENTS}}
    if native.operational_values(apps[native.APP], apps[native.SEAWEED]) != normal:
        raise RuntimeError('Data handoff requires normal operation flags and replicas')
    if any(obj.get('status', {}).get('sync', {}).get('status') != 'Synced'
           or obj.get('status', {}).get('health', {}).get('status') != 'Healthy' for obj in apps.values()):
        raise RuntimeError('Data handoff requires ready legacy owners')
    actual = apps[native.APP]['spec']['source']['helm']['valuesObject']
    if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise RuntimeError('Authenticated data settings differ from the existing owner')
    previous = journal(owner)
    value = {'phase': 'armed', 'target': copy.deepcopy(target), 'pins': copy.deepcopy(pins),
             'owners': dict(owners, applications=copy.deepcopy(owner['applications'])),
             'specs': {name: copy.deepcopy(obj['spec']) for name, obj in apps.items()},
             'settings': copy.deepcopy(actual), 'resources': resources(),
             'absence': [native.SETTINGS, native.APP + '-source']}
    if previous:
        if previous != value:
            raise RuntimeError('Data handoff cannot rebuild or retarget its durable evidence')
        return False
    absence(target)
    owner['handoff'] = value
    return control.atomic(control.BASE / 'ownership.json', owner)


def prepare(target):
    with control.locked():
        owner = state()
        if owner.get('settings_uid'):
            native.operation()
            if journal(owner)['target'] != target:
                raise RuntimeError('Completed data handoff target changed')
            return False
        quiescent()
        source = native.projection(owner, preparation=True)
        if source.target != target or source.public['data']['configuration']['enabled'] is not False:
            raise RuntimeError('Data preparation requires its exact accepted binding and disabled owner')
        binding = native.receipt(native.BINDING)
        owners = {key: binding[key] for key in ('root_uid', 'project_uid', 'controller_uid')}
        pins = {key: source.public['data']['configuration'][key] for key in ('revision', 'seaweedfsRevision')}
        legacy_projects(source.public, target)
        return capture(owner, target, pins, source.expected, owners)


def prepare_binding(evidence, target, root, read):
    """The caller holds GitOps then DataLock before the first Root source effect."""
    binding_target(target)
    if not evidence['required']:
        return
    owner = state()
    if owner.get('settings_uid') or native.native_application(read('application.argoproj.io', native.APP)):
        return
    owners = {'root_uid': root['metadata']['uid'],
              'project_uid': read('appproject.argoproj.io', 'cloudlab-root')['metadata']['uid'],
              'controller_uid': read('statefulset', 'argocd-application-controller')['metadata']['uid']}
    legacy_projects({'repository': evidence['repository']}, target)
    capture(owner, target, {key: evidence[key] for key in ('revision', 'seaweedfsRevision')}, evidence['settings'], owners)


def transition_guard(evidence, target, root, read):
    """Permit only the captured first-binding rollout to resume its controller."""
    owner = state(); value = active(owner)
    if not value or owner.get('settings_uid'):
        return False
    if (target != value['target'] or {key: evidence[key] for key in value['pins']} != value['pins']
            or value['owners']['applications'] != owner.get('applications')
            or value['owners']['root_uid'] != (root or {}).get('metadata', {}).get('uid')
            or evidence['settings'] != value['settings']
            or evidence.get('authority', {}).get('specs') != value['specs']):
        raise RuntimeError('Pending data transition differs from its armed authority')
    quiescent()
    public = {'repository': owner['publicSource']['repository'], 'data': {'configuration': value['pins']}}
    meta = root.get('metadata', {}); spec = root.get('spec', {})
    if (meta.get('deletionTimestamp') or meta.get('ownerReferences') or meta.get('finalizers')
            or str(meta.get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() == 'true'
            or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id')
            or meta.get('labels', {}).get('cloudlab.io/owner') or spec.get('project') != 'cloudlab-root'
            or spec.get('sources') or spec.get('source', {}).get('repoURL') != public['repository']
            or spec['source'].get('targetRevision') != 'main' or spec['source'].get('path') != 'gitops/roots/public'
            or spec.get('syncPolicy', {}).get('automated', {}).get('prune', False)
            or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}):
        raise RuntimeError('Pending data Root ownership or scope changed')
    operations = []
    if root.get('operation') is not None:
        operations.append(root['operation'])
    running = root.get('status', {}).get('operationState', {})
    if running.get('phase') == 'Running':
        operations.append(running.get('operation'))
    for operation in operations:
        sync = operation.get('sync', {}) if isinstance(operation, dict) else {}
        if (not isinstance(operation, dict) or not sync
                or set(operation) - {'initiatedBy', 'sync', 'retry'}
                or operation.get('initiatedBy') != {'automated': True}
                or set(sync) - {'revision', 'prune', 'syncOptions', 'syncStrategy'}
                or not isinstance(sync.get('revision'), str) or not re.fullmatch('[a-f0-9]{40}', sync['revision']) or sync.get('prune', False)
                or ('syncOptions' in sync and sync['syncOptions'] != spec.get('syncPolicy', {}).get('syncOptions', []))
                or ('syncStrategy' in sync and sync['syncStrategy'] != {'hook': {}})
                or ('retry' in operation and operation['retry'] != spec.get('syncPolicy', {}).get('retry'))):
            raise RuntimeError('Pending data Root operation is outside its automated reconciliation')
    if operations:
        _, revision = native.published_source(owner, deadline=time.monotonic() + 120)
        for operation in operations:
            candidate = copy.deepcopy(root); candidate['operation'] = operation
            if not native.quiet_operation(candidate, [revision]):
                raise RuntimeError('Pending data Root operation differs from protected public main')
        if running.get('phase') == 'Running' and (running.get('syncResult', {}).get('source') != spec['source']
                or running.get('syncResult', {}).get('revision') != revision):
            raise RuntimeError('Pending data Root running source differs from its approved operation')
    elif not native.quiet(root):
        raise RuntimeError('Pending data Root has no safe recorded reconciliation')
    project = read('appproject.argoproj.io', 'cloudlab-root') or {}
    if (not native.quiet(project) or project['metadata'].get('uid') != value['owners']['project_uid']
            or project.get('spec', {}).get('sourceRepos') != [public['repository']]):
        raise RuntimeError('Pending data Root Project ownership or scope changed')
    native.identity_project_rules(project)
    for name in (native.APP, native.SEAWEED):
        project = read('appproject.argoproj.io', name) or {}
        native.project_guard(name, project, public, target, transitioning=True)
    native.source_credentials(target['valuesRepository'], native.APP + '-source', native.APP, pending=True)
    for name in (native.APP, native.SEAWEED):
        obj = read('application.argoproj.io', name) or {}; meta = obj.get('metadata', {})
        desired = copy.deepcopy(value['specs'][name])
        desired.update(native.application_sources(name, public, target,
            {'maintenance': False, 'hibernated': False}, {c: 1 for c in native.COMPONENTS}))
        is_native = native.native_application(obj)
        actual_spec = copy.deepcopy(obj.get('spec'))
        if is_native and name == native.APP and isinstance(actual_spec, dict):
            actual_spec.setdefault('source', None)
        revisions = [value['pins']['revision'], target['valuesRevision']] if name == native.APP else [value['pins']['seaweedfsRevision']]
        if (meta.get('uid') != owner['applications'][name]
                or actual_spec != (desired if is_native else value['specs'][name])
                or not (native.quiet_operation(obj, revisions) if is_native else native.quiet(obj))
                or meta.get('labels', {}).get('cloudlab.io/owner') != ('data-platform' if is_native else control.OWNER)
                or (is_native and meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                    native.TRACKING + 'Application:argocd/' + name)):
            raise RuntimeError('Pending data owner changed outside the armed rollout')
    if resources() != value['resources']:
        raise RuntimeError('Pending data transition changed resource identities')
    cm = native.get('configmap', native.SETTINGS, control.NAMESPACE)
    if cm:
        meta = cm.get('metadata', {})
        if (not meta.get('uid') or meta.get('deletionTimestamp') or meta.get('ownerReferences') or meta.get('finalizers')
                or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                    native.APP + ':/ConfigMap:cloudlab-data/' + native.SETTINGS
                or set(cm.get('data', {})) != {'settings'} or cm.get('binaryData')
                or json.dumps(json.loads(cm['data']['settings']), sort_keys=True) != json.dumps(value['settings'], sort_keys=True)):
            raise RuntimeError('Pending data settings are not the armed projection')
    return True


def complete_locked():
    """Only the data owner holding DataLock may perform first registration."""
    owner = state()
    value = journal(owner)
    if not value:
        raise RuntimeError('Native data registration requires its pre-effect handoff journal')
    if value['phase'] == 'completed':
        return native.operation()
    quiescent()
    source = native.projection(owner)
    binding = native.receipt(native.BINDING)
    if (source.target != value['target'] or {key: source.public['data']['configuration'][key] for key in value['pins']} != value['pins']
            or {key: binding[key] for key in ('root_uid', 'project_uid', 'controller_uid')} !=
               {key: value['owners'][key] for key in ('root_uid', 'project_uid', 'controller_uid')}
            or owner.get('applications') != value['owners']['applications']):
        raise RuntimeError('Data handoff source or owner coordinates changed')
    source.observe(initial=True)
    if source.flags != {'maintenance': False, 'hibernated': False} or any(value != 1 for value in source.replicas.values()):
        raise RuntimeError('Data handoff cannot register during an operational transition')
    native.source_credentials(source.target['valuesRepository'], native.APP + '-source', native.APP)
    obj = native.get('configmap', native.SETTINGS, control.NAMESPACE) or {}
    uid = obj.get('metadata', {}).get('uid')
    source._settings(uid)
    if resources() != value['resources']:
        raise RuntimeError('Data resources or credential contents changed during handoff')
    owner['settings_uid'] = uid
    owner['handoff']['phase'] = 'completed'
    control.atomic(control.BASE / 'ownership.json', owner)
    source.state = owner
    source.settings()
    return source


def reconcile_source():
    owner = state()
    if active(owner):
        apps = [native.get('application.argoproj.io', name, 'argocd') or {} for name in (native.APP, native.SEAWEED)]
        if any(native.native_application(obj) for obj in apps):
            return complete_locked()
    return control.operation()


def probe():
    owner = state()
    apps = {name: native.get('application.argoproj.io', name, 'argocd') for name in (native.APP, native.SEAWEED)}
    recorded = owner.get('applications', {})
    if set(recorded) == set(apps):
        if any(not apps[name] or apps[name]['metadata'].get('uid') != recorded[name] for name in apps):
            raise RuntimeError('Accepted data owner is missing or replaced')
        if active(owner) and any(native.native_application(obj) for obj in apps.values()):
            # Classification cannot register or expose settings during convergence.
            return 'observe'
        native.operation()
        return 'observe'
    if owner.get('settings_uid') or journal(owner):
        raise RuntimeError('Data bootstrap cannot replace an accepted native owner')
    if set(recorded) - set(apps):
        raise RuntimeError('Partial data bootstrap has unknown owners')
    for name, obj in apps.items():
        if obj and (native.native_application(obj) or obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != control.OWNER
                    or (name in recorded and obj['metadata'].get('uid') != recorded[name])):
            raise RuntimeError('Partial data bootstrap owner changed')
    return 'initial'


def rotation_reserve(attempt):
    if not isinstance(attempt, str) or not re.fullmatch('[a-f0-9]{32}', attempt):
        raise ValueError('Rotation requires its exact attempt identifier')
    with control.locked():
        path = control.BASE / ROTATION
        previous = native.receipt(path, missing=True) or None
        completed = control.BASE / 'rotation-receipt.json'
        proof = native.receipt(completed, missing=True)
        if proof.get('attempt') == attempt:
            if proof.get('rotated_and_verified') is not True:
                raise RuntimeError('Rotation completion evidence is incomplete')
            if previous and previous != {'attempt': attempt}:
                raise RuntimeError('A different rotation reservation remains')
            if previous:
                path.unlink()
            return {'completed': True, 'attempt': attempt}
        fence('credential rotation')
        if previous is not None and previous != {'attempt': attempt}:
            raise RuntimeError('A different credential rotation is reserved')
        if any((control.BASE / name).exists() for name in PENDING):
            raise RuntimeError('Data recovery must finish before credential rotation')
        source = native.operation()
        if control.settings(source).get('maintenance'):
            raise RuntimeError('Data maintenance must finish before credential rotation')
        control.atomic(path, {'attempt': attempt})
        return {'completed': False, 'attempt': attempt}


def rotation_required(attempt):
    fence('credential rotation')
    path = control.BASE / ROTATION
    if (not isinstance(attempt, str) or not re.fullmatch('[a-f0-9]{32}', attempt) or not path.exists()
            or native.receipt(path) != {'attempt': attempt}):
        raise RuntimeError('Credential rotation has no matching pre-write reservation')


def main(action, payload):
    if action == 'probe':
        return {'mode': probe()}
    if action == 'prepare':
        return {'changed': prepare(payload)}
    if action == 'prepare-local':
        from dotenv import dotenv_values
        from playbooks.access.files.preflight import ssh
        os.umask(0o077)
        environment = dotenv_values(control.ROOT / '.env', interpolate=False)
        for name in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
            os.environ[name] = environment[name]
        os.environ['VM_PORT'] = environment.get('VM_PORT') or '22'
        with Path('/state/data-vault-provision.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if Path('/state/data-rotation-pending.json').exists():
                raise RuntimeError('Resume the pending credential rotation before arming data handoff')
            return json.loads(ssh('VM', environment['VM_HOST'],
                'python3 /opt/cloudlab/playbooks/data/files/handoff.py prepare', input=json.dumps(payload), timeout=300))
    if action == 'rotation-reserve':
        return rotation_reserve(payload['attempt'])
    if action == 'complete':
        def ready():
            apps = [native.get('application.argoproj.io', name, 'argocd') or {} for name in (native.APP, native.SEAWEED)]
            return all(native.native_application(app) and native.quiet(app)
                       and app.get('status', {}).get('health', {}).get('status') == 'Healthy'
                       and app.get('status', {}).get('sync', {}).get('status') == 'Synced' for app in apps)
        native.wait(ready, 'prepared native data owners', timeout=600)
        with control.locked():
            complete_locked()
        return {'changed': False, 'native_registered': True}
    raise ValueError('Unknown data handoff operation')


if __name__ == '__main__':
    try:
        print(json.dumps(main(sys.argv[1], {} if sys.argv[1] in ('probe', 'complete') else json.load(sys.stdin))))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Data handoff failed; evidence retained') from None
