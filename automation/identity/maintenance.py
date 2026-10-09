"""Quiesce identity through its Argo owner inside the existing backup boundary."""
import json
import fcntl
from pathlib import Path

from automation.mesh.kube import condition, get, kube, wait

APP = 'cloudlab-identity'
NAMESPACE = 'cloudlab-identity'
OWNER = 'cloudlab-identity-bootstrap'
BASE = Path('/var/lib/cloudlab/identity')


def _set_maintenance(enabled, identities=None):
    app = get('application.argoproj.io', APP, 'argocd')
    if identities and (not app or app['metadata']['uid'] != identities['application_uid']):
        raise RuntimeError('Startup recovery resource identity changed')
    if not app:
        return False
    if app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
        raise RuntimeError('Identity backup boundary cannot modify a foreign Application')
    desired = app['spec']['source']['helm']['valuesObject']
    if not desired.get('enabled'):
        return False
    def server():
        actual = get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE) or {}
        if identities and actual.get('metadata', {}).get('uid') != identities['keycloak_uid']:
            raise RuntimeError('Startup recovery resource identity changed')
        return actual
    if identities:
        server()
    if bool(desired.get('maintenance')) != enabled:
        kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=json',
             '--field-manager=' + OWNER, '-p', json.dumps([
                 {'op': 'test', 'path': '/metadata/uid', 'value': app['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': app['metadata']['resourceVersion']},
                 {'op': 'add', 'path': '/spec/source/helm/valuesObject/maintenance', 'value': enabled}]))
    wait(lambda: server().get('spec', {}).get('instances')
         == (0 if enabled else 1), 'identity capture declaration convergence')
    if enabled:
        # Running jobs finish within their deadline. Do not revoke machine writers.
        wait(lambda: not [p for p in (get('pods', namespace=NAMESPACE) or {}).get('items', [])
                          if p['metadata'].get('labels', {}).get('app') == 'keycloak'
                          or (p['spec'].get('serviceAccountName') in ('identity-writer', 'identity-health')
                              and p['status']['phase'] not in ('Succeeded', 'Failed'))],
             'identity server and realm writer shutdown', timeout=420)
    else:
        wait(lambda: condition(server(), 'Ready'),
             'identity server resume', timeout=900)
    return True


def set_maintenance(enabled):
    app = get('application.argoproj.io', APP, 'argocd')
    if not app:
        return False
    if app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
        raise RuntimeError('Identity backup boundary cannot modify a foreign Application')
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (BASE / 'owner.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another identity operation owns the maintenance boundary') from None
        return _set_maintenance(enabled)


def recover_startup():
    """Replace a failed initial Pod through its sole Argo/Operator owners."""
    from automation.data.control import atomic
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ownership = json.loads((BASE / 'ownership.json').read_text())
        app = get('application.argoproj.io', APP, 'argocd') or {}
        values = app.get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {})
        if (ownership.get('phase') != 'server' or app.get('metadata', {}).get('uid') != ownership.get('uid') or
                app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER or
                not values.get('enabled') or not values.get('serverEnabled') or
                values.get('reconciliationEnabled') or values.get('operation')):
            raise RuntimeError('Startup recovery requires the existing server-only identity owner')
        server = get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE) or {}
        path = BASE / 'startup-recovery.json'
        checkpoint = json.loads(path.read_text()) if path.exists() else None
        identities = {'application_uid': ownership['uid'], 'keycloak_uid': server.get('metadata', {}).get('uid')}
        if not identities['keycloak_uid'] or (checkpoint and any(checkpoint.get(k) != v for k, v in identities.items())):
            raise RuntimeError('Startup recovery resource identity changed')
        if checkpoint and checkpoint.get('phase') not in ('stopping', 'starting', 'accepted'):
            raise RuntimeError('Unknown startup recovery checkpoint')
        ready = condition(server, 'Ready')
        if ready and not values.get('maintenance') and (not checkpoint or checkpoint['phase'] == 'accepted'):
            return {'changed': False, 'server_ready': True, 'initial_server_recovery': True}
        if not checkpoint or checkpoint['phase'] == 'accepted':
            if values.get('maintenance'):
                raise RuntimeError('Another maintenance boundary must be resumed by its owner')
            stateful = get('statefulset', 'cloudlab-keycloak', NAMESPACE) or {}
            failed = get('pod', 'cloudlab-keycloak-0', NAMESPACE) or {}
            if (not any(r.get('uid') == identities['keycloak_uid'] for r in stateful.get('metadata', {}).get('ownerReferences', [])) or
                    not any(r.get('uid') == stateful.get('metadata', {}).get('uid') for r in failed.get('metadata', {}).get('ownerReferences', [])) or
                    failed.get('metadata', {}).get('labels', {}).get('controller-revision-hash') == stateful.get('status', {}).get('updateRevision') or
                    not any(c.get('state', {}).get('waiting', {}).get('reason') == 'CrashLoopBackOff'
                            for c in failed.get('status', {}).get('containerStatuses', []))):
                raise RuntimeError('Startup recovery requires a failed stale Pod and its corrected owned template')
            checkpoint = dict(identities, phase='stopping')
            atomic(path, checkpoint)
        if checkpoint['phase'] == 'stopping':
            if not _set_maintenance(True, identities):
                raise RuntimeError('Startup recovery owner became unavailable')
            checkpoint['phase'] = 'starting'
            atomic(path, checkpoint)
        if not _set_maintenance(False, identities):
            raise RuntimeError('Startup recovery owner became unavailable')
        current = get('application.argoproj.io', APP, 'argocd') or {}
        actual = get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE) or {}
        if (current.get('metadata', {}).get('uid') != identities['application_uid'] or
                actual.get('metadata', {}).get('uid') != identities['keycloak_uid']):
            raise RuntimeError('Startup recovery resource identity changed')
        checkpoint['phase'] = 'accepted'
        atomic(path, checkpoint)
        return {'changed': True, 'server_ready': True, 'initial_server_recovery': True,
                'direct_realm_writes': 0, 'database_reinitialized': False}
