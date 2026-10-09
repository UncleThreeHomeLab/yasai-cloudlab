"""Quiesce identity through its Argo owner inside the existing backup boundary."""
import json
import fcntl
from pathlib import Path

from automation.mesh.kube import get, kube, wait

APP = 'cloudlab-identity'
NAMESPACE = 'cloudlab-identity'
OWNER = 'cloudlab-identity-bootstrap'
BASE = Path('/var/lib/cloudlab/identity')


def _set_maintenance(enabled):
    app = get('application.argoproj.io', APP, 'argocd')
    if not app:
        return False
    if app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
        raise RuntimeError('Identity backup boundary cannot modify a foreign Application')
    desired = app['spec']['source']['helm']['valuesObject']
    if not desired.get('enabled'):
        return False
    if bool(desired.get('maintenance')) != enabled:
        kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=merge',
             '--field-manager=' + OWNER, '-p', json.dumps({'spec': {'source': {'helm': {
                 'valuesObject': {'maintenance': enabled}}}}}))
    wait(lambda: get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE)['spec']['instances']
         == (0 if enabled else 1), 'identity capture declaration convergence')
    if enabled:
        # Running jobs finish within their deadline. Do not revoke machine writers.
        wait(lambda: not [p for p in (get('pods', namespace=NAMESPACE) or {}).get('items', [])
                          if p['metadata'].get('labels', {}).get('app') == 'keycloak'
                          or (p['spec'].get('serviceAccountName') in ('identity-writer', 'identity-health')
                              and p['status']['phase'] not in ('Succeeded', 'Failed'))],
             'identity server and realm writer shutdown', timeout=420)
    else:
        wait(lambda: any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in
                         get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE).get('status', {}).get('conditions', [])),
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
