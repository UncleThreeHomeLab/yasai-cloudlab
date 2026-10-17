"""Bounded identity Application owner; Argo alone owns rendered workloads."""
import fcntl
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
if not (ROOT / 'platform').is_dir():
    ROOT = ROOT.parent
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(ROOT))
from playbooks.data.files.control import atomic
from playbooks.keycloak.files.maintenance import APP, NAMESPACE, OWNER, BASE
from playbooks.istio.files.kube import application_ready, condition, contains, get, kube, wait
from playbooks.argocd.files.sync_recovery import recovered_secret_sync
from playbooks.keycloak.files.lease import available, previous_writer_done

from playbooks.keycloak.files.ownership import (PHASES, completed_job_retention, check_private_owner,
    private_resources, discover, application, prerequisites, private_inputs, branch_handoff_patches, enrollment_handoff)


def writer_idle():
    lease = get('lease', 'identity-writer', NAMESPACE)
    return bool(lease) and available(lease.get('spec', {}), time.time()) and previous_writer_done(
        lease.get('spec', {}), get('pods', namespace=NAMESPACE)['items'])


def reconciled(revision, uid):
    app = get('application.argoproj.io', APP, 'argocd') or {}
    if app.get('metadata', {}).get('uid') != uid:
        raise RuntimeError('Identity Application identity changed during convergence')
    compared = app.get('status', {}).get('sync', {}).get('comparedTo', {}).get('source', {})
    operation = app.get('status', {}).get('operationState', {})
    patches = recovered_secret_sync(app, revision,
        lambda name, namespace: get('externalsecret.external-secrets.io', name, namespace))
    if patches:
        kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=json',
             '-p', json.dumps(patches))
        return False
    if (contains(compared, app['spec']['source']) and operation.get('phase') in ('Failed', 'Error') and
            operation.get('syncResult', {}).get('revision') == revision and not app.get('operation')):
        raise RuntimeError('Identity reconciliation failed at the requested revision; preserve the phase checkpoint')
    return contains(compared, app['spec']['source']) and application_ready(APP, revision)


def run(payload, phase, *, retained_only=False):
    os.umask(0o077)
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BASE.resolve() != BASE:
        raise RuntimeError('Identity state must stay beneath its exact owner')
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        retirement_path = BASE / 'retirement.json'
        retirement = json.loads(retirement_path.read_text()) if retirement_path.exists() else None
        if retirement and retirement.get('phase') != 'accepted':
            raise RuntimeError('Resume the pending retirement owner before identity bootstrap')
        desired = application(payload, phase, retired=bool(retirement),
                              retired_item='keycloak-emergency-' + retirement['nonce'] if retirement else '')
        prerequisites(payload)
        receipt = BASE / 'ownership.json'
        state = json.loads(receipt.read_text()) if receipt.exists() else None
        if retained_only and (phase != 'scoped' or not retirement or not state or state.get('phase') != 'scoped'):
            raise RuntimeError('Normal apply requires an accepted retired scoped identity owner')
        current = get('application.argoproj.io', APP, 'argocd')
        if current and (not state or current['metadata']['uid'] != state['uid'] or
                        current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER or
                        current['metadata'].get('finalizers') or current['metadata'].get('ownerReferences')):
            raise RuntimeError('Identity Application has conflicting or changed ownership')
        if state and not current:
            raise RuntimeError('Identity Application identity was lost; automatic recreation refused')
        if retirement and (not state or retirement.get('application_uid') != state['uid']):
            raise RuntimeError('Accepted retirement resource identity changed; bootstrap recreation refused')
        if retirement and retirement.get('keycloak_uid') != (get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE) or {}).get('metadata', {}).get('uid'):
            raise RuntimeError('Accepted retirement server identity changed; recovery review required')
        previous = state['phase'] if state else None
        recovery = BASE / 'startup-recovery.json'
        if recovery.exists() and json.loads(recovery.read_text()).get('phase') != 'accepted':
            raise RuntimeError('Complete the pending initial server recovery before advancing identity')
        if (previous is None and phase != 'server') or (previous is not None and
                PHASES.index(phase) not in (PHASES.index(previous), PHASES.index(previous) + 1)):
            raise RuntimeError('Identity bootstrap phase transition is not permitted')
        if previous is not None and previous != phase and (not application_ready(APP, payload['revision']) or
                not condition(get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE), 'Ready')):
            raise RuntimeError('Previous identity phase must converge before advancing')
        if current and current['spec']['source']['helm']['valuesObject'].get('operation'):
            raise RuntimeError('Complete the pending identity lifecycle operation before bootstrap')
        if current and current['spec']['source']['helm']['valuesObject'].get('maintenance'):
            raise RuntimeError('Resume monthly maintenance before identity bootstrap')
        private_uids = dict(state.get('private_uids', {})) if state else {}
        private_changed = False
        for resource in private_resources(payload):
            kind, name = resource['kind'], resource['metadata']['name']
            actual = get(kind, name, 'argocd')
            saved = private_uids.get(kind)
            check_private_owner(kind, actual, saved)
            if not actual or not contains(actual, resource):
                kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=resource)
                private_changed = True
            private_uids[kind] = get(kind, name, 'argocd')['metadata']['uid']
        if phase != 'server':
            private_inputs(payload)
        changed = not current or not contains(current, desired)
        if changed:
            if current and current['spec']['source']['helm']['valuesObject'].get('reconciliationEnabled'):
                wait(writer_idle, 'previous identity writer completion and lease expiry', timeout=300)
            if current:
                current = get('application.argoproj.io', APP, 'argocd')
                handoff_receipt = enrollment_handoff(current, state, BASE) or retirement
                patches = branch_handoff_patches(current, desired, handoff_receipt)
                if patches:
                    kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=json',
                         '--field-manager=' + OWNER, '-p', json.dumps(patches))
            kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
        current = get('application.argoproj.io', APP, 'argocd')
        # Save identity before waiting so interrupted convergence can resume safely.
        checkpoint = {'uid': current['metadata']['uid'], 'phase': phase, 'revision': payload['revision'],
                      'private_uids': private_uids}
        receipt_changed = state != checkpoint
        atomic(receipt, checkpoint)
        changed = changed or private_changed or receipt_changed
        wait(lambda: reconciled(payload['revision'], current['metadata']['uid']) and
             condition(get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE), 'Ready'),
             'identity Application and server readiness convergence', timeout=900)
        if phase == 'scoped':
            crons = {name: get('cronjob', name, NAMESPACE) or {} for name in ('identity-health', 'identity-reconcile')}
            for job in get('jobs', namespace=NAMESPACE)['items']:
                patches = completed_job_retention(job, crons, bool(retirement), time.time())
                if patches:
                    kube('patch', 'job', job['metadata']['name'], '-n', NAMESPACE, '--type=json', '-p', json.dumps(patches))
                    changed = True
        return {'changed': changed, 'phase': phase, 'bootstrap_admin_retired': bool(retirement),
                'real_clients_ready': False, 'owner': 'argocd'}


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['argo']:
            from playbooks.keycloak.files.argo import run as native_argo
            result = native_argo(json.load(sys.stdin))
        elif sys.argv[1:] == ['recover-startup']:
            from playbooks.keycloak.files.maintenance import recover_startup
            json.load(sys.stdin)
            result = recover_startup()
        elif sys.argv[1:] == ['health']:
            from playbooks.keycloak.files.verify import run as verify_live
            result = verify_live(json.load(sys.stdin))
        elif sys.argv[1:] == ['retained']:
            result = run(json.load(sys.stdin), 'scoped', retained_only=True)
        else:
            result = discover() if sys.argv[1:] == ['inputs'] else run(json.load(sys.stdin), sys.argv[1])
        print(json.dumps(result))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else
                         'Identity bootstrap failed; private diagnostics withheld') from None
