"""Native desired-state verify: revisions, private SHA/digest, parent comparison
with live digest equality, 6 children, storage, alertmanager checkpoint/loading,
two completed post-quiescence generations, native health.
Read-only; never patches root or unpauses.
"""
import copy
import json
import re
import sys
import time

from kube import BASE, contains, get, kube, wait
import native

HEX40 = '[a-f0-9]{40}'
HEX64 = '[a-f0-9]{64}'


def parent_ok(ev, decl, paused):
    p = get('applicationset.argoproj.io', 'cloudlab-observability-gitops') or {}
    a = get('application.argoproj.io', 'cloudlab-observability-gitops') or {}
    want = copy.deepcopy(decl['parent']['template']['spec'])
    for s in want['sources']:
        if isinstance(s.get('targetRevision'), str) and 'Consumer source acceptance refused' in s['targetRevision']:
            s['targetRevision'] = ev['acceptedRevision']
    if p.get('spec') != decl['parent'] or a.get('spec') != want:
        return False
    if a.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') != str(paused).lower():
        return False
    if a['spec']['syncPolicy']['automated']['enabled'] == paused:
        return False
    live = {a.get('metadata', {}).get('annotations', {}).get('cloudlab.io/observability-input-digest')}
    for s in a.get('spec', {}).get('sources', []):
        values = (s.get('helm') or {}).get('valuesObject', {})
        if isinstance(values, dict) and 'nativeInputDigest' in values:
            live.add(values['nativeInputDigest'])
    live.discard(None)
    if live != {ev.get('native', {}).get('digest')}:
        return False
    st = a.get('status', {})
    revs = st.get('sync', {}).get('revisions', [])
    if revs != [decl['public_revision'], ev['acceptedRevision']] and not paused:
        return False
    if not paused:
        compared = st.get('sync', {}).get('comparedTo', {}).get('sources', [])
        identity = lambda s: {k: s.get(k) for k in ('repoURL', 'targetRevision', 'path', 'ref')}
        if [identity(s) for s in compared] != [identity(s) for s in a['spec']['sources']]:
            return False
    if not paused and (st.get('sync', {}).get('status') != 'Synced'
                       or st.get('health', {}).get('status') != 'Healthy'):
        return False
    if a.get('operation') or any(c.get('type', '').endswith('Error') for c in st.get('conditions', [])):
        return False
    return {'reported_revisions': revs, 'digest': ev['native']['digest'],
            'public_revision': decl['public_revision'],
            'private_revision': ev['acceptedRevision']}


def storage_ok():
    sc = get('storageclass', 'cloudlab-telemetry') or {}
    q = get('resourcequota', 'telemetry-budget', 'cloudlab-observability') or {}
    if sc.get('provisioner') != 'driver.longhorn.io' or sc.get('reclaimPolicy') != 'Retain':
        return False
    if q.get('spec', {}).get('hard', {}).get('persistentvolumeclaims') != '5':
        return False
    items = json.loads(kube('get', 'pvc', '-n', 'cloudlab-observability', '-o', 'json'))['items']
    if not items or any(i.get('spec', {}).get('storageClassName') != 'cloudlab-telemetry' for i in items):
        return False
    return True


def alertmanager_ok(native_mod, paused):
    am = get('alertmanager.monitoring.coreos.com', 'cloudlab', 'cloudlab-observability') or {}
    spec = am.get('spec', {})
    tpl = spec.get('storage', {}).get('volumeClaimTemplate', {}).get('spec', {})
    if tpl.get('storageClassName') != 'cloudlab-telemetry':
        return False
    if tpl.get('resources', {}).get('requests', {}).get('storage') != '1Gi':
        return False
    if spec.get('persistentVolumeClaimRetentionPolicy') != {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}:
        return False
    if paused:
        return True
    conds = am.get('status', {}).get('conditions', [])
    return any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in conds)


def quiescent(n, native_mod, paused, timeout=60):
    """Two completed post-quiescence generations within an explicit bound."""
    base = None
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        comp = native_mod.completion(n, paused=paused)
        if (paused or all(comp['children'].values())) and json.dumps(comp, sort_keys=True) == base:
            return comp
        base = json.dumps(comp, sort_keys=True) if paused or all(comp['children'].values()) else None
        time.sleep(10)
    raise AssertionError('observability did not reach quiescence')


def run(payload):
    n = payload['native']
    assert re.fullmatch(HEX40, n['configuration_revision'])
    assert re.fullmatch(HEX40, payload['acceptedRevision'])
    assert re.fullmatch(HEX64, n['digest'])
    paused = bool(payload['paused'])
    native.executor(n, paused=paused)
    chain = parent_ok(payload, {'parent': payload['applicationSet'],
                               'public_revision': payload['public_revision']}, paused)
    assert chain, 'parent comparison failed'
    comp = quiescent(n, native, paused)
    if not paused:
        assert all(comp['children'].values()), 'children not converged'
    assert storage_ok(), 'storage desired state failed'
    assert alertmanager_ok(n, paused), 'alertmanager checkpoint/loading failed'
    snap = native.snapshot_evidence() if not paused else None
    return {'paused': paused, 'children': comp['children'], 'storage': True,
            'alertmanager': True, 'revision_chain': chain, 'snapshots': snap}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Observability verification failed; private diagnostics withheld') from None
