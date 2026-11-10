"""Read-only native telemetry handoff observation.

backend() returns desired children, executor() is the fence+lock+ownership
guard, completion() returns storage/alertmanager/health evidence,
snapshot_evidence() returns post-quiescence snapshot-generation evidence.
Never writes, adopts, fences, or unpauses.
"""
import calendar
import json
import re
import time

from kube import contains, get, kube

CHILDREN = {
    'cloudlab-observability': ('platform/observability', '-20', 10),
    'cloudlab-prometheus': ('platform/observability/prometheus', '0', 0),
    'cloudlab-loki': ('platform/observability/loki', '0', 10),
    'cloudlab-tempo': ('platform/observability/tempo', '0', 10),
    'cloudlab-alloy': ('platform/observability/alloy', '0', 10),
    'cloudlab-kiali': ('platform/observability/kiali', '0', 10),
}


def backend(native):
    assert re.fullmatch('[a-f0-9]{40}', native['configuration_revision'])
    assert re.fullmatch('[a-f0-9]{64}', native['digest'])
    return {n: {'path': p, 'wave': w, 'history': h,
                'repo': native['repository'], 'rev': native['configuration_revision'],
                'digest': native['digest']}
            for n, (p, w, h) in CHILDREN.items()}


def executor(native, *, paused):
    fence = get('configmap', 'cloudlab-observability-retirement', 'argocd') or {}
    assert fence.get('data', {}).get('phase', 'clear') == 'clear', 'retirement fence blocks observation'
    return {'fence': 'clear', 'locks': 'caller-held-main-then-history', 'paused': bool(paused)}


def child_ok(name, exp, paused):
    a = get('application.argoproj.io', name, 'argocd') or {}
    m = a.get('metadata', {})
    s = a.get('spec', {})
    src = s.get('source', {})
    st = a.get('status', {})
    an = m.get('annotations', {})
    v = (src.get('helm') or {}).get('valuesObject', {})
    if (m.get('labels', {}).get('cloudlab.io/owner') != 'observability-platform'
            or an.get('cloudlab.io/observability-health') != 'required'
            or an.get('cloudlab.io/observability-input-digest') != exp['digest']
            or not re.fullmatch('[a-f0-9]{64}', an.get('cloudlab.io/observability-input-digest', ''))
            or v.get('nativeInputDigest') != exp['digest']
            or s.get('project') != 'cloudlab-observability'
            or s.get('destination') != {'server': 'https://kubernetes.default.svc',
                                        'namespace': 'cloudlab-observability'}
            or src.get('path') != exp['path']
            or src.get('repoURL') != exp['repo']
            or src.get('targetRevision') != exp['rev']
            or s.get('sources') is not None
            or an.get('argocd.argoproj.io/sync-wave') != exp['wave']
            or s.get('revisionHistoryLimit') != exp['history']
            or s.get('syncPolicy', {}).get('automated') != {'enabled': True, 'prune': True,
                                                            'selfHeal': True, 'allowEmpty': False}):
        return False
    if paused:
        return True
    if (an.get('argocd.argoproj.io/skip-reconcile') == 'true'
            or a.get('operation')
            or st.get('operationState', {}).get('phase') in ('Running', 'Terminating')
            or any(c.get('type', '').endswith('Error') for c in st.get('conditions', []))):
        return False
    if (st.get('sync', {}).get('comparedTo', {}).get('source') != src
            or st.get('sync', {}).get('comparedTo', {}).get('destination') != s['destination']
            or st.get('sync', {}).get('revision') != exp['rev']):
        return False
    if st.get('sync', {}).get('status') != 'Synced' or st.get('health', {}).get('status') != 'Healthy':
        return False
    return True


def completion(native, *, paused):
    exp = backend(native)
    fence = get('configmap', 'cloudlab-observability-retirement', 'argocd') or {}
    return {'children': {n: child_ok(n, e, paused) for n, e in exp.items()},
            'retirement': {'fence': (fence.get('data') or {}).get('phase', 'clear')}}


NAMESPACE = 'cloudlab-observability'
ALERTMANAGER_STATEFULSET = 'alertmanager-cloudlab'
# Native 15-minute maintenance cadence; shortened intervals are synthetic-fixture-only.
SNAPSHOT_INTERVAL_SECONDS = 900
SNAPSHOT_GENERATIONS = 2
SNAPSHOT_IO_BOUND_SECONDS = 300


def snapshot_evidence(*, interval_seconds=SNAPSHOT_INTERVAL_SECONDS):
    """Two completed post-quiescence generations per native snapshot store.

    Steady-state encoding, read once after external quiescence (never waited
    inline): the quiesced singleton must stay alive, so its two native stores
    (nflog, silences) complete one generation per maintenance cycle on a
    continuously Ready incarnation. Requires exactly one owned pod,
    Running/Ready, zero restarts, started before two cycles plus bounded I/O.
    Any restart ends the quiesced incarnation and fails closed. Does not read
    snapshot bytes; byte-level silence/dedup survival is proven by the
    post-merge live test.
    """
    pods = json.loads(kube('get', 'pod', '-n', NAMESPACE, '-o', 'json'))['items']
    owned = [p for p in pods if any(o.get('kind') == 'StatefulSet'
                                    and o.get('name') == ALERTMANAGER_STATEFULSET
                                    for o in p.get('metadata', {}).get('ownerReferences', []))]
    assert len(owned) == 1, 'alertmanager singleton is not exactly one pod'
    pod = owned[0]
    st = pod.get('status', {})
    assert st.get('phase') == 'Running', 'alertmanager pod is not running'
    assert any(c.get('type') == 'Ready' and c.get('status') == 'True'
               for c in st.get('conditions', [])), 'alertmanager pod is not ready'
    restarts = sum(c.get('restartCount', 0) for c in st.get('containerStatuses', []))
    assert restarts == 0, 'alertmanager pod restarted; quiesced incarnation ended'
    start = st.get('startTime', '')
    age = time.time() - calendar.timegm(time.strptime(start, '%Y-%m-%dT%H:%M:%SZ'))
    required = SNAPSHOT_GENERATIONS * interval_seconds + SNAPSHOT_IO_BOUND_SECONDS
    assert age >= required, 'two post-quiescence snapshot generations not yet complete'
    return {'pod': pod['metadata']['name'], 'start_time': start,
            'age_seconds': int(age), 'restarts': restarts,
            'required_age_seconds': required, 'generations': SNAPSHOT_GENERATIONS,
            'interval_seconds': interval_seconds}
