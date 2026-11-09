"""Read-only native telemetry handoff observation.

backend() returns desired children, executor() is the fence+lock+ownership
guard, completion() returns storage/alertmanager/health evidence.
Never writes, adopts, fences, or unpauses.
"""
import re

from kube import contains, get

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
    return {'children': {n: child_ok(n, e, paused) for n, e in exp.items()}}
