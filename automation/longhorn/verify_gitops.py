"""Require real Argo repair without rolling storage workloads."""
import json
import sys

from kube import get, kubectl, wait


def verify(backup=False):
    app_name = 'cloudlab-longhorn-backup' if backup else 'cloudlab-longhorn'
    kind, name, label = 'deployment', 'longhorn-ui', 'helm.sh/chart'
    if backup:
        from backup_policy import load_policy
        kind, name, label = 'recurringjobs.longhorn.io', load_policy()['job_name'], 'app.kubernetes.io/managed-by'
    def converged():
        app = get('application.argoproj.io', app_name, 'argocd')
        status = app.get('status', {})
        return (status.get('sync', {}).get('status') == 'Synced'
                and status.get('health', {}).get('status') == 'Healthy' and not app.get('operation'))
    wait('Longhorn Argo application ready for drift proof', converged)
    original = get(kind, name)
    expected = original['metadata']['labels'][label]
    if not original['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(app_name + ':'):
        raise RuntimeError('Longhorn drift fixture requires Argo ownership')
    try:
        kubectl('patch', kind, name, '-n', 'longhorn-system', '--type=merge',
                '-p', json.dumps({'metadata': {'labels': {label: 'drift-fixture'}}}))
        def repaired():
            current = get(kind, name)
            if current['metadata']['uid'] != original['metadata']['uid'] or current['spec'] != original['spec']:
                raise RuntimeError('Longhorn metadata fixture changed workload identity or spec')
            return current['metadata']['labels'].get(label) == expected
        wait('Argo repaired Longhorn metadata drift without replacing its workload', repaired, timeout=180)
    finally:
        current = get(kind, name)
        if current['metadata']['labels'].get(label) == 'drift-fixture':
            kubectl('patch', kind, name, '-n', 'longhorn-system', '--type=merge',
                    '-p', json.dumps({'metadata': {'labels': {label: expected}}}))


if __name__ == '__main__':
    try:
        verify(backup=sys.argv[1:] == ['backup'])
    except Exception:
        raise SystemExit('Longhorn GitOps drift verification failed; diagnostics withheld') from None
