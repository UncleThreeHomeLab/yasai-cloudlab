"""Require real Argo repair without rolling storage workloads."""
import json

from kube import get, kubectl, wait


def verify():
    def converged():
        app = get('application.argoproj.io', 'cloudlab-longhorn', 'argocd')
        status = app.get('status', {})
        return (status.get('sync', {}).get('status') == 'Synced'
                and status.get('health', {}).get('status') == 'Healthy' and not app.get('operation'))
    wait('Longhorn Argo application ready for drift proof', converged)
    original = get('deployment', 'longhorn-ui')
    label = 'helm.sh/chart'
    expected = original['metadata']['labels'][label]
    if not original['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-longhorn:'):
        raise RuntimeError('Longhorn drift fixture requires Argo ownership')
    try:
        kubectl('patch', 'deployment', 'longhorn-ui', '-n', 'longhorn-system', '--type=merge',
                '-p', json.dumps({'metadata': {'labels': {label: 'drift-fixture'}}}))
        def repaired():
            current = get('deployment', 'longhorn-ui')
            if current['metadata']['uid'] != original['metadata']['uid'] or current['spec'] != original['spec']:
                raise RuntimeError('Longhorn metadata fixture changed workload identity or spec')
            return current['metadata']['labels'].get(label) == expected
        wait('Argo repaired Longhorn metadata drift without replacing its workload', repaired, timeout=180)
    finally:
        current = get('deployment', 'longhorn-ui')
        if current['metadata']['labels'].get(label) == 'drift-fixture':
            kubectl('patch', 'deployment', 'longhorn-ui', '-n', 'longhorn-system', '--type=merge',
                    '-p', json.dumps({'metadata': {'labels': {label: expected}}}))


if __name__ == '__main__':
    try:
        verify()
    except Exception:
        raise SystemExit('Longhorn GitOps drift verification failed; diagnostics withheld') from None
