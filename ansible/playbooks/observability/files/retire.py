"""Observability retirement readiness gate; dormant offline leg.

Evaluates the guarded retirement preconditions read-only: an explicit retiring
fence phase, exact native ownership of all six children while fully converged,
and the preserved Alertmanager retained claim without a legacy emptyDir. The
bound digest plus strict child ownership is the completed-handoff evidence; no
separate receipt exists. Never mutates: owned-config pruning runs through
reviewed Git removal plus the live leg after these gates pass.
"""
import json
import re
import sys
from pathlib import Path

from kube import get
import native

HEX40 = '[a-f0-9]{40}'
HEX64 = '[a-f0-9]{64}'
INSTALL_PATHS = [Path('/opt/cloudlab/playbooks/observability/files'),
                 Path('/opt/cloudlab/automation/observability')]


def retained_claim():
    am = get('alertmanager.monitoring.coreos.com', 'cloudlab', 'cloudlab-observability') or {}
    spec = am.get('spec', {})
    storage = spec.get('storage', {})
    tpl = storage.get('volumeClaimTemplate', {}).get('spec', {})
    return bool(tpl.get('storageClassName') == 'cloudlab-telemetry'
                and tpl.get('resources', {}).get('requests', {}).get('storage') == '1Gi'
                and spec.get('persistentVolumeClaimRetentionPolicy') == {'whenDeleted': 'Retain',
                                                                         'whenScaled': 'Retain'}
                and storage.get('emptyDir') is None)


def evaluate(payload):
    n = payload['native']
    assert re.fullmatch(HEX40, n['configuration_revision'])
    assert re.fullmatch(HEX40, payload['acceptedRevision'])
    assert re.fullmatch(HEX64, n['digest'])
    comp = native.completion(n, paused=False)
    if comp['retirement']['fence'] != 'retiring':
        raise ValueError('Observability retirement gate is not open')
    if not all(comp['children'].values()):
        raise ValueError('Native observability children are not fully converged')
    if not retained_claim():
        raise ValueError('Alertmanager retained claim is not preserved')
    return {'retirement_ready': True, 'fence': comp['retirement']['fence'],
            'children': comp['children'], 'alertmanager_retained': True,
            'legacy_paths': [str(p) for p in INSTALL_PATHS if p.exists()]}


if __name__ == '__main__':
    try:
        print(json.dumps(evaluate(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Observability retirement not ready; private diagnostics withheld') from None
