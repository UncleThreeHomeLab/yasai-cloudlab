"""Withdraw journaled execution through the existing irreversible lifecycle state."""
import copy
import json
import re
import sys

sys.path.insert(0, '/opt/cloudlab')
from playbooks.previews.files.contract import OWNER, STATE
from playbooks.previews.files.lifecycle import record_approval
from playbooks.istio.files.kube import get, kube


def withdraw(current, request):
    if (not isinstance(request, dict) or set(request) != {'stateUID', 'entries'} or
            not isinstance(request['entries'], dict) or not 1 <= len(request['entries']) <= 2):
        raise ValueError('Withdrawal requires one journaled state UID and at most two exact approvals')
    meta = (current or {}).get('metadata', {})
    if (not request['stateUID'] or meta.get('uid') != request['stateUID'] or not meta.get('resourceVersion') or
            meta.get('labels', {}).get('cloudlab.io/owner') != OWNER or meta.get('ownerReferences') or meta.get('finalizers')):
        raise ValueError('Withdrawal runtime state identity or ownership changed')
    state = json.loads(current['data']['state.json'])
    if state.get('format') != 1 or not isinstance(state.get('entries'), dict):
        raise ValueError('Withdrawal runtime state is invalid')
    for instance, expected in request['entries'].items():
        if (not isinstance(instance, str) or not re.fullmatch('[a-f0-9]{32}', instance) or
                not isinstance(expected, str) or not re.fullmatch('[a-f0-9]{64}', expected)):
            raise ValueError('Withdrawal journal identity is invalid')
        record = state['entries'].get(instance)
        if not record or record.get('approvalDigest') != expected:
            raise ValueError('Withdrawal approval differs from the journal')
        if record.get('phase') != 'retired':
            record_approval(instance, record)
        if record.get('phase') not in ('pending', 'active', 'retiring', 'retired'):
            raise ValueError('Withdrawal lifecycle phase is invalid')
    desired = copy.deepcopy(current)
    for instance in request['entries']:
        record = state['entries'][instance]
        if record['phase'] not in ('retiring', 'retired'):
            record.update(phase='retiring', reason='operator-withdrawal')
    desired['data']['state.json'] = json.dumps(state, sort_keys=True)
    return desired


def run(request):
    current = get('configmap', STATE, 'argocd')
    desired = withdraw(current, request)
    changed = json.loads(current['data']['state.json']) != json.loads(desired['data']['state.json'])
    if changed:
        # Native replace enforces the inspected resourceVersion; no patch/adoption.
        kube('replace', '-f', '-', document=desired)
    return {'changed': changed, 'retirement_requested': True, 'lifecycle_cleanup_pending': True}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Preview withdrawal refused; existing owner and private diagnostics retained') from None
