"""Explicit proof that the public root repairs one native certificate owner label.

Cross-resource reads are not an atomic lock. Recheck source intent immediately
before writes; child UID/version/spec/label tests reject concurrent child changes.
"""
import copy
import json
import re
import sys
import time
import uuid

try:
    from playbooks.certificates.files import native
except ModuleNotFoundError:
    import native

APP = 'cloudlab-certificates'
ROOT = 'cloudlab-public-root'
OWNER = 'certificate-platform'
LABEL = 'cloudlab.io/owner'
LABEL_PATH = '/metadata/labels/cloudlab.io~1owner'
TRACKING_PATH = '/metadata/annotations/argocd.argoproj.io~1tracking-id'


class ProofError(RuntimeError):
    pass


def idle(app):
    return (app.get('operation') is None
            and app.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'))


def root_ready(app):
    status = app.get('status', {})
    return (idle(app) and status.get('sync', {}).get('status') == 'Synced'
            and status.get('health', {}).get('status') == 'Healthy'
            and status.get('operationState', {}).get('phase') in (None, 'Succeeded'))


def root_gate(contract, root, baseline=None, *, require_idle=False):
    metadata, spec = root.get('metadata', {}), root.get('spec', {})
    source = spec.get('source', {})
    policy = spec.get('syncPolicy', {}).get('automated', {})
    binding = source.get('helm', {}).get('valuesObject', {}).get('identity', {}).get('argo', {})
    if (metadata.get('name') != ROOT or metadata.get('namespace') != 'argocd'
            or not metadata.get('uid') or metadata.get('deletionTimestamp') or metadata.get('ownerReferences')
            or metadata.get('finalizers') or spec.get('project') != 'cloudlab-root' or spec.get('sources')
            or source.get('repoURL') != contract['repository'] or source.get('targetRevision') != 'main'
            or source.get('path') != 'gitops/roots/public'
            or not isinstance(binding, dict) or binding.get('valuesRepository') != contract['private_repository']
            or not isinstance(binding.get('valuesRevision'), str) or not re.fullmatch('[a-f0-9]{40}', binding['valuesRevision'])
            or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
            or policy not in ({'prune': False, 'selfHeal': True, 'allowEmpty': False},
                              {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False})
            or policy.get('enabled', True) is not True
            or str(metadata.get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() == 'true'
            or root.get('status', {}).get('sync', {}).get('revision') != contract['public_revision']
            or any(condition.get('type', '').endswith('Error') for condition in root.get('status', {}).get('conditions', []))
            or (baseline is not None and (metadata['uid'] != baseline['metadata']['uid'] or spec != baseline['spec']))
            or (require_idle and not idle(root))):
        raise ProofError('Public root identity, source or pending intent changed')


def readers():
    name = APP + '-source'
    return tuple(native.get(kind, name, 'argocd')['metadata']['uid']
                 for kind in ('externalsecret.external-secrets.io', 'secret'))


def gates(contract, baseline, *, require_idle=False):
    child = native.get('application.argoproj.io', APP, 'argocd') or {}
    metadata = child.get('metadata', {})
    if (metadata.get('name') != APP or metadata.get('namespace') != 'argocd'
            or metadata.get('uid') != baseline['child']['metadata']['uid'] or not metadata.get('resourceVersion')
            or child.get('spec') != baseline['child']['spec']
            or metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id') != native.TRACKING
            or str(metadata.get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() == 'true'
            or metadata.get('labels', {}).get(LABEL) not in (OWNER, baseline['nonce'])
            or metadata.get('deletionTimestamp') or metadata.get('finalizers') or metadata.get('ownerReferences')
            or not idle(child) or readers() != baseline['readers']):
        raise ProofError('Certificate source identity, policy or reader changed')
    # Read the parent last, immediately before any caller can patch the child.
    root = native.get('application.argoproj.io', ROOT, 'argocd') or {}
    root_gate(contract, root, baseline['root'], require_idle=require_idle)
    return child, root


def attest(contract, state, baseline, label):
    expected = contract
    if label == baseline['nonce']:
        expected = copy.deepcopy(contract)
        expected['application']['metadata']['labels'][LABEL] = baseline['nonce']
    elif label != OWNER:
        raise ProofError('Certificate proof refuses another owner label')
    native.guard(expected, state, expected_tls=baseline['tls'])


def attest_nonce(contract, state, baseline):
    try:
        attest(contract, state, baseline, baseline['nonce'])
    except Exception:
        child, _ = gates(contract, baseline)
        if child['metadata']['labels'][LABEL] != OWNER:
            raise
        # The root may repair between our nonce read and the strict native guard.
        attest(contract, state, baseline, OWNER)


def patch(child, expected_label, replacement):
    operations = [{'op': 'test', 'path': '/metadata/uid', 'value': child['metadata']['uid']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': child['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/spec', 'value': child['spec']},
        {'op': 'test', 'path': TRACKING_PATH, 'value': native.TRACKING},
        {'op': 'test', 'path': LABEL_PATH, 'value': expected_label},
        {'op': 'replace', 'path': LABEL_PATH, 'value': replacement}]
    raw = native.kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=json',
        '--patch-file=/dev/stdin', '-o', 'json', document=operations)
    witnessed = json.loads(raw)
    if (witnessed.get('metadata', {}).get('uid') != child['metadata']['uid']
            or witnessed.get('metadata', {}).get('labels', {}).get(LABEL) != replacement):
        raise ProofError('Certificate label mutation lacks a same-identity persistence witness')


def cleanup(contract, state, baseline):
    child, _ = gates(contract, baseline, require_idle=True)
    label = child['metadata']['labels'][LABEL]
    if label == baseline['nonce']:
        attest_nonce(contract, state, baseline)
    else:
        attest(contract, state, baseline, label)
    if label == OWNER:
        return False
    child, _ = gates(contract, baseline, require_idle=True)
    if child['metadata']['labels'][LABEL] == OWNER:
        attest(contract, state, baseline, OWNER)
        return False
    patch(child, baseline['nonce'], OWNER)
    return True


def run(contract, *, timeout=180):
    if (not isinstance(contract, dict) or contract.get('application', {}).get('metadata', {}).get('name') != APP
            or contract['application']['metadata'].get('namespace') != 'argocd'
            or contract['application']['metadata'].get('labels', {}).get(LABEL) != OWNER):
        raise ProofError('Certificate proof requires its fixed authenticated native target')
    state = json.loads((native.BASE / 'ownership.json').read_text())
    evidence = native.guard(contract, state)
    child = native.get('application.argoproj.io', APP, 'argocd')
    root = native.get('application.argoproj.io', ROOT, 'argocd') or {}
    root_gate(contract, root, require_idle=True)
    if not root_ready(root):
        raise ProofError('Public root is not ready for a scoped drift proof')
    baseline = {'child': copy.deepcopy(child), 'root': copy.deepcopy(root), 'tls': evidence['tls'],
                'readers': readers(), 'nonce': 'cloudlab-proof-' + uuid.uuid4().hex}
    child, _ = gates(contract, baseline, require_idle=True)
    if child['metadata']['labels'][LABEL] != OWNER:
        raise ProofError('Certificate label must already match Git before a new attempt')
    result = {'nonce_persisted': False, 'root_repair_verified': False,
              'cleanup_restored': False, 'cleanup_complete': False}
    try:
        attest(contract, state, baseline, OWNER)
        child, root = gates(contract, baseline, require_idle=True)
        if child['metadata']['labels'][LABEL] != OWNER or not root_ready(root):
            raise ProofError('Certificate owner or parent readiness changed before injection')
        patch(child, OWNER, baseline['nonce'])
        result['nonce_persisted'] = True
        attest_nonce(contract, state, baseline)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            child, root = gates(contract, baseline)
            if child['metadata']['labels'][LABEL] == OWNER and root_ready(root):
                attest(contract, state, baseline, OWNER)
                child, root = gates(contract, baseline, require_idle=True)
                if child['metadata']['labels'][LABEL] == OWNER and root_ready(root):
                    result['root_repair_verified'] = True
                    break
            time.sleep(3)
        if not result['root_repair_verified']:
            raise ProofError('Public root did not repair certificate metadata within the observation limit')
    except ProofError as error:
        result['failure'] = str(error)
    except Exception:
        result['failure'] = 'Certificate metadata proof unavailable or uncertain'
    finally:
        try:
            result['cleanup_restored'] = cleanup(contract, state, baseline)
            result['cleanup_complete'] = True
            if result['cleanup_restored']:
                result['root_repair_verified'] = False
                result.setdefault('failure', 'Owned label restored by cleanup; root repair is not verified')
        except Exception:
            result['root_repair_verified'] = False
            result['failure'] = 'Owned label cleanup declined or unavailable; metadata drift may remain'
    return result


if __name__ == '__main__':
    try:
        raw = sys.stdin.read(1048577)
        if len(raw) > 1048576:
            raise ProofError('Certificate proof envelope exceeds its bound')
        result = run(json.loads(raw)['native'])
    except Exception:
        result = {'root_repair_verified': False, 'failure': 'Certificate proof input or initial guards failed'}
    print(json.dumps(result))
    raise SystemExit(0 if result['root_repair_verified'] else 1)
