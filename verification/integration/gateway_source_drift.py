"""Explicit proof that the public root repairs one native gateway owner label.

Cross-resource reads are not an atomic lock. Recheck source intent immediately
before writes; child UID/version/spec/label tests reject concurrent child changes.
"""
import copy
import json
import hashlib
import sys
import time
import uuid

from public_root_proof import ROOT, ProofError, idle, root_ready, root_gate as public_root_gate

try:
    from playbooks.istio.files import native
except ModuleNotFoundError:
    import native

APP = 'cloudlab-gateways'
OWNER = 'mesh-platform'
LABEL = 'cloudlab.io/owner'
LABEL_PATH = '/metadata/labels/cloudlab.io~1owner'
TRACKING_PATH = '/metadata/annotations/argocd.argoproj.io~1tracking-id'


def root_gate(contract, root, baseline=None, *, require_idle=False):
    public_root_gate(contract, root, baseline, require_idle=require_idle)
    binding = root['spec']['source']['helm']['valuesObject']['identity']['argo']
    if binding['valuesRevision'] != contract['identity_revision']:
        raise ProofError('Gateway identity approval changed')


def readers():
    name = APP + '-source'
    result = []
    for kind, field in (('externalsecret.external-secrets.io', 'spec'), ('secret', 'data')):
        obj = native.get(kind, name, 'argocd') or {}
        metadata = obj.get('metadata', {})
        if not metadata.get('uid') or metadata.get('deletionTimestamp') or field not in obj:
            raise ProofError('Gateway reader is missing or terminating')
        digest = hashlib.sha256(json.dumps(obj[field], sort_keys=True).encode()).hexdigest()
        result.append((metadata['uid'], digest))
    return tuple(result)


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
        raise ProofError('Gateway source identity, policy or reader changed')
    # Read the parent last, immediately before any caller can patch the child.
    root = native.get('application.argoproj.io', ROOT, 'argocd') or {}
    root_gate(contract, root, baseline['root'], require_idle=require_idle)
    return child, root


def attest(contract, payload, state, baseline, label):
    expected = contract
    if label == baseline['nonce']:
        expected = copy.deepcopy(contract)
        expected['application']['metadata']['labels'][LABEL] = baseline['nonce']
    elif label != OWNER:
        raise ProofError('Gateway proof refuses another owner label')
    native.guard(expected, state, payload, expected_tls=baseline['tls'])


def attest_nonce(contract, payload, state, baseline):
    try:
        attest(contract, payload, state, baseline, baseline['nonce'])
    except Exception:
        child, _ = gates(contract, baseline)
        if child['metadata']['labels'][LABEL] != OWNER:
            raise
        # The root may repair between our nonce read and the strict native guard.
        attest(contract, payload, state, baseline, OWNER)


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
        raise ProofError('Gateway label mutation lacks a same-identity persistence witness')


def cleanup(contract, payload, state, baseline):
    child, _ = gates(contract, baseline, require_idle=True)
    label = child['metadata']['labels'][LABEL]
    if label == baseline['nonce']:
        attest_nonce(contract, payload, state, baseline)
    else:
        attest(contract, payload, state, baseline, label)
    if label == OWNER:
        return False
    child, _ = gates(contract, baseline, require_idle=True)
    if child['metadata']['labels'][LABEL] == OWNER:
        attest(contract, payload, state, baseline, OWNER)
        return False
    patch(child, baseline['nonce'], OWNER)
    return True


def run(contract, payload, *, timeout=180):
    if (not isinstance(contract, dict) or contract.get('application', {}).get('metadata', {}).get('name') != APP
            or contract['application']['metadata'].get('namespace') != 'argocd'
            or contract['application']['metadata'].get('labels', {}).get(LABEL) != OWNER
            or not isinstance(payload, dict) or payload.get('repository') != contract.get('repository')
            or payload.get('revision') != contract.get('public_revision')):
        raise ProofError('Gateway proof requires its fixed authenticated native target')
    state = json.loads((native.BASE / 'ownership.json').read_text())
    evidence = native.guard(contract, state, payload)
    child = native.get('application.argoproj.io', APP, 'argocd')
    root = native.get('application.argoproj.io', ROOT, 'argocd') or {}
    root_gate(contract, root, require_idle=True)
    if not root_ready(root):
        raise ProofError('Public root is not ready for a scoped drift proof')
    baseline = {'child': copy.deepcopy(child), 'root': copy.deepcopy(root), 'tls': evidence['tls'],
                'readers': readers(), 'nonce': 'cloudlab-proof-' + uuid.uuid4().hex}
    child, _ = gates(contract, baseline, require_idle=True)
    if child['metadata']['labels'][LABEL] != OWNER:
        raise ProofError('Gateway label must already match Git before a new attempt')
    result = {'nonce_persisted': False, 'root_repair_verified': False,
              'cleanup_restored': False, 'cleanup_complete': False}
    try:
        attest(contract, payload, state, baseline, OWNER)
        child, root = gates(contract, baseline, require_idle=True)
        if child['metadata']['labels'][LABEL] != OWNER or not root_ready(root):
            raise ProofError('Gateway owner or parent readiness changed before injection')
        patch(child, OWNER, baseline['nonce'])
        result['nonce_persisted'] = True
        attest_nonce(contract, payload, state, baseline)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            child, root = gates(contract, baseline)
            if child['metadata']['labels'][LABEL] == OWNER and root_ready(root):
                attest(contract, payload, state, baseline, OWNER)
                child, root = gates(contract, baseline, require_idle=True)
                if child['metadata']['labels'][LABEL] == OWNER and root_ready(root):
                    result['root_repair_verified'] = True
                    break
            time.sleep(3)
        if not result['root_repair_verified']:
            raise ProofError('Public root did not repair gateway metadata within the observation limit')
    except ProofError as error:
        result['failure'] = str(error)
    except Exception:
        result['failure'] = 'Gateway metadata proof unavailable or uncertain'
    finally:
        try:
            result['cleanup_restored'] = cleanup(contract, payload, state, baseline)
            result['cleanup_complete'] = True
            if result['cleanup_restored']:
                result['root_repair_verified'] = False
                result.setdefault('failure', 'Owned label restored by cleanup; root repair is not verified')
        except Exception:
            result['root_repair_verified'] = False
            result['failure'] = 'Owned label cleanup declined or unavailable; metadata drift may remain'
    return result


MAX_ENVELOPE_BYTES = 4 * 1024 * 1024


def read_envelope(stream):
    raw = stream.read(MAX_ENVELOPE_BYTES + 1)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ProofError('Gateway proof envelope exceeds its bound')
    envelope = json.loads(raw)
    if not isinstance(envelope, dict) or set(envelope) != {'native', 'public'}:
        raise ProofError('Gateway proof requires its authenticated native and public mesh inputs')
    return envelope


if __name__ == '__main__':
    try:
        envelope = read_envelope(sys.stdin.buffer)
        result = run(envelope['native'], envelope['public'])
    except Exception:
        result = {'root_repair_verified': False, 'failure': 'Gateway proof input or initial guards failed'}
    print(json.dumps(result))
    raise SystemExit(0 if result['root_repair_verified'] else 1)
