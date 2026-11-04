"""Explicit proof that the public root repairs one native access owner label.

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
    from playbooks.access.files import native
except ModuleNotFoundError:
    import native

APP = 'cloudlab-access'
OWNER = 'access-platform'
LABEL = 'cloudlab.io/owner'
LABEL_PATH = '/metadata/labels/cloudlab.io~1owner'
TRACKING_PATH = '/metadata/annotations/argocd.argoproj.io~1tracking-id'


def root_gate(contract, root, baseline=None, *, require_idle=False):
    public_root_gate(contract, root, baseline, require_idle=require_idle)
    binding = root['spec']['source']['helm']['valuesObject']['identity']['argo']
    if binding['valuesRevision'] != contract['private_revision']:
        raise ProofError('Access identity approval changed')


def snapshot(kind, name, fields):
    obj = native.get(kind, name, 'argocd') or {}
    meta = obj.get('metadata', {})
    finalizers = meta.get('finalizers', [])
    allowed = ['externalsecrets.external-secrets.io/externalsecret-cleanup'] if kind == 'externalsecret.external-secrets.io' else []
    if (not meta.get('uid') or meta.get('deletionTimestamp') or (meta.get('ownerReferences') and kind != 'secret')
            or (finalizers and finalizers != allowed) or any(field not in obj for field in fields)):
        raise ProofError('Access proof resource identity or lifecycle changed')
    return {'uid': meta['uid'], 'tracking': meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id'),
        'owners': copy.deepcopy(meta.get('ownerReferences', [])),
        **{field: hashlib.sha256(json.dumps(obj[field], sort_keys=True).encode()).hexdigest() for field in fields}}


def snapshots():
    return {'configured': native.authority.receipt(), 'binding': native.binding_receipt(),
        'rbac': snapshot('clusterrolebinding.rbac.authorization.k8s.io', native.authority.BINDING, ('roleRef', 'subjects')),
        'project': snapshot('appproject.argoproj.io', APP, ('spec',)),
        'root_project': snapshot('appproject.argoproj.io', 'cloudlab-root', ('spec',)),
        'controller': snapshot('statefulset', 'argocd-application-controller', ('spec',)),
        'reader': snapshot('externalsecret.external-secrets.io', APP + '-source', ('spec',)),
        'reader_secret': snapshot('secret', APP + '-source', ('data',))}


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
            or not idle(child) or snapshots() != baseline['snapshots']):
        raise ProofError('Access source identity, policy or reader changed')
    declared = copy.deepcopy(contract['application']['metadata'])
    declared['labels'].pop(LABEL)
    if not native.contains(metadata, declared):
        raise ProofError('Access declared metadata changed outside the owned label')
    # Read the parent last, immediately before any caller can patch the child.
    root = native.get('application.argoproj.io', ROOT, 'argocd') or {}
    root_gate(contract, root, baseline['root'], require_idle=require_idle)
    return child, root


def attest(contract, baseline):
    child, root = gates(contract, baseline)
    # The runtime owner guard stays strict. Only this attempt's label is exempt
    # from the proof-local immutable baseline during the intentional mutation.
    state = baseline['snapshots']['configured']
    native.authority.administrator_binding(state, lambda kind, name: native.get(kind, name, 'argocd'))
    native.retained(state, contract['public_revision'], baseline['credentials'])
    native.reader_guard(contract, 'native')
    receipt = baseline['snapshots']['binding']
    if (receipt.get('phase') != 'accepted'
            or receipt.get('target') != {'valuesRepository': contract['private_repository'], 'valuesRevision': contract['private_revision']}
            or receipt.get('root_uid') != root['metadata']['uid']
            or receipt.get('project_uid') != baseline['snapshots']['root_project']['uid']
            or receipt.get('controller_uid') != baseline['snapshots']['controller']['uid']):
        raise ProofError('Access proof accepted binding identity changed')
    # Recheck after the full read-only attestation, including a racing Root repair.
    gates(contract, baseline)


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
        raise ProofError('Access label mutation lacks a same-identity persistence witness')


def cleanup(contract, baseline):
    child, _ = gates(contract, baseline, require_idle=True)
    label = child['metadata']['labels'][LABEL]
    attest(contract, baseline)
    if label == OWNER:
        native.guard(contract, expected_credentials=baseline['credentials'])
        return False
    child, _ = gates(contract, baseline, require_idle=True)
    if child['metadata']['labels'][LABEL] == OWNER:
        native.guard(contract, expected_credentials=baseline['credentials'])
        return False
    patch(child, baseline['nonce'], OWNER)
    return True


def run(contract, *, timeout=180):
    validate_contract(contract)
    evidence = native.guard(contract)
    child = native.get('application.argoproj.io', APP, 'argocd')
    root = native.get('application.argoproj.io', ROOT, 'argocd') or {}
    root_gate(contract, root, require_idle=True)
    if not root_ready(root):
        raise ProofError('Public root is not ready for a scoped drift proof')
    baseline = {'child': copy.deepcopy(child), 'root': copy.deepcopy(root), 'credentials': evidence['credentials'],
                'snapshots': snapshots(), 'nonce': 'cloudlab-proof-' + uuid.uuid4().hex}
    child, _ = gates(contract, baseline, require_idle=True)
    if child['metadata']['labels'][LABEL] != OWNER:
        raise ProofError('Access label must already match Git before a new attempt')
    result = {'nonce_persisted': False, 'root_repair_verified': False,
              'cleanup_restored': False, 'cleanup_complete': False}
    try:
        attest(contract, baseline)
        native.guard(contract, expected_credentials=baseline['credentials'])
        child, root = gates(contract, baseline, require_idle=True)
        if child['metadata']['labels'][LABEL] != OWNER or not root_ready(root):
            raise ProofError('Access owner or parent readiness changed before injection')
        patch(child, OWNER, baseline['nonce'])
        result['nonce_persisted'] = True
        attest(contract, baseline)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            child, root = gates(contract, baseline)
            if child['metadata']['labels'][LABEL] == OWNER and root_ready(root):
                attest(contract, baseline)
                native.guard(contract, expected_credentials=baseline['credentials'])
                child, root = gates(contract, baseline, require_idle=True)
                if child['metadata']['labels'][LABEL] == OWNER and root_ready(root):
                    result['root_repair_verified'] = True
                    break
            time.sleep(3)
        if not result['root_repair_verified']:
            raise ProofError('Public root did not repair access metadata within the observation limit')
    except ProofError as error:
        result['failure'] = str(error)
    except Exception:
        result['failure'] = 'Access metadata proof unavailable or uncertain'
    finally:
        try:
            result['cleanup_restored'] = cleanup(contract, baseline)
            result['cleanup_complete'] = True
            if result['cleanup_restored']:
                result['root_repair_verified'] = False
                result.setdefault('failure', 'Owned label restored by cleanup; root repair is not verified')
        except Exception:
            result['root_repair_verified'] = False
            result['failure'] = 'Owned label cleanup declined or unavailable; metadata drift may remain'
    return result


REVIEWED_REVISION = '6000ae0876664edce08b6553438327a68a417fa2'
MAX_ENVELOPE_BYTES = 65536


def validate_contract(contract):
    fields = {'repository', 'public_revision', 'configuration_revision', 'private_repository', 'private_revision',
              'evidence', 'application', 'project', 'reader'}
    if (not isinstance(contract, dict) or set(contract) != fields or contract.get('configuration_revision') != REVIEWED_REVISION
            or contract.get('application', {}).get('metadata', {}).get('name') != APP
            or contract['application']['metadata'].get('namespace') != 'argocd'
            or contract['application']['metadata'].get('labels', {}).get(LABEL) != OWNER):
        raise ProofError('Access proof requires its fixed authenticated immutable contract')
    if len(json.dumps({'native': contract}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > MAX_ENVELOPE_BYTES:
        raise ProofError('Access proof envelope exceeds its bound')
    expected = [
        {'repoURL': contract['repository'], 'targetRevision': REVIEWED_REVISION, 'path': 'platform/connectivity/access',
         'helm': {'releaseName': APP, 'valueFiles': ['$values/platform/access.yaml']}},
        {'repoURL': contract['private_repository'], 'targetRevision': contract['private_revision'], 'ref': 'values'}]
    if contract['application'].get('spec', {}).get('sources') != expected or contract['application']['spec'].get('source') is not None:
        raise ProofError('Access proof source coordinates changed')
    native.authority.validate(contract['evidence'], {'valuesRepository': contract['private_repository'], 'valuesRevision': contract['private_revision']})


def read_envelope(stream):
    raw = stream.read(MAX_ENVELOPE_BYTES + 1)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ProofError('Access proof envelope exceeds its bound')
    envelope = json.loads(raw.decode('utf-8'))
    if not isinstance(envelope, dict) or set(envelope) != {'native'}:
        raise ProofError('Access proof requires only its authenticated native contract')
    validate_contract(envelope['native'])
    return envelope


if __name__ == '__main__':
    try:
        envelope = read_envelope(sys.stdin.buffer)
        result = run(envelope['native'])
    except Exception:
        result = {'root_repair_verified': False, 'failure': 'Access proof input or initial guards failed'}
    print(json.dumps(result))
    raise SystemExit(0 if result['root_repair_verified'] else 1)
