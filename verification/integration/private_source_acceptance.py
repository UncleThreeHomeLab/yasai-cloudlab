"""Explicit fixed-scope native qualification; never a production onboarding writer.

Parent supplies private config/receipt A and B, and edits only its dedicated proof
branch. Create, accept A, then test each invalid/missing receipt from an accepted
baseline; refresh is test-only. Restore valid A and accept cleared native errors
between negative cases. Drift never refreshes/syncs; compensation is not repair.
After publishing valid B, approve-b then accept by normal controller polling.
Remove-marker/accept checks ordinary pruning with retained-data unchanged.
Cleanup deletes only captured fixture UIDs; unknown namespace objects block it.
"""
import base64
import copy
import hashlib
import json
import re
import sys
import time
import uuid

sys.path.insert(0, '/opt/cloudlab')
from playbooks.data.files import native
from playbooks.argocd.files.private_sources import acceptance_spec, validate_acceptance
from playbooks.istio.files.kube import get, kube

VERSION = 'cloudlab-source-acceptance-proof/v1'
NAME = 'cloudlab-prices-source-proof'
OWNER = 'source-acceptance-proof'
PUBLIC = 'https://github.com/UncleThreeHomeLab/yasai-cloudlab.git'
CHART = 'ansible/playbooks/argocd/tests/fixtures/source-acceptance'
RETAINED = {'sentinel': 'retained-source-proof-v1'}
RESOURCES = {
    'Namespace': ('namespace', NAME, None, '/api/v1/namespaces/'),
    'Project': ('appproject.argoproj.io', NAME, 'argocd', '/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/'),
    'ExternalSecret': ('externalsecret.external-secrets.io', NAME + '-source', 'argocd', '/apis/external-secrets.io/v1/namespaces/argocd/externalsecrets/'),
    'Secret': ('secret', NAME + '-source', 'argocd', '/api/v1/namespaces/argocd/secrets/'),
    'ApplicationSet': ('applicationset.argoproj.io', NAME, 'argocd', '/apis/argoproj.io/v1alpha1/namespaces/argocd/applicationsets/'),
    'Application': ('application.argoproj.io', NAME, 'argocd', '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/'),
    'Marker': ('configmap', 'approval-marker', NAME, '/api/v1/namespaces/' + NAME + '/configmaps/'),
    'Retained': ('configmap', 'retained-data', NAME, '/api/v1/namespaces/' + NAME + '/configmaps/'),
    'DefaultAccount': ('serviceaccount', 'default', NAME, '/api/v1/namespaces/' + NAME + '/serviceaccounts/'),
    'RootCA': ('configmap', 'kube-root-ca.crt', NAME, '/api/v1/namespaces/' + NAME + '/configmaps/'),
    'IstioRoot': ('configmap', 'istio-ca-root-cert', NAME, '/api/v1/namespaces/' + NAME + '/configmaps/'),
    'IstioCRL': ('configmap', 'istio-ca-crl', NAME, '/api/v1/namespaces/' + NAME + '/configmaps/'),
}


class ProofError(RuntimeError):
    pass


def config_guard(config, state=None):
    fields = {'version', 'attempt', 'publicRevision', 'privateRepository', 'privateBranch', 'receiptA', 'receiptB'}
    if (not isinstance(config, dict) or set(config) != fields or config['version'] != VERSION
            or not re.fullmatch('[a-f0-9]{32}', config.get('attempt', ''))
            or not re.fullmatch('[a-f0-9]{40}', config.get('publicRevision', ''))
            or not re.fullmatch(r'https://github[.]com/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+[.]git', config.get('privateRepository', ''))
            or config['privateRepository'] == PUBLIC
            or not re.fullmatch(r'proof/prices-source-[a-f0-9]{32}', config.get('privateBranch', ''))):
        raise ProofError('Invalid fixed source proof inputs')
    for approval in ('A', 'B'):
        receipt = config['receipt' + approval]
        validate_acceptance(receipt, config['privateRepository'], commitment(config, approval))
    if (config['receiptA']['revision'] == config['receiptB']['revision'] or config['receiptA']['nonce'] == config['receiptB']['nonce']):
        raise ProofError('Proof revisions and receipt nonces must differ')
    if state is not None and (not isinstance(state, dict) or set(state) != {'version', 'attempt', 'publicRevision', 'authority', 'identities', 'approval', 'markerEnabled', 'sourceAvailable', 'acceptedApproval', 'acceptedMarkerEnabled', 'lastObservation'}
            or state['version'] != VERSION or state['publicRevision'] != config['publicRevision']
            or state['attempt'] != config['attempt']
            or state['approval'] not in ('A', 'B') or state['acceptedApproval'] not in (None, 'A', 'B')
            or state['lastObservation'] not in ('pending', 'accepted', 'rejected')
            or not isinstance(state['authority'], dict) or set(state['authority']) != {'Root', 'ApplicationSetController'}
            or any(not isinstance(uid, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', uid) for uid in state['authority'].values())
            or any(type(state[key]) is not bool for key in ('markerEnabled', 'sourceAvailable', 'acceptedMarkerEnabled'))
            or not isinstance(state['identities'], dict) or not set(state['identities']) <= set(RESOURCES)
            or any(not isinstance(uid, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', uid) for uid in state['identities'].values())):
        raise ProofError('Invalid captured source proof scope')


def commitment(config, approval):
    row = config['receipt' + approval]
    return hashlib.sha256(('\n'.join([row['version'], row['consumer'], config['privateRepository'],
        'platform/sources.yaml', row['revision'], row['nonce'], ''])).encode()).hexdigest()


def read(key):
    kind, name, namespace, _ = RESOURCES[key]
    return get(kind, name, namespace)


def artifact_lock(config, deadline):
    path = 'platform/delivery/argocd/artifact.lock.json'
    document = native.source_snapshot.request('repos/' + native.repository(PUBLIC) + '/contents/' + path + '?ref=' + config['publicRevision'], deadline)
    if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('path') != path
            or document.get('encoding') != 'base64' or type(document.get('size')) is not int
            or not 0 < document['size'] <= 16384 or not isinstance(document.get('sha'), str)
            or not re.fullmatch('[a-f0-9]{40}', document['sha'])):
        raise ProofError('Published controller artifact lock is not a bounded regular file')
    raw = base64.b64decode(''.join(document['content'].split()), validate=True)
    if (len(raw) != document['size'] or hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != document['sha']):
        raise ProofError('Published controller artifact lock Git blob integrity changed')
    return json.loads(raw)


def context(config, state=None):
    config_guard(config, state)
    deadline = time.monotonic() + 180
    public, head = native.published_source({'publicSource': {'repository': PUBLIC, 'branch': 'main'}}, deadline=deadline)
    if state is None and head != config['publicRevision']:
        raise ProofError('Proof artifact must be the independently protected published head')
    root = get('application.argoproj.io', 'cloudlab-public-root', 'argocd') or {}
    source = root.get('spec', {}).get('source', {})
    binding = source.get('helm', {}).get('valuesObject', {}).get('identity', {}).get('argo', {})
    if (not native.quiet(root) or source.get('repoURL') != PUBLIC or source.get('targetRevision') != 'main'
            or source.get('path') != 'gitops/roots/public' or root['spec'].get('project') != 'cloudlab-root'
            or root['spec'].get('sources') or root['spec'].get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
            or binding.get('valuesRepository') != config['privateRepository'] or not native.matches_revision(root, head)
            or root.get('status', {}).get('health', {}).get('status') != 'Healthy'
            or root.get('status', {}).get('sync', {}).get('status') != 'Synced'):
        raise ProofError('Proof requires the accepted designated Root binding')
    snapshot = lambda path: native.source_snapshot.chart_files({'repository': PUBLIC, 'revision': config['publicRevision'], 'path': path}, deadline=deadline)
    files = snapshot('gitops/roots/public')
    fixture = snapshot(CHART)
    images = artifact_lock(config, deadline)['images']
    images = [name + '@' + digest for name, digest in images.items() if name.startswith('quay.io/argoproj/argocd:')]
    controller = get('deployment', 'argocd-applicationset-controller', 'argocd') or {}
    containers = controller.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
    args = containers[0].get('args', []) if len(containers) == 1 else []
    if (len(images) != 1 or len(containers) != 1 or containers[0].get('image') != images[0]
            or [arg for arg in args if arg.startswith('--policy')] != ['--policy=create-update']
            or [arg for arg in args if arg.startswith('--enable-policy-override')] != ['--enable-policy-override=false']
            or not controller.get('metadata', {}).get('uid') or controller['metadata'].get('deletionTimestamp')
            or controller.get('spec', {}).get('replicas') != 1 or controller.get('status', {}).get('availableReplicas') != 1
            or controller.get('status', {}).get('observedGeneration') != controller['metadata'].get('generation')):
        raise ProofError('Native ApplicationSet controller policy or pinned readiness differs')
    authority = {'Root': root['metadata']['uid'], 'ApplicationSetController': controller['metadata']['uid']}
    if state is not None and state['authority'] != authority:
        raise ProofError('Captured trusted Root or ApplicationSet controller was replaced')
    return public, files, fixture, authority


def authority_guard(state):
    for key, kind, name in (('Root', 'application.argoproj.io', 'cloudlab-public-root'),
            ('ApplicationSetController', 'deployment', 'argocd-applicationset-controller')):
        obj = get(kind, name, 'argocd') or {}
        if obj.get('metadata', {}).get('uid') != state['authority'][key] or obj['metadata'].get('deletionTimestamp'):
            raise ProofError('Captured trusted Root or ApplicationSet controller was replaced')


def declarations(config, state, public, files):
    labels = {'cloudlab.io/owner': OWNER, 'cloudlab.io/proof-attempt': config['attempt']}
    meta = lambda name, namespace='argocd': dict(name=name, labels=labels.copy(), **({'namespace': namespace} if namespace else {}))
    values = copy.deepcopy(public)
    values['privateSources'] = {'enabled': True, 'revision': config['publicRevision'], 'acceptanceCommitment': commitment(config, state['approval'])}
    spec = acceptance_spec(values, config['privateRepository'], config['publicRevision'], files=files)
    branch = config['privateBranch'] if state['sourceAvailable'] else config['privateBranch'] + '-unavailable-' + config['attempt']
    spec['generators'][0]['merge']['generators'][1]['git']['revision'] = branch
    child = spec['template']; child['metadata'] = meta(NAME)
    child['spec']['project'] = NAME; child['spec']['destination']['namespace'] = NAME
    child['spec']['sources'][0].update(path=CHART)
    gate = child['spec']['sources'][1]['targetRevision']
    child['spec']['sources'][0]['helm']['parameters'] = [{'name': 'acceptedRevision', 'value': gate, 'forceString': True},
        {'name': 'proofAttempt', 'value': config['attempt'], 'forceString': True}, {'name': 'markerEnabled', 'value': str(state['markerEnabled']).lower()}]
    child['spec']['syncPolicy']['automated']['allowEmpty'] = False
    secret_spec = native.reader_spec(config['privateRepository'], NAME + '-source', NAME)
    secret_spec['target']['template']['metadata']['labels'].update(labels)
    parent_meta = meta(NAME); parent_meta['annotations'] = {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}
    return {
        'Namespace': {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': meta(NAME, None)},
        'Project': {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject', 'metadata': meta(NAME), 'spec': {
            'sourceRepos': [PUBLIC, config['privateRepository']], 'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': NAME}],
            'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [{'group': '', 'kind': 'ConfigMap'}]}},
        'ExternalSecret': {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'metadata': meta(NAME + '-source'), 'spec': secret_spec},
        'ApplicationSet': {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'metadata': parent_meta, 'spec': spec},
    }


def owned(obj, uid, config, *, owners=None):
    meta = (obj or {}).get('metadata', {})
    labels = meta.get('labels', {})
    if (not uid or meta.get('uid') != uid or not meta.get('resourceVersion') or meta.get('deletionTimestamp')
            or meta.get('ownerReferences', []) != (owners or [])
            or meta.get('finalizers', []) not in ([], [native.ESO_FINALIZER])
            or labels.get('cloudlab.io/owner') != OWNER or labels.get('cloudlab.io/proof-attempt') != config['attempt']):
        raise ProofError('Proof resource identity or ownership changed')
    eso_labels = {'reconcile.external-secrets.io/managed', 'reconcile.external-secrets.io/created-by'}
    if (set(labels) - {'cloudlab.io/owner', 'cloudlab.io/proof-attempt', 'kubernetes.io/metadata.name', 'argocd.argoproj.io/instance', 'argocd.argoproj.io/secret-type'} - eso_labels
            or ('kubernetes.io/metadata.name' in labels and labels['kubernetes.io/metadata.name'] != NAME)
            or ('argocd.argoproj.io/instance' in labels and labels['argocd.argoproj.io/instance'] != NAME)
            or ('argocd.argoproj.io/secret-type' in labels and (obj.get('kind') != 'Secret' or labels['argocd.argoproj.io/secret-type'] != 'repository'))):
        raise ProofError('Proof resource has unexpected labels')
    if obj.get('kind') == 'Secret':
        if (meta.get('name') != NAME + '-source' or meta.get('namespace') != 'argocd'
                or labels.get('reconcile.external-secrets.io/managed') != 'true'
                or labels.get('reconcile.external-secrets.io/created-by') != hashlib.sha3_224(('argocd/' + NAME + '-source').encode()).hexdigest()):
            raise ProofError('Proof Secret native ESO metadata differs from its fixed owner profile')
    elif eso_labels & set(labels):
        raise ProofError('Native ESO Secret labels are forbidden on other proof resources')
    if meta.get('finalizers') and obj.get('kind') != 'ExternalSecret':
        raise ProofError('Proof resource has unexpected finalizers')


def declaration_guard(key, obj, uid, config, desired):
    owned(obj, uid, config)
    if (obj.get('kind') != desired[key]['kind'] or obj.get('apiVersion') != desired[key]['apiVersion']
            or obj['metadata'].get('name') != desired[key]['metadata']['name']
            or obj['metadata'].get('namespace') != desired[key]['metadata'].get('namespace')
            or set(obj) - {'apiVersion', 'kind', 'metadata', 'spec', 'status'}
            or ('spec' in desired[key] and obj.get('spec') != desired[key]['spec'])
            or (key == 'Namespace' and obj.get('spec', {}) not in ({}, {'finalizers': ['kubernetes']}, {'finalizers': []}))):
        raise ProofError('Proof source, project or credential declaration changed')


def controls(config, state, desired):
    authority_guard(state)
    for key in ('Namespace', 'Project', 'ExternalSecret', 'ApplicationSet'):
        declaration_guard(key, read(key), state['identities'].get(key), config, desired)
    secret = read('Secret') or {}
    external = read('ExternalSecret')
    if not secret:
        if 'Secret' in state['identities']: raise ProofError('Captured proof credential is missing')
        return False
    owner = {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'name': NAME + '-source',
        'uid': state['identities']['ExternalSecret'], 'controller': True, 'blockOwnerDeletion': True}
    owned(secret, state['identities'].get('Secret', secret.get('metadata', {}).get('uid')), config, owners=[owner])
    data = {key: base64.b64decode(value, validate=True).decode() for key, value in secret.get('data', {}).items()}
    if (set(data) != {'type', 'url', 'project', 'githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'}
            or data['type'] != 'git' or data['url'] != config['privateRepository'] or data['project'] != NAME
            or not all(data[key] for key in ('githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'))
            or secret.get('type') not in (None, 'Opaque') or secret.get('kind') != 'Secret' or secret.get('apiVersion') != 'v1'
            or secret['metadata'].get('name') != NAME + '-source' or secret['metadata'].get('namespace') != 'argocd'
            or secret['metadata'].get('labels', {}).get('argocd.argoproj.io/secret-type') != 'repository'
            or set(secret) - {'apiVersion', 'kind', 'metadata', 'data', 'type'}):
        raise ProofError('Proof repository credential is not ready or exact-scoped')
    state['identities'].setdefault('Secret', secret['metadata']['uid'])
    return native.condition(external, 'Ready')


def child_spec(config, state, desired, approval, marker):
    spec = copy.deepcopy(desired['ApplicationSet']['spec']['template']['spec'])
    revision = config['receipt' + approval]['revision']
    spec['sources'][1]['targetRevision'] = revision
    spec['sources'][0]['helm']['parameters'][0]['value'] = revision
    spec['sources'][0]['helm']['parameters'][2]['value'] = str(marker).lower()
    return spec


def quiet_child(app):
    # Call only after validating its exact captured AppSet owner (or scoped orphan).
    current = copy.deepcopy(app)
    current.get('metadata', {}).pop('ownerReferences', None)
    return native.quiet(current)


def child(config, state, desired, approval, marker, *, ready=True, drift=None):
    app = read('Application') or {}
    if not app:
        if 'Application' in state['identities']: raise ProofError('Captured proof Application is missing')
        return False
    owners = [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': NAME,
        'uid': state['identities']['ApplicationSet'], 'controller': True, 'blockOwnerDeletion': True}]
    owned(app, state['identities'].get('Application', app.get('metadata', {}).get('uid')), config, owners=owners)
    if app.get('spec') != child_spec(config, state, desired, approval, marker):
        if (state['acceptedApproval'] and (approval != state['acceptedApproval'] or marker != state['acceptedMarkerEnabled'])
                and app.get('spec') == child_spec(config, state, desired, state['acceptedApproval'], state['acceptedMarkerEnabled'])):
            return False
        raise ProofError('Proof child source or scope differs from accepted intent')
    state['identities'].setdefault('Application', app['metadata']['uid'])
    if ready and (not quiet_child(app) or not native.matches_revision(app, config['publicRevision'])
            or app.get('status', {}).get('sync', {}).get('status') != 'Synced'
            or app.get('status', {}).get('health', {}).get('status') != 'Healthy'
            or any(row.get('type', '').endswith('Error') for row in app.get('status', {}).get('conditions', []))):
        return False
    for key, data in (('Retained', RETAINED), ('Marker', {'revision': drift or config['receipt' + approval]['revision']})):
        obj = read(key)
        if key == 'Marker' and not marker:
            if obj:
                owned(obj, state['identities'].get(key), config)
                if obj.get('data') != {'revision': config['receipt' + state['acceptedApproval']]['revision']}:
                    raise ProofError('Removal refuses a marker changed outside accepted intent')
                return False
            continue
        if not obj:
            if key in state['identities']: raise ProofError('Captured proof ConfigMap is missing')
            return False
        owned(obj, state['identities'].get(key, (obj or {}).get('metadata', {}).get('uid')), config)
        meta = obj['metadata']
        if (key == 'Marker' and approval != state['acceptedApproval'] and state['acceptedApproval']
                and obj.get('data') == {'revision': config['receipt' + state['acceptedApproval']]['revision']}):
            return False
        if (obj.get('apiVersion') != 'v1' or obj.get('kind') != 'ConfigMap' or obj.get('data') != data
                or obj.get('binaryData') or obj.get('immutable')
                or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') != NAME + ':/ConfigMap:' + NAME + '/' + RESOURCES[key][1]):
            raise ProofError('Proof marker or retained synthetic data changed')
        state['identities'].setdefault(key, meta['uid'])
    return True


def poll(check, *, timeout=240):
    if type(timeout) is not int or not 1 <= timeout <= 300: raise ProofError('Invalid proof observation limit')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check(): return
        time.sleep(3)
    raise ProofError('Native proof did not converge within its observation limit')


def defaults(state):
    account, ca = read('DefaultAccount'), read('RootCA')
    if not account or not ca: return False
    trust_uids = {}
    for key, field in (('IstioRoot', 'root-cert.pem'), ('IstioCRL', 'ca-crl.pem')):
        target = read(key)
        reference = get('configmap', RESOURCES[key][1], 'argocd')
        if not target or not reference: return False
        for obj, namespace in ((target, NAME), (reference, 'argocd')):
            meta = obj.get('metadata', {})
            data = obj.get('data', {})
            if (obj.get('apiVersion') != 'v1' or obj.get('kind') != 'ConfigMap'
                    or set(obj) - {'apiVersion', 'kind', 'metadata', 'data'}
                    or meta.get('name') != RESOURCES[key][1] or meta.get('namespace') != namespace
                    or not isinstance(meta.get('uid'), str) or not meta['uid']
                    or not isinstance(meta.get('resourceVersion'), str) or not meta['resourceVersion']
                    or meta.get('labels') != {'istio.io/config': 'true'} or meta.get('annotations', {}) != {}
                    or meta.get('ownerReferences', []) != [] or meta.get('finalizers', []) != [] or meta.get('deletionTimestamp')
                    or not isinstance(data, dict) or set(data) != {field} or not isinstance(data[field], str)
                    or (key == 'IstioRoot' and not data[field])):
                raise ProofError('Native Istio trust copy or trusted reference profile changed')
        uid = target['metadata']['uid']
        if (target['data'] != reference['data'] or target['metadata']['labels'] != reference['metadata']['labels']
                or (key in state['identities'] and state['identities'][key] != uid)):
            raise ProofError('Native Istio trust copy differs or its captured identity changed')
        trust_uids[key] = uid
    expected_ca = get('configmap', 'kube-root-ca.crt', 'argocd') or {}
    for key, obj, kind in (('DefaultAccount', account, 'ServiceAccount'), ('RootCA', ca, 'ConfigMap')):
        meta = obj.get('metadata', {})
        if (obj.get('apiVersion') != 'v1' or obj.get('kind') != kind
                or meta.get('name') != RESOURCES[key][1] or meta.get('namespace') != NAME
                or not meta.get('uid') or not meta.get('resourceVersion') or meta.get('ownerReferences')
                or meta.get('finalizers') or meta.get('deletionTimestamp') or meta.get('labels')
                or set(meta.get('annotations', {})) - {'kubernetes.io/description'}
                or ('uid' in meta and key in state['identities'] and meta['uid'] != state['identities'][key])):
            raise ProofError('Native namespace default identity or profile changed')
        if key == 'DefaultAccount' and (set(obj) - {'apiVersion', 'kind', 'metadata', 'secrets', 'imagePullSecrets'}
                or obj.get('secrets') or obj.get('imagePullSecrets')):
            raise ProofError('Default ServiceAccount contains unexpected bindings')
        if key == 'RootCA' and (set(obj) - {'apiVersion', 'kind', 'metadata', 'data'}
                or set(obj.get('data', {})) != {'ca.crt'} or not obj['data']['ca.crt']
                or obj['data'] != expected_ca.get('data')):
            raise ProofError('Namespace root CA differs from its native public trust profile')
        state['identities'].setdefault(key, meta['uid'])
    state['identities'].update(trust_uids)
    return True


def namespace_inventory(state):
    """Every namespaced API must be readable; unknown objects retain the namespace."""
    deadline = time.monotonic() + 180
    resources = kube('api-resources', '--namespaced=true', '--verbs=list', '-o', 'name', timeout=35).splitlines()
    if (not resources or len(resources) > 256 or len(set(resources)) != len(resources)
            or any(not re.fullmatch(r'[a-z][a-z0-9.-]*', row) for row in resources)):
        raise ProofError('Namespaced API discovery is incomplete or exceeds its proof bound')
    allowed = {(kind, RESOURCES[key][1]): state['identities'].get(key) for key, kind in (
        ('Marker', 'ConfigMap'), ('Retained', 'ConfigMap'), ('RootCA', 'ConfigMap'), ('DefaultAccount', 'ServiceAccount'),
        ('IstioRoot', 'ConfigMap'), ('IstioCRL', 'ConfigMap'))}
    for resource in resources:
        if time.monotonic() >= deadline: raise ProofError('Namespace inspection exceeded its cleanup bound')
        result = json.loads(kube('get', resource, '-n', NAME, '-o', 'json', timeout=35))
        if not isinstance(result.get('items'), list): raise ProofError('Namespace resource list is incomplete')
        for obj in result['items']:
            meta = obj.get('metadata', {})
            uid = allowed.get((obj.get('kind'), meta.get('name')))
            if not uid or meta.get('uid') != uid or meta.get('namespace') != NAME:
                raise ProofError('Unexpected namespace resource blocks fixture cleanup; retained')


def create(config):
    public, files, _, authority = context(config)
    if any(read(key) for key in RESOURCES): raise ProofError('Proof refuses every preexisting fixture resource')
    state = {'version': VERSION, 'attempt': config['attempt'], 'publicRevision': config['publicRevision'], 'authority': authority, 'identities': {}, 'approval': 'A',
        'markerEnabled': True, 'sourceAvailable': True, 'acceptedApproval': None, 'acceptedMarkerEnabled': True, 'lastObservation': 'pending'}
    desired = declarations(config, state, public, files)
    try:
        for key in ('Namespace', 'Project', 'ExternalSecret', 'ApplicationSet'):
            if key == 'ApplicationSet' and any(read(child) for child in ('Application', 'Marker', 'Retained')):
                raise ProofError('Creation refuses preexisting child resources before enabling its controller')
            authority_guard(state)
            obj = json.loads(kube('create', '-f', '-', '-o', 'json', document=desired[key]))
            uid = obj.get('metadata', {}).get('uid'); owned(obj, uid, config)
            state['identities'][key] = uid
            declaration_guard(key, obj, uid, config, desired)
    except Exception:
        return {'state': state, 'created': False, 'failure': 'Fixture creation incomplete; only captured UID scope may be cleaned'}
    return {'state': state, 'created': True}


def resume_create(config, state):
    public, files, _, _ = context(config, state)
    if (state['acceptedApproval'] is not None or state['approval'] != 'A' or not state['markerEnabled']
            or not state['sourceAvailable'] or state['lastObservation'] != 'pending'):
        raise ProofError('Only interrupted initial fixture creation may resume')
    desired = declarations(config, state, public, files)
    for key in ('Namespace', 'Project', 'ExternalSecret', 'ApplicationSet'):
        obj = read(key)
        if not obj:
            if key in state['identities']: raise ProofError('Resume refuses a missing captured fixture owner')
            if key == 'ApplicationSet' and any(read(child) for child in ('Application', 'Marker', 'Retained')):
                raise ProofError('Resume refuses preexisting child resources before enabling its controller')
            authority_guard(state)
            obj = json.loads(kube('create', '-f', '-', '-o', 'json', document=desired[key]))
        # Recovery may capture only this unique attempt's exact fixed declaration.
        uid = state['identities'].get(key, obj.get('metadata', {}).get('uid'))
        declaration_guard(key, obj, uid, config, desired)
        state['identities'].setdefault(key, uid)
    return {'state': state, 'created': True}


def observe(config, state, *, rejected=False, timeout=240):
    public, files, _, _ = context(config, state); desired = declarations(config, state, public, files)
    if rejected and state['lastObservation'] == 'rejected':
        raise ProofError('Restore valid A and observe cleared native error before another rejection case')
    def check():
        if not controls(config, state, desired): return False
        if rejected:
            if state['acceptedApproval'] is None: raise ProofError('Receipt rejection requires a captured accepted child')
            if not child(config, state, desired, state['acceptedApproval'], state['acceptedMarkerEnabled']): return False
            conditions = (read('ApplicationSet') or {}).get('status', {}).get('conditions', [])
            return (not (read('ApplicationSet') or {}).get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/application-set-refresh')
                and any(row.get('type') == 'ErrorOccurred' and row.get('status') == 'True'
                    and (('Private source acceptance refused' in row.get('message', '')) == state['sourceAvailable'])
                    for row in conditions))
        conditions = (read('ApplicationSet') or {}).get('status', {}).get('conditions', [])
        if (any(row.get('type') == 'ErrorOccurred' and row.get('status') == 'True' for row in conditions)
                or not any(row.get('type') == 'ParametersGenerated' and row.get('status') == 'True' for row in conditions)):
            return False
        if not child(config, state, desired, state['approval'], state['markerEnabled']): return False
        if not defaults(state): return False
        state.update(acceptedApproval=state['approval'], acceptedMarkerEnabled=state['markerEnabled'])
        return True
    poll(check, timeout=timeout)
    state['lastObservation'] = 'rejected' if rejected else 'accepted'
    return {'state': state, 'parent_error_retains_child': rejected, 'accepted': not rejected}


def change(config, state, *, approval=None, marker=None, available=None):
    public, files, _, _ = context(config, state); old = declarations(config, state, public, files)
    if not controls(config, state, old): raise ProofError('Proof credentials are pending')
    if state['acceptedApproval'] is None: raise ProofError('Proof change requires its captured accepted child')
    if (approval is not None or marker is not None or available is False) and state['lastObservation'] != 'accepted':
        raise ProofError('Restore valid input and observe a fresh accepted baseline before a new case')
    if not child(config, state, old, state['acceptedApproval'], state['acceptedMarkerEnabled']): raise ProofError('Accepted proof child is not ready')
    updated = copy.deepcopy(state)
    updated['lastObservation'] = 'pending'
    if approval is not None:
        if approval != 'B' or state['acceptedApproval'] != 'A': raise ProofError('Only the approved A-to-B fixture transition is allowed')
        updated['approval'] = approval
    if marker is not None:
        if marker is not False or state['acceptedApproval'] != 'B': raise ProofError('Only explicit synthetic marker removal is allowed')
        updated['markerEnabled'] = marker
    if available is not None:
        if type(available) is not bool: raise ProofError('Invalid synthetic source availability request')
        if available == state['sourceAvailable']: raise ProofError('Source availability declaration is already at this state')
        updated['sourceAvailable'] = available
    current = read('ApplicationSet'); new = declarations(config, updated, public, files)['ApplicationSet']['spec']
    ops = [{'op': 'test', 'path': '/metadata/uid', 'value': state['identities']['ApplicationSet']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/spec', 'value': old['ApplicationSet']['spec']}, {'op': 'replace', 'path': '/spec', 'value': new}]
    authority_guard(state)
    result = json.loads(kube('patch', 'applicationset', NAME, '-n', 'argocd', '--type=json', '--patch-file=/dev/stdin', '-o', 'json', document=ops))
    if result.get('spec') != new or result.get('metadata', {}).get('uid') != state['identities']['ApplicationSet']:
        raise ProofError('Proof declaration update has no same-UID persistence witness')
    return {'state': updated, 'updated': True}


def marker_patch(obj, data, config, state, before):
    owned(obj, state['identities'].get('Marker'), config)
    if (obj.get('data') != before or obj['metadata'].get('name') != 'approval-marker'
            or obj['metadata'].get('namespace') != NAME or obj.get('binaryData') or obj.get('immutable')
            or obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != NAME + ':/ConfigMap:' + NAME + '/approval-marker'):
        raise ProofError('Proof marker changed before its scoped patch')
    ops = [{'op': 'test', 'path': '/metadata/uid', 'value': state['identities']['Marker']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/data', 'value': obj['data']}, {'op': 'replace', 'path': '/data', 'value': data}]
    authority_guard(state)
    result = json.loads(kube('patch', 'configmap', 'approval-marker', '-n', NAME, '--type=json', '--patch-file=/dev/stdin', '-o', 'json', document=ops))
    if result.get('metadata', {}).get('uid') != obj['metadata']['uid'] or result.get('data') != data:
        raise ProofError('Proof marker patch has no same-UID persistence witness')


def drift(config, state, *, timeout=240):
    public, files, _, _ = context(config, state); desired = declarations(config, state, public, files)
    if not controls(config, state, desired): raise ProofError('Proof credentials are pending')
    approval = state['acceptedApproval']
    if approval is None or not state['acceptedMarkerEnabled'] or not child(config, state, desired, approval, True):
        raise ProofError('Drift requires an already accepted healthy fixture')
    if state['approval'] != approval or state['markerEnabled'] != state['acceptedMarkerEnabled']:
        raise ProofError('Drift refuses an unaccepted approval or marker-removal transition')
    expected = {'revision': config['receipt' + approval]['revision']}
    nonce = {'revision': 'source-proof-drift-' + uuid.uuid4().hex}
    result = {'self_heal_verified': False, 'cleanup_restored': False, 'cleanup_complete': False}
    try:
        marker_patch(read('Marker'), nonce, config, state, expected)
        def repaired():
            if not controls(config, state, desired): raise ProofError('Proof credentials became pending')
            actual = read('Marker')
            if actual.get('data') == expected: return child(config, state, desired, approval, True)
            if actual.get('data') != nonce: raise ProofError('Marker drift changed outside this attempt')
            child(config, state, desired, approval, True, ready=False, drift=nonce['revision'])
            return False
        poll(repaired, timeout=timeout); result['self_heal_verified'] = True
    except Exception:
        result['failure'] = 'Native marker repair unavailable or unverified'
    finally:
        try:
            if not controls(config, state, desired): raise ProofError('Proof credentials became pending')
            actual = read('Marker')
            if actual.get('data') != expected:
                if actual.get('data') != nonce: raise ProofError('Compensation refuses unowned drift')
                child(config, state, desired, approval, True, ready=False, drift=nonce['revision'])
                if not quiet_child(read('Application')): raise ProofError('Compensation refuses pending reconciliation')
                marker_patch(actual, expected, config, state, nonce); result['cleanup_restored'] = True; result['self_heal_verified'] = False
            result['cleanup_complete'] = True
        except Exception:
            result['self_heal_verified'] = False; result['failure'] = 'Owned marker compensation declined; drift may remain'
    return result


def refresh(config, state):
    """Explicit synthetic generator refresh; never used to count natural marker repair."""
    public, files, _, _ = context(config, state); desired = declarations(config, state, public, files)
    if state['lastObservation'] != 'accepted': raise ProofError('Synthetic refresh requires a fresh accepted baseline')
    if not controls(config, state, desired): raise ProofError('Proof credentials are pending')
    appset = read('ApplicationSet'); annotations = appset['metadata'].get('annotations', {})
    if annotations != desired['ApplicationSet']['metadata']['annotations']:
        raise ProofError('Synthetic refresh refuses unexpected parent annotations')
    ops = [{'op': 'test', 'path': '/metadata/uid', 'value': state['identities']['ApplicationSet']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': appset['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/spec', 'value': desired['ApplicationSet']['spec']},
        {'op': 'test', 'path': '/metadata/annotations', 'value': annotations},
        {'op': 'add', 'path': '/metadata/annotations/argocd.argoproj.io~1application-set-refresh', 'value': 'true'}]
    authority_guard(state)
    result = json.loads(kube('patch', 'applicationset', NAME, '-n', 'argocd', '--type=json', '--patch-file=/dev/stdin', '-o', 'json', document=ops))
    if (result.get('metadata', {}).get('uid') != state['identities']['ApplicationSet']
            or result['metadata'].get('annotations', {}).get('argocd.argoproj.io/application-set-refresh') != 'true'):
        raise ProofError('Synthetic refresh has no same-UID persistence witness')
    state['lastObservation'] = 'pending'
    return {'state': state, 'refresh_queued': True}


def cleanup(config, state):
    public, files, _, _ = context(config, state); desired = declarations(config, state, public, files)
    if read('Namespace'):
        owned(read('Namespace'), state['identities'].get('Namespace'), config)
        if not defaults(state): raise ProofError('Namespace defaults are not captured; cleanup retained')
        namespace_inventory(state)
    order = ('ApplicationSet', 'Application', 'ExternalSecret', 'Secret', 'Marker', 'Retained', 'Project', 'Namespace')
    def target(key, obj):
        uid = state['identities'].get(key)
        owners = obj.get('metadata', {}).get('ownerReferences', [])
        expected = []
        if key in ('Application', 'Secret'):
            parent_key = 'ApplicationSet' if key == 'Application' else 'ExternalSecret'
            parent_kind = parent_key; parent_name = NAME if key == 'Application' else NAME + '-source'
            expected = [{'apiVersion': 'argoproj.io/v1alpha1' if key == 'Application' else 'external-secrets.io/v1',
                'kind': parent_kind, 'name': parent_name, 'uid': state['identities'].get(parent_key), 'controller': True, 'blockOwnerDeletion': True}]
            if not read(parent_key) and not owners: expected = []  # Exact captured child after orphaning its parent.
        owned(obj, uid, config, owners=expected)
        if key in desired:
            declaration_guard(key, obj, uid, config, desired)
        if key == 'Application':
            if (obj.get('kind') != 'Application' or obj.get('apiVersion') != 'argoproj.io/v1alpha1'
                    or obj['metadata'].get('name') != NAME or obj['metadata'].get('namespace') != 'argocd'
                    or set(obj) - {'apiVersion', 'kind', 'metadata', 'spec', 'status'}
                    or obj.get('operation') is not None or obj.get('status', {}).get('operationState', {}).get('phase') in ('Running', 'Terminating')
                    or obj.get('spec') != child_spec(config, state, desired, state['acceptedApproval'] or state['approval'],
                        state['acceptedMarkerEnabled'] if state['acceptedApproval'] else state['markerEnabled'])):
                raise ProofError('Cleanup refuses pending or changed child reconciliation')
        if key == 'Marker' and obj.get('data') != {'revision': config['receipt' + (state['acceptedApproval'] or state['approval'])]['revision']}:
            raise ProofError('Cleanup refuses marker data outside accepted scope')
        if key == 'Retained' and obj.get('data') != RETAINED:
            raise ProofError('Cleanup refuses foreign retained data')
        if key in ('Marker', 'Retained') and (set(obj) - {'apiVersion', 'kind', 'metadata', 'data'}
                or obj.get('kind') != 'ConfigMap' or obj.get('apiVersion') != 'v1'
                or obj['metadata'].get('name') != RESOURCES[key][1] or obj['metadata'].get('namespace') != NAME
                or obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                    NAME + ':/ConfigMap:' + NAME + '/' + RESOURCES[key][1]):
            raise ProofError('Cleanup refuses unexpected synthetic ConfigMap fields')
        if key == 'Namespace' and obj.get('spec', {}) not in ({}, {'finalizers': ['kubernetes']}, {'finalizers': []}):
            raise ProofError('Cleanup refuses unexpected Namespace finalizers')
        if key == 'Secret':
            data = {name: base64.b64decode(value, validate=True).decode() for name, value in obj.get('data', {}).items()}
            if (set(obj) - {'apiVersion', 'kind', 'metadata', 'data', 'type'} or obj.get('type') not in (None, 'Opaque')
                    or obj.get('kind') != 'Secret' or obj.get('apiVersion') != 'v1'
                    or obj['metadata'].get('name') != NAME + '-source' or obj['metadata'].get('namespace') != 'argocd'
                    or set(data) != {'type', 'url', 'project', 'githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'}
                    or data['url'] != config['privateRepository'] or data['project'] != NAME or data['type'] != 'git'
                    or not all(data.values())):
                raise ProofError('Cleanup refuses changed credential scope or fields')
    # Validate every remaining target before removing a reconciler or its data.
    for key in order:
        obj = read(key)
        if obj: target(key, obj)
    for key in order:
        obj = read(key)
        if not obj: continue
        target(key, obj)
        uid = state['identities'][key]
        if key == 'Namespace':
            if not defaults(state): raise ProofError('Namespace defaults became unavailable; cleanup retained')
            namespace_inventory(state)
        _, name, _, path = RESOURCES[key]
        authority_guard(state)
        kube('delete', '--raw=' + path + name, '-f', '-', document={'apiVersion': 'v1', 'kind': 'DeleteOptions',
            'preconditions': {'uid': uid, 'resourceVersion': obj['metadata']['resourceVersion']}, 'propagationPolicy': 'Orphan'})
        poll(lambda: read(key) is None, timeout=180)
    return {'cleanup_complete': True}


def main(envelope):
    if (not isinstance(envelope, dict) or not {'action', 'config'} <= set(envelope)
            or set(envelope) - {'action', 'config', 'state', 'timeout'}): raise ProofError('Invalid proof operation envelope')
    action, config, state = envelope['action'], envelope['config'], envelope.get('state')
    if action == 'create': return create(config)
    config_guard(config, state)
    if state is None: raise ProofError('Proof operation requires its captured UID scope')
    if action == 'resume-create': return resume_create(config, state)
    if action in ('accept', 'reject'): return observe(config, state, rejected=action == 'reject', timeout=envelope.get('timeout', 240))
    if action == 'refresh': return refresh(config, state)
    if action == 'approve-b': return change(config, state, approval='B')
    if action == 'remove-marker': return change(config, state, marker=False)
    if action == 'source-failure': return change(config, state, available=False)
    if action == 'restore-source': return change(config, state, available=True)
    if action == 'drift': return drift(config, state, timeout=envelope.get('timeout', 240))
    if action == 'cleanup': return cleanup(config, state)
    raise ProofError('Unknown fixed proof operation')


def failure_result(envelope, error):
    actions = ('create', 'resume-create', 'accept', 'reject', 'refresh', 'approve-b', 'remove-marker',
        'source-failure', 'restore-source', 'drift', 'cleanup')
    operation = envelope.get('action') if isinstance(envelope, dict) else None
    result = {'verified': False, 'operation': operation if operation in actions else 'input',
        'failure': str(error) if isinstance(error, ProofError) else 'Fixed native source proof declined; private diagnostics withheld'}
    try:
        config_guard(envelope['config'], envelope['state'])
        result['state'] = envelope['state']  # Captured UID recovery scope, never private source inputs.
    except Exception:
        pass
    return result


if __name__ == '__main__':
    envelope = None
    try:
        raw = sys.stdin.read(1048577)
        if len(raw) > 1048576: raise ProofError('Proof envelope exceeds its bound')
        envelope = json.loads(raw)
        result = main(envelope)
    except Exception as error:
        result = failure_result(envelope, error)
    print(json.dumps(result))
    raise SystemExit(1 if result.get('failure') else 0)
