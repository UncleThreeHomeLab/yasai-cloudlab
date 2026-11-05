"""Explicit fixed-scope native qualification; never a production onboarding writer.

Parent supplies private config/receipt A and B, and edits only its dedicated proof
branch. Persist each returned state: create, seed, adopt, accept A.
Seed intent precedes child creation; adoption intent precedes AppSet
creation. The healthy seed and its resources must keep their UIDs after adoption.
Then test each invalid/missing receipt from an accepted
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
from playbooks.argocd.files.private_sources import acceptance_spec, validate_acceptance, consumer_contract, validate_consumer_acceptance
from playbooks.istio.files.kube import get, kube

VERSION = 'cloudlab-source-acceptance-proof/v1'
NAME = 'cloudlab-prices-source-proof'
TRACKING_OWNER = 'cloudlab-prices-source-proof-root'
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

REGISTRY_PROFILE = {'consumer': None, 'version': VERSION, 'name': NAME, 'tracking_owner': TRACKING_OWNER,
    'chart': CHART, 'resources': RESOURCES, 'rejection': 'Private source acceptance refused'}
CONSUMER_VERSION = 'cloudlab-consumer-source-proof/v1'


def _consumer_profile(consumer, name):
    return {'consumer': consumer, 'version': CONSUMER_VERSION, 'name': name, 'tracking_owner': name + '-root',
        'chart': 'ansible/playbooks/argocd/tests/fixtures/consumer-acceptance', 'rejection': 'Consumer source acceptance refused',
        'resources': {key: tuple(value.replace(NAME, name) if isinstance(value, str) else value for value in row)
            for key, row in RESOURCES.items()}}


CONSUMER_PROFILES = {'observability': _consumer_profile('observability', 'cloudlab-prices-observability-proof'),
    'permissions': _consumer_profile('permissions', 'cloudlab-prices-permissions-proof')}


class ProofError(RuntimeError):
    pass


def config_guard(config, state=None, *, profile=REGISTRY_PROFILE):
    fields = {'version', 'attempt', 'publicRevision', 'privateRepository', 'privateBranch', 'receiptA', 'receiptB'}
    consumer = profile['consumer']
    fixed = CONSUMER_PROFILES.get(consumer) if consumer is not None else REGISTRY_PROFILE
    if (fixed is None or profile.get('resources') is not fixed['resources']
            or any(profile.get(key) != value for key, value in fixed.items()) or set(profile) - set(fixed) - {'peer'}):
        raise ProofError('Unknown fixed proof profile')
    if consumer is not None: fields.add('consumer')
    if (not isinstance(config, dict) or set(config) != fields or config['version'] != profile['version']
            or not re.fullmatch('[a-f0-9]{32}', config.get('attempt', ''))
            or not re.fullmatch('[a-f0-9]{40}', config.get('publicRevision', ''))
            or not re.fullmatch(r'https://github[.]com/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+[.]git', config.get('privateRepository', ''))
            or config['privateRepository'] == PUBLIC
            or not re.fullmatch(r'proof/prices-source-[a-f0-9]{32}' if consumer is None else r'proof/prices-consumers-[a-f0-9]{32}', config.get('privateBranch', ''))
            or (consumer is not None and (config.get('consumer') != consumer or config['privateBranch'] != 'proof/prices-consumers-' + config['attempt']))):
        raise ProofError('Invalid fixed source proof inputs')
    for approval in ('A', 'B'):
        receipt = config['receipt' + approval]
        if consumer is None:
            validate_acceptance(receipt, config['privateRepository'], commitment(config, approval, profile=profile))
        else:
            validate_consumer_acceptance(receipt, config['privateRepository'], consumer_contract(consumer_public(config, approval, profile), consumer))
    if (config['receiptA']['revision'] == config['receiptB']['revision'] or config['receiptA']['nonce'] == config['receiptB']['nonce']):
        raise ProofError('Proof revisions and receipt nonces must differ')
    state_fields = {'version', 'attempt', 'publicRevision', 'authority', 'identities', 'approval', 'markerEnabled', 'sourceAvailable', 'acceptedApproval', 'acceptedMarkerEnabled', 'lastObservation', 'adoptionPhase'}
    if consumer is not None: state_fields.add('consumer')
    if state is not None and (not isinstance(state, dict) or set(state) != state_fields
            or state['version'] != profile['version'] or state['publicRevision'] != config['publicRevision']
            or state['attempt'] != config['attempt']
            or (consumer is not None and state.get('consumer') != consumer)
            or state['approval'] not in ('A', 'B') or state['acceptedApproval'] not in (None, 'A', 'B')
            or state['lastObservation'] not in ('pending', 'accepted', 'rejected')
            or state['adoptionPhase'] not in ('seed-intent', 'seeded', 'adopting', 'adopted')
            or not isinstance(state['authority'], dict) or set(state['authority']) != {'Root', 'ApplicationSetController'}
            or any(not isinstance(uid, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', uid) for uid in state['authority'].values())
            or any(type(state[key]) is not bool for key in ('markerEnabled', 'sourceAvailable', 'acceptedMarkerEnabled'))
            or not isinstance(state['identities'], dict) or not set(state['identities']) <= set(profile['resources'])
            or any(not isinstance(uid, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', uid) for uid in state['identities'].values())):
        raise ProofError('Invalid captured source proof scope')
    if state is not None and state['adoptionPhase'] in ('adopting', 'adopted'):
        required = {'Namespace', 'Project', 'ExternalSecret', 'Secret', 'Application', 'Marker', 'Retained',
            'DefaultAccount', 'RootCA', 'IstioRoot', 'IstioCRL'}
        if state['adoptionPhase'] == 'adopted': required.add('ApplicationSet')
        if not required <= set(state['identities']):
            raise ProofError('Adoption requires every previously observed seed identity')


def commitment(config, approval, *, profile=REGISTRY_PROFILE):
    row = config['receipt' + approval]
    if profile['consumer'] is not None:
        return hashlib.sha256(('\n'.join([row['version'], row['consumer'], config['privateRepository'], str(len(row['paths'])),
            *row['paths'], row['revision'], row['nonce'], ''])).encode()).hexdigest()
    return hashlib.sha256(('\n'.join([row['version'], row['consumer'], config['privateRepository'],
        'platform/sources.yaml', row['revision'], row['nonce'], ''])).encode()).hexdigest()


def consumer_public(config, approval, profile):
    """Synthetic qualification context only; never a production reader override."""
    public = {'repository': PUBLIC, 'revision': 'main', 'identity': {'enabled': True},
        'externalSecrets': {'enabled': True, 'reconcile': True}, 'admission': {'enabled': True},
        'services': {'enabled': True, 'revision': config['publicRevision'], 'catalogPath': 'services/catalog-source-proof.yaml'}}
    settings = {'enabled': True, 'revision': config['publicRevision'], 'acceptanceCommitment': commitment(config, approval, profile=profile)}
    public[profile['consumer']] = ({'enabled': True, 'configuration': dict(settings, paused=False)}
        if profile['consumer'] == 'observability' else settings)
    return public


def selected_profile(config):
    if not isinstance(config, dict): raise ProofError('Invalid fixed proof inputs')
    if config.get('version') == VERSION: return REGISTRY_PROFILE
    if config.get('version') == CONSUMER_VERSION and config.get('consumer') in CONSUMER_PROFILES:
        return CONSUMER_PROFILES[config['consumer']]
    raise ProofError('Unknown fixed proof version or consumer')


def peer_snapshot(profile):
    if profile['consumer'] is None: return None
    other = CONSUMER_PROFILES['permissions' if profile['consumer'] == 'observability' else 'observability']
    result = {}
    for key, body in (('Application', 'spec'), ('Retained', 'data')):
        obj = read(key, profile=other)
        if obj is None:
            result[key] = None
        else:
            meta = obj.get('metadata', {})
            if not meta.get('uid'): raise ProofError('Other consumer observation lacks its resource identity')
            result[key] = {'body': copy.deepcopy(obj.get(body)), 'metadata': {field: copy.deepcopy(meta.get(field))
                for field in ('uid', 'ownerReferences', 'labels', 'annotations', 'finalizers', 'deletionTimestamp')}}
    return result


def peer_guard(profile):
    if profile['consumer'] is not None and (not isinstance(profile.get('peer'), dict)
            or peer_snapshot(profile) != profile['peer']['snapshot']):
        raise ProofError('Other consumer resource changed during this operation; retry serialized proof')


def read(key, *, profile=REGISTRY_PROFILE):
    kind, name, namespace, _ = profile['resources'][key]
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


def context(config, state=None, *, profile=REGISTRY_PROFILE):
    config_guard(config, state, profile=profile)
    deadline = time.monotonic() + 180
    if profile['consumer'] is not None:
        if not isinstance(profile.get('peer'), dict): raise ProofError('Consumer actions require their fixed operation envelope')
        quota = native.source_snapshot.request('rate_limit', deadline).get('resources', {}).get('core', {})
        remaining = quota.get('remaining')
        if type(remaining) is not int or remaining < (4 if profile.get('peer', {}).get('cleanup') else 12):
            raise ProofError('Public source API budget reserved for cleanup; retry after reset')
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
    metadata = {}
    def fetch(path, deadline):
        if path not in metadata: metadata[path] = native.source_snapshot.request(path, deadline)
        return metadata[path]
    snapshot = lambda path: native.source_snapshot.chart_files({'repository': PUBLIC, 'revision': config['publicRevision'], 'path': path}, fetch=fetch, deadline=deadline)
    files = snapshot('gitops/roots/public')
    fixture = snapshot(profile['chart'])
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


def authority_guard(state, *, profile=REGISTRY_PROFILE):
    peer_guard(profile)
    for key, kind, name in (('Root', 'application.argoproj.io', 'cloudlab-public-root'),
            ('ApplicationSetController', 'deployment', 'argocd-applicationset-controller')):
        obj = get(kind, name, 'argocd') or {}
        if obj.get('metadata', {}).get('uid') != state['authority'][key] or obj['metadata'].get('deletionTimestamp'):
            raise ProofError('Captured trusted Root or ApplicationSet controller was replaced')


def declarations(config, state, public, files, *, profile=REGISTRY_PROFILE):
    labels = {'cloudlab.io/owner': OWNER, 'cloudlab.io/proof-attempt': config['attempt']}
    meta = lambda name, namespace='argocd': dict(name=name, labels=labels.copy(), **({'namespace': namespace} if namespace else {}))
    values = copy.deepcopy(public)
    values['privateSources'] = {'enabled': True, 'revision': config['publicRevision'], 'acceptanceCommitment': commitment(config, state['approval'], profile=profile)}
    if profile['consumer'] is None:
        spec = acceptance_spec(values, config['privateRepository'], config['publicRevision'], files=files)
    else:
        contract = consumer_contract(consumer_public(config, state['approval'], profile), profile['consumer'])
        gate = files['consumer-source-acceptance.tmpl'].decode()
        constants = {'VERSION': contract['version'], 'CONSUMER': contract['consumer'], 'PRIVATE_REPOSITORY': config['privateRepository'],
            'COMMITMENT': contract['acceptanceCommitment'], 'PATHS_LF': '\n'.join(contract['paths'])}
        for key, value in constants.items(): gate = gate.replace('@@' + key + '@@', json.dumps(value))
        spec = {'goTemplate': True, 'goTemplateOptions': ['missingkey=error'], 'generators': [{'merge': {
            'mergeKeys': ['consumer'], 'generators': [{'list': {'elements': [{'consumer': profile['consumer']}]}}, {'git': {
                'repoURL': config['privateRepository'], 'revision': 'main', 'files': [{'path': contract['receiptPath']}]}}]}}],
            'syncPolicy': {'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True}, 'template': {'metadata': {}, 'spec': {
                'project': profile['name'], 'destination': {'server': 'https://kubernetes.default.svc', 'namespace': profile['name']},
                'sources': [{'repoURL': PUBLIC, 'targetRevision': config['publicRevision'], 'path': profile['chart'], 'helm': {
                    'valueFiles': ['$values/' + path for path in contract['paths']]}},
                    {'repoURL': config['privateRepository'], 'targetRevision': gate, 'ref': 'values'}],
                'syncPolicy': {'automated': {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': False},
                    'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true', 'PruneLast=true']}}}}
    branch = config['privateBranch'] if state['sourceAvailable'] else config['privateBranch'] + '-unavailable-' + config['attempt']
    spec['generators'][0]['merge']['generators'][1]['git']['revision'] = branch
    child = spec['template']; child['metadata'] = meta(profile['name'])
    child['metadata']['annotations'] = {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false',
        'argocd.argoproj.io/tracking-id': profile['tracking_owner'] + ':argoproj.io/Application:argocd/' + profile['name']}
    child['spec']['project'] = profile['name']; child['spec']['destination']['namespace'] = profile['name']
    child['spec']['sources'][0].update(path=profile['chart'])
    gate = child['spec']['sources'][1]['targetRevision']
    child['spec']['sources'][0]['helm']['parameters'] = [{'name': 'acceptedRevision', 'value': gate, 'forceString': True},
        {'name': 'proofAttempt', 'value': config['attempt'], 'forceString': True}, {'name': 'markerEnabled', 'value': str(state['markerEnabled']).lower()}]
    if profile['consumer'] is not None:
        child['spec']['sources'][0]['helm']['parameters'].append({'name': 'consumer', 'value': profile['consumer'], 'forceString': True})
    child['spec']['syncPolicy']['automated']['allowEmpty'] = False
    secret_spec = native.reader_spec(config['privateRepository'], profile['name'] + '-source', profile['name'])
    secret_spec['target']['template']['metadata']['labels'].update(labels)
    parent_meta = meta(profile['name']); parent_meta['annotations'] = {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}
    return {
        'Namespace': {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': meta(profile['name'], None)},
        'Project': {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject', 'metadata': meta(profile['name']), 'spec': {
            'sourceRepos': [PUBLIC, config['privateRepository']], 'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': profile['name']}],
            'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [{'group': '', 'kind': 'ConfigMap'}]}},
        'ExternalSecret': {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'metadata': meta(profile['name'] + '-source'), 'spec': secret_spec},
        'ApplicationSet': {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'metadata': parent_meta, 'spec': spec},
    }


def owned(obj, uid, config, *, owners=None, profile=REGISTRY_PROFILE):
    meta = (obj or {}).get('metadata', {})
    labels = meta.get('labels', {})
    if (not uid or meta.get('uid') != uid or not meta.get('resourceVersion') or meta.get('deletionTimestamp')
            or meta.get('ownerReferences', []) != (owners or [])
            or meta.get('finalizers', []) not in ([], [native.ESO_FINALIZER])
            or labels.get('cloudlab.io/owner') != OWNER or labels.get('cloudlab.io/proof-attempt') != config['attempt']):
        raise ProofError('Proof resource identity or ownership changed')
    eso_labels = {'reconcile.external-secrets.io/managed', 'reconcile.external-secrets.io/created-by'}
    if (set(labels) - {'cloudlab.io/owner', 'cloudlab.io/proof-attempt', 'kubernetes.io/metadata.name', 'argocd.argoproj.io/instance', 'argocd.argoproj.io/secret-type'} - eso_labels
            or ('kubernetes.io/metadata.name' in labels and labels['kubernetes.io/metadata.name'] != profile['name'])
            or ('argocd.argoproj.io/instance' in labels and labels['argocd.argoproj.io/instance'] != profile['name'])
            or ('argocd.argoproj.io/secret-type' in labels and (obj.get('kind') != 'Secret' or labels['argocd.argoproj.io/secret-type'] != 'repository'))):
        raise ProofError('Proof resource has unexpected labels')
    if obj.get('kind') == 'Secret':
        if (meta.get('name') != profile['name'] + '-source' or meta.get('namespace') != 'argocd'
                or labels.get('reconcile.external-secrets.io/managed') != 'true'
                or labels.get('reconcile.external-secrets.io/created-by') != hashlib.sha3_224(('argocd/' + profile['name'] + '-source').encode()).hexdigest()):
            raise ProofError('Proof Secret native ESO metadata differs from its fixed owner profile')
    elif eso_labels & set(labels):
        raise ProofError('Native ESO Secret labels are forbidden on other proof resources')
    if meta.get('finalizers') and obj.get('kind') != 'ExternalSecret':
        raise ProofError('Proof resource has unexpected finalizers')


def declaration_guard(key, obj, uid, config, desired, *, profile=REGISTRY_PROFILE):
    owned(obj, uid, config, profile=profile)
    if (obj.get('kind') != desired[key]['kind'] or obj.get('apiVersion') != desired[key]['apiVersion']
            or obj['metadata'].get('name') != desired[key]['metadata']['name']
            or obj['metadata'].get('namespace') != desired[key]['metadata'].get('namespace')
            or set(obj) - {'apiVersion', 'kind', 'metadata', 'spec', 'status'}
            or ('spec' in desired[key] and obj.get('spec') != desired[key]['spec'])
            or (key == 'Namespace' and obj.get('spec', {}) not in ({}, {'finalizers': ['kubernetes']}, {'finalizers': []}))):
        raise ProofError('Proof source, project or credential declaration changed')


def controls(config, state, desired, *, profile=REGISTRY_PROFILE):
    authority_guard(state, profile=profile)
    keys = ('Namespace', 'Project', 'ExternalSecret')
    if state['adoptionPhase'] in ('adopting', 'adopted'): keys += ('ApplicationSet',)
    elif read('ApplicationSet', profile=profile): raise ProofError('AppSet exists before recorded adoption intent')
    for key in keys:
        declaration_guard(key, read(key, profile=profile), state['identities'].get(key), config, desired, profile=profile)
    secret = read('Secret', profile=profile) or {}
    external = read('ExternalSecret', profile=profile)
    if not secret:
        if 'Secret' in state['identities']: raise ProofError('Captured proof credential is missing')
        return False
    owner = {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'name': profile['name'] + '-source',
        'uid': state['identities']['ExternalSecret'], 'controller': True, 'blockOwnerDeletion': True}
    owned(secret, state['identities'].get('Secret', secret.get('metadata', {}).get('uid')), config, owners=[owner], profile=profile)
    data = {key: base64.b64decode(value, validate=True).decode() for key, value in secret.get('data', {}).items()}
    if (set(data) != {'type', 'url', 'project', 'githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'}
            or data['type'] != 'git' or data['url'] != config['privateRepository'] or data['project'] != profile['name']
            or not all(data[key] for key in ('githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'))
            or secret.get('type') not in (None, 'Opaque') or secret.get('kind') != 'Secret' or secret.get('apiVersion') != 'v1'
            or secret['metadata'].get('name') != profile['name'] + '-source' or secret['metadata'].get('namespace') != 'argocd'
            or secret['metadata'].get('labels', {}).get('argocd.argoproj.io/secret-type') != 'repository'
            or set(secret) - {'apiVersion', 'kind', 'metadata', 'data', 'type'}):
        raise ProofError('Proof repository credential is not ready or exact-scoped')
    state['identities'].setdefault('Secret', secret['metadata']['uid'])
    return native.condition(external, 'Ready')


def child_spec(config, state, desired, approval, marker, *, profile=REGISTRY_PROFILE):
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


def child_metadata(app, desired, *, profile=REGISTRY_PROFILE):
    expected = desired['ApplicationSet']['spec']['template']['metadata']
    if (app.get('kind') != 'Application' or app.get('apiVersion') != 'argoproj.io/v1alpha1'
            or app['metadata'].get('name') != profile['name'] or app['metadata'].get('namespace') != 'argocd'
            or app['metadata'].get('annotations', {}) != expected['annotations']
            or set(app) - {'apiVersion', 'kind', 'metadata', 'spec', 'status', 'operation'}):
        raise ProofError('Proof child metadata or protection differs from recorded intent')


def child(config, state, desired, approval, marker, *, ready=True, drift=None, profile=REGISTRY_PROFILE):
    app = read('Application', profile=profile) or {}
    if not app:
        if 'Application' in state['identities']: raise ProofError('Captured proof Application is missing')
        return False
    pending_owner = state['adoptionPhase'] == 'adopting' and not app['metadata'].get('ownerReferences')
    owners = []
    if state['adoptionPhase'] in ('adopting', 'adopted') and not pending_owner:
        owners = [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': profile['name'],
            'uid': state['identities']['ApplicationSet'], 'controller': True, 'blockOwnerDeletion': True}]
    owned(app, state['identities'].get('Application', app.get('metadata', {}).get('uid')), config, owners=owners, profile=profile)
    child_metadata(app, desired, profile=profile)
    if app.get('spec') != child_spec(config, state, desired, approval, marker, profile=profile):
        if (state['acceptedApproval'] and (approval != state['acceptedApproval'] or marker != state['acceptedMarkerEnabled'])
                and app.get('spec') == child_spec(config, state, desired, state['acceptedApproval'], state['acceptedMarkerEnabled'], profile=profile)):
            return False
        raise ProofError('Proof child source or scope differs from accepted intent')
    state['identities'].setdefault('Application', app['metadata']['uid'])
    if pending_owner: return False
    if ready and (not quiet_child(app) or not native.matches_revision(app, config['publicRevision'])
            or app.get('status', {}).get('sync', {}).get('status') != 'Synced'
            or app.get('status', {}).get('health', {}).get('status') != 'Healthy'
            or any(row.get('type', '').endswith('Error') for row in app.get('status', {}).get('conditions', []))):
        return False
    for key, data in (('Retained', RETAINED), ('Marker', {'revision': drift or config['receipt' + approval]['revision']})):
        obj = read(key, profile=profile)
        if key == 'Marker' and not marker:
            if obj:
                owned(obj, state['identities'].get(key), config, profile=profile)
                if obj.get('data') != {'revision': config['receipt' + state['acceptedApproval']]['revision']}:
                    raise ProofError('Removal refuses a marker changed outside accepted intent')
                return False
            continue
        if not obj:
            if key in state['identities']: raise ProofError('Captured proof ConfigMap is missing')
            return False
        owned(obj, state['identities'].get(key, (obj or {}).get('metadata', {}).get('uid')), config, profile=profile)
        meta = obj['metadata']
        if (key == 'Marker' and approval != state['acceptedApproval'] and state['acceptedApproval']
                and obj.get('data') == {'revision': config['receipt' + state['acceptedApproval']]['revision']}):
            return False
        if (obj.get('apiVersion') != 'v1' or obj.get('kind') != 'ConfigMap' or obj.get('data') != data
                or obj.get('binaryData') or obj.get('immutable')
                or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') != profile['name'] + ':/ConfigMap:' + profile['name'] + '/' + profile['resources'][key][1]):
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


def defaults(state, *, profile=REGISTRY_PROFILE):
    account, ca = read('DefaultAccount', profile=profile), read('RootCA', profile=profile)
    if not account or not ca: return False
    trust_uids = {}
    for key, field in (('IstioRoot', 'root-cert.pem'), ('IstioCRL', 'ca-crl.pem')):
        target = read(key, profile=profile)
        reference = get('configmap', profile['resources'][key][1], 'argocd')
        if not target or not reference: return False
        for obj, namespace in ((target, profile['name']), (reference, 'argocd')):
            meta = obj.get('metadata', {})
            data = obj.get('data', {})
            if (obj.get('apiVersion') != 'v1' or obj.get('kind') != 'ConfigMap'
                    or set(obj) - {'apiVersion', 'kind', 'metadata', 'data'}
                    or meta.get('name') != profile['resources'][key][1] or meta.get('namespace') != namespace
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
                or meta.get('name') != profile['resources'][key][1] or meta.get('namespace') != profile['name']
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


def namespace_inventory(state, *, profile=REGISTRY_PROFILE):
    """Every namespaced API must be readable; unknown objects retain the namespace."""
    deadline = time.monotonic() + 180
    resources = kube('api-resources', '--namespaced=true', '--verbs=list', '-o', 'name', timeout=35).splitlines()
    if (not resources or len(resources) > 256 or len(set(resources)) != len(resources)
            or any(not re.fullmatch(r'[a-z][a-z0-9.-]*', row) for row in resources)):
        raise ProofError('Namespaced API discovery is incomplete or exceeds its proof bound')
    allowed = {(kind, profile['resources'][key][1]): state['identities'].get(key) for key, kind in (
        ('Marker', 'ConfigMap'), ('Retained', 'ConfigMap'), ('RootCA', 'ConfigMap'), ('DefaultAccount', 'ServiceAccount'),
        ('IstioRoot', 'ConfigMap'), ('IstioCRL', 'ConfigMap'))}
    for resource in resources:
        if time.monotonic() >= deadline: raise ProofError('Namespace inspection exceeded its cleanup bound')
        result = json.loads(kube('get', resource, '-n', profile['name'], '-o', 'json', timeout=35))
        if not isinstance(result.get('items'), list): raise ProofError('Namespace resource list is incomplete')
        for obj in result['items']:
            meta = obj.get('metadata', {})
            uid = allowed.get((obj.get('kind'), meta.get('name')))
            if not uid or meta.get('uid') != uid or meta.get('namespace') != profile['name']:
                raise ProofError('Unexpected namespace resource blocks fixture cleanup; retained')


def create(config, *, profile=REGISTRY_PROFILE):
    public, files, _, authority = context(config, profile=profile)
    if any(read(key, profile=profile) for key in profile['resources']) or get('application.argoproj.io', profile['tracking_owner'], 'argocd'):
        raise ProofError('Proof refuses preexisting fixture resources or its synthetic tracking owner')
    state = {'version': profile['version'], 'attempt': config['attempt'], 'publicRevision': config['publicRevision'], 'authority': authority, 'identities': {}, 'approval': 'A',
        'markerEnabled': True, 'sourceAvailable': True, 'acceptedApproval': None, 'acceptedMarkerEnabled': True, 'lastObservation': 'pending',
        'adoptionPhase': 'seed-intent'}
    if profile['consumer'] is not None: state['consumer'] = profile['consumer']
    desired = declarations(config, state, public, files, profile=profile)
    try:
        for key in ('Namespace', 'Project', 'ExternalSecret'):
            authority_guard(state, profile=profile)
            obj = json.loads(kube('create', '-f', '-', '-o', 'json', document=desired[key]))
            uid = obj.get('metadata', {}).get('uid'); owned(obj, uid, config, profile=profile)
            state['identities'][key] = uid
            declaration_guard(key, obj, uid, config, desired, profile=profile)
    except Exception:
        return {'state': state, 'created': False, 'failure': 'Fixture creation incomplete; only captured UID scope may be cleaned'}
    return {'state': state, 'created': True}


def resume_create(config, state, *, profile=REGISTRY_PROFILE):
    public, files, _, _ = context(config, state, profile=profile)
    if (state['adoptionPhase'] != 'seed-intent' or state['acceptedApproval'] is not None or state['approval'] != 'A' or not state['markerEnabled']
            or not state['sourceAvailable'] or state['lastObservation'] != 'pending'):
        raise ProofError('Only interrupted initial fixture creation may resume')
    desired = declarations(config, state, public, files, profile=profile)
    if any(read(key, profile=profile) for key in ('ApplicationSet', 'Application', 'Marker', 'Retained')):
        raise ProofError('Base creation resume refuses preexisting child resources')
    for key in ('Namespace', 'Project', 'ExternalSecret'):
        obj = read(key, profile=profile)
        if not obj:
            if key in state['identities']: raise ProofError('Resume refuses a missing captured fixture owner')
            authority_guard(state, profile=profile)
            obj = json.loads(kube('create', '-f', '-', '-o', 'json', document=desired[key]))
        # Recovery may capture only this unique attempt's exact fixed declaration.
        uid = state['identities'].get(key, obj.get('metadata', {}).get('uid'))
        declaration_guard(key, obj, uid, config, desired, profile=profile)
        state['identities'].setdefault(key, uid)
    return {'state': state, 'created': True}


def seed(config, state, *, timeout=240, profile=REGISTRY_PROFILE):
    public, files, _, _ = context(config, state, profile=profile); desired = declarations(config, state, public, files, profile=profile)
    if state['adoptionPhase'] not in ('seed-intent', 'seeded') or state['acceptedApproval'] is not None:
        raise ProofError('Seed requires recorded pre-adoption intent')
    try:
        if not controls(config, state, desired, profile=profile): raise ProofError('Proof credentials are pending')
        obj = read('Application', profile=profile)
        if not obj:
            if 'Application' in state['identities']: raise ProofError('Captured seed Application is missing')
            if any(read(key, profile=profile) for key in ('Marker', 'Retained')): raise ProofError('Seed refuses preexisting workload resources')
            authority_guard(state, profile=profile)
            obj = json.loads(kube('create', '-f', '-', '-o', 'json', document={
                'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
                'metadata': desired['ApplicationSet']['spec']['template']['metadata'],
                'spec': child_spec(config, state, desired, 'A', True, profile=profile)}))
        # A lost create response is recoverable only under the already recorded seed intent.
        owned(obj, state['identities'].get('Application', obj.get('metadata', {}).get('uid')), config, profile=profile)
        child_metadata(obj, desired, profile=profile)
        if obj.get('spec') != child_spec(config, state, desired, 'A', True, profile=profile):
            raise ProofError('Seed source or scope differs from recorded intent')
        state['identities'].setdefault('Application', obj['metadata']['uid'])
        state['adoptionPhase'] = 'seeded'
        def healthy():
            return controls(config, state, desired, profile=profile) and child(config, state, desired, 'A', True, profile=profile) and defaults(state, profile=profile)
        poll(healthy, timeout=timeout)
        state['adoptionPhase'] = 'adopting'  # Returned durable parent-creation intent, after real seed readiness.
        return {'state': state, 'seed_healthy': True}
    except Exception as error:
        return dict(failure_result({'action': 'seed', 'config': config, 'state': state}, error), seed_healthy=False)


def adopt(config, state, *, profile=REGISTRY_PROFILE):
    public, files, _, _ = context(config, state, profile=profile); desired = declarations(config, state, public, files, profile=profile)
    if (state['adoptionPhase'] != 'adopting' or state['acceptedApproval'] is not None
            or not {'Application', 'Marker', 'Retained', 'DefaultAccount', 'RootCA', 'IstioRoot', 'IstioCRL', 'Secret'} <= set(state['identities'])):
        raise ProofError('Adoption requires captured healthy seed identities and recorded intent')
    obj = read('ApplicationSet', profile=profile)
    if not obj:
        if 'ApplicationSet' in state['identities']: raise ProofError('Captured adoption parent is missing')
        # Check the recorded ownerless seed again before enabling its only new controller.
        seed_state = copy.deepcopy(state); seed_state['adoptionPhase'] = 'seeded'
        if not (controls(config, seed_state, desired, profile=profile) and child(config, seed_state, desired, 'A', True, profile=profile) and defaults(seed_state, profile=profile)):
            raise ProofError('Adoption requires the same healthy ownerless seed')
        authority_guard(state, profile=profile)
        obj = json.loads(kube('create', '-f', '-', '-o', 'json', document=desired['ApplicationSet']))
    uid = state['identities'].get('ApplicationSet', obj.get('metadata', {}).get('uid'))
    declaration_guard('ApplicationSet', obj, uid, config, desired, profile=profile)
    state['identities'].setdefault('ApplicationSet', uid)
    return {'state': state, 'adoption_queued': True}


def observe(config, state, *, rejected=False, timeout=240, profile=REGISTRY_PROFILE):
    public, files, _, _ = context(config, state, profile=profile); desired = declarations(config, state, public, files, profile=profile)
    if state['adoptionPhase'] not in ('adopting', 'adopted') or 'ApplicationSet' not in state['identities']:
        raise ProofError('Native observation requires the recorded adoption parent')
    if rejected and state['lastObservation'] == 'rejected':
        raise ProofError('Restore valid A and observe cleared native error before another rejection case')
    def check():
        if not controls(config, state, desired, profile=profile): return False
        if rejected:
            if state['acceptedApproval'] is None: raise ProofError('Receipt rejection requires a captured accepted child')
            if not child(config, state, desired, state['acceptedApproval'], state['acceptedMarkerEnabled'], profile=profile): return False
            conditions = (read('ApplicationSet', profile=profile) or {}).get('status', {}).get('conditions', [])
            return (not (read('ApplicationSet', profile=profile) or {}).get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/application-set-refresh')
                and any(row.get('type') == 'ErrorOccurred' and row.get('status') == 'True'
                    and ((profile['rejection'] in row.get('message', '')) == state['sourceAvailable'])
                    for row in conditions))
        conditions = (read('ApplicationSet', profile=profile) or {}).get('status', {}).get('conditions', [])
        if (any(row.get('type') == 'ErrorOccurred' and row.get('status') == 'True' for row in conditions)
                or not any(row.get('type') == 'ParametersGenerated' and row.get('status') == 'True' for row in conditions)):
            return False
        if not child(config, state, desired, state['approval'], state['markerEnabled'], profile=profile): return False
        if not defaults(state, profile=profile): return False
        state.update(acceptedApproval=state['approval'], acceptedMarkerEnabled=state['markerEnabled'])
        state['adoptionPhase'] = 'adopted'
        return True
    poll(check, timeout=timeout)
    state['lastObservation'] = 'rejected' if rejected else 'accepted'
    return {'state': state, 'parent_error_retains_child': rejected, 'accepted': not rejected}


def change(config, state, *, approval=None, marker=None, available=None, profile=REGISTRY_PROFILE):
    public, files, _, _ = context(config, state, profile=profile); old = declarations(config, state, public, files, profile=profile)
    if not controls(config, state, old, profile=profile): raise ProofError('Proof credentials are pending')
    if state['acceptedApproval'] is None: raise ProofError('Proof change requires its captured accepted child')
    if (approval is not None or marker is not None or available is False) and state['lastObservation'] != 'accepted':
        raise ProofError('Restore valid input and observe a fresh accepted baseline before a new case')
    if not child(config, state, old, state['acceptedApproval'], state['acceptedMarkerEnabled'], profile=profile): raise ProofError('Accepted proof child is not ready')
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
    current = read('ApplicationSet', profile=profile); new = declarations(config, updated, public, files, profile=profile)['ApplicationSet']['spec']
    ops = [{'op': 'test', 'path': '/metadata/uid', 'value': state['identities']['ApplicationSet']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/spec', 'value': old['ApplicationSet']['spec']}, {'op': 'replace', 'path': '/spec', 'value': new}]
    authority_guard(state, profile=profile)
    result = json.loads(kube('patch', 'applicationset', profile['name'], '-n', 'argocd', '--type=json', '--patch-file=/dev/stdin', '-o', 'json', document=ops))
    if result.get('spec') != new or result.get('metadata', {}).get('uid') != state['identities']['ApplicationSet']:
        raise ProofError('Proof declaration update has no same-UID persistence witness')
    return {'state': updated, 'updated': True}


def marker_patch(obj, data, config, state, before, *, profile=REGISTRY_PROFILE):
    owned(obj, state['identities'].get('Marker'), config, profile=profile)
    if (obj.get('data') != before or obj['metadata'].get('name') != 'approval-marker'
            or obj['metadata'].get('namespace') != profile['name'] or obj.get('binaryData') or obj.get('immutable')
            or obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != profile['name'] + ':/ConfigMap:' + profile['name'] + '/approval-marker'):
        raise ProofError('Proof marker changed before its scoped patch')
    ops = [{'op': 'test', 'path': '/metadata/uid', 'value': state['identities']['Marker']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/data', 'value': obj['data']}, {'op': 'replace', 'path': '/data', 'value': data}]
    authority_guard(state, profile=profile)
    result = json.loads(kube('patch', 'configmap', 'approval-marker', '-n', profile['name'], '--type=json', '--patch-file=/dev/stdin', '-o', 'json', document=ops))
    if result.get('metadata', {}).get('uid') != obj['metadata']['uid'] or result.get('data') != data:
        raise ProofError('Proof marker patch has no same-UID persistence witness')


def drift(config, state, *, timeout=240, profile=REGISTRY_PROFILE):
    public, files, _, _ = context(config, state, profile=profile); desired = declarations(config, state, public, files, profile=profile)
    if not controls(config, state, desired, profile=profile): raise ProofError('Proof credentials are pending')
    approval = state['acceptedApproval']
    if approval is None or not state['acceptedMarkerEnabled'] or not child(config, state, desired, approval, True, profile=profile):
        raise ProofError('Drift requires an already accepted healthy fixture')
    if state['approval'] != approval or state['markerEnabled'] != state['acceptedMarkerEnabled']:
        raise ProofError('Drift refuses an unaccepted approval or marker-removal transition')
    expected = {'revision': config['receipt' + approval]['revision']}
    nonce = {'revision': 'source-proof-drift-' + uuid.uuid4().hex}
    result = {'self_heal_verified': False, 'cleanup_restored': False, 'cleanup_complete': False}
    try:
        marker_patch(read('Marker', profile=profile), nonce, config, state, expected, profile=profile)
        def repaired():
            if not controls(config, state, desired, profile=profile): raise ProofError('Proof credentials became pending')
            actual = read('Marker', profile=profile)
            if actual.get('data') == expected: return child(config, state, desired, approval, True, profile=profile)
            if actual.get('data') != nonce: raise ProofError('Marker drift changed outside this attempt')
            child(config, state, desired, approval, True, ready=False, drift=nonce['revision'], profile=profile)
            return False
        poll(repaired, timeout=timeout); result['self_heal_verified'] = True
    except Exception:
        result['failure'] = 'Native marker repair unavailable or unverified'
    finally:
        try:
            if not controls(config, state, desired, profile=profile): raise ProofError('Proof credentials became pending')
            actual = read('Marker', profile=profile)
            if actual.get('data') != expected:
                if actual.get('data') != nonce: raise ProofError('Compensation refuses unowned drift')
                child(config, state, desired, approval, True, ready=False, drift=nonce['revision'], profile=profile)
                if not quiet_child(read('Application', profile=profile)): raise ProofError('Compensation refuses pending reconciliation')
                marker_patch(actual, expected, config, state, nonce, profile=profile); result['cleanup_restored'] = True; result['self_heal_verified'] = False
            result['cleanup_complete'] = True
        except Exception:
            result['self_heal_verified'] = False; result['failure'] = 'Owned marker compensation declined; drift may remain'
    return result


def refresh(config, state, *, profile=REGISTRY_PROFILE):
    """Explicit synthetic generator refresh; never used to count natural marker repair."""
    public, files, _, _ = context(config, state, profile=profile); desired = declarations(config, state, public, files, profile=profile)
    if state['lastObservation'] != 'accepted': raise ProofError('Synthetic refresh requires a fresh accepted baseline')
    if not controls(config, state, desired, profile=profile): raise ProofError('Proof credentials are pending')
    appset = read('ApplicationSet', profile=profile); annotations = appset['metadata'].get('annotations', {})
    if annotations != desired['ApplicationSet']['metadata']['annotations']:
        raise ProofError('Synthetic refresh refuses unexpected parent annotations')
    ops = [{'op': 'test', 'path': '/metadata/uid', 'value': state['identities']['ApplicationSet']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': appset['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/spec', 'value': desired['ApplicationSet']['spec']},
        {'op': 'test', 'path': '/metadata/annotations', 'value': annotations},
        {'op': 'add', 'path': '/metadata/annotations/argocd.argoproj.io~1application-set-refresh', 'value': 'true'}]
    authority_guard(state, profile=profile)
    result = json.loads(kube('patch', 'applicationset', profile['name'], '-n', 'argocd', '--type=json', '--patch-file=/dev/stdin', '-o', 'json', document=ops))
    if (result.get('metadata', {}).get('uid') != state['identities']['ApplicationSet']
            or result['metadata'].get('annotations', {}).get('argocd.argoproj.io/application-set-refresh') != 'true'):
        raise ProofError('Synthetic refresh has no same-UID persistence witness')
    state['lastObservation'] = 'pending'
    return {'state': state, 'refresh_queued': True}


def cleanup(config, state, *, profile=REGISTRY_PROFILE):
    public, files, _, _ = context(config, state, profile=profile); desired = declarations(config, state, public, files, profile=profile)
    if read('Namespace', profile=profile):
        owned(read('Namespace', profile=profile), state['identities'].get('Namespace'), config, profile=profile)
        if not defaults(state, profile=profile): raise ProofError('Namespace defaults are not captured; cleanup retained')
        namespace_inventory(state, profile=profile)
    order = ('ApplicationSet', 'Application', 'ExternalSecret', 'Secret', 'Marker', 'Retained', 'Project', 'Namespace')
    def target(key, obj):
        uid = state['identities'].get(key)
        owners = obj.get('metadata', {}).get('ownerReferences', [])
        expected = []
        if key in ('Application', 'Secret'):
            parent_key = 'ApplicationSet' if key == 'Application' else 'ExternalSecret'
            parent_kind = parent_key; parent_name = profile['name'] if key == 'Application' else profile['name'] + '-source'
            expected = [{'apiVersion': 'argoproj.io/v1alpha1' if key == 'Application' else 'external-secrets.io/v1',
                'kind': parent_kind, 'name': parent_name, 'uid': state['identities'].get(parent_key), 'controller': True, 'blockOwnerDeletion': True}]
            if not read(parent_key, profile=profile) and not owners: expected = []  # Exact captured child after orphaning its parent.
            if (key == 'Application' and state['adoptionPhase'] == 'adopting'
                    and state['acceptedApproval'] is None and state['lastObservation'] == 'pending' and not owners
                    and state['identities'].get('ApplicationSet')
                    and (read('ApplicationSet', profile=profile) or {}).get('metadata', {}).get('uid') == state['identities']['ApplicationSet']):
                expected = []  # Captured healthy seed awaiting its already captured parent.
            if key == 'Application' and state['adoptionPhase'] in ('seed-intent', 'seeded'):
                if read('ApplicationSet', profile=profile): raise ProofError('Cleanup refuses an unrecorded adoption parent')
                expected = []
        owned(obj, uid, config, owners=expected, profile=profile)
        if key in desired:
            declaration_guard(key, obj, uid, config, desired, profile=profile)
        if key == 'Application':
            child_metadata(obj, desired, profile=profile)
            if (obj.get('kind') != 'Application' or obj.get('apiVersion') != 'argoproj.io/v1alpha1'
                    or obj['metadata'].get('name') != profile['name'] or obj['metadata'].get('namespace') != 'argocd'
                    or set(obj) - {'apiVersion', 'kind', 'metadata', 'spec', 'status'}
                    or obj.get('operation') is not None or obj.get('status', {}).get('operationState', {}).get('phase') in ('Running', 'Terminating')
                    or obj.get('spec') != child_spec(config, state, desired, state['acceptedApproval'] or state['approval'],
                        state['acceptedMarkerEnabled'] if state['acceptedApproval'] else state['markerEnabled'], profile=profile)):
                raise ProofError('Cleanup refuses pending or changed child reconciliation')
        if key == 'Marker' and obj.get('data') != {'revision': config['receipt' + (state['acceptedApproval'] or state['approval'])]['revision']}:
            raise ProofError('Cleanup refuses marker data outside accepted scope')
        if key == 'Retained' and obj.get('data') != RETAINED:
            raise ProofError('Cleanup refuses foreign retained data')
        if key in ('Marker', 'Retained') and (set(obj) - {'apiVersion', 'kind', 'metadata', 'data'}
                or obj.get('kind') != 'ConfigMap' or obj.get('apiVersion') != 'v1'
                or obj['metadata'].get('name') != profile['resources'][key][1] or obj['metadata'].get('namespace') != profile['name']
                or obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                    profile['name'] + ':/ConfigMap:' + profile['name'] + '/' + profile['resources'][key][1]):
            raise ProofError('Cleanup refuses unexpected synthetic ConfigMap fields')
        if key == 'Namespace' and obj.get('spec', {}) not in ({}, {'finalizers': ['kubernetes']}, {'finalizers': []}):
            raise ProofError('Cleanup refuses unexpected Namespace finalizers')
        if key == 'Secret':
            data = {name: base64.b64decode(value, validate=True).decode() for name, value in obj.get('data', {}).items()}
            if (set(obj) - {'apiVersion', 'kind', 'metadata', 'data', 'type'} or obj.get('type') not in (None, 'Opaque')
                    or obj.get('kind') != 'Secret' or obj.get('apiVersion') != 'v1'
                    or obj['metadata'].get('name') != profile['name'] + '-source' or obj['metadata'].get('namespace') != 'argocd'
                    or set(data) != {'type', 'url', 'project', 'githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'}
                    or data['url'] != config['privateRepository'] or data['project'] != profile['name'] or data['type'] != 'git'
                    or not all(data.values())):
                raise ProofError('Cleanup refuses changed credential scope or fields')
    # Validate every remaining target before removing a reconciler or its data.
    for key in order:
        obj = read(key, profile=profile)
        if obj: target(key, obj)
    for key in order:
        obj = read(key, profile=profile)
        if not obj: continue
        target(key, obj)
        uid = state['identities'][key]
        if key == 'Namespace':
            if not defaults(state, profile=profile): raise ProofError('Namespace defaults became unavailable; cleanup retained')
            namespace_inventory(state, profile=profile)
        _, name, _, path = profile['resources'][key]
        authority_guard(state, profile=profile)
        kube('delete', '--raw=' + path + name, '-f', '-', document={'apiVersion': 'v1', 'kind': 'DeleteOptions',
            'preconditions': {'uid': uid, 'resourceVersion': obj['metadata']['resourceVersion']}, 'propagationPolicy': 'Orphan'})
        poll(lambda: read(key, profile=profile) is None, timeout=180)
    return {'cleanup_complete': True}


def dispatch(envelope, profile):
    if (not isinstance(envelope, dict) or not {'action', 'config'} <= set(envelope)
            or set(envelope) - {'action', 'config', 'state', 'timeout'}): raise ProofError('Invalid proof operation envelope')
    action, config, state = envelope['action'], envelope['config'], envelope.get('state')
    if action == 'create': return create(config, profile=profile)
    config_guard(config, state, profile=profile)
    if state is None: raise ProofError('Proof operation requires its captured UID scope')
    if action == 'resume-create': return resume_create(config, state, profile=profile)
    if action == 'seed': return seed(config, state, timeout=envelope.get('timeout', 240), profile=profile)
    if action == 'adopt': return adopt(config, state, profile=profile)
    if action in ('accept', 'reject'): return observe(config, state, rejected=action == 'reject', timeout=envelope.get('timeout', 240), profile=profile)
    if action == 'refresh': return refresh(config, state, profile=profile)
    if action == 'approve-b': return change(config, state, approval='B', profile=profile)
    if action == 'remove-marker': return change(config, state, marker=False, profile=profile)
    if action == 'source-failure': return change(config, state, available=False, profile=profile)
    if action == 'restore-source': return change(config, state, available=True, profile=profile)
    if action == 'drift': return drift(config, state, timeout=envelope.get('timeout', 240), profile=profile)
    if action == 'cleanup': return cleanup(config, state, profile=profile)
    raise ProofError('Unknown fixed proof operation')


def main(envelope):
    if not isinstance(envelope, dict) or not isinstance(envelope.get('config'), dict):
        raise ProofError('Invalid proof operation envelope')
    profile = selected_profile(envelope['config'])
    config_guard(envelope['config'], envelope.get('state'), profile=profile)
    if profile['consumer']:
        profile = dict(profile, peer={'snapshot': peer_snapshot(profile), 'cleanup': envelope.get('action') == 'cleanup'})
    result = dispatch(envelope, profile)
    if 'state' in result: envelope['state'] = result['state']
    peer_guard(profile)
    return result


def failure_result(envelope, error):
    actions = ('create', 'resume-create', 'seed', 'adopt', 'accept', 'reject', 'refresh', 'approve-b', 'remove-marker',
        'source-failure', 'restore-source', 'drift', 'cleanup')
    operation = envelope.get('action') if isinstance(envelope, dict) else None
    result = {'verified': False, 'operation': operation if operation in actions else 'input',
        'failure': str(error) if isinstance(error, ProofError) else 'Fixed native source proof declined; private diagnostics withheld'}
    try:
        profile = selected_profile(envelope['config'])
        config_guard(envelope['config'], envelope['state'], profile=profile)
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
