"""Observe controller convergence and exercise admission without creating workloads."""
import copy
import json
from pathlib import Path
import re
import sys
import time
import urllib.parse

sys.path.insert(0, '/opt/cloudlab')

from playbooks.istio.files.kube import application_ready, condition, get, kube, wait, condition_status_ready as policy_ready

PERMISSIONS_GUARD_NAME = 'cloudlab-permissions-ownership'
PERMISSIONS_CONTROLLER = 'system:serviceaccount:argocd:argocd-application-controller'
PERMISSIONS_GUARD_MESSAGE = 'Permission catalog writes require the native Argo owner, exact tracking and an unchanged owned scope.'
from playbooks.admission.files.namespace_guard import (
    NAMESPACE_GUARD_NAME, namespace_guard_desired, namespace_guard_validate, namespace_guard_denied)


def permission_guard_desired(path=None):
    import yaml
    path = path or Path(__file__).resolve().parents[4] / 'platform/delivery/admission/policies/templates/permissions.yaml'
    return list(yaml.safe_load_all(Path(path).read_text()))


def permission_input_desired(path=None):
    import yaml
    path = path or Path(__file__).resolve().parents[4] / 'platform/delivery/admission/policies/templates/permission-input.yaml'
    return list(yaml.safe_load_all(Path(path).read_text()))


def namespace_guard_create_probe(declaration=None):
    document = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
        'name': 'cloudlab-app-native-guard-probe', 'labels': {'cloudlab.io/owner': 'foreign'}}}
    message = namespace_guard_desired(declaration)[0]['spec']['validations'][0]['message']
    result = kube('create', '--dry-run=server', '-f', '-', document=document, allow_failure=True)
    if not result.returncode or not namespace_guard_denied(result.stderr, message):
        raise RuntimeError('Native namespace guard did not deny its synthetic CREATE probe')


def permission_tracking(kind, name, namespace='argocd'):
    return 'cloudlab-permissions:rbac.authorization.k8s.io/' + kind + ':' + namespace + '/' + name


def permission_guard_validate(documents, expected):
    if not isinstance(expected, list) or len(expected) != 4 or len(documents) != 4:
        raise RuntimeError('Permission guard requires both complete typed policies and bindings')
    names = {PERMISSIONS_GUARD_NAME + '-roles': ['clusterroles'],
             PERMISSIONS_GUARD_NAME + '-bindings': ['clusterrolebindings', 'rolebindings']}
    required = {(name, kind) for name in names for kind in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding')}
    if {(row.get('metadata', {}).get('name'), row.get('kind')) for row in expected} != required:
        raise RuntimeError('Permission guard requires its exact typed policies and bindings')
    for actual, reference in zip(documents, expected, strict=True):
        kind = reference['kind']
        name = reference['metadata']['name']
        if kind == 'ValidatingAdmissionPolicy':
            constraints = {'matchPolicy': 'Exact', 'namespaceSelector': {}, 'objectSelector': {}, 'resourceRules': [{
                'apiGroups': ['rbac.authorization.k8s.io'], 'apiVersions': ['v1'], 'operations': ['CREATE', 'UPDATE'],
                'resources': names[name], 'scope': '*'}]}
            if reference['spec'].get('failurePolicy') != 'Fail' or reference['spec'].get('matchConstraints') != constraints:
                raise RuntimeError('Permission guard must retain its fail-closed exact RBAC scope')
        elif reference.get('spec') != {'policyName': name, 'validationActions': ['Deny']}:
            raise RuntimeError('Permission guard bindings must enforce their exact typed policies')
        marker = 'cloudlab-workload-policy:admissionregistration.k8s.io/' + kind + ':cloudlab-policy/' + reference['metadata']['name']
        if (not isinstance(actual, dict) or actual.get('apiVersion') != 'admissionregistration.k8s.io/v1' or
                actual.get('kind') != kind or actual.get('metadata', {}).get('name') != reference['metadata']['name'] or
                actual.get('spec') != reference['spec'] or
                actual.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id') != marker):
            raise RuntimeError('Permission guard differs from its exact native owner')
        metadata = actual['metadata']
        if (not isinstance(metadata.get('uid'), str) or not metadata['uid'] or
                metadata.get('deletionTimestamp') or metadata.get('ownerReferences') or metadata.get('finalizers')):
            raise RuntimeError('Permission guard has no stable non-deleting native owner')
        if kind == 'ValidatingAdmissionPolicy':
            status = actual.get('status', {})
            type_checking = status.get('typeChecking', {})
            if (not actual['metadata'].get('generation') or
                    status.get('observedGeneration') != actual['metadata']['generation'] or
                    not isinstance(type_checking, dict) or type_checking.get('expressionWarnings') or
                    any(condition.get('status') == 'False' for condition in status.get('conditions', []))):
                raise RuntimeError('Permission guard type-checking is incomplete or has warnings')
    return True


def permission_candidate():
    kind, name = 'ClusterRole', 'cloudlab-permissions-guard-proof-namespace'
    return {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': kind,
            'metadata': {'name': name, 'labels': {'cloudlab.io/owner': 'permissions-platform',
                'cloudlab.io/permission-profile': 'guard-proof', 'cloudlab.io/permission-scope': 'namespace'},
                'annotations': {'argocd.argoproj.io/tracking-id': permission_tracking(kind, name)}},
            'rules': [{'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get']}]}


def permission_guard_probes(dry_run):
    """dry_run returns status and diagnostics from server dry-run only."""
    good = permission_candidate()
    status, _ = dry_run(good, PERMISSIONS_CONTROLLER)
    if status:
        raise RuntimeError('Native permission-owner dry-run was not admitted')
    wrong_tracking = copy.deepcopy(good)
    wrong_tracking['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
    foreign = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding',
               'metadata': {'name': 'cloudlab-foreign-permission-proof'},
               'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': good['metadata']['name']},
               'subjects': [{'kind': 'User', 'apiGroup': 'rbac.authorization.k8s.io', 'name': 'fixture-user'}]}
    binding = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding',
               'metadata': copy.deepcopy(good['metadata']), 'roleRef': copy.deepcopy(foreign['roleRef']),
               'subjects': copy.deepcopy(foreign['subjects'])}
    binding['metadata'].update(name='cloudlab-permissions-guard-binding-proof', namespace='argocd')
    binding['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = permission_tracking(
        'RoleBinding', binding['metadata']['name'], 'argocd')
    if dry_run(binding, PERMISSIONS_CONTROLLER)[0]:
        raise RuntimeError('Native permission-owner namespace dry-run was not admitted')
    wrong_binding = copy.deepcopy(binding)
    wrong_binding['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
    for document, caller in ((good, None), (wrong_tracking, PERMISSIONS_CONTROLLER), (foreign, PERMISSIONS_CONTROLLER),
                             (binding, None), (wrong_binding, PERMISSIONS_CONTROLLER)):
        status, diagnostics = dry_run(document, caller)
        guard_name = PERMISSIONS_GUARD_NAME + ('-roles' if document['kind'] == 'ClusterRole' else '-bindings')
        if (not status or not re.search(r'(?<![\w.-])' + guard_name + r'(?![\w.-])', diagnostics) or
                PERMISSIONS_GUARD_MESSAGE not in diagnostics):
            raise RuntimeError('Permission violation was not denied by its exact native guard')
    return True


def workload_source(namespace):
    """Mirror the namespace's own deployed workload for admission probes.

    Per-namespace artifact pinning admits only each service's own image and
    the workload contract requires a named service account, so a generic
    probe can never pass. Resolve both from the namespace's first deployed
    workload template instead; anything unpinned or unnamed fails closed.
    Namespaces without deployments (retirement shells) have no workload to
    exercise and report None so only namespace-level checks apply to them.
    """
    deployments = sorted(
        (get('deployment', namespace=namespace) or {}).get('items', []),
        key=lambda row: row['metadata']['name'])
    if not deployments:
        return None
    template = deployments[0]['spec']['template']['spec']
    image = (template.get('containers') or [{}])[0].get('image') or ''
    account = template.get('serviceAccountName') or ''
    if not re.fullmatch('.+@sha256:[a-f0-9]{64}', image):
        raise RuntimeError('Deployed workload image is not a pinned digest')
    if not account or account == 'default':
        raise RuntimeError('Deployed workload requires its named service account')
    return image, account


def probe(namespace, image, account):
    return {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': 'cloudlab-admission-proof', 'namespace': namespace},
            'spec': {'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                     'serviceAccountName': account,
                     'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532,
                                         'seccompProfile': {'type': 'RuntimeDefault'}},
                     'containers': [{'name': 'proof',
                         'image': image,
                         'command': ['true'],
                         'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                             'capabilities': {'drop': ['ALL']}},
                         'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                                       'limits': {'cpu': '100m', 'memory': '64Mi'}}}]}}


def dry_run(document):
    return kube('create', '--dry-run=server', '-f', '-', '-o', 'json',
                document=document, allow_failure=True)


def digest_result(result, enforce):
    native = 'Workload images must use an immutable SHA-256 digest.' in result.stderr
    # The repository webhook can reject the tag before the digest webhook runs.
    artifact = all(message in result.stderr for message in (
        'application-artifacts', 'approved-repositories',
        'Images require the approved application repository or retained bootstrap digest.'))
    return bool(result.returncode) == enforce and (native or (enforce and artifact))


def admission(namespace, enforce, image, account):
    good = probe(namespace, image, account)
    if dry_run(good).returncode:
        raise RuntimeError('Restricted digest workload did not pass server admission')
    mutable = copy.deepcopy(good)
    mutable['spec']['containers'][0]['image'] = image.split('@')[0]
    unbounded = copy.deepcopy(good)
    unbounded['spec']['containers'][0]['resources']['requests']['cpu'] = '0'
    unbounded['spec']['containers'][0]['resources']['limits']['cpu'] = '0'
    token = copy.deepcopy(good)
    token['spec']['volumes'] = [{'name': 'api', 'projected': {
        'sources': [{'serviceAccountToken': {'path': 'token'}}]}}]
    bound = copy.deepcopy(good)
    bound['spec']['volumes'] = [{'name': 'api', 'projected': {'sources': [{'serviceAccountToken': {
        'path': 'token', 'audience': account, 'expirationSeconds': 600}}]}}]
    stale = copy.deepcopy(bound)
    stale['spec']['volumes'][0]['projected']['sources'][0]['serviceAccountToken']['expirationSeconds'] = 86400
    shared = copy.deepcopy(good)
    shared['metadata']['labels'] = {'cloudlab.io/workload': 'foreign-workload'}
    owned = copy.deepcopy(good)
    owned['metadata']['labels'] = {'cloudlab.io/workload': account}
    if not digest_result(dry_run(mutable), enforce):
        raise RuntimeError('Mutable image did not match the declared policy mode')
    if dry_run(bound).returncode:
        raise RuntimeError('Bound audience token did not pass server admission')
    if dry_run(owned).returncode:
        raise RuntimeError('Own workload account selection did not pass server admission')
    for document, message in (
            (unbounded, 'Every workload container requires positive CPU and memory requests and limits.'),
            (token, 'Workload token projections require a bound audience and short expiry.'),
            (stale, 'Workload token projections require a bound audience and short expiry.'),
            (shared, 'Workload pods must select their own workload service account.')):
        result = dry_run(document)
        if bool(result.returncode) != enforce or message not in result.stderr:
            raise RuntimeError('Workload violation did not match the declared policy mode')
    privileged = copy.deepcopy(good)
    privileged['spec']['containers'][0]['securityContext'].update(privileged=True, allowPrivilegeEscalation=True)
    denied = dry_run(privileged)
    if not denied.returncode or 'violates PodSecurity' not in denied.stderr:
        raise RuntimeError('Application Pod Security must reject privileged workloads')


def ephemeral_admission(namespace, enforce):
    pods = (get('pod', namespace=namespace) or {}).get('items', [])
    target = next((row for row in pods if condition(row, 'Ready') and
                   not row['metadata'].get('deletionTimestamp')), None)
    if not target:
        return False
    path = ('/api/v1/namespaces/' + urllib.parse.quote(namespace, safe='') + '/pods/' +
            urllib.parse.quote(target['metadata']['name'], safe='') + '/ephemeralcontainers?dryRun=All')
    base = target['spec']['containers'][0]['image']
    # The hardened skeleton carries the live image: ephemeral containers forbid
    # the live container's probes and resources, so only the image is mirrored.
    skeleton = probe(namespace, base, target['spec'].get('serviceAccountName') or 'default')
    container = copy.deepcopy(skeleton['spec']['containers'][0])
    container.pop('resources')  # Kubernetes forbids per-container resources on this subresource.
    container['name'] = 'cloudlab-admission-proof'
    target = copy.deepcopy(target)
    target['spec'].setdefault('ephemeralContainers', []).append(container)
    for mutable in (False, True):
        if mutable:
            container['image'] = base.split('@')[0]
        result = kube('replace', '--raw', path, '-f', '-', document=target, allow_failure=True)
        warned = 'Workload images must use an immutable SHA-256 digest.' in result.stderr
        if ((mutable and not digest_result(result, enforce)) or
                (not mutable and (result.returncode or warned))):
            raise RuntimeError('Ephemeral image admission did not preserve its declared digest rule')
    return True


def controllers():
    deployments = get('deployment', namespace='cloudlab-policy')['items']
    pods = get('pod', namespace='cloudlab-policy')['items']
    if len(deployments) != 2 or any(not condition(row, 'Available') for row in deployments):
        raise RuntimeError('Admission deployments are not available')
    admission_pods = [row for row in pods if row['metadata'].get('labels', {}).get(
        'app.kubernetes.io/component') == 'admission-controller' and condition(row, 'Ready')]
    if len(admission_pods) != 2 or len({row['spec']['nodeName'] for row in admission_pods}) != 2:
        raise RuntimeError('Admission replicas must be ready on both nodes')
    return sorted((row['metadata']['uid'], row['spec']['nodeName'],
                   tuple((container['name'], container.get('restartCount', 0))
                         for container in row.get('status', {}).get('containerStatuses', [])))
                  for row in pods if condition(row, 'Ready'))


def namespace_policy(name):
    wait(lambda: policy_ready(get('validatingpolicy.policies.kyverno.io', name)),
         'namespace guard readiness', timeout=180)
    policy = get('validatingpolicy.policies.kyverno.io', name)
    if (not policy_ready(policy) or policy['spec'].get('validationActions') != ['Deny'] or
            policy['spec'].get('failurePolicy') != 'Fail' or
            policy['spec'].get('evaluation', {}).get('admission') != {'enabled': True} or
            'namespaceSelector' in policy['spec'].get('matchConstraints', {}) or
            policy['spec'].get('matchConstraints', {}).get('resourceRules') != [{
                'apiGroups': [''], 'apiVersions': ['v1'], 'operations': ['CREATE', 'UPDATE'], 'resources': ['namespaces']}] or
            not policy['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-workload-policy:')):
        raise RuntimeError('Namespace guard is absent or differs from its fail-closed owner')


def composition_guard():
    name = 'cloudlab-composition-namespace'
    namespace_policy(name)
    namespace = 'cloudlab-app-admission-proof'
    if get('namespace', namespace) or get('validatingpolicy.policies.kyverno.io', 'cloudlab-composition-admission-proof'):
        raise RuntimeError('Composition guard proof requires its unused synthetic name')
    result = kube('create', '--dry-run=server', '-f', '-', allow_failure=True, document={
        'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace, 'labels': {
            'cloudlab.io/owner': 'service-platform', 'cloudlab.io/composition': 'approved',
            'istio.io/dataplane-mode': 'ambient', 'cloudlab.io/service-secrets': 'approved',
            'pod-security.kubernetes.io/enforce': 'privileged', 'pod-security.kubernetes.io/enforce-version': 'v1.36',
            'pod-security.kubernetes.io/audit': 'restricted', 'pod-security.kubernetes.io/warn': 'restricted'}}})
    if not result.returncode or name not in result.stderr:
        raise RuntimeError('Composition namespace without a profile was not denied by its native guard')


def namespace_candidate(row):
    metadata = row['metadata']
    labels = metadata.get('labels', {})
    return (metadata['name'].startswith('cloudlab-app-') or
            labels.get('cloudlab.io/owner') == 'service-platform' or 'cloudlab.io/composition' in labels)


def namespace_profile(row):
    metadata = row['metadata']
    labels = metadata.get('labels', {})
    required = {'cloudlab.io/owner': 'service-platform', 'istio.io/dataplane-mode': 'ambient',
                'cloudlab.io/service-secrets': 'approved', 'pod-security.kubernetes.io/enforce-version': 'v1.36'}
    if (not metadata['name'].startswith('cloudlab-app-') or
            any(labels.get(key) != value for key, value in required.items())):
        raise RuntimeError('Application namespace security labels differ; verify ownership before migration')
    if 'cloudlab.io/composition' in labels and labels['cloudlab.io/composition'] != 'approved':
        raise RuntimeError('Composition namespace approval differs from its approved owner')
    composition = labels.get('cloudlab.io/composition') == 'approved'
    if composition:
        required = {'cloudlab.io/composition': 'approved', 'pod-security.kubernetes.io/enforce': 'privileged',
                    'pod-security.kubernetes.io/audit': 'restricted', 'pod-security.kubernetes.io/warn': 'restricted'}
    else:
        required = {'pod-security.kubernetes.io/enforce': 'restricted'}
    if any(labels.get(key) != value for key, value in required.items()):
        raise RuntimeError('Application namespace Pod Security profile differs from its approved owner')
    return composition


def namespace_admission(row):
    good = copy.deepcopy(row)
    good['metadata'].setdefault('annotations', {})['cloudlab.io/admission-proof'] = 'dry-run'
    result = kube('replace', '--dry-run=server', '-f', '-', allow_failure=True, document=good)
    if result.returncode:
        raise RuntimeError('Existing application namespace metadata update was not admitted')
    for labels in ({}, dict(row['metadata']['labels'], **{'istio.io/dataplane-mode': 'none'})):
        changed = copy.deepcopy(row)
        changed['metadata']['labels'] = labels
        result = kube('replace', '--dry-run=server', '-f', '-', allow_failure=True, document=changed)
        if (not result.returncode or not namespace_guard_denied(result.stderr,
                'Application namespaces must retain their platform owner, ambient capture, secret eligibility and pinned Pod Security labels.')):
            raise RuntimeError('Application namespace security-label change was not denied by its native guard')


def namespaces(workloads, enforce, catalog):
    """Fence every workload namespace; prove workload admission on ordinary ones.

    The retired services runtime used to approve composition namespaces from
    its catalog and prove their workload admission separately. Composition
    approval now arrives as the GitOps-owned namespace label (bound to the
    approved value by namespace_profile) and the namespace guard denies any
    mutation of that fence; workload admission dry-runs apply to ordinary
    namespaces only. The catalog argument stays for the evidence contract.
    """
    ephemeral_checked = 0
    composition_checked = 0
    restricted_checked = 0
    for row in workloads:
        namespace = row['metadata']['name']
        composition = namespace_profile(row)
        namespace_admission(row)
        if composition:
            composition_checked += 1
        else:
            source = workload_source(namespace)
            if source is None:
                continue
            admission(namespace, enforce, *source)
            ephemeral_checked += ephemeral_admission(namespace, enforce)
            restricted_checked += 1
    if not ephemeral_checked:
        raise RuntimeError('Ephemeral admission requires at least one existing ready workload')
    return ephemeral_checked, composition_checked, restricted_checked


def controller_namespace_policy(actions):
    """Deny bare and debug pods in controller namespaces; admit controller-owned ones.

    The probe image is a synthetic pinned digest: server dry-run exercises
    admission only and never pulls it.
    """
    name = 'cloudlab-controller-namespace'
    wait(lambda: policy_ready(get('validatingpolicy.policies.kyverno.io', name)),
         'native controller-namespace policy readiness', timeout=180)
    policy = get('validatingpolicy.policies.kyverno.io', name)
    variables = {row['name']: row['expression']
                 for row in policy['spec'].get('variables', [])}
    if (not policy_ready(policy) or policy['spec']['validationActions'] != actions or
            policy['spec'].get('failurePolicy') != 'Fail' or
            'namespaceSelector' in policy['spec'].get('matchConstraints', {}) or
            "'cloudlab-policy'" not in variables.get('selected', '')):
        raise RuntimeError('Native controller-namespace policy is not ready or its declared scope changed')
    enforce = actions == ['Deny']
    image = 'registry.k8s.io/pause@sha256:' + '0' * 64
    bare = probe('cloudlab-policy', image, 'cloudlab-admission-proof')
    owned = copy.deepcopy(bare)
    owned['metadata']['ownerReferences'] = [
        {'apiVersion': 'apps/v1', 'kind': 'ReplicaSet', 'name': 'cloudlab-admission-proof'}]
    if dry_run(owned).returncode:
        raise RuntimeError('Controller-owned pod did not pass server admission')
    result = dry_run(bare)
    if (bool(result.returncode) != enforce or
            'Controller namespaces accept only controller-managed pods.' not in result.stderr):
        raise RuntimeError('Controller-namespace violation did not match the declared policy mode')
    controller_ephemeral(enforce)


def controller_ephemeral(enforce):
    pods = (get('pod', namespace='cloudlab-policy') or {}).get('items', [])
    target = next((row for row in pods if condition(row, 'Ready') and
                   not row['metadata'].get('deletionTimestamp')), None)
    if not target:
        raise RuntimeError('Controller-namespace debug admission requires an existing ready pod')
    path = ('/api/v1/namespaces/cloudlab-policy/pods/' +
            urllib.parse.quote(target['metadata']['name'], safe='') + '/ephemeralcontainers?dryRun=All')
    container = {'name': 'cloudlab-admission-debug', 'image': target['spec']['containers'][0]['image'],
                 'command': ['true'], 'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532,
                     'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                     'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'RuntimeDefault'}}}
    target = copy.deepcopy(target)
    target['spec'].setdefault('ephemeralContainers', []).append(container)
    result = kube('replace', '--raw', path, '-f', '-', document=target, allow_failure=True)
    if (bool(result.returncode) != enforce or
            'Controller namespaces cannot add ephemeral debug containers.' not in result.stderr):
        raise RuntimeError('Controller-namespace violation did not match the declared policy mode')


def secretref_catalog_policy(actions, namespace):
    """Admit exact owner-shaped ExternalSecrets; deny foreign store, template and refs.

    All probes are server dry-runs: nothing is created. The positive control
    mirrors the services owner's render (catalog store, 24h refresh, Owner
    creation, Retain deletion, guarded v2 template, single whole-item extract).
    """
    name = 'cloudlab-secretref-catalog'
    wait(lambda: policy_ready(get('validatingpolicy.policies.kyverno.io', name)),
         'native secretref catalog policy readiness', timeout=180)
    policy = get('validatingpolicy.policies.kyverno.io', name)
    variables = {row['name']: row['expression']
                 for row in policy['spec'].get('variables', [])}
    messages = [row.get('message') for row in policy['spec'].get('validations', [])]
    if (not policy_ready(policy) or policy['spec']['validationActions'] != actions or
            policy['spec'].get('failurePolicy') != 'Fail' or
            policy['spec'].get('evaluation', {}).get('admission') != {'enabled': True} or
            policy['spec'].get('evaluation', {}).get('background') != {'enabled': False} or
            policy['spec']['matchConstraints']['resourceRules'] != [{
                'apiGroups': ['external-secrets.io'], 'apiVersions': ['v1'],
                'operations': ['CREATE', 'UPDATE'], 'resources': ['externalsecrets']}] or
            'namespaceSelector' in policy['spec'].get('matchConstraints', {}) or
            variables.get('selected') != "request.namespace.startsWith('cloudlab-app-')" or
            messages != ['Application ExternalSecrets require the catalog owner store, shape and retention.',
                         'Application ExternalSecrets require the guarded v2 delivery template.',
                         'Application ExternalSecrets require a single whole-item vault reference.']):
        raise RuntimeError('Native secretref catalog policy is not ready or its declared scope changed')
    enforce = actions == ['Deny']
    good = {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret',
            'metadata': {'name': 'cloudlab-secretref-proof', 'namespace': namespace},
            'spec': {'refreshInterval': '24h',
                     'secretStoreRef': {'name': 'cloudlab', 'kind': 'ClusterSecretStore'},
                     'target': {'name': 'cloudlab-secretref-proof', 'creationPolicy': 'Owner',
                                'deletionPolicy': 'Retain',
                                'template': {'engineVersion': 'v2', 'mergePolicy': 'Replace',
                                             'data': {'token': '{{ .token }}'}}},
                     'dataFrom': [{'extract': {'key': 'prices-session'}}]}}
    if dry_run(good).returncode:
        raise RuntimeError('Owner-shaped ExternalSecret did not pass server admission')
    foreign = copy.deepcopy(good)
    foreign['spec']['secretStoreRef']['name'] = 'foreign'
    untemplated = copy.deepcopy(good)
    del untemplated['spec']['target']['template']
    direct = copy.deepcopy(good)
    direct['spec']['data'] = [{'secretKey': 'token',
                               'remoteRef': {'key': 'prices-session', 'property': 'token'}}]
    split = copy.deepcopy(good)
    split['spec']['dataFrom'].append({'extract': {'key': 'prices-extra'}})
    for document, message in (
            (foreign, 'Application ExternalSecrets require the catalog owner store, shape and retention.'),
            (untemplated, 'Application ExternalSecrets require the guarded v2 delivery template.'),
            (direct, 'Application ExternalSecrets require a single whole-item vault reference.'),
            (split, 'Application ExternalSecrets require a single whole-item vault reference.')):
        result = dry_run(document)
        if bool(result.returncode) != enforce or message not in result.stderr:
            raise RuntimeError('ExternalSecret violation did not match the declared policy mode')


def run(revision, actions, catalog=None, guard_expected=None, namespace_expected=None):
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Admission verification requires the exact published source revision')
    if actions not in (['Audit', 'Warn'], ['Deny']):
        raise ValueError('Admission verification requires the declared audit or enforcement actions')
    enforce = actions == ['Deny']
    names = ('cloudlab-kyverno', 'cloudlab-workload-policy')
    wait(lambda: all(application_ready(name, revision) for name in names),
         'admission GitOps convergence', timeout=600)
    expected = guard_expected if guard_expected is not None else permission_guard_desired()
    def permission_guard_ready():
        documents = [get(reference['kind'], reference['metadata']['name']) for reference in expected]
        try:
            return permission_guard_validate(documents, expected)
        except RuntimeError:
            return False
    wait(permission_guard_ready, 'native permission guard qualification', timeout=180)
    def permission_dry_run(document, caller):
        arguments = ['create', '--dry-run=server', '-f', '-', '-o', 'json']
        if caller: arguments += ['--as=' + caller]
        result = kube(*arguments, document=document, allow_failure=True)
        return result.returncode, result.stderr
    permission_guard_probes(permission_dry_run)
    def namespace_guard_ready():
        documents = [get(row['kind'], row['metadata']['name']) for row in namespace_guard_desired(namespace_expected)]
        try:
            return namespace_guard_validate(documents, namespace_expected)
        except RuntimeError:
            return False
    wait(namespace_guard_ready, 'native namespace guard convergence', timeout=180)
    namespace_guard_create_probe(namespace_expected)
    for name, background, resources in (
            ('cloudlab-workload-contract', True, ['pods']),
            ('cloudlab-workload-ephemeral', False, ['pods/ephemeralcontainers'])):
        wait(lambda: policy_ready(get('validatingpolicy.policies.kyverno.io', name)),
             'native workload policy readiness', timeout=180)
        policy = get('validatingpolicy.policies.kyverno.io', name)
        variables = {row['name']: row['expression']
                     for row in policy['spec'].get('variables', [])}
        if (not policy_ready(policy) or policy['spec']['validationActions'] != actions or
                policy['spec']['failurePolicy'] != 'Fail' or
                policy['spec']['evaluation']['background']['enabled'] is not background or
                policy['spec']['matchConstraints']['resourceRules'][0]['resources'] != resources or
                'namespaceSelector' in policy['spec'].get('matchConstraints', {}) or
                variables.get('selected') != "request.namespace.startsWith('cloudlab-app-')"):
            raise RuntimeError('Native workload policy is not ready or its declared mode or scope changed')
    controller_namespace_policy(actions)
    namespace = get('namespace', 'cloudlab-policy')
    if namespace['metadata'].get('labels', {}).get('pod-security.kubernetes.io/enforce') != 'restricted':
        raise RuntimeError('Admission controllers require restricted Pod Security')
    namespace_policy('cloudlab-workload-namespace')
    composition_guard()
    workloads = [row for row in get('namespace')['items'] if namespace_candidate(row)]
    if not workloads:
        raise RuntimeError('Application namespaces require their existing restricted Pod Security owner')
    secretref_catalog_policy(actions, workloads[0]['metadata']['name'])
    ephemeral_checked, composition_checked, restricted_checked = namespaces(workloads, enforce, catalog)
    initial = controllers()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        time.sleep(5)
        if controllers() != initial or not all(application_ready(name, revision) for name in names):
            raise RuntimeError('Admission controllers changed during bounded stability verification')
    outcome = 'denied' if enforce else 'warned'
    return {'applications_converged': 2, 'admission_nodes': 2, 'policy_mode': 'enforce' if enforce else 'audit',
            **{name + '_' + outcome: True for name in (
                'mutable_image', 'zero_resources', 'projected_token', 'stale_token', 'shared_account',
                'ephemeral_image', 'controller_bare_pod', 'controller_ephemeral',
                'secretref_store', 'secretref_template', 'secretref_shape')},
            'ephemeral_namespaces_checked': ephemeral_checked,
            'composition_namespaces_checked': composition_checked,
            'unapproved_composition_namespace_denied': True,
            'namespace_security_labels_denied': True,
            'native_namespace_guard_verified': True,
            'restricted_workload_admitted': restricted_checked > 0,
            'bound_token_admitted': True, 'own_account_admitted': True,
            'controller_owned_admitted': True, 'secretref_owner_admitted': True,
            'privileged_workload_denied': True, 'workloads_created': 0, 'controllers_stable': True}


if __name__ == '__main__':
    try:
        raw = sys.stdin.read() if not sys.stdin.isatty() else ''
        data = json.loads(raw) if raw.strip() else []
        print(json.dumps(run(sys.argv[1], json.loads(sys.argv[2]),
            data['catalog'] if isinstance(data, dict) else data,
            data.get('permissionsGuard') if isinstance(data, dict) else None,
            data.get('namespaceGuard') if isinstance(data, dict) else None), sort_keys=True))
    except Exception:
        raise SystemExit('Admission verification incomplete; existing workloads and policy mode retained') from None
