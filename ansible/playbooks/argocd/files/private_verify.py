"""Observe actual private configuration reconciliation without changing sources or data."""
import base64
import copy
import fcntl
import json
import os
import re
import sys
import time

from bootstrap import BASE, get, kube, matches_revision
from private_activation import APP, OWNER, TRACKING, sources_match, catalog_owner, prepared_contract
from controller_stability import fingerprint, sample as foundation_sample


def wait(check, description, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(3)
    raise RuntimeError('Private GitOps ' + description + ' failed; diagnostics withheld')


def healthy(name):
    return application_healthy(get('application.argoproj.io', name) or {})


def application_healthy(app):
    status = app.get('status', {})
    sync = status.get('sync', {})
    revision = sync.get('revision') or next(iter(sync.get('revisions', [])), None)
    return (status.get('sync', {}).get('status') == 'Synced' and
            bool(revision) and matches_revision(app, revision) and
            status.get('health', {}).get('status') == 'Healthy' and
            not app.get('operation') and
            not any(c['type'].endswith('Error') for c in status.get('conditions', [])) and
            # Reattaching retained, already matching resources needs no sync
            # operation. A resolved revision and converged comparison suffice.
            status.get('operationState', {}).get('phase') in (None, 'Succeeded'))


def credential_owner(app, repository, secrets, externals):
    project = app['spec']['project']
    def decoded(secret, key):
        return base64.b64decode(secret.get('data', {}).get(key, '')).decode()
    credentials = [secret for secret in secrets if
        secret['metadata'].get('labels', {}).get('argocd.argoproj.io/secret-type') == 'repository' and
        decoded(secret, 'url') == repository and decoded(secret, 'project') == project]
    if len(credentials) != 1:
        raise RuntimeError('Private configuration requires one project-scoped repository credential')
    secret = credentials[0]
    owners = secret['metadata'].get('ownerReferences', [])
    if not any(owner.get('kind') == 'ExternalSecret' and owner.get('name') == external['metadata']['name'] and
               owner.get('controller') is True and owner.get('uid') == external['metadata']['uid'] and
               external['metadata']['name'] == secret['metadata']['name'] and
               any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
                   for condition in external.get('status', {}).get('conditions', []))
               for owner in owners for external in externals):
        raise RuntimeError('Private repository credential lacks its ready ESO owner')
    if not all(decoded(secret, field) for field in ('githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey')):
        raise RuntimeError('Private repository credential is incomplete')


def configuration_healthy(name, repository, revision, symbolic_revisions=None):
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        return False
    symbolic_revisions = {} if symbolic_revisions is None else symbolic_revisions
    if (not isinstance(symbolic_revisions, dict) or len(symbolic_revisions) > 20
            or any(not isinstance(ref, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_.-]*', ref)
                   or ref == 'main' or re.fullmatch('[a-f0-9]{40}', ref)
                   or not isinstance(sha, str) or not re.fullmatch('[a-f0-9]{40}', sha)
                   for ref, sha in symbolic_revisions.items())):
        return False
    def expected(source):
        ref = source.get('targetRevision')
        if ref == 'main':
            return revision
        if not isinstance(ref, str):
            return None
        return ref if re.fullmatch('[a-f0-9]{40}', ref) else symbolic_revisions.get(ref)
    app = get('application.argoproj.io', name) or {}
    if not app:
        return False
    sources = app['spec'].get('sources', [app['spec'].get('source', {})])
    sync = app.get('status', {}).get('sync', {})
    revisions = sync.get('revisions', [sync.get('revision')])
    if not (len(sources) == len(revisions) and any(source.get('repoURL') == repository for source in sources) and all(
        expected(source) is not None and resolved == expected(source)
        for source, resolved in zip(sources, revisions) if source.get('repoURL') == repository)):
        return False
    # Compare mutable private refs against authenticated snapshots, preserving other source pin checks.
    compared = copy.deepcopy(app)
    for source in compared['spec'].get('sources', [compared['spec'].get('source', {})]):
        if source.get('repoURL') == repository:
            source['targetRevision'] = expected(source)
    return application_healthy(compared)


def controller_items(items):
    """Exclude scheduled Jobs and only Pods proven to belong to a listed Job."""
    jobs = set()
    for obj in items:
        if obj.get('kind') == 'Job' and obj.get('apiVersion') == 'batch/v1':
            metadata = obj.get('metadata', {})
            identity = tuple(metadata.get(key) for key in ('namespace', 'name', 'uid'))
            if all(isinstance(value, str) and value for value in identity):
                jobs.add(identity)
    result = []
    for obj in items:
        if obj.get('kind') == 'Job':
            continue
        metadata = obj.get('metadata', {})
        owners = metadata.get('ownerReferences') or []
        if obj.get('kind') == 'Pod' and isinstance(owners, list) and any(
                isinstance(owner, dict) and owner.get('apiVersion') == 'batch/v1'
                and owner.get('kind') == 'Job' and owner.get('controller') is True
                and all(isinstance(value, str) and value for value in
                        (metadata.get('namespace'), owner.get('name'), owner.get('uid')))
                and (metadata['namespace'], owner['name'], owner['uid']) in jobs for owner in owners):
            continue
        result.append(obj)
    return result


def pending_verification_context(evidence, repository):
    """Derive explicit recovery mode only from the protected pending operation."""
    from playbooks.data.files import native
    from playbooks.argocd.files import source_transition
    binding = native.receipt(native.BINDING, missing=True)
    if not binding or binding.get('phase') == 'accepted':
        return None, False
    public = (evidence or {}).get('contract', {}).get('context', {}).get('repository')
    if binding.get('target', {}).get('valuesRepository') != repository:
        raise RuntimeError('Pending verification private repository changed')
    root = source_transition.get('application.argoproj.io', 'cloudlab-public-root') or {}
    context = {'checkpoint': binding, 'sourceState': source_transition.binding_source(binding, root),
        'rootSource': copy.deepcopy(root.get('spec', {}).get('source'))}
    identity = binding.get('originalSource', {}).get('helm', {}).get('valuesObject', {}).get('identity', {})
    if not isinstance(identity, dict):
        raise RuntimeError('Pending verification original identity source is malformed')
    initial = 'argo' not in identity
    source_transition.pending_root_authority(context, public, first_binding=initial)
    return context, initial


def permissions_declaration(evidence, repository, *, first_binding=None, recovery=None):
    """Authenticate current approval once; polling never reads credentials or Git."""
    from playbooks.data.files import native
    from playbooks.argocd.files.private_sources import consumer_contract, validate_consumer_acceptance, acceptance_spec
    if not isinstance(evidence, dict) or not isinstance(evidence.get('contract'), dict):
        raise RuntimeError('Permissions verification requires its authenticated contract')
    deadline = time.monotonic() + 120
    contract = evidence.get('contract', {})
    public_repository = contract.get('context', {}).get('repository')
    with native.public_metadata({'publicSource': {'repository': public_repository, 'branch': 'main'}}, deadline=deadline, first_binding=first_binding, recovery=recovery) as fetch:
        public, revision = native.published_source({'publicSource': {'repository': public_repository, 'branch': 'main'}}, fetch=fetch, deadline=deadline)
        current = consumer_contract(public, 'permissions')
        if (not current['enabled'] or current != contract or revision != evidence.get('publicRevision')
                or evidence.get('acceptanceCommitment') != current['acceptanceCommitment']):
            raise RuntimeError('Permissions approval differs from current protected public intent')
        validate_consumer_acceptance(evidence.get('acceptanceReceipt'), repository, current)
        if evidence.get('acceptedRevision') != evidence['acceptanceReceipt']['revision']:
            raise RuntimeError('Permissions revision differs from its approved receipt')
        files = native.source_snapshot.chart_files({'repository': public_repository, 'revision': revision,
            'path': 'gitops/roots/public'}, fetch=fetch, deadline=deadline)
        profile_files = native.source_snapshot.chart_files({'repository': public_repository,
            'revision': current['context']['permissions']['revision'], 'path': 'platform/connectivity/permissions'}, fetch=fetch, deadline=deadline)
        policy_files = native.source_snapshot.chart_files({'repository': public_repository,
            'revision': revision, 'path': 'platform/delivery/admission/policies'}, fetch=fetch, deadline=deadline)
    pending = first_binding if first_binding is not None else recovery
    if pending is not None:
        from playbooks.argocd.files.source_transition import pending_root_context
        pending_root_context(pending, public, first_binding=first_binding is not None)
    expected = acceptance_spec(public, repository, evidence['acceptedRevision'], files=files, consumer='permissions')
    if expected != evidence.get('applicationSet'):
        raise RuntimeError('Permissions parent differs from its authenticated native declaration')
    projection = native.render_objects(profile_files, [{'mode': 'profiles', 'context': {
        'repository': public_repository, 'revision': current['context']['permissions']['revision'],
        'commitment': current['acceptanceCommitment'], 'namespace': 'argocd'}}])
    policies = [row for row in native.render_objects(policy_files, [])
        if row['kind'] in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding')
        and row['metadata']['name'] in ('cloudlab-permissions-input', 'cloudlab-permissions-profiles')]
    if (len(projection) != 1 or projection[0]['kind'] != 'ConfigMap' or len(policies) != 4
            or {(row['kind'], row['metadata']['name']) for row in policies} != {
                (kind, name) for kind in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding')
                for name in ('cloudlab-permissions-input', 'cloudlab-permissions-profiles')}):
        raise RuntimeError('Permissions require their canonical public projection and input policy')
    roots = native.render_objects(files, [public | {'identity': public['identity'] | {'argo': {
        'valuesRepository': repository, 'valuesRevision': evidence['acceptedRevision']}}}])
    profile_apps = [row for row in roots if row['kind'] == 'Application' and row['metadata']['name'] == 'cloudlab-permissions-profiles']
    if len(profile_apps) != 1:
        raise RuntimeError('Permissions public profile owner is missing')
    if pending is not None: pending_root_context(pending, public, first_binding=first_binding is not None)
    return {'parent': expected, 'projection': projection[0], 'policies': policies, 'profileApplication': profile_apps[0]}


def permissions_healthy(evidence, repository, expected):
    # Observe stored declarations, ownership, type checking and admitted-source
    # convergence only. This is not current-evaluator effectiveness proof and
    # cannot alone authorize production activation.
    guard = expected
    expected = guard['parent']
    name = 'cloudlab-permissions'
    parent = get('applicationset.argoproj.io', name) or {}
    meta = parent.get('metadata', {})
    conditions = parent.get('status', {}).get('conditions', [])
    if (not isinstance(meta.get('uid'), str) or not meta['uid'] or meta.get('deletionTimestamp')
            or meta.get('ownerReferences') or meta.get('finalizers')
            or meta.get('labels', {}).get('cloudlab.io/owner') != 'permissions-platform'
            or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + name
            or parent.get('spec') != expected or not isinstance(conditions, list) or not conditions
            or any(not isinstance(row, dict) or row.get('type') == 'ErrorOccurred' and row.get('status') == 'True'
                or str(row.get('type', '')).endswith('Error')
                or row.get('type') == 'ResourcesUpToDate' and row.get('status') != 'True' for row in conditions)
            or not any(row.get('type') == 'ParametersGenerated' and row.get('status') == 'True' for row in conditions)):
        return False
    child = get('application.argoproj.io', name) or {}
    child_meta = child.get('metadata', {})
    desired = copy.deepcopy(expected['template']['spec'])
    actual_source = child.get('spec', {}).get('source', {})
    # Admission owns normalized private semantics; readiness observes its admitted
    # source and proves that it belongs to this exact accepted parent revision.
    desired['source'].setdefault('helm', {})['valuesObject'] = actual_source.get('helm', {}).get('valuesObject')
    annotations = copy.deepcopy(expected['template']['metadata']['annotations'])
    annotations['cloudlab.io/permission-revision'] = evidence['acceptedRevision']
    owner = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': name,
        'uid': meta['uid'], 'controller': True, 'blockOwnerDeletion': True}
    if (not isinstance(child_meta.get('uid'), str) or not child_meta['uid']
            or child_meta.get('deletionTimestamp') or child_meta.get('finalizers')
            or child_meta.get('ownerReferences') != [owner]
            or child_meta.get('labels', {}).get('cloudlab.io/owner') != 'permissions-platform'
            or any(child_meta.get('annotations', {}).get(key) != value for key, value in annotations.items())
            or child.get('spec') != desired
            or not isinstance(desired['source']['helm']['valuesObject'], dict)
            or set(desired['source']['helm']['valuesObject']) != {'permissions'}
            or child.get('status', {}).get('sync', {}).get('comparedTo', {}).get('source') != desired['source']
            or child.get('status', {}).get('sync', {}).get('comparedTo', {}).get('destination') != desired['destination']
            or not application_healthy(child)):
        return False
    projection = get('configmap', 'cloudlab-permissions-profiles') or {}
    projection_meta = projection.get('metadata', {})
    profile_app = get('application.argoproj.io', 'cloudlab-permissions-profiles') or {}
    if (not projection_meta.get('uid') or projection_meta.get('deletionTimestamp') or projection_meta.get('ownerReferences')
            or projection_meta.get('labels', {}).get('cloudlab.io/owner') != 'permissions-profile-platform'
            or projection_meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-permissions-profiles:/ConfigMap:argocd/cloudlab-permissions-profiles'
            or projection.get('data') != guard['projection'].get('data')
            or profile_app.get('spec') != guard['profileApplication']['spec']
            or profile_app.get('status', {}).get('sync', {}).get('comparedTo', {}).get('source') != guard['profileApplication']['spec']['source']
            or profile_app.get('status', {}).get('sync', {}).get('comparedTo', {}).get('destination') != guard['profileApplication']['spec']['destination']
            or not profile_app.get('metadata', {}).get('uid')
            or profile_app['metadata'].get('deletionTimestamp') or profile_app['metadata'].get('ownerReferences')
            or profile_app['metadata'].get('finalizers')
            or profile_app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-public-root:argoproj.io/Application:argocd/cloudlab-permissions-profiles'
            or not application_healthy(profile_app)):
        return False
    for reference in guard['policies']:
        kind, policy_name = reference['kind'], reference['metadata']['name']
        policy = get(kind.lower() + '.admissionregistration.k8s.io', policy_name) or {}
        policy_meta = policy.get('metadata', {})
        status = policy.get('status', {})
        if (not policy_meta.get('uid') or policy_meta.get('deletionTimestamp') or policy_meta.get('ownerReferences')
                or policy.get('apiVersion') != reference['apiVersion'] or policy.get('kind') != kind
                or policy_meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                    'cloudlab-workload-policy:admissionregistration.k8s.io/' + kind + ':cloudlab-policy/' + policy_name
                or policy.get('spec') != reference['spec']):
            return False
        if kind == 'ValidatingAdmissionPolicy' and (
                type(policy_meta.get('generation')) is not int
                or status.get('observedGeneration') != policy_meta['generation']
                or not isinstance(status.get('typeChecking'), dict)
                or status['typeChecking'].get('expressionWarnings')
                or any(row.get('status') == 'False' for row in status.get('conditions') or [])):
            return False
    root = get('application.argoproj.io', 'cloudlab-public-root') or {}
    source = root.get('spec', {}).get('source', {})
    helm = source.get('helm', {})
    if not isinstance(helm, dict) or set(helm) - {'releaseName', 'valuesObject'}: return False
    overrides = helm.get('valuesObject', {})
    if not isinstance(overrides, dict): return False
    for key, desired in evidence['contract']['context'].items():
        if key not in overrides: continue
        actual = overrides[key]
        if key == 'identity' and isinstance(actual, dict): actual = {field: value for field, value in actual.items() if field != 'argo'}
        if isinstance(desired, dict):
            if (not isinstance(actual, dict) or any(field not in desired or type(value) is not type(desired[field])
                    or value != desired[field] for field, value in actual.items())): return False
        elif type(actual) is not type(desired) or actual != desired: return False
    binding = source.get('helm', {}).get('valuesObject', {}).get('identity', {}).get('argo', {})
    return (root.get('metadata', {}).get('uid') and not root['metadata'].get('deletionTimestamp')
        and not root['metadata'].get('ownerReferences') and not root['metadata'].get('finalizers')
        and root.get('spec', {}).get('project') == 'cloudlab-root' and not root['spec'].get('sources')
        and source.get('repoURL') == evidence['contract']['context']['repository']
        and source.get('targetRevision') == 'main' and source.get('path') == 'gitops/roots/public'
        and binding.get('valuesRepository') == repository
        and isinstance(binding.get('valuesRevision'), str) and re.fullmatch('[a-f0-9]{40}', binding['valuesRevision']) is not None
        and root.get('status', {}).get('sync', {}).get('revision') == evidence['publicRevision']
        and application_healthy(root))


def run(payload):
    repository = payload.get('configuration_repository')
    if not repository:
        raise RuntimeError('Private verification requires the actual configuration repository')
    permissions = payload.get('permissions')
    pending, initial = pending_verification_context(permissions, repository) if permissions is not None else (None, False)
    applications = json.loads(kube('get', 'applications.argoproj.io', '-n', 'argocd', '-o', 'json'))['items']
    consumers = [app for app in applications if any(source.get('repoURL') == repository for source in
                 app['spec'].get('sources', [app['spec'].get('source', {})]))]
    revision = payload.get('configuration_revision')
    symbolic_revisions = payload.get('symbolic_revisions')
    if not revision:
        raise RuntimeError('Private verification requires an authenticated configuration revision')
    if permissions is None and (any(app.get('metadata', {}).get('name') == 'cloudlab-permissions' for app in applications)
            or (get('applicationset.argoproj.io', 'cloudlab-permissions') or {}).get('metadata', {}).get('name') == 'cloudlab-permissions'):
        raise RuntimeError('Active permissions require authenticated consumer approval evidence')
    if not consumers and permissions is None:
        raise RuntimeError('Actual private configuration source has no reconciled consumers')
    permission_spec = permissions_declaration(permissions, repository, first_binding=pending if initial else None, recovery=pending if not initial else None) if permissions is not None else None
    if permission_spec is not None:
        wait(lambda: permissions_healthy(permissions, repository, permission_spec), 'permissions approval convergence')
    secrets = json.loads(kube('get', 'secrets', '-n', 'argocd', '-o', 'json'))['items']
    externals = json.loads(kube('get', 'externalsecrets.external-secrets.io', '-n', 'argocd', '-o', 'json'))['items']
    for app in consumers:
        wait(lambda: configuration_healthy(app['metadata']['name'], repository, revision, symbolic_revisions), 'configuration convergence')
        credential_owner(app, repository, secrets, externals)
    if permission_spec is not None:
        credential_owner({'spec': {'project': 'cloudlab-permissions'}}, repository, secrets, externals)
    if payload.get('catalog_enabled'):
        catalog = get('application.argoproj.io', APP) or {}
        evidence = {'repository': payload['public_repository'], 'revision': payload['platform_revision'],
                    'private_repository': repository}
        evidence.update({key: payload.get(key) for key in ('acceptanceCommitment', 'acceptedRevision', 'acceptanceReceipt', 'applicationSet')})
        prepared_contract(evidence, get)
        if (catalog.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER
                or catalog.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id') != TRACKING
                or catalog.get('metadata', {}).get('finalizers') or not sources_match(catalog, evidence)
                or not catalog_owner(catalog, evidence, get) or catalog.get('metadata', {}).get('deletionTimestamp')
                or catalog.get('spec', {}).get('project') != APP
                or catalog.get('spec', {}).get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
                or catalog.get('spec', {}).get('syncPolicy', {}).get('automated') !=
                    {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': True}
                or catalog.get('spec', {}).get('syncPolicy', {}).get('syncOptions') !=
                    ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true', 'PruneLast=true']):
            raise RuntimeError('Private catalog ownership or source differs from reviewed declarations')
        for desired in payload['objects']:
            kind = desired['kind']
            name = desired['metadata']['name']
            group = desired['apiVersion'].split('/')[0] if '/' in desired['apiVersion'] else ''
            resource = kind.lower() + ('.' + group if group else '')
            raw = kube('get', resource, name, *(['-n', 'argocd'] if kind != 'Namespace' else []), '-o', 'json')
            actual = json.loads(raw)
            expected_tracking = APP + ':' + group + '/' + kind + ':argocd/' + name
            if (actual['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != expected_tracking
                    or actual['metadata'].get('deletionTimestamp') or actual['metadata'].get('ownerReferences')
                    or (kind == 'Application' and actual['metadata'].get('finalizers'))
                    or not contains(actual, desired)):
                raise RuntimeError('Private registration differs from its native declaration')
    def child_healthy(entry):
        name = 'cloudlab-private-' + entry['name']
        return configuration_healthy(name, repository, revision, symbolic_revisions) if entry['repository'] == repository else healthy(name)
    for entry in payload['sources']:
        name = 'cloudlab-private-' + entry['name']
        wait(lambda: child_healthy(entry), 'convergence')
        credential_owner(get('application.argoproj.io', name), entry['repository'], secrets, externals)
    def controllers():
        argo = json.loads(kube('get', 'deployments,daemonsets,statefulsets,jobs,pods', '-n', 'argocd', '-o', 'json'))
        return foundation_sample(), fingerprint(controller_items(argo['items']))
    baseline = controllers()
    started = time.monotonic()
    while time.monotonic() - started < 60:
        time.sleep(10)
        if (controllers() != baseline
                or permission_spec is not None and not permissions_healthy(permissions, repository, permission_spec)
                or not all(configuration_healthy(app['metadata']['name'], repository, revision, symbolic_revisions) for app in consumers)
                or not all(child_healthy(entry) for entry in payload['sources'])):
            raise RuntimeError('Controllers or private convergence changed during stability observation')
    return {'private_roots_converged': len(payload['sources']), 'private_configuration_consumers': len(consumers),
            'private_access_verified': True, 'eso_credentials_verified': True,
            'controllers_stable': True, 'stability_seconds': round(time.monotonic() - started, 1),
            'failure_injection': False}


def contains(actual, desired):
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(key in actual and contains(actual[key], value)
                                               for key, value in desired.items())
    return actual == desired



if __name__ == '__main__':
    try:
        os.umask(0o077)
        with (BASE / 'verification.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(run(json.load(sys.stdin))))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Private GitOps verification failed; diagnostics withheld') from None
