"""Read-only ownership checks before enabling the private Git source catalog."""
import copy
import json
import re
import subprocess
import uuid

APP = 'cloudlab-private-sources'
OWNER = 'private-source-platform'
CHILD_OWNER = 'private-gitops'
TRACKING = 'cloudlab-public-root:argoproj.io/Application:argocd/' + APP
POLICIES = ('cloudlab-private-source-ownership', 'cloudlab-private-source-credentials')


def prepare(public, repository, revision, registry=None):
    try:
        from .private_sources import registry_enabled, policy_specs
    except ImportError:
        from private_sources import registry_enabled, policy_specs
    enabled = registry_enabled(public)
    return validate({'required': enabled, 'repository': public['repository'],
                     'revision': public.get('privateSources', {}).get('revision'),
                     'private_repository': repository, 'private_revision': revision, 'registry': registry,
                     'policies': policy_specs(POLICIES) if enabled else None},
                    {'valuesRepository': repository, 'valuesRevision': revision})


def validate(evidence, target, root=None):
    fields = {'required', 'repository', 'revision', 'private_repository', 'private_revision', 'registry', 'policies'}
    if (not isinstance(evidence, dict) or not fields <= set(evidence) <= fields | {'existing', 'identities', 'policyIdentities'}
            or type(evidence['required']) is not bool or set(target) != {'valuesRepository', 'valuesRevision'}
            or evidence['private_repository'] != target['valuesRepository']
            or evidence['private_revision'] != target['valuesRevision']
            or not isinstance(evidence['private_revision'], str)
            or not re.fullmatch('[a-f0-9]{40}', evidence['private_revision'])):
        raise RuntimeError('Private activation inputs do not match the recorded source')
    pattern = r'https://github[.]com/([A-Za-z0-9][A-Za-z0-9-]*)/[A-Za-z0-9][A-Za-z0-9_.-]*[.]git'
    public = re.fullmatch(pattern, evidence['repository'] or '')
    private = re.fullmatch(pattern, evidence['private_repository'] or '')
    if (not public or not private or public[1].lower() != private[1].lower()
            or evidence['repository'].lower() == evidence['private_repository'].lower()):
        raise RuntimeError('Private activation requires its designated repository pair')
    policy_ids = evidence.get('policyIdentities', {})
    if (not isinstance(policy_ids, dict) or not set(policy_ids) <= set(POLICIES)
            or any(not isinstance(uid, str) or not uid for uid in policy_ids.values())):
        raise RuntimeError('Private source policy identities are invalid')
    if root:
        source = root.get('spec', {}).get('source', {})
        overrides = source.get('helm', {}).get('valuesObject', {}).get('privateSources', {})
        if (root.get('spec', {}).get('project') != 'cloudlab-root'
                or source.get('path') != 'gitops/roots/public' or root.get('spec', {}).get('sources')
                or root.get('spec', {}).get('syncPolicy', {}).get('automated', {}).get('prune', False)
                or root.get('metadata', {}).get('finalizers') or source.get('repoURL') != evidence['repository']
                or any(key in overrides and overrides[key] != value for key, value in
                       (('enabled', evidence['required']), ('revision', evidence['revision'])))):
            raise RuntimeError('Private activation differs from the current public root')
    if evidence['required']:
        registry = evidence['registry']
        if (not isinstance(evidence['revision'], str) or not re.fullmatch('[a-f0-9]{40}', evidence['revision'])
                or not isinstance(registry, dict) or set(registry) != {'sources'}
                or not isinstance(registry['sources'], list) or len(registry['sources']) > 20):
            raise RuntimeError('Private activation requires a complete validated registry and immutable chart pin')
        names = set()
        for row in registry['sources']:
            if (not isinstance(row, dict) or set(row) != {'name', 'repository', 'revision', 'path'}
                    or not all(isinstance(value, str) for value in row.values())
                    or not re.fullmatch(r'[a-z][a-z0-9-]{0,28}[a-z0-9]|[a-z]', row['name'])
                    or row['name'] in names | {'sources', 'sources-source'}
                    or not re.fullmatch(pattern, row['repository'])
                    or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_.-]*', row['revision'])
                    or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_.-]*', row['path']) or '..' in row['path'].split('/')):
                raise RuntimeError('Private activation registry has invalid ownership bindings')
            names.add(row['name'])
        policies = evidence['policies']
        if (not isinstance(policies, dict) or set(policies) != set(POLICIES)
                or any(not isinstance(spec, dict) or spec.get('validationActions') != ['Deny']
                    or spec.get('failurePolicy') != 'Fail' or not spec.get('validations')
                    or any(not isinstance(row.get('message'), str) or not row['message']
                        for row in spec['validations']) for spec in policies.values())):
            raise RuntimeError('Private activation requires its reviewed ownership policy definitions')
    elif evidence['registry'] is not None or evidence['policies'] is not None:
        raise RuntimeError('Disabled private activation cannot carry registry inputs')
    allowed = {'appproject.argoproj.io', 'externalsecret.external-secrets.io', 'secret'}
    if evidence['required']:
        allowed |= {kind + '/cloudlab-private-' + row['name'] for row in evidence['registry']['sources']
                    for kind in ('namespace', 'appproject.argoproj.io', 'application.argoproj.io',
                                 'externalsecret.external-secrets.io', 'secret')}
    identities = evidence.get('identities', {})
    if (not isinstance(identities, dict) or not set(identities) <= allowed or
            any(not isinstance(uid, str) or not uid for uid in identities.values())):
        raise RuntimeError('Private catalog resource identities are invalid')
    existing = evidence.get('existing')
    if existing is not None and (not isinstance(existing, dict) or set(existing) != {'uid', 'sources'}
            or not isinstance(existing['uid'], str) or not existing['uid'] or not isinstance(existing['sources'], list)):
        raise RuntimeError('Private catalog identity snapshot is invalid')
    return copy.deepcopy(evidence)


def sources_match(app, evidence):
    return app.get('spec', {}).get('sources') == [
        {'repoURL': evidence['repository'], 'targetRevision': evidence['revision'],
         'path': 'platform/delivery/private-sources', 'helm': {'valueFiles': ['$values/platform/sources.yaml']}},
        {'repoURL': evidence['private_repository'], 'targetRevision': 'main', 'ref': 'values'}]


def server_probe(document):
    """Admission inspection only: these requests cannot persist an object."""
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=30s', 'create',
                             '--dry-run=server', '-f', '-', '-o', 'json'], input=json.dumps(document),
                            capture_output=True, text=True, timeout=45)
    return result.returncode, result.stderr


def _policies(evidence, read):
    result = {}
    for name in POLICIES:
        policy = read('validatingpolicy.policies.kyverno.io', name) or {}
        meta = policy.get('metadata', {})
        status = policy.get('status', {}).get('conditionStatus', {})
        generation = meta.get('generation')
        conditions = status.get('conditions', [])
        if (not meta.get('uid') or type(generation) is not int or meta.get('deletionTimestamp')
                or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                    'cloudlab-workload-policy:policies.kyverno.io/ValidatingPolicy:cloudlab-policy/' + name
                or meta.get('ownerReferences') or policy.get('spec') != evidence['policies'][name]
                or status.get('ready') is not True or not conditions
                or not {'WebhookConfigured', 'RBACPermissionsGranted'} <= {row.get('type') for row in conditions}
                or any(row.get('status') != 'True' or ('observedGeneration' in row and
                    row['observedGeneration'] != generation) for row in conditions)
                or any('observedGeneration' in row and row['observedGeneration'] != generation
                       for row in (policy.get('status', {}), status))):
            raise RuntimeError('Private source policies must match their reviewed ownership and ready webhook contract')
        if name in evidence.get('policyIdentities', {}) and evidence['policyIdentities'][name] != meta['uid']:
            raise RuntimeError('Private source policy identity changed during activation')
        result[name] = {'uid': meta['uid'], 'generation': generation, 'spec': copy.deepcopy(policy['spec'])}
    return result


def _probe_controls(evidence, probe):
    if probe is None:
        raise RuntimeError('Private source activation requires nonpersistent admission controls')
    for kind in ('Namespace', 'AppProject', 'Secret'):
        name = 'cloudlab-private-proof-' + uuid.uuid4().hex[:12]
        group = '' if kind == 'Namespace' else 'argoproj.io'
        metadata = {'name': name, 'labels': {'cloudlab.io/owner': CHILD_OWNER}}
        document = {'apiVersion': 'v1' if kind in ('Namespace', 'Secret') else 'argoproj.io/v1alpha1',
                    'kind': kind, 'metadata': metadata}
        if kind != 'Namespace': metadata['namespace'] = 'argocd'
        if kind == 'Secret':
            policy = POLICIES[1]
            metadata['labels']['argocd.argoproj.io/secret-type'] = 'repository'
            metadata['ownerReferences'] = [{'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret',
                'name': name, 'uid': str(uuid.uuid4()), 'controller': True}]
            document.update(type='Opaque', data={})
        else:
            policy = POLICIES[0]
            metadata['annotations'] = {'argocd.argoproj.io/tracking-id': APP + ':' + group + '/' + kind + ':' +
                                       'argocd/' + name}
            if kind == 'Namespace':
                metadata['labels'].update({'pod-security.kubernetes.io/enforce': 'restricted',
                                           'pod-security.kubernetes.io/enforce-version': 'v1.36'})
            else:
                document['spec'] = {'sourceRepos': [], 'destinations': [],
                                    'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': []}
        if probe(document)[0] != 0:
            raise RuntimeError('Private source admission positive control failed; diagnostics withheld')
        rejected = copy.deepcopy(document)
        if kind == 'Secret': rejected['metadata'].pop('ownerReferences')
        else: rejected['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
        code, error = probe(rejected)
        message = evidence['policies'][policy]['validations'][0]['message']
        errors = ('failed to evaluate', 'evaluation error', 'evaluation resulted in error', 'compilation error',
                  'no such key', 'no matching overload', 'undeclared reference', 'failed calling webhook',
                  'connection refused', 'timeout', 'timed out', 'forbidden: user', 'cannot create resource', 'rbac',
                  'permission denied', 'unauthorized', 'error evaluating', 'failed evaluating')
        if (code == 0 or policy not in error or message not in error or
                not any(marker in error.lower() for marker in ('denied the request', 'was blocked', 'validation failed'))
                or any(text in error.lower() for text in errors)):
            raise RuntimeError('Private source admission negative control did not prove its expected named denial')


def guard(evidence, target, read, root=None, probe=None):
    evidence = validate(evidence, target, root)
    if not evidence['required']:
        return evidence
    policies = _policies(evidence, read)
    _probe_controls(evidence, probe)
    if _policies(evidence, read) != policies:
        raise RuntimeError('Private source policies changed during admission controls; retry this activation')
    evidence['policyIdentities'] = {name: snapshot['uid'] for name, snapshot in policies.items()}
    identities = {}
    for kind, title, group, name in (
            ('appproject.argoproj.io', 'AppProject', 'argoproj.io', APP),
            ('externalsecret.external-secrets.io', 'ExternalSecret', 'external-secrets.io', APP + '-source')):
        obj = read(kind, name)
        if obj:
            meta = obj['metadata']
            if (meta.get('labels', {}).get('cloudlab.io/owner') != OWNER
                    or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                        'cloudlab-public-root:' + group + '/' + title + ':argocd/' + name
                    or meta.get('deletionTimestamp') or meta.get('ownerReferences')):
                raise RuntimeError('Private catalog bootstrap resource has another owner; implicit adoption refused')
            identities[kind] = meta['uid']
    secret = read('secret', APP + '-source')
    if secret:
        meta = secret['metadata']
        if (meta.get('labels', {}).get('cloudlab.io/owner') != OWNER or meta.get('deletionTimestamp')
                or not any(owner.get('kind') == 'ExternalSecret' and owner.get('name') == APP + '-source'
                    and owner.get('uid') == identities.get('externalsecret.external-secrets.io')
                    and owner.get('controller') is True for owner in meta.get('ownerReferences', []))):
            raise RuntimeError('Private catalog reader has another owner; implicit adoption refused')
        identities['secret'] = meta['uid']
    for row in evidence['registry']['sources']:
        name = 'cloudlab-private-' + row['name']
        # Argo tracking IDs use destination namespaces even for cluster-scoped objects.
        for kind, group, tracking_namespace in (('namespace', '', 'argocd'), ('appproject.argoproj.io', 'argoproj.io', 'argocd'),
                                       ('application.argoproj.io', 'argoproj.io', 'argocd'),
                                       ('externalsecret.external-secrets.io', 'external-secrets.io', 'argocd')):
            obj = read(kind, name)
            title = {'namespace': 'Namespace', 'appproject.argoproj.io': 'AppProject',
                     'application.argoproj.io': 'Application', 'externalsecret.external-secrets.io': 'ExternalSecret'}[kind]
            expected = APP + ':' + group + '/' + title + ':' + tracking_namespace + '/' + name
            if obj and (obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != CHILD_OWNER
                        or obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != expected
                        or obj['metadata'].get('deletionTimestamp')
                        or (title == 'Application' and obj['metadata'].get('finalizers'))):
                raise RuntimeError('Private source resource has another owner; implicit adoption refused')
            if obj: identities[kind + '/' + name] = obj['metadata']['uid']
        secret = read('secret', name)
        external = read('externalsecret.external-secrets.io', name)
        if secret and (not external or secret['metadata'].get('labels', {}).get('cloudlab.io/owner') != CHILD_OWNER
                or not any(owner.get('kind') == 'ExternalSecret' and owner.get('name') == name
                    and owner.get('uid') == external['metadata'].get('uid') and owner.get('controller') is True
                    for owner in secret['metadata'].get('ownerReferences', []))):
            raise RuntimeError('Private source credential has another owner; implicit adoption refused')
        if secret: identities['secret/' + name] = secret['metadata']['uid']
    if any(identities.get(kind) != uid for kind, uid in evidence.get('identities', {}).items()):
        raise RuntimeError('Private catalog resource identity changed during activation')
    evidence['identities'] = identities
    app = read('application.argoproj.io', APP)
    existing = evidence.get('existing')
    if existing is not None and (not app or app['metadata'].get('uid') != existing.get('uid')
                                or app.get('spec', {}).get('sources') != existing.get('sources')):
        raise RuntimeError('Private catalog identity or source changed during activation')
    if app:
        meta, spec, status = app['metadata'], app.get('spec', {}), app.get('status', {})
        if (meta.get('labels', {}).get('cloudlab.io/owner') != OWNER
                or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') != TRACKING
                or meta.get('finalizers') or meta.get('ownerReferences') or meta.get('deletionTimestamp')
                or not sources_match(app, evidence) or spec.get('project') != APP
                or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
                or spec.get('syncPolicy', {}).get('automated') !=
                    {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': True}
                or spec.get('syncPolicy', {}).get('syncOptions') !=
                    ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true', 'PruneLast=true']
                or app.get('operation') or status.get('operationState', {}).get('phase') in ('Running', 'Terminating')):
            raise RuntimeError('Private activation requires its exact idle root-owned catalog')
        evidence['existing'] = {'uid': meta['uid'], 'sources': copy.deepcopy(spec['sources'])}
    return evidence
