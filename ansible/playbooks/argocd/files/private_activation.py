"""Read-only ownership checks before enabling the private Git source catalog."""
import copy
import json
import re
import subprocess
import uuid
import time

APP = 'cloudlab-private-sources'
OWNER = 'private-source-platform'
CHILD_OWNER = 'private-gitops'
TRACKING = 'cloudlab-public-root:argoproj.io/Application:argocd/' + APP
POLICIES = ('cloudlab-private-source-ownership', 'cloudlab-private-source-credentials')


def prepare(public, repository, revision, registry=None, *, acceptance=None):
    try:
        from .private_sources import registry_enabled, policy_specs, acceptance_commitment, acceptance_spec
    except ImportError:
        from private_sources import registry_enabled, policy_specs, acceptance_commitment, acceptance_spec
    enabled = registry_enabled(public)
    expected = acceptance_commitment(public) if enabled else None
    if enabled and (not isinstance(acceptance, dict)
            or set(acceptance) != {'acceptanceCommitment', 'acceptedRevision', 'acceptanceReceipt'}
            or acceptance.get('acceptanceCommitment') != expected):
        raise RuntimeError('Private source acceptance requires its authenticated receipt')
    evidence = {'required': enabled, 'repository': public['repository'],
                     'revision': public.get('privateSources', {}).get('revision'),
                     'private_repository': repository, 'private_revision': revision, 'registry': registry,
                     'policies': policy_specs(POLICIES) if enabled else None}
    if enabled:
        evidence.update(acceptance, applicationSet=acceptance_spec(public, repository, revision))
    return validate(evidence, {'valuesRepository': repository, 'valuesRevision': revision})


def validate(evidence, target, root=None):
    fields = {'required', 'repository', 'revision', 'private_repository', 'private_revision', 'registry', 'policies'}
    accepted = {'acceptanceCommitment', 'acceptedRevision', 'acceptanceReceipt', 'applicationSet'}
    if (not isinstance(evidence, dict) or not fields <= set(evidence) <= fields | {'existing', 'identities', 'policyIdentities'} | accepted
            or type(evidence['required']) is not bool or set(target) != {'valuesRepository', 'valuesRevision'}
            or evidence['private_repository'] != target['valuesRepository']
            or evidence['private_revision'] != target['valuesRevision']
            or not isinstance(evidence['private_revision'], str)
            or not re.fullmatch('[a-f0-9]{40}', evidence['private_revision'])):
        raise RuntimeError('Private activation inputs do not match the recorded source')
    if evidence['required'] or accepted & set(evidence):
        if (not accepted <= set(evidence) or not evidence['required']
                or not isinstance(evidence['acceptanceCommitment'], str) or not re.fullmatch('[a-f0-9]{64}', evidence['acceptanceCommitment'])
                or not isinstance(evidence['acceptedRevision'], str) or not re.fullmatch('[a-f0-9]{40}', evidence['acceptedRevision'])
                or not isinstance(evidence['applicationSet'], dict)):
            raise RuntimeError('Enabled private sources require complete native approval evidence; legacy pending recovery is blocked')
        try:
            from .private_sources import validate_acceptance
        except ImportError:
            from private_sources import validate_acceptance
        validate_acceptance(evidence['acceptanceReceipt'], evidence['private_repository'], evidence['acceptanceCommitment'])
        if evidence['acceptanceReceipt']['revision'] != evidence['acceptedRevision']:
            raise RuntimeError('Private source acceptance revision differs from its approved receipt')
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
                       (('enabled', evidence['required']), ('revision', evidence['revision']),
                        ('acceptanceCommitment', evidence.get('acceptanceCommitment', ''))))):
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
    if evidence['required']: allowed.add('applicationset.argoproj.io')
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
        {'repoURL': evidence['private_repository'], 'targetRevision': evidence['acceptedRevision'], 'ref': 'values'}]


def catalog_parent(evidence, read):
    parent = read('applicationset.argoproj.io', APP) or {}
    meta = parent.get('metadata', {})
    valid = (meta.get('uid') and not meta.get('deletionTimestamp') and not meta.get('ownerReferences') and not meta.get('finalizers')
        and meta.get('labels', {}).get('cloudlab.io/owner') == OWNER
        and meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') == 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + APP
        and parent.get('spec') == evidence.get('applicationSet'))
    return meta['uid'] if valid else None


def _declaration_intent(evidence, root, *, proposed=None):
    """Compare declarations with fresh public intent; grant no source-effect authority."""
    from playbooks.argocd.files.private_sources import acceptance_spec, validate_acceptance
    from playbooks.argocd.files.github_app import PUBLIC_READER, public_metadata
    from playbooks.argocd.files import source_snapshot
    from playbooks.secrets.files.vault import fields
    import yaml
    source = root.get('spec', {}).get('source', {})
    identity = source.get('helm', {}).get('valuesObject', {}).get('identity', {})
    if (not root.get('metadata', {}).get('uid') or root.get('metadata', {}).get('deletionTimestamp')
            or root.get('metadata', {}).get('ownerReferences') or root.get('metadata', {}).get('finalizers')
            or root.get('spec', {}).get('project') != 'cloudlab-root' or root.get('spec', {}).get('sources')
            or source.get('repoURL') != evidence['repository'] or source.get('targetRevision') != 'main'
            or source.get('path') != 'gitops/roots/public' or not isinstance(identity, dict)):
        raise RuntimeError('Private source acceptance requires the current designated Root binding')
    if evidence['repository'] != 'https://github.com/' + PUBLIC_READER + '.git':
        raise RuntimeError('Private source acceptance requires the designated public repository')
    deadline = time.monotonic() + 120
    with public_metadata(fields('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY')), deadline=deadline) as fetch:
        branch = fetch('repos/' + PUBLIC_READER + '/branches/main', deadline)
        if (not isinstance(branch, dict) or branch.get('protected') is not True
                or not isinstance(branch.get('commit', {}).get('sha'), str)
                or not re.fullmatch('[a-f0-9]{40}', branch['commit']['sha'])):
            raise RuntimeError('Protected public main is invalid')
        revision = branch['commit']['sha']
        files = source_snapshot.chart_files({'repository': evidence['repository'], 'revision': revision,
            'path': 'gitops/roots/public'}, fetch=fetch, deadline=deadline)
    public = yaml.safe_load(files['values.yaml'])
    settings = public.get('privateSources', {})
    enabled = evidence.get('required', True)
    if type(settings.get('enabled')) is not bool or settings['enabled'] != enabled:
        raise RuntimeError('Private source acceptance differs from current protected public intent')
    overrides = source.get('helm', {}).get('valuesObject', {}).get('privateSources', {})
    if (not isinstance(overrides, dict) or any(key not in settings or type(value) is not type(settings[key])
            or value != settings[key] for key, value in overrides.items())):
        raise RuntimeError('Private source Root override conflicts with current protected public intent')
    if not enabled: return
    if (settings.get('revision') != evidence['revision']
            or settings.get('acceptanceCommitment') != evidence.get('acceptanceCommitment')):
        raise RuntimeError('Private source acceptance differs from current protected public intent')
    validate_acceptance(evidence.get('acceptanceReceipt'), evidence['private_repository'], evidence.get('acceptanceCommitment'))
    if evidence['acceptanceReceipt']['revision'] != evidence.get('acceptedRevision'):
        raise RuntimeError('Private source acceptance revision differs from its approved receipt')
    target = identity['argo'] if 'argo' in identity else proposed
    if (not isinstance(target, dict) or set(target) != {'valuesRepository', 'valuesRevision'}
            or target['valuesRepository'] != evidence['private_repository']
            or not isinstance(target['valuesRevision'], str) or not re.fullmatch('[a-f0-9]{40}', target['valuesRevision'])):
        raise RuntimeError('Private source acceptance requires the current designated Root binding')
    if acceptance_spec(public, evidence['private_repository'], target['valuesRevision'], files=files) != evidence.get('applicationSet'):
        raise RuntimeError('Private source acceptance parent differs from the authenticated public declaration')


def preflight(evidence, target, read, root=None):
    """Reject invalid incoming intent before recording or stopping a handoff."""
    root = root or read('application.argoproj.io', 'cloudlab-public-root') or {}
    checked = validate(evidence, target, root)
    captured = {'existing', 'identities', 'policyIdentities'} & set(checked)
    if captured:
        try:
            from .source_transition import pending_identity_checkpoint
        except ImportError:
            from source_transition import pending_identity_checkpoint
        recorded = pending_identity_checkpoint(target)['privateActivation']
        if any(key not in recorded or checked[key] != recorded[key] for key in captured):
            raise RuntimeError('Incoming private source intent cannot invent captured operation authority')
    identity = root.get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {}).get('identity', {})
    if checked['required'] and isinstance(identity, dict) and 'argo' not in identity:
        try:
            from .source_transition import quiet
        except ImportError:
            from source_transition import quiet
        if not quiet(root):
            raise RuntimeError('First native private binding requires a quiet original Root before stopping its controller')
    _declaration_intent(checked, root, proposed=target)


def prepared_contract(evidence, read, root=None, *, binding=None, target=None):
    """Recheck current intent, then require actual binding or durable paused authority."""
    root = root or read('application.argoproj.io', 'cloudlab-public-root') or {}
    _declaration_intent(evidence, root, proposed=target)
    if not evidence.get('required', True): return
    identity = root['spec']['source'].get('helm', {}).get('valuesObject', {}).get('identity', {})
    if 'argo' not in identity:
        try:
            from .source_transition import pending_private_target
        except ImportError:
            from source_transition import pending_private_target
        pending_private_target(binding, evidence, root)


def catalog_owner(app, evidence, read):
    """Only the exact reviewed native parent owns the catalog Application."""
    owners = app.get('metadata', {}).get('ownerReferences', [])
    uid = catalog_parent(evidence, read)
    return bool(uid and owners == [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
        'name': APP, 'uid': uid, 'controller': True, 'blockOwnerDeletion': True}])


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


def guard(evidence, target, read, root=None, probe=None, *, binding=None):
    evidence = validate(evidence, target, root)
    prepared_contract(evidence, read, root, binding=binding, target=target)
    if not evidence['required']:
        return evidence
    policies = _policies(evidence, read)
    _probe_controls(evidence, probe)
    if _policies(evidence, read) != policies:
        raise RuntimeError('Private source policies changed during admission controls; retry this activation')
    evidence['policyIdentities'] = {name: snapshot['uid'] for name, snapshot in policies.items()}
    identities = {}
    if read('applicationset.argoproj.io', APP):
        uid = catalog_parent(evidence, read)
        if not uid: raise RuntimeError('Private source acceptance parent differs from its reviewed declaration')
        identities['applicationset.argoproj.io'] = uid
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
                or meta.get('finalizers') or not catalog_owner(app, evidence, read) or meta.get('deletionTimestamp')
                or not sources_match(app, evidence) or spec.get('project') != APP
                or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
                or spec.get('syncPolicy', {}).get('automated') !=
                    {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': True}
                or spec.get('syncPolicy', {}).get('syncOptions') !=
                    ['FailOnSharedResource=true', 'ClientSideApplyMigration=false', 'PruneLast=true']
                or app.get('operation') or status.get('operationState', {}).get('phase') in ('Running', 'Terminating')):
            raise RuntimeError('Private activation requires its exact idle root-owned catalog')
        evidence['existing'] = {'uid': meta['uid'], 'sources': copy.deepcopy(spec['sources'])}
    return evidence
