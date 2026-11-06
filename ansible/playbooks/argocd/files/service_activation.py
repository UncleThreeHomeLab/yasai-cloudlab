"""Read-only service activation checks before the root gains its private source."""
import copy
import re

APP = 'cloudlab-services'
OWNER = 'service-platform'
TRACKING = 'cloudlab-public-root:argoproj.io/Application:argocd/' + APP


def catalog_path(value='services/catalog.json'):
    if not isinstance(value, str) or not re.fullmatch(r'services/catalog(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?[.](?:json|yaml)', value) or len(value) > 128:
        raise ValueError('Service catalog path must be a bounded catalog JSON or YAML file directly under services')
    return value


def prepare(public, private_repository, private_revision, catalog=None, *, namespace_declaration=None, acceptance=None):
    """Capture already validated non-secret inputs at the identity source revision."""
    try:
        from .private_sources import acceptance_spec, consumer_contract, validate_consumer_acceptance
    except ImportError:
        from private_sources import acceptance_spec, consumer_contract, validate_consumer_acceptance
    evidence = {'required': public.get('services', {}).get('enabled', False),
                     'repository': public['repository'],
                     'revision': public.get('services', {}).get('revision'),
                     'private_repository': private_repository, 'private_revision': private_revision,
                     'telemetry': public.get('observability', {}).get('enabled', False),
                     'catalog': catalog}
    if 'catalogPath' in public.get('services', {}):
        evidence['catalogPath'] = catalog_path(public['services']['catalogPath'])
    if evidence['required']:
        from playbooks.admission.files.namespace_guard import namespace_guard_desired
        if namespace_declaration is None:
            from pathlib import Path
            import yaml
            namespace_declaration = yaml.safe_load((Path(__file__).resolve().parents[4] /
                'platform/delivery/admission/policies/templates/workload-namespace.yaml').read_text())
        namespace_guard_desired(namespace_declaration)
        evidence['namespaceGuard'] = copy.deepcopy(namespace_declaration)
        if (not isinstance(acceptance, dict)
                or set(acceptance) != {'acceptanceCommitment', 'acceptedRevision', 'acceptanceReceipt'}
                or acceptance.get('acceptanceCommitment') != public['services'].get('acceptanceCommitment')):
            raise RuntimeError('Service source acceptance requires its authenticated receipt')
        validate_consumer_acceptance(acceptance['acceptanceReceipt'], private_repository,
                                     consumer_contract(public, 'services'))
        if acceptance['acceptanceReceipt']['revision'] != acceptance['acceptedRevision']:
            raise RuntimeError('Service source acceptance revision differs from its approved receipt')
        evidence.update(acceptance, applicationSet=acceptance_spec(
            public, private_repository, private_revision, consumer='services'))
    return validate(evidence,
                    {'valuesRepository': private_repository, 'valuesRevision': private_revision})


def validate(evidence, target, root=None, *, allow_missing_namespace_guard=False):
    required = {'required', 'repository', 'revision', 'private_repository', 'private_revision', 'telemetry', 'catalog'}
    accepted = {'acceptanceCommitment', 'acceptedRevision', 'acceptanceReceipt', 'applicationSet'}
    if (not isinstance(evidence, dict) or not required <= set(evidence) <= required | {'existing', 'catalogPath', 'namespaceGuard', 'namespaceAuthority'} | accepted
            or type(evidence['required']) is not bool or type(evidence['telemetry']) is not bool
            or set(target) != {'valuesRepository', 'valuesRevision'}
            or evidence['private_repository'] != target['valuesRepository']
            or evidence['private_revision'] != target['valuesRevision']
            or not re.fullmatch('[a-f0-9]{40}', evidence['private_revision'] or '')):
        raise RuntimeError('Service activation inputs do not match the recorded private source')
    path = catalog_path(evidence.get('catalogPath', catalog_path()))
    if evidence['required'] or accepted & set(evidence):
        if (not accepted <= set(evidence) or not evidence['required']
                or not isinstance(evidence['acceptanceCommitment'], str) or not re.fullmatch('[a-f0-9]{64}', evidence['acceptanceCommitment'])
                or not isinstance(evidence['acceptedRevision'], str) or not re.fullmatch('[a-f0-9]{40}', evidence['acceptedRevision'])
                or not isinstance(evidence['applicationSet'], dict)):
            raise RuntimeError('Enabled service catalog requires complete native approval evidence')
        try:
            from .private_sources import CONSUMER_ACCEPTANCE_VERSION, validate_consumer_acceptance
        except ImportError:
            from private_sources import CONSUMER_ACCEPTANCE_VERSION, validate_consumer_acceptance
        try:
            validate_consumer_acceptance(evidence['acceptanceReceipt'], evidence['private_repository'], {
                'version': CONSUMER_ACCEPTANCE_VERSION, 'consumer': 'services', 'enabled': True,
                'receiptPath': 'platform/acceptance/services.yaml',
                'paths': [path, 'identity/argo-values.yaml'],
                'acceptanceCommitment': evidence['acceptanceCommitment'], 'context': {}})
        except ValueError as error:
            raise RuntimeError('Service source acceptance receipt is invalid') from error
        if evidence['acceptanceReceipt']['revision'] != evidence['acceptedRevision']:
            raise RuntimeError('Service source acceptance revision differs from its approved receipt')
    pattern = r'https://github[.]com/([A-Za-z0-9-]+)/[A-Za-z0-9_.-]+[.]git'
    public = re.fullmatch(pattern, evidence['repository'] or '')
    private = re.fullmatch(pattern, evidence['private_repository'] or '')
    if (not public or not private or public[1].lower() != private[1].lower()
            or evidence['repository'].lower() == evidence['private_repository'].lower()):
        raise RuntimeError('Service activation requires its designated public and private sources')
    if root:
        source = root.get('spec', {}).get('source', {})
        overrides = source.get('helm', {}).get('valuesObject', {}).get('services', {})
        if (root.get('spec', {}).get('project') != 'cloudlab-root'
                or source.get('path') != 'gitops/roots/public' or root.get('spec', {}).get('sources')
                or root.get('spec', {}).get('syncPolicy', {}).get('automated', {}).get('prune', False)
                or root.get('metadata', {}).get('finalizers')
                or source.get('repoURL') != evidence['repository']
                or any(key in overrides and overrides[key] != value for key, value in
                       (('enabled', evidence['required']), ('revision', evidence['revision']), ('catalogPath', path),
                        ('acceptanceCommitment', evidence.get('acceptanceCommitment', ''))))):
            raise RuntimeError('Service activation differs from the current public root')
    if evidence['required']:
        from playbooks.admission.files.namespace_guard import namespace_guard_desired
        if 'namespaceGuard' not in evidence:
            if not allow_missing_namespace_guard:
                raise RuntimeError('Service activation requires its trusted public Namespace declaration')
        else:
            if not isinstance(evidence['namespaceGuard'], dict):
                raise RuntimeError('Service activation requires its explicit public Namespace declaration')
            namespace_guard_desired(evidence['namespaceGuard'])
        if 'namespaceAuthority' in evidence and (not isinstance(evidence['namespaceAuthority'], list) or
                len(evidence['namespaceAuthority']) != 2 or any(not isinstance(row, dict) or
                set(row) != {'uid', 'generation', 'annotations', 'labels', 'spec'} or
                not isinstance(row['uid'], str) or not row['uid'] or type(row['generation']) is not int or
                row['generation'] < 1 or any(not isinstance(row[key], dict) for key in ('annotations', 'labels', 'spec'))
                for row in evidence['namespaceAuthority'])):
            raise RuntimeError('Service activation Namespace authority is incomplete')
        catalog = evidence['catalog']
        if (not re.fullmatch('[a-f0-9]{40}', evidence['revision'] or '') or not isinstance(catalog, dict)
                or set(catalog) != {'catalog', 'dataApprovals'} or not isinstance(catalog['catalog'], list)
                or len(catalog['catalog']) > 20 or not isinstance(catalog['dataApprovals'], dict)):
            raise RuntimeError('Service activation requires its validated complete catalog and immutable pin')
        names = set()
        for entry in catalog['catalog']:
            approval = entry.get('approval', {})
            name = approval.get('name', '')
            if (set(entry) != {'definition', 'approval', 'publication'}
                    or entry['publication'] not in ('ready', 'published', 'retired')
                    or not re.fullmatch('[a-z][a-z0-9-]{0,30}', name)
                    or approval.get('namespace') != 'cloudlab-app-' + name or name in names):
                raise RuntimeError('Service activation catalog has invalid ownership bindings')
            names.add(name)
    return copy.deepcopy(evidence)


def sources_match(app, evidence):
    sources = app.get('spec', {}).get('sources', [])
    return (len(sources) == 2 and sources[0].get('repoURL') == evidence['repository']
            and sources[0].get('targetRevision') == evidence['revision']
            and sources[0].get('path') == 'platform/delivery/services'
            and sources[0].get('helm', {}).get('valueFiles') ==
                ['$values/' + catalog_path(evidence.get('catalogPath', catalog_path())), '$values/identity/argo-values.yaml']
            and sources[0].get('helm', {}).get('valuesObject') ==
                {'repository': evidence['repository'], 'revision': evidence['revision'], 'telemetry': evidence['telemetry']}
            and sources[1] == {'repoURL': evidence['private_repository'], 'targetRevision': evidence['acceptedRevision'], 'ref': 'values'})


def catalog_parent(evidence, read):
    parent = read('applicationset.argoproj.io', APP) or {}
    meta = parent.get('metadata', {})
    valid = (meta.get('uid') and not meta.get('deletionTimestamp') and not meta.get('ownerReferences') and not meta.get('finalizers')
        and meta.get('labels', {}).get('cloudlab.io/owner') == OWNER
        and meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') == 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + APP
        and parent.get('spec') == evidence.get('applicationSet'))
    return meta['uid'] if valid else None


def catalog_owner(app, evidence, read):
    """Only the exact reviewed native parent owns the catalog Application."""
    owners = app.get('metadata', {}).get('ownerReferences', [])
    uid = catalog_parent(evidence, read)
    return bool(uid and owners == [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
        'name': APP, 'uid': uid, 'controller': True, 'blockOwnerDeletion': True}])


def namespace_preflight(evidence, target, read, root=None, *, probe=None):
    """Qualify the public installer while its reconciler can still run."""
    evidence = validate(evidence, target, root)
    if not evidence['required']:
        return evidence
    if probe is None:
        raise RuntimeError('Service activation requires its Namespace server dry-run adapter')
    from playbooks.admission.files.namespace_guard import qualify
    evidence['namespaceAuthority'] = qualify(evidence['namespaceGuard'], read, probe,
        evidence.get('namespaceAuthority'))
    return evidence


def guard(evidence, target, read, root=None, *, probe=None):
    """Refuse initial adoption of foreign objects; never create or repair resources."""
    evidence = namespace_preflight(evidence, target, read, root, probe=probe)
    return authority_guard(evidence, target, read, root)


def authority_guard(evidence, target, read, root=None):
    """Preserve catalog ownership checks independently of new Namespace readiness."""
    evidence = validate(evidence, target, root, allow_missing_namespace_guard=True)
    if not evidence['required']:
        return evidence
    entries = evidence['catalog']['catalog']
    if any(row['approval'].get('composition') for row in entries):
        policy = read('validatingpolicy.policies.kyverno.io', 'cloudlab-composition-namespace') or {}
        status = policy.get('status', {}).get('conditionStatus', {})
        conditions = status.get('conditions', [])
        generation = policy.get('metadata', {}).get('generation')
        if not (status.get('ready') is True and conditions and all(
                row.get('status') == 'True' and row.get('observedGeneration', generation) == generation
                for row in conditions)):
            raise RuntimeError('Composition namespace admission must be ready before service activation')
    for entry in entries:
        approval = entry['approval']
        namespace = read('namespace', approval['namespace'])
        if namespace and (namespace['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                or not namespace['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(APP + ':')
                or namespace['metadata'].get('deletionTimestamp')):
            raise RuntimeError('Service namespace has another owner; implicit adoption refused')
        for kind in ('appproject.argoproj.io', 'applicationset.argoproj.io'):
            obj = read(kind, approval['name'])
            if obj and (not obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(APP + ':')
                        or obj['metadata'].get('deletionTimestamp')):
                raise RuntimeError('Service declaration collides with an existing platform object')
    app = read('application.argoproj.io', APP)
    existing = evidence.get('existing')
    if existing is not None and (not app or app['metadata'].get('uid') != existing.get('uid')
                                  or app.get('spec', {}).get('sources') != existing.get('sources')):
        raise RuntimeError('Catalog Application identity or source changed during service activation')
    if app:
        meta, spec, status = app['metadata'], app.get('spec', {}), app.get('status', {})
        tracking = meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id')
        if (meta.get('labels', {}).get('cloudlab.io/owner') != OWNER or meta.get('finalizers')
                or meta.get('deletionTimestamp')
                or tracking != TRACKING or not catalog_owner(app, evidence, read)
                or not sources_match(app, evidence)
                or spec.get('project') != APP
                or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
                or spec.get('syncPolicy', {}).get('automated', {}).get('prune') is not False
                or app.get('operation') or status.get('operationState', {}).get('phase') in ('Running', 'Terminating')
                or status.get('health', {}).get('status') != 'Healthy'
                or status.get('sync', {}).get('status') != 'Synced'
                or any(row.get('type', '').endswith('Error') for row in status.get('conditions', []))):
            raise RuntimeError('Service activation requires its exact idle catalog owner; pending operations require inspection or recovery')
        evidence['existing'] = {'uid': meta['uid'], 'sources': copy.deepcopy(spec['sources'])}
    return evidence
