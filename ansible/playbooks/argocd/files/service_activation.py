"""Read-only service activation checks before the root gains its private source."""
import copy
import re

APP = 'cloudlab-services'
OWNER = 'service-platform'
TRACKING = 'cloudlab-public-root:argoproj.io/Application:argocd/' + APP


def prepare(public, private_repository, private_revision, catalog=None):
    """Capture already validated non-secret inputs at the identity source revision."""
    return validate({'required': public.get('services', {}).get('enabled', False),
                     'repository': public['repository'],
                     'revision': public.get('services', {}).get('revision'),
                     'private_repository': private_repository, 'private_revision': private_revision,
                     'telemetry': public.get('observability', {}).get('enabled', False),
                     'catalog': catalog},
                    {'valuesRepository': private_repository, 'valuesRevision': private_revision})


def validate(evidence, target, root=None):
    required = {'required', 'repository', 'revision', 'private_repository', 'private_revision', 'telemetry', 'catalog'}
    if (not isinstance(evidence, dict) or not required <= set(evidence) <= required | {'existing'}
            or type(evidence['required']) is not bool or type(evidence['telemetry']) is not bool
            or set(target) != {'valuesRepository', 'valuesRevision'}
            or evidence['private_repository'] != target['valuesRepository']
            or evidence['private_revision'] != target['valuesRevision']
            or not re.fullmatch('[a-f0-9]{40}', evidence['private_revision'] or '')):
        raise RuntimeError('Service activation inputs do not match the recorded private source')
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
                       (('enabled', evidence['required']), ('revision', evidence['revision'])))):
            raise RuntimeError('Service activation differs from the current public root')
    if evidence['required']:
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
                ['$values/services/catalog.json', '$values/identity/argo-values.yaml']
            and sources[0].get('helm', {}).get('valuesObject') ==
                {'repository': evidence['repository'], 'revision': evidence['revision'], 'telemetry': evidence['telemetry']}
            and sources[1] == {'repoURL': evidence['private_repository'], 'targetRevision': 'main', 'ref': 'values'})


def guard(evidence, target, read, root=None):
    """Refuse initial adoption of foreign objects; never create or repair resources."""
    evidence = validate(evidence, target, root)
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
        owners = [row for row in meta.get('managedFields', []) if 'f:sources' in row.get('fieldsV1', {}).get('f:spec', {})]
        # Adoption must remain healthy even if root tracking appears on a retry.
        adoption = tracking is None or bool(existing and existing.get('adoption', True))
        if (meta.get('labels', {}).get('cloudlab.io/owner') != OWNER or meta.get('finalizers')
                or meta.get('ownerReferences') or meta.get('deletionTimestamp')
                or tracking not in (None, TRACKING) or not sources_match(app, evidence)
                or spec.get('project') != APP
                or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
                or spec.get('syncPolicy', {}).get('automated', {}).get('prune') is not False
                or (tracking is None and (len(owners) != 1 or owners[0].get('manager') != OWNER
                                         or owners[0].get('operation') != 'Apply'))
                or (tracking == TRACKING and any(row.get('manager') not in
                        (OWNER, 'argocd-controller', 'argocd-application-controller') for row in owners))
                or app.get('operation') or status.get('operationState', {}).get('phase') in ('Running', 'Terminating')
                or (adoption and (status.get('health', {}).get('status') != 'Healthy'
                    or status.get('sync', {}).get('status') != 'Synced'
                    or any(row.get('type', '').endswith('Error') for row in status.get('conditions', []))))):
            raise RuntimeError('Service activation requires its exact idle catalog owner; pending operations require inspection or recovery')
        evidence['existing'] = {'uid': meta['uid'], 'sources': copy.deepcopy(spec['sources']), 'adoption': adoption}
    return evidence
