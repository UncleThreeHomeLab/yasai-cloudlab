"""Read-only authority checks shared by both retained telemetry writers."""
import os
from pathlib import Path
import re
import stat

MAIN_LOCK = '/run/lock/cloudlab-observability.lock'
HISTORY_LOCK = '/run/lock/cloudlab-observability-history.lock'
# Handoff must hold BOTH locks, main then history, before fencing or adoption.
RETIREMENT_FENCE = Path('/var/lib/cloudlab/observability/legacy-writer-retired.json')
PARENT = 'cloudlab-observability-gitops'
CHILDREN = ('cloudlab-observability', 'cloudlab-prometheus', 'cloudlab-loki',
            'cloudlab-tempo', 'cloudlab-alloy', 'cloudlab-kiali')
OWNER = 'observability-platform'
DESTINATION = {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-observability'}
REPOSITORY = r'https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[.]git'
PIN = r'[a-f0-9]{40}'
DIGEST = 'cloudlab.io/observability-input-digest'


def refuse():
    raise RuntimeError('Telemetry legacy writer authority unavailable; inspect native ownership and retry after recovery')


def check_fence():
    """Missing protected paths are harmless; ambiguous or present fences are not."""
    for path in reversed((RETIREMENT_FENCE, *RETIREMENT_FENCE.parents)):
        try:
            mode = os.lstat(path)
        except FileNotFoundError:
            return
        if (path == RETIREMENT_FENCE or not stat.S_ISDIR(mode.st_mode) or
                mode.st_uid != 0 or mode.st_mode & 0o022):
            refuse()


def metadata_safe(current, name):
    metadata = current.get('metadata', {})
    return (current.get('apiVersion') == 'argoproj.io/v1alpha1' and current.get('kind') == 'Application' and
            metadata.get('name') == name and metadata.get('namespace') == 'argocd' and
            metadata.get('labels', {}).get('cloudlab.io/owner') == OWNER and
            not any(metadata.get(key) for key in ('ownerReferences', 'finalizers', 'deletionTimestamp')))


def check_child(current, name, repository=None):
    if current is None:
        return
    spec, metadata = current.get('spec', {}), current.get('metadata', {})
    source = spec.get('source', {})
    helm = source.get('helm', {}) if isinstance(source, dict) else {}
    path = 'platform/observability' + ('' if name == 'cloudlab-observability' else '/' + name.removeprefix('cloudlab-'))
    annotations = metadata.get('annotations', {})
    if (not metadata_safe(current, name) or 'sources' in spec or not isinstance(source, dict) or
            spec.get('project') != 'cloudlab-observability' or spec.get('destination') != DESTINATION or
            source.get('path') != path or not re.fullmatch(REPOSITORY, source.get('repoURL', '')) or
            (repository is not None and source.get('repoURL') != repository) or
            not re.fullmatch(PIN, source.get('targetRevision', '')) or
            set(source) != {'repoURL', 'targetRevision', 'path', 'helm'} or
            not isinstance(helm, dict) or set(helm) - {'releaseName', 'valueFiles', 'valuesObject'} or
            helm.get('releaseName') != name or
            (helm.get('valueFiles', []) != ([] if name == 'cloudlab-observability' else ['values.json'])) or
            DIGEST in annotations or
            any(key in annotations for key in ('argocd.argoproj.io/tracking-id', 'argocd.argoproj.io/installation-id')) or
            any(key in metadata.get('labels', {}) for key in ('argocd.argoproj.io/instance', 'app.kubernetes.io/instance'))):
        refuse()


def check_parent(current, repository=None):
    if current is None:
        return
    spec = current.get('spec', {})
    sources = spec.get('sources', [])
    if (not metadata_safe(current, PARENT) or current.get('operation') or
            current.get('status', {}).get('operationState', {}).get('phase') in ('Running', 'Terminating') or
            current.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') != 'true' or
            spec.get('syncPolicy') != {'automated': {'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False},
                                      'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']} or
            spec.get('project') != PARENT or 'source' in spec or len(sources) != 2 or
            spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}):
        refuse()
    public, private = sources
    helm = public.get('helm', {})
    native = helm.get('valuesObject', {}).get('nativeSource', {})
    files = helm.get('valueFiles', [])
    if (set(public) != {'repoURL', 'targetRevision', 'path', 'helm'} or
            public.get('path') != 'platform/observability/gitops' or
            not re.fullmatch(REPOSITORY, public.get('repoURL', '')) or
            (repository is not None and public['repoURL'] != repository) or
            not re.fullmatch(PIN, public.get('targetRevision', '')) or
            set(helm) != {'releaseName', 'valueFiles', 'valuesObject'} or helm.get('releaseName') != PARENT or
            set(helm['valuesObject']) != {'nativeSource'} or len(files) != 2 or
            not re.fullmatch(r'\$values/services/catalog(-[a-z0-9]+(-[a-z0-9]+)*)?[.](json|yaml)', files[0]) or
            files[1] != '$values/platform/observability.yaml' or
            set(private) != {'repoURL', 'targetRevision', 'ref'} or private.get('targetRevision') != 'main' or
            private.get('ref') != 'values' or not re.fullmatch(REPOSITORY, private.get('repoURL', '')) or
            private['repoURL'] == public['repoURL'] or
            native != {'repository': public['repoURL'], 'revision': public['targetRevision'], 'valuesRepository': private['repoURL']}):
        refuse()


def check_application_sets(current):
    """No native Set coexistence until authenticated handoff evidence is supported."""
    if (not isinstance(current, dict) or not isinstance(current.get('items'), list)
            or len(current['items']) > 128):
        refuse()
    protected = (PARENT, *CHILDREN)
    def overrides(value):
        if isinstance(value, dict):
            return any(key in ('template', 'templatePatch') or overrides(item) for key, item in value.items())
        return isinstance(value, list) and any(overrides(item) for item in value)
    for obj in current['items']:
        metadata, spec = obj.get('metadata', {}), obj.get('spec', {})
        template = spec.get('template', {})
        name = template.get('metadata', {}).get('name', '')
        project = template.get('spec', {}).get('project', '')
        # A literal name prefix cannot be removed by generator substitutions.
        prefix = name.split('{{', 1)[0] if isinstance(name, str) else ''
        if (obj.get('apiVersion') != 'argoproj.io/v1alpha1' or obj.get('kind') != 'ApplicationSet'
                or metadata.get('namespace') != 'argocd' or metadata.get('name') in protected
                or not prefix or not re.fullmatch(r'[a-z0-9][a-z0-9-]*', prefix)
                or any(target.startswith(prefix) for target in protected)
                or project in ('cloudlab-observability', PARENT) or not isinstance(project, str)
                or not re.fullmatch(r'[a-z0-9][a-z0-9-]*', project)
                or spec.get('templatePatch') or overrides(spec.get('generators', []))):
            refuse()
        template_spec = template.get('spec', {})
        if 'source' in template_spec and 'sources' in template_spec:
            refuse()
        sources = template_spec.get('sources')
        if sources is None:
            sources = [template.get('spec', {}).get('source', {})]
        if not isinstance(sources, list) or not sources:
            refuse()
        for source in sources:
            if not isinstance(source, dict) or 'plugin' in source:
                refuse()
            path = source.get('path')
            if path is None and source.get('ref') == 'values':
                continue
            if (not isinstance(path, str) or not path or '{{' in path or '}}' in path
                    or path.startswith('/') or '\\' in path or any(part in ('', '.', '..') for part in path.split('/'))
                    or path == 'platform/observability' or path.startswith('platform/observability/')):
                refuse()


def inspect(get, repository=None):
    """API errors propagate; only successful --ignore-not-found means absence."""
    check_fence()
    check_application_sets(get('applicationsets.argoproj.io', namespace='argocd'))
    parent = get('application.argoproj.io', PARENT, 'argocd')
    children = {name: get('application.argoproj.io', name, 'argocd') for name in CHILDREN}
    repositories = {row.get('spec', {}).get('source', {}).get('repoURL') for row in children.values()
                    if row and isinstance(row.get('spec', {}).get('source'), dict)}
    if repository is None and len(repositories) == 1:
        repository = next(iter(repositories))
    if len(repositories) > 1:
        refuse()
    check_parent(parent, repository)
    for name, current in children.items():
        check_child(current, name, repository)
    return children
