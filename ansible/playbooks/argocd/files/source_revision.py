"""Check public convergence and pinned secondary values sources."""
import re


def matches_revision(application, revision):
    status = application.get('status', {}).get('sync', {})
    sources = application.get('spec', {}).get('sources')
    if not sources:
        return status.get('revision') == revision
    observed = status.get('revisions', [])
    return (len(sources) >= 2 and len(observed) == len(sources) and observed[0] == revision and
            all(re.fullmatch('[a-f0-9]{40}', source.get('targetRevision', '')) and
                source['targetRevision'] == observed[index]
                for index, source in enumerate(sources[1:], start=1)))


def identity_project_rules(project):
    spec = project.get('spec', {})
    baseline = [{'group': 'argoproj.io', 'kind': kind} for kind in ('Application', 'AppProject')]
    application_sets = {'group': 'argoproj.io', 'kind': 'ApplicationSet'}
    if application_sets in spec.get('namespaceResourceWhitelist', []):
        baseline.append(application_sets)
    desired = baseline + [{'group': 'external-secrets.io', 'kind': 'ExternalSecret'}]
    if (spec.get('destinations') != [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}]
            or spec.get('clusterResourceWhitelist') != [{'group': '', 'kind': 'Namespace'}]
            or spec.get('namespaceResourceWhitelist') not in (baseline, desired)
            or spec.get('namespaceResourceBlacklist')):
        raise RuntimeError('Identity source grant requires the exact bounded root project')
    return desired
