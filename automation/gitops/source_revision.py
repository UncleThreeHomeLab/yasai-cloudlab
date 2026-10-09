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
