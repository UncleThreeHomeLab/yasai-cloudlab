"""Bind live observability parent state to committed render expectations.

Reads {"parent": live Application, "public": committed render payload} and emits
the native observation inputs verify.py needs. Read-only: no secrets, no
network, no writes. Authenticity of the digest comes from Argo (parent spec
equality plus Synced/Healthy); this binder only extracts the observed value and
requires parent fields to agree with each other.
"""
import json
import re
import sys

HEX40 = '[a-f0-9]{40}'
HEX64 = '[a-f0-9]{64}'
REPO = r'https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[.]git'
PARENT = 'cloudlab-observability-gitops'


def prepare(parent, public):
    """Return native observation inputs for one live parent and render."""
    if not isinstance(parent, dict) or not isinstance(public, dict):
        raise ValueError('Observability inputs require a parent and a public payload')
    public_revision = public.get('revision')
    repository = public.get('repository')
    if not re.fullmatch(HEX40, public_revision or ''):
        raise ValueError('Public revision is not an exact commit')
    if not re.fullmatch(REPO, repository or ''):
        raise ValueError('Public repository is not an explicit GitHub HTTPS remote')
    sets = [obj for obj in public.get('roots', [])
            if isinstance(obj, dict) and obj.get('kind') == 'ApplicationSet'
            and obj.get('metadata', {}).get('name') == PARENT]
    if len(sets) != 1 or not isinstance(sets[0].get('spec'), dict):
        raise ValueError('Committed render lacks exactly one observability parent')
    annotations = parent.get('metadata', {}).get('annotations', {})
    if not isinstance(annotations, dict):
        raise ValueError('Live parent has no readable annotations')
    paused = annotations.get('argocd.argoproj.io/skip-reconcile') == 'true'
    sources = parent.get('spec', {}).get('sources', [])
    if not isinstance(sources, list) or not sources:
        raise ValueError('Live parent has no multi-source spec')
    public_sources = [s for s in sources if s.get('repoURL') == repository]
    if len(public_sources) != 1 or public_sources[0].get('targetRevision') != public_revision:
        raise ValueError('Live parent does not bind the committed public revision')
    private = [s for s in sources if s.get('repoURL') != repository]
    accepted = {s.get('targetRevision') for s in private}
    if len(private) < 1 or len(accepted) != 1:
        raise ValueError('Live parent lacks exactly one private source revision')
    accepted_revision = accepted.pop()
    if not re.fullmatch(HEX40, accepted_revision or ''):
        raise ValueError('Accepted private revision is not an exact commit')
    if not paused:
        revisions = parent.get('status', {}).get('sync', {}).get('revisions', [])
        if accepted_revision not in revisions or public_revision not in revisions:
            raise ValueError('Live parent spec and sync status disagree')
    digests = {annotations.get('cloudlab.io/observability-input-digest')}
    for source in sources:
        values = (source.get('helm') or {}).get('valuesObject', {})
        if isinstance(values, dict) and 'nativeInputDigest' in values:
            digests.add(values['nativeInputDigest'])
    digests.discard(None)
    if len(digests) != 1:
        raise ValueError('Live parent lacks exactly one input digest')
    digest = digests.pop()
    if not re.fullmatch(HEX64, digest or ''):
        raise ValueError('Observed input digest is malformed')
    return {'native': {'repository': repository, 'configuration_revision': public_revision,
                       'digest': digest},
            'acceptedRevision': accepted_revision, 'paused': paused,
            'applicationSet': sets[0]['spec'], 'public_revision': public_revision}


if __name__ == '__main__':
    try:
        envelope = json.load(sys.stdin)
        print(json.dumps(prepare(envelope['parent'], envelope['public'])))
    except Exception:
        raise SystemExit('Native observability inputs unavailable; private diagnostics withheld') from None
