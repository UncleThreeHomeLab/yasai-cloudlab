"""Bounded Git read failure proof; no workload or credential writer."""
import hashlib
import json
import uuid
from playbooks.istio.files.kube import get, kube, wait
from playbooks.services.files.bootstrap import APP, OWNER, converged


def snapshot():
    result = {}
    namespaces = [row['metadata']['name'] for row in get('namespaces')['items']
                  if row['metadata']['name'].startswith('cloudlab-app-')]
    for namespace in namespaces:
      for kind in ('deployments.apps', 'services', 'secrets', 'persistentvolumeclaims'):
        for row in get(kind, namespace=namespace)['items']:
            meta = row['metadata']
            if not meta.get('namespace', '').startswith('cloudlab-app-'):
                continue
            key = '/'.join((kind, meta['namespace'], meta['name']))
            result[key] = [meta['uid'], hashlib.sha256(json.dumps(row.get('data', {}), sort_keys=True).encode()).hexdigest()]
    return result


def run(payload):
    app = get('application.argoproj.io', APP, 'argocd')
    if (not converged(payload) or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
            or app['metadata'].get('ownerReferences') or app['metadata'].get('finalizers')):
        raise RuntimeError('Git outage proof requires the exact converged catalog owner')
    before = snapshot()
    sources = app['spec']['sources']
    uid = app['metadata']['uid']
    branch = 'cloudlab-unavailable-' + uuid.uuid4().hex
    replacement = json.loads(json.dumps(sources))
    replacement[1]['targetRevision'] = branch
    def patch(expected, desired):
        kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=json', '-p', json.dumps([
            {'op': 'test', 'path': '/metadata/uid', 'value': uid},
            {'op': 'test', 'path': '/spec/sources', 'value': expected},
            {'op': 'replace', 'path': '/spec/sources', 'value': desired}]))
    try:
        patch(sources, replacement)
        wait(lambda: any(c.get('type') == 'ComparisonError' for c in
             get('application.argoproj.io', APP, 'argocd').get('status', {}).get('conditions', [])),
             'unavailable private Git revision refusal', timeout=420)
        if snapshot() != before:
            raise RuntimeError('Unavailable catalog changed retained workloads or credentials')
    finally:
        current = get('application.argoproj.io', APP, 'argocd')
        if current['metadata']['uid'] != uid:
            raise RuntimeError('Catalog ownership changed; source repair refused')
        observed = current['spec']['sources']
        if observed == replacement:
            patch(replacement, sources)
        elif observed != sources:
            raise RuntimeError('Catalog source changed independently; repair refused')
        wait(lambda: converged(payload), 'private Git source recovery', timeout=600)
    if snapshot() != before:
        raise RuntimeError('Private source recovery changed retained identities or contents')
    return {'private_source_failure_retained_resources': True, 'private_source_recovered': True}
