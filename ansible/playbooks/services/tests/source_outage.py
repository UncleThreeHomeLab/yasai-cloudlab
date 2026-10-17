"""Bounded Git read failure proof; no workload or credential writer."""
import hashlib
import json
import uuid
from playbooks.istio.files.kube import get, kube, wait
from playbooks.services.files.bootstrap import APP, OWNER, converged


def snapshot():
    result = {}
    namespaces = [row['metadata']['name'] for row in (get('namespaces') or {'items': []})['items']
                  if row['metadata']['name'].startswith('cloudlab-app-')]
    for namespace in namespaces:
      for kind in ('deployments.apps', 'services', 'secrets', 'persistentvolumeclaims'):
        for row in (get(kind, namespace=namespace) or {'items': []})['items']:
            meta = row['metadata']
            if not meta.get('namespace', '').startswith('cloudlab-app-'):
                continue
            key = '/'.join((kind, meta['namespace'], meta['name']))
            result[key] = [meta['uid'], hashlib.sha256(json.dumps(row.get('data', {}), sort_keys=True).encode()).hexdigest()]
    return result


def source_managers(app):
    return {row.get('manager') for row in app['metadata'].get('managedFields', [])
            if 'f:sources' in row.get('fieldsV1', {}).get('f:spec', {})}


def run(payload, *, recovery=None):
    app = get('application.argoproj.io', APP, 'argocd')
    if (not converged(payload) or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
            or app['metadata'].get('ownerReferences') or app['metadata'].get('finalizers')):
        raise RuntimeError('Git outage proof requires the exact converged catalog owner')
    sources = app['spec']['sources']
    uid = app['metadata']['uid']
    if recovery is not None:
        if (not isinstance(recovery, dict) or not isinstance(recovery.get('time'), str)
                or recovery != {'uid': uid, 'sources': sources, 'manager': 'kubectl-patch', 'time': recovery['time']}):
            raise RuntimeError('Source ownership recovery differs from the exact known fixture')
    legacy = [row for row in app['metadata'].get('managedFields', []) if row.get('manager') == 'kubectl-patch']
    known_legacy = (recovery is not None and source_managers(app) == {'kubectl-patch'} and len(legacy) == 1
                    and legacy[0].get('operation') == 'Update' and legacy[0].get('time') == recovery['time'])
    if source_managers(app) != {OWNER} and not known_legacy:
        raise RuntimeError('Catalog source has a foreign or ambiguous field manager')
    before = snapshot()
    branch = 'cloudlab-unavailable-' + uuid.uuid4().hex
    replacement = json.loads(json.dumps(sources))
    replacement[1]['targetRevision'] = branch
    def patch(expected, desired):
        kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=json',
             '--field-manager=' + OWNER, '-p', json.dumps([
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
        if (current['metadata']['uid'] != uid
                or current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                or current['metadata'].get('ownerReferences') or current['metadata'].get('finalizers')
                or source_managers(current) != {OWNER}):
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
