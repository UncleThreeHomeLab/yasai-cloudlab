"""Bounded Git read failure proof; no workload or credential writer."""
import hashlib
import json
import re
import time
import uuid
from playbooks.istio.files.kube import get, kube, wait
from playbooks.services.files.bootstrap import APP, OWNER, application, converged


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


def owned_sources(app):
    entries = [row for row in app['metadata'].get('managedFields', [])
               if 'f:sources' in row.get('fieldsV1', {}).get('f:spec', {})]
    return (len(entries) == 1 and entries[0].get('manager') == OWNER
            and entries[0].get('operation') == 'Apply')


def run(payload, *, next_revision):
    if not re.fullmatch(r'[0-9a-f]{40}', next_revision) or next_revision == payload['revision']:
        raise ValueError('Future source proof requires another approved immutable public revision')
    app = get('application.argoproj.io', APP, 'argocd')
    if (not converged(payload) or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
            or app['metadata'].get('ownerReferences') or app['metadata'].get('finalizers')
            or app['metadata'].get('deletionTimestamp') or not owned_sources(app)
            or app['spec'] != application(payload)['spec']):
        raise RuntimeError('Git outage proof requires the exact converged catalog owner')
    sources = app['spec']['sources']
    uid = app['metadata']['uid']
    before = snapshot()
    branch = 'cloudlab-unavailable-' + uuid.uuid4().hex
    replacement = json.loads(json.dumps(sources))
    replacement[1]['targetRevision'] = branch
    def apply(expected, desired, *, dry_run=False):
        for _ in range(6):
            current = get('application.argoproj.io', APP, 'argocd')
            complete = application(payload)
            complete['spec']['sources'] = expected
            if (current['metadata']['uid'] != uid or current['spec'] != complete['spec']
                    or current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                    or current['metadata'].get('ownerReferences') or current['metadata'].get('finalizers')
                    or current['metadata'].get('deletionTimestamp') or not owned_sources(current)):
                raise RuntimeError('Catalog ownership changed; source repair refused')
            declaration = application(payload)
            declaration['spec']['sources'] = desired
            declaration['metadata'].update(uid=uid, resourceVersion=current['metadata']['resourceVersion'])
            result = kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-',
                          *(['--dry-run=server'] if dry_run else []), document=declaration, allow_failure=True)
            if result.returncode == 0:
                return
            if 'the object has been modified' not in result.stderr:
                raise RuntimeError('Complete catalog Apply failed; diagnostics withheld')
            time.sleep(1)
        raise RuntimeError('Catalog changed repeatedly; source operation refused')
    next_payload = dict(payload, revision=next_revision)
    next_sources = application(next_payload)['spec']['sources']
    apply(sources, next_sources, dry_run=True)
    try:
        apply(sources, replacement)
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
                or not owned_sources(current)):
            raise RuntimeError('Catalog ownership changed; source repair refused')
        observed = current['spec']['sources']
        if observed == replacement:
            apply(replacement, sources)
        elif observed != sources:
            raise RuntimeError('Catalog source changed independently; repair refused')
        wait(lambda: converged(payload), 'private Git source recovery', timeout=600)
    if snapshot() != before:
        raise RuntimeError('Private source recovery changed retained identities or contents')
    apply(sources, next_sources, dry_run=True)
    return {'private_source_failure_retained_resources': True, 'private_source_recovered': True,
            'next_source_pin_server_dry_run': True}
