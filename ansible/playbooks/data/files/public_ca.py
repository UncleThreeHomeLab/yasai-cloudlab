"""Project the CNPG public CA under the existing data-owner lock and repair cadence."""
import base64
import json
import re
from playbooks.istio.files.kube import get, kube

OWNER = 'cloudlab-data-bootstrap'


def reconcile(values):
    cluster = get('cluster.postgresql.cnpg.io', 'cloudlab-postgres', 'cloudlab-data')
    ca = get('secret', 'cloudlab-postgres-ca', 'cloudlab-data')
    if (not cluster or not ca or not any(ref.get('uid') == cluster['metadata']['uid']
            for ref in ca['metadata'].get('ownerReferences', []))):
        raise RuntimeError('Database CA lacks its current CNPG owner')
    public = base64.b64decode(ca['data']['ca.crt'], validate=True).decode()
    if '-----BEGIN CERTIFICATE-----' not in public:
        raise RuntimeError('Database public CA is invalid')
    changed = False
    # Consumers include the existing Notes database, whose provisioning request
    # is removed by inputs after verifying its original data-owner scope.
    for namespace in values.get('serviceConsumers', []):
        if not isinstance(namespace, str) or not re.fullmatch(r'cloudlab-app-[a-z][a-z0-9-]{0,30}', namespace):
            raise ValueError('CA projection requires an approved service namespace')
        service = namespace.removeprefix('cloudlab-app-')
        ns = get('namespace', namespace)
        if not ns:
            continue  # Git creates namespaces; required external data provisioning stays explicit.
        if (ns['metadata'].get('labels', {}).get('cloudlab.io/owner') != 'service-platform'
                or not ns['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-services:')
                or ns['metadata'].get('ownerReferences')):
            raise RuntimeError('CA projection namespace has an ambiguous owner')
        current = get('configmap', 'database-ca', namespace)
        if current:
            meta = current['metadata']
            owner = meta.get('labels', {}).get('cloudlab.io/owner')
            tracking = meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id')
            if (meta.get('ownerReferences') or (owner != OWNER and not (
                    owner is None and tracking and tracking.startswith(service + '-' + service + ':')))):
                raise RuntimeError('Database CA configuration has an ambiguous owner')
            if tracking:
                app = get('application.argoproj.io', service + '-' + service, 'argocd') or {}
                sources = app.get('spec', {}).get('sources') or [app.get('spec', {}).get('source', {})]
                source = sources[0]
                status = app.get('status', {})
                operation = status.get('operationState', {})
                revision = source.get('targetRevision')
                if (not source.get('helm', {}).get('valuesObject', {}).get('definition')
                        or status.get('sync', {}).get('revision') != revision
                        or status.get('sync', {}).get('status') != 'Synced'
                        or status.get('health', {}).get('status') != 'Healthy'
                        or operation.get('phase') in ('Running', 'Terminating') or app.get('operation')
                        or any(c.get('type', '').endswith('Error') for c in status.get('conditions', []))):
                    continue  # Current rendered chart releases the writer, including a no-op Git revision.

            if current.get('data', {}).keys() - {'ca.crt'}:
                raise RuntimeError('Database CA configuration contains unrelated fields')
            if owner == OWNER and tracking:
                raise RuntimeError('Database CA has competing writers')
            if owner == OWNER and current.get('data') == {'ca.crt': public}:
                continue
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': meta['uid']},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': meta['resourceVersion']},
                     {'op': 'add', 'path': '/data', 'value': {'ca.crt': public}},
                     {'op': 'add', 'path': '/metadata/labels',
                      'value': dict(meta.get('labels', {}), **{'cloudlab.io/owner': OWNER})}]
            if tracking:
                patch.append({'op': 'remove', 'path': '/metadata/annotations/argocd.argoproj.io~1tracking-id'})
            kube('patch', 'configmap', 'database-ca', '-n', namespace,
                 '--type=json', '-p', json.dumps(patch))
        else:
            kube('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'ConfigMap',
                 'metadata': {'name': 'database-ca', 'namespace': namespace,
                              'labels': {'cloudlab.io/owner': OWNER}}, 'data': {'ca.crt': public}})
        changed = True
    return changed
