"""Coordinated cold snapshots of the four application volumes; no live-volume races."""
import json
import re
import time

from automation.data import control
from automation.mesh.kube import condition, get, kube, wait

LH = 'longhorn-system'
OWNER = 'cloudlab-application-backup'
CLAIMS = {
    'postgres': 'cloudlab-postgres-1',
    'master': 'data-cloudlab-data-cloudlab-seaweedfs-master-0',
    'filer': 'data-filer-cloudlab-seaweedfs-filer-0',
    'volume': 'data1-cloudlab-seaweedfs-volume-0',
}


def inventory():
    claims = get('pvc', namespace=control.NAMESPACE)['items']
    if {c['metadata']['name'] for c in claims} != set(CLAIMS.values()):
        raise RuntimeError('Backup requires exactly the declared four application PVCs')
    result = {}
    for component, name in CLAIMS.items():
        claim = next(c for c in claims if c['metadata']['name'] == name)
        pv = get('pv', claim['spec']['volumeName'])
        volume = get('volumes.longhorn.io', pv['spec']['csi']['volumeHandle'], LH)
        if (claim['status']['phase'] != 'Bound' or claim['spec']['storageClassName'] != 'cloudlab-data'
                or pv['spec']['claimRef']['uid'] != claim['metadata']['uid']
                or volume['spec']['numberOfReplicas'] != 2 or volume['status']['robustness'] != 'healthy'
                or volume['spec'].get('backupCompressionMethod') != 'lz4'
                or volume['spec'].get('backupTargetName') != 'default'):
            raise RuntimeError('Application backup source binding or replica health changed')
        result[component] = {'claim': name, 'claim_uid': claim['metadata']['uid'],
                             'volume': volume['metadata']['name'], 'volume_uid': volume['metadata']['uid'],
                             'size': claim['spec']['resources']['requests']['storage'],
                             'actual_bytes': int(volume['status']['actualSize'])}
    return result


def patch_values(app, values):
    obj = get('application.argoproj.io', app, 'argocd')
    if obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != control.OWNER:
        raise RuntimeError('Cannot suspend a foreign application owner')
    kube('patch', 'application.argoproj.io', app, '-n', 'argocd', '--type=merge',
         '--field-manager=' + control.OWNER,
         '-p', json.dumps({'spec': {'source': {'helm': {'valuesObject': values}}}}))


def resume():
    # The runtime Applications retain sole ownership of desired workload state.
    patch_values('cloudlab-seaweedfs', {'seaweedfs': {c: {'replicas': 1} for c in ('master', 'volume', 'filer', 's3')}})
    patch_values(control.APP, {'hibernated': False})
    wait(lambda: condition(get('cluster.postgresql.cnpg.io', 'cloudlab-postgres', control.NAMESPACE), 'Ready'),
         'resume PostgreSQL after cold snapshot', timeout=900)
    for component in ('master', 'volume', 'filer', 's3'):
        kind = 'deployment' if component == 's3' else 'statefulset'
        wait(lambda: get(kind, 'cloudlab-seaweedfs-' + component, control.NAMESPACE)['spec']['replicas'] == 1,
             'Argo resume ' + component, timeout=600)
        kube('rollout', 'status', kind + '/cloudlab-seaweedfs-' + component, '-n', control.NAMESPACE,
             '--timeout=600s', timeout=630)
    control.maintenance(False)
    (control.BASE / 'cold-maintenance.json').unlink(missing_ok=True)


def stop():
    control.atomic(control.BASE / 'cold-maintenance.json', {'started_at': time.time()})
    # Stop S3 first, then filer, volume and master, allowing each to flush cleanly.
    for component in ('s3', 'filer', 'volume', 'master'):
        patch_values('cloudlab-seaweedfs', {'seaweedfs': {component: {'replicas': 0}}})
        wait(lambda: not [p for p in (get('pods', namespace=control.NAMESPACE) or {}).get('items', [])
                          if p['metadata'].get('labels', {}).get('app.kubernetes.io/component') == component],
             'stop ' + component + ' writers', timeout=600)
    patch_values(control.APP, {'hibernated': True})
    wait(lambda: condition(get('cluster.postgresql.cnpg.io', 'cloudlab-postgres', control.NAMESPACE), 'cnpg.io/hibernation'),
         'clean PostgreSQL shutdown', timeout=600)
    if (get('pods', namespace=control.NAMESPACE) or {}).get('items', []):
        raise RuntimeError('Application pods remain during cold snapshot boundary')


def validate_sources(manifest):
    if not re.fullmatch(r'data-[a-f0-9]{24}', manifest['generation']) or set(manifest['volumes']) != set(CLAIMS):
        raise ValueError('Invalid coordinated generation identity')
    for component, row in manifest['volumes'].items():
        if (row['claim'] != CLAIMS[component] or not re.fullmatch(r'pvc-[a-f0-9-]{36}', row['volume'])
                or not re.fullmatch(r'[1-9][0-9]*(Gi|Mi)', row['size'])
                or row['snapshot'] != manifest['generation'] + '-' + component):
            raise ValueError('Invalid application volume identity')


def snapshots(manifest):
    validate_sources(manifest)
    for row in manifest['volumes'].values():
        volume = get('volumes.longhorn.io', row['volume'], LH)
        if not volume or volume['metadata']['uid'] != row['volume_uid']:
            raise RuntimeError('Application volume identity changed before snapshot')
        existing = get('snapshots.longhorn.io', row['snapshot'], LH)
        if existing:
            raise RuntimeError('Snapshot identity already exists; resume its recorded generation')
        kube('create', '-f', '-', document={'apiVersion': 'longhorn.io/v1beta2', 'kind': 'Snapshot',
             'metadata': {'name': row['snapshot'], 'namespace': LH, 'labels': {'cloudlab.io/owner': OWNER}},
             'spec': {'volume': row['volume'], 'createSnapshot': True,
                      'labels': {'cloudlab-generation': manifest['generation']}}})
        wait(lambda: (get('snapshots.longhorn.io', row['snapshot'], LH) or {}).get('status', {}).get('readyToUse'),
             'cold application snapshot', timeout=600)


def cleanup_snapshots(manifest):
    validate_sources(manifest)
    for row in manifest['volumes'].values():
        snapshot = get('snapshots.longhorn.io', row['snapshot'], LH)
        if not snapshot:
            continue
        if (snapshot['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                or snapshot['spec']['volume'] != row['volume']):
            raise RuntimeError('Refusing to delete a snapshot outside its recorded owner')
        # Longhorn may retain a removed parent as part of the active volume chain;
        # it is no longer a recoverable snapshot, not a retained local backup.
        kube('delete', 'snapshots.longhorn.io', row['snapshot'], '-n', LH, '--wait=false')
        wait(lambda: not (s := get('snapshots.longhorn.io', row['snapshot'], LH))
             or s.get('status', {}).get('markRemoved'), 'remove temporary recovery snapshot', timeout=600)
