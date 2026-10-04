"""Exercise real volumes, cross-node attachment, and external backup restoration.

Runs on the server with its local kubectl. Creates unique resources and cleans up
only resources owned by this run. Never drains, reboots, or deletes existing nodes.
"""

import json
import sys
import time
import uuid

from kube import create, delete, get, kubectl, wait
from verify_health import conditions_ready, healthy_volume, verify_health
from verify_backup import create_backup
from monthly_window import require_window


def verify(config):
    if config.get('cloud_backup', False):
        require_window(reserve=3600)
    verify_health(config)
    nodes = config['nodes']
    policy = config['policy']

    run = 'storage-verify-' + uuid.uuid4().hex[:12]
    namespace_created = False
    restore_class_created = False
    backup_created = False
    volumes = []

    def pvc(name, storage_class):
        create('PersistentVolumeClaim', name,
               {'accessModes': ['ReadWriteOnce'], 'storageClassName': storage_class,
                'resources': {'requests': {'storage': '1Gi'}}}, namespace=run)

    def pod(name, node, claim):
        create('Pod', name, {'nodeSelector': {'kubernetes.io/hostname': node},
               'restartPolicy': 'Never', 'activeDeadlineSeconds': 1800,
               'containers': [{'name': 'test', 'image': config['image'],
                   'command': ['sh', '-c', 'sleep 1800'],
                   'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                                 'limits': {'cpu': '250m', 'memory': '64Mi'}},
                   'volumeMounts': [{'name': 'data', 'mountPath': '/data'}]}],
               'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': claim}}]}, namespace=run)
        wait('Test volume mounted', lambda: conditions_ready(
            get('pod', name, run).get('status', {}).get('conditions', []), ['Ready']))

    def execute(name, command):
        return kubectl('exec', '-n', run, name, '--', 'sh', '-ec', command).strip()

    def volume_name(claim):
        pv = get('persistentvolumeclaim', claim, run)['spec']['volumeName']
        handle = get('persistentvolume', pv, None)['spec']['csi']['volumeHandle']
        volumes.append(handle)
        return handle

    try:
        create('Namespace', run, namespace=None)
        namespace_created = True
        pvc('source', policy['storage_class'])
        pod('writer', nodes[0], 'source')
        source = volume_name('source')
        wait('Two healthy replicas on separate nodes', lambda: healthy_volume(source, nodes))
        started = time.monotonic()
        checksum = execute('writer', 'dd if=/dev/urandom of=/data/proof.bin bs=1M count=8 2>/dev/null; sync; sha256sum /data/proof.bin').split()[0]
        print('8 MiB write, sync and checksum completed in %.2f seconds (smoke test, not a benchmark)' %
              (time.monotonic() - started), flush=True)
        delete('pod', 'writer', run)
        wait('Volume detached from first node', lambda: get('volumes.longhorn.io', source)['status']['state'] == 'detached')
        pod('reader', nodes[1], 'source')
        if execute('reader', 'sha256sum /data/proof.bin').split()[0] != checksum:
            raise RuntimeError('Cross-node data checksum mismatch')
        wait('Replicas healthy after cross-node attachment', lambda: healthy_volume(source, nodes))
        print('Persistent data survived movement between both nodes: passed', flush=True)

        if config.get('cloud_backup', False):
            backup_created = True
            backup_url = create_backup(source, run)
            base = get('storageclass', policy['storage_class'], None)
            parameters = dict(base['parameters'], fromBackup=backup_url)
            create('StorageClass', run, namespace=None, api='storage.k8s.io/v1',
                   provisioner='driver.longhorn.io', allowVolumeExpansion=True, reclaimPolicy='Delete',
                   volumeBindingMode='Immediate', parameters=parameters)
            restore_class_created = True
            pvc('restored', run)
            pod('restored', nodes[0], 'restored')
            restored = volume_name('restored')
            wait('Restored volume has two healthy replicas', lambda: healthy_volume(restored, nodes))
            if execute('restored', 'sha256sum /data/proof.bin').split()[0] != checksum:
                raise RuntimeError('Restored backup checksum mismatch')
            print('External backup restored into a new volume with matching SHA-256: passed', flush=True)
        else:
            print('External backup restore: excluded from local proof; not tested', flush=True)
    finally:
        # Attempt every cleanup even if one resource takes too long to terminate.
        failures = []
        operations = []
        if namespace_created:
            operations.append(lambda: delete('namespace', run, None))
        if restore_class_created:
            operations.append(lambda: delete('storageclass', run, None))
        if backup_created:
            operations.append(lambda: (require_window(), delete('backups.longhorn.io', run)))
        for operation in operations:
            try:
                operation()
            except RuntimeError:
                failures.append('resource cleanup failed')
        for volume in volumes:
            try:
                wait('Disposable volume removed', lambda: all(v['metadata']['name'] != volume
                     for v in get('volumes.longhorn.io')['items']), timeout=180)
                # BackupVolume deletion removes only the disposable test volume's remote backup directory.
                for backup_volume in (get('backupvolumes.longhorn.io')['items'] if backup_created else []):
                    if backup_volume.get('spec', {}).get('volumeName') == volume:
                        require_window()
                        delete('backupvolumes.longhorn.io', backup_volume['metadata']['name'])
            except RuntimeError:
                failures.append('volume cleanup failed')
        if failures:
            raise RuntimeError('Disposable storage cleanup incomplete: ' + ', '.join(failures))
        print('Disposable storage verification resources removed', flush=True)


if __name__ == '__main__':
    try:
        verify(json.load(sys.stdin))
    except (RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from None
