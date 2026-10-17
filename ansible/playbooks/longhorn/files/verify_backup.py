"""Create a real external backup for the caller's disposable test volume."""

from kube import create, get, wait
from monthly_window import require_window


def create_backup(volume, name):
    """Return the completed backup URL; the caller owns cleanup of these resources."""
    require_window(reserve=3600)
    create('Snapshot', name, {'volume': volume, 'createSnapshot': True}, api='longhorn.io/v1beta2')
    wait('Snapshot ready', lambda: get('snapshots.longhorn.io', name).get('status', {}).get('readyToUse'))
    create('Backup', name, {'snapshotName': name, 'backupMode': 'incremental'}, api='longhorn.io/v1beta2')

    def completed():
        status = get('backups.longhorn.io', name).get('status', {})
        if status.get('error') or status.get('state') == 'Error':
            raise RuntimeError('External backup failed; inspect private Longhorn diagnostics')
        return status.get('url') if status.get('state') == 'Completed' else False

    return wait('External backup completed', completed)
