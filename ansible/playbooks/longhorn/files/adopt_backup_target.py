"""Adopt only an untouched Longhorn-created default target, without force apply."""
import json
import subprocess
import sys

FIELDS = {'backupTargetURL', 'credentialSecret', 'pollInterval'}


def adoption_patch(current, desired):
    if (desired.get('apiVersion') != 'longhorn.io/v1beta2' or
            desired.get('kind') != 'BackupTarget' or
            desired.get('metadata') != {'name': 'default', 'namespace': 'longhorn-system'} or
            set(desired.get('spec', {})) != FIELDS):
        raise RuntimeError('Backup target adoption input exceeds the declared scope')
    if all(current['spec'].get(k) == desired['spec'][k] for k in FIELDS):
        return []
    owners = {m['manager'] for m in current['metadata'].get('managedFields', [])
              if any('f:' + k in m.get('fieldsV1', {}).get('f:spec', {}) for k in FIELDS)}
    if owners == {'cloudlab'}:
        return []  # Ordinary SSA owns subsequent configuration and drift repair.
    if (owners != {'longhorn-manager'} or current['spec'].get('backupTargetURL') != '' or
            current['spec'].get('credentialSecret') != '' or current['spec'].get('pollInterval') != '5m0s'):
        raise RuntimeError('Backup target is not an untouched Longhorn default; adoption refused')
    return [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']}] + [
        {'op': 'replace', 'path': '/spec/' + key, 'value': desired['spec'][key]} for key in sorted(FIELDS)]


def main():
    desired = json.load(sys.stdin)
    command = ['/usr/local/bin/k3s', 'kubectl']
    result = subprocess.run(command + ['get', 'backuptargets.longhorn.io', 'default', '-n',
                            'longhorn-system', '--show-managed-fields', '-o', 'json'],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Cannot inspect default backup target; private output withheld')
    patch = adoption_patch(json.loads(result.stdout), desired)
    if patch:
        result = subprocess.run(command + ['patch', 'backuptargets.longhorn.io', 'default', '-n',
            'longhorn-system', '--type=json', '--field-manager=cloudlab', '--patch-file=/dev/stdin'],
            input=json.dumps(patch), capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError('Guarded backup target adoption failed; private output withheld')
    print(json.dumps({'changed': bool(patch)}))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'Backup target adoption failed') from None
