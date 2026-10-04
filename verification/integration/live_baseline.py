"""Read-only M0 inventory. Never read Secret data or print deployment endpoints."""

import json
from pathlib import Path
import subprocess


def get(kind, *args):
    return json.loads(subprocess.check_output(
        ['/usr/local/bin/k3s', 'kubectl', 'get', kind, *args, '--show-managed-fields', '-o', 'json']))


database = Path('/var/lib/rancher/k3s/server/db')
result = {'datastore': {'sqlite_file_present': (database / 'state.db').is_file(),
                        'embedded_etcd_member_present': (database / 'etcd/member').is_dir()}}
for namespace in ('external-secrets', 'longhorn-system'):
    objects = get('deployments,daemonsets', '-n', namespace)['items']
    result[namespace] = [dict(
        kind=item['kind'], name=item['metadata']['name'],
        managers=sorted({x['manager'] for x in item['metadata'].get('managedFields', [])}),
        desired=item['spec'].get('replicas'),
        ready=item['status'].get('readyReplicas', item['status'].get('numberReady', 0)),
        images=[c['image'] for c in item['spec']['template']['spec']['containers']],
    ) for item in objects]
result['crds'] = [dict(name=x['metadata']['name'], managers=sorted({
    f['manager'] for f in x['metadata'].get('managedFields', [])}))
    for x in get('crds')['items']
    if x['metadata']['name'].endswith(('.longhorn.io', '.external-secrets.io'))]
result['storage_classes'] = [dict(name=x['metadata']['name'],
    provisioner=x['provisioner'], parameters=x.get('parameters', {}),
    default=x['metadata'].get('annotations', {}).get('storageclass.kubernetes.io/is-default-class'))
    for x in get('storageclasses')['items'] if x['metadata']['name'] in ('longhorn', 'local-path')]
target = get('backuptargets.longhorn.io', 'default', '-n', 'longhorn-system')
result['backup'] = dict(poll_interval=target['spec']['pollInterval'],
    credential_secret=target['spec']['credentialSecret'])
setting_names = {'default-replica-count', 'default-data-path', 'default-data-locality',
                 'replica-soft-anti-affinity', 'storage-over-provisioning-percentage',
                 'storage-minimal-available-percentage', 'storage-reserved-percentage-for-default-disk',
                 'v1-data-engine', 'v2-data-engine', 'upgrade-checker',
                 'allow-collecting-longhorn-usage-metrics'}
result['settings'] = {x['metadata']['name']: x['value']
    for x in get('settings.longhorn.io', '-n', 'longhorn-system')['items']
    if x['metadata']['name'] in setting_names}
result['jobs'] = [dict(name=x['metadata']['name'], cron=x['spec']['cron'],
    retain=x['spec']['retain'], concurrency=x['spec']['concurrency'])
    for x in get('recurringjobs.longhorn.io', '-n', 'longhorn-system')['items']]
print(json.dumps(result, sort_keys=True))
