"""Restore immutable generations into disposable, isolated service fixtures."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

import yaml

from automation.data import control
from automation.data.capture import verify
from automation.data.s3 import S3, S3Error
from automation.mesh.kube import condition, get, kube, wait

NAMESPACE = 'cloudlab-data-restore'
LABEL = {'cloudlab.io/fixture': 'application-data-restore'}


def postgres(arguments, *, source=None, data=None):
    primary = get('cluster.postgresql.cnpg.io', 'data-restore', NAMESPACE)['status']['currentPrimary']
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', 'exec', '-i', '-n', NAMESPACE,
                             primary, '-c', 'postgres', '--', *arguments], stdin=source,
                            input=data, capture_output=True, timeout=1800)
    if result.returncode:
        raise RuntimeError('Isolated PostgreSQL restore failed; private diagnostics withheld')
    return result.stdout


def sql(statement, database='postgres'):
    return postgres(['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-d', database], data=statement.encode()).decode().strip()


def cleanup():
    namespace = get('namespace', NAMESPACE)
    if not namespace:
        return
    if namespace['metadata'].get('labels', {}).get('cloudlab.io/fixture') != LABEL['cloudlab.io/fixture']:
        raise RuntimeError('Restore namespace is not owned by this fixture')
    # Retain-class PVs outlive PVC deletion. Record only this fixture's exact UIDs.
    claims = get('pvc', namespace=NAMESPACE)['items']
    targets = []
    for claim in claims:
        name = claim['spec'].get('volumeName')
        if not name:
            continue
        volume = get('pv', name)
        ref = volume['spec'].get('claimRef', {})
        if ref.get('namespace') != NAMESPACE or ref.get('uid') != claim['metadata']['uid']:
            raise RuntimeError('Restore PVC binding changed before cleanup')
        targets.append((name, volume['metadata']['uid'], ref['uid']))
    kube('delete', 'namespace', NAMESPACE, '--wait=true', '--timeout=300s', timeout=330)
    for name, uid, claim_uid in targets:
        wait(lambda: not get('pv', name) or get('pv', name)['status']['phase'] == 'Released', 'fixture volume release', timeout=120)
        volume = get('pv', name)
        if not volume:
            continue
        if volume['metadata']['uid'] != uid or volume['spec']['claimRef']['uid'] != claim_uid or volume['status']['phase'] != 'Released':
            raise RuntimeError('Disposable restore volume is not safely released')
        kube('patch', 'pv', name, '--type=merge', '-p', '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}')
        kube('delete', 'pv', name, '--wait=true', '--timeout=300s', timeout=330)


def run(directory):
    manifest = verify(directory)
    if get('namespace', NAMESPACE):
        raise RuntimeError('Previous isolated restore remains; inspect and run fixture cleanup before retrying')
    started = time.monotonic()
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Namespace',
        'metadata': {'name': NAMESPACE, 'labels': {**LABEL, 'istio-injection': 'disabled',
            'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.36'}}})
    try:
        pin = json.loads((control.ROOT / 'platform/data/cnpg/artifact.lock.json').read_text())['postgres_image']
        cluster = {'apiVersion': 'postgresql.cnpg.io/v1', 'kind': 'Cluster',
            'metadata': {'name': 'data-restore', 'namespace': NAMESPACE, 'labels': LABEL},
            'spec': {'instances': 1, 'imageName': pin, 'enableSuperuserAccess': False,
                'storage': {'size': '8Gi', 'storageClass': 'cloudlab-data'},
                'bootstrap': {'initdb': {'database': 'restore_bootstrap', 'owner': 'restore_owner'}},
                'resources': {'requests': {'cpu': '250m', 'memory': '512Mi'}, 'limits': {'cpu': '2', 'memory': '2Gi'}}}}
        kube('apply', '-f', '-', document=cluster)
        wait(lambda: condition(get('cluster.postgresql.cnpg.io', 'data-restore', NAMESPACE), 'Ready'), 'isolated PostgreSQL', timeout=600)
        sql((directory / 'roles.sql').read_text())
        with (directory / 'database.dump').open('rb') as source:
            postgres(['pg_restore', '--exit-on-error', '--create', '-d', 'postgres'], source=source)
        actual_extensions = json.loads(sql("SELECT coalesce(json_agg(json_build_object('name',extname,'version',extversion)), '[]'::json) FROM pg_extension", manifest['database']))
        if sorted(actual_extensions, key=lambda e: e['name']) != sorted(manifest['extensions'], key=lambda e: e['name']):
            raise RuntimeError('Restored extension inventory differs')
        # Query with the restored application privileges, not a superuser bypass.
        role = control.identity(manifest['roles'][0])
        if sql('SET ROLE ' + role + '; SELECT current_user;', manifest['database']).splitlines()[-1] != manifest['roles'][0]:
            raise RuntimeError('Restored application role cannot query')
        forbidden = sql("SELECT count(*) FROM pg_roles WHERE rolname IN (" + ','.join("'" + name + "'" for name in manifest['roles']) + ') AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)')
        if forbidden != '0':
            raise RuntimeError('Restored application role acquired elevated privileges')
        for name in ('cloudlab-s3-tls', 'cloudlab-s3-config'):
            original = get('secret', name, control.NAMESPACE)
            data = original['data']
            if name == 'cloudlab-s3-config':
                # Restore happens after maintenance releases; use current identities.
                config = control.secret(name)['seaweedfs_s3_config']
                data = {'seaweedfs_s3_config': base64.b64encode(config.encode()).decode()}
            kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Secret',
                 'metadata': {'name': name, 'namespace': NAMESPACE, 'labels': LABEL},
                 'type': original.get('type', 'Opaque'), 'data': data})
        chart = control.ROOT / 'platform/data/seaweedfs'
        result = subprocess.run(['helm', 'template', 'data-restore', str(chart), '--namespace', NAMESPACE,
                                 '--kube-version', '1.36.5', '--set-json',
                                 'seaweedfs.volume.dataDirs=[{"name":"data1","type":"persistentVolumeClaim","size":"12Gi","storageClass":"cloudlab-data","maxVolumes":10}]'],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise RuntimeError('Isolated SeaweedFS render failed')
        for obj in yaml.safe_load_all(result.stdout):
            if not obj:
                continue
            if obj['kind'] not in ('ServiceAccount', 'Service', 'ConfigMap', 'StatefulSet', 'Deployment', 'Issuer', 'Certificate', 'NetworkPolicy'):
                raise RuntimeError('Restore chart contains an unexpected resource kind')
            obj['metadata']['namespace'] = NAMESPACE
            obj['metadata'].setdefault('labels', {}).update(LABEL)
            kube('apply', '-f', '-', document=obj)
        for name in ('master', 'volume', 'filer'):
            kube('rollout', 'status', 'statefulset/data-restore-seaweedfs-' + name, '-n', NAMESPACE, '--timeout=600s', timeout=630)
        kube('rollout', 'status', 'deployment/data-restore-seaweedfs-s3', '-n', NAMESPACE, '--timeout=600s', timeout=630)
        service = get('service', 'data-restore-seaweedfs-s3', NAMESPACE)
        values = control.settings()
        source = control.s3()
        endpoint = 'https://' + values['s3Host'] + ':8334'
        client = S3(endpoint, source.access, source.secret, address=service['spec']['clusterIP'])
        client.ensure_bucket(manifest['bucket'])
        for row in manifest['objects']:
            client.upload(manifest['bucket'], row['key'], directory / row['file'], headers=row['headers'])
            client.request('PUT', manifest['bucket'], row['key'], query={'tagging': ''}, data=row['tags'].encode())
            with tempfile.TemporaryFile() as target:
                response = client.request('GET', manifest['bucket'], row['key'], target=target,
                                          limit=16 * 1024**3)
            record = next(item for item in manifest['files'] if item['file'] == row['file'])
            if response['sha256'] != record['sha256'] or response['bytes'] != record['bytes']:
                raise RuntimeError('Restored object checksum differs')
            headers = {key.lower(): value for key, value in response['headers'].items()}
            if any(headers.get(key) != value for key, value in row['headers'].items()):
                raise RuntimeError('Restored object metadata differs')
            expected_tags = sorted((e.tag.split('}')[-1], e.text) for e in ET.fromstring(row['tags']).iter() if e.text and e.text.strip())
            actual_tags = sorted((e.tag.split('}')[-1], e.text) for e in ET.fromstring(client.request('GET', manifest['bucket'], row['key'], query={'tagging': ''})['data']).iter() if e.text and e.text.strip())
            if actual_tags != expected_tags:
                raise RuntimeError('Restored object tags differ')
        app_source = control.s3(False)
        app = S3(endpoint, app_source.access, app_source.secret, address=service['spec']['clusterIP'])
        if {r['key'] for r in app.objects(manifest['bucket'])} != {r['key'] for r in manifest['objects']}:
            raise RuntimeError('Restored application cannot list its complete bucket')
        try:
            S3(endpoint, 'unrelated-restore-fixture', 'invalid-secret', address=service['spec']['clusterIP']).request('GET', manifest['bucket'])
            raise RuntimeError('Restored S3 accepted unrelated credentials')
        except S3Error as error:
            if error.status not in (401, 403):
                raise
        # Restart only isolated service fixtures; never the live database or the
        # single control plane. Their PVCs and metadata must survive unchanged.
        pods = get('pods', namespace=NAMESPACE)['items']
        for pod in pods:
            if pod['status'].get('phase') != 'Running':
                continue
            kube('delete', 'pod', pod['metadata']['name'], '-n', NAMESPACE, '--wait=true', '--timeout=120s')
        wait(lambda: condition(get('cluster.postgresql.cnpg.io', 'data-restore', NAMESPACE), 'Ready'), 'restarted restore database', timeout=600)
        wait(lambda: condition(get('pod', get('cluster.postgresql.cnpg.io', 'data-restore', NAMESPACE)['status']['currentPrimary'], NAMESPACE), 'Ready'), 'restarted PostgreSQL pod', timeout=600)
        for name in ('master', 'volume', 'filer'):
            kube('rollout', 'status', 'statefulset/data-restore-seaweedfs-' + name, '-n', NAMESPACE, '--timeout=600s', timeout=630)
        kube('rollout', 'status', 'deployment/data-restore-seaweedfs-s3', '-n', NAMESPACE, '--timeout=600s', timeout=630)
        for row in manifest['objects']:
            record = next(item for item in manifest['files'] if item['file'] == row['file'])
            with tempfile.TemporaryFile() as target:
                recovered = app.request('GET', manifest['bucket'], row['key'], target=target, limit=16 * 1024**3)
            if recovered['sha256'] != record['sha256']:
                raise RuntimeError('Restart lost restored committed object data')
        if 'notes_probe' in manifest:
            recovered = json.loads(sql('SET ROLE ' + role + "; SELECT coalesce(json_agg(t ORDER BY id),'[]'::json) FROM public.cloudlab_recovery_probe t", manifest['database']).splitlines()[-1])
            if recovered != manifest['notes_probe']:
                raise RuntimeError('Restart lost restored notes or attachment references')
        return {'restored': True, 'objects': len(manifest['objects']), 'roles': len(manifest['roles']),
                'extensions': len(actual_extensions), 'seconds': round(time.monotonic() - started, 3),
                'same_existing_hosts': True, 'offsite_reads': False, 'fixture_restarts': True,
                'notes_object_generation_verified': 'notes_probe' in manifest}
    finally:
        cleanup()
