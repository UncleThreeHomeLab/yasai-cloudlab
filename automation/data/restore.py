"""Restore immutable generations into disposable, isolated service fixtures."""
import base64
import ipaddress
import json
import socket
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

import yaml

from automation.data import control, physical
from automation.data.capture import verify
from automation.data.s3 import S3, S3Error
from automation.mesh.kube import condition, get, kube, wait

NAMESPACE = 'cloudlab-data-restore'
LABEL = {'cloudlab.io/fixture': 'application-data-restore'}


def object_tags(document):
    return sorted((tag.findtext('{*}Key'), tag.findtext('{*}Value'))
                  for tag in ET.fromstring(document).findall('.//{*}Tag'))


def s3_ready(client, bucket):
    try:
        client.request('HEAD', bucket)
        return True
    except S3Error as error:
        if error.status != 404:
            raise
        return True
    except RuntimeError:
        return False


def restore_source_cidrs(node, source):
    addresses = {source}
    subnet = ipaddress.ip_network(node['spec']['podCIDR'])
    interfaces = json.loads(subprocess.check_output(['ip', '-j', 'address'], stderr=subprocess.PIPE))
    for interface in interfaces:
        if interface['ifname'] in ('cni0', 'flannel.1'):
            addresses.update(row['local'] for row in interface['addr_info'] if row['family'] == 'inet'
                             and ipaddress.ip_address(row['local']) in subnet)
    if any(ipaddress.ip_address(address).version != 4 or not ipaddress.ip_address(address).is_private for address in addresses):
        raise RuntimeError('Restore client policy requires private host addresses')
    return [address + '/32' for address in sorted(addresses)]


def postgres(arguments, *, source=None, data=None):
    pods = [p for p in get('pods', namespace=NAMESPACE)['items']
            if p['metadata'].get('labels', {}).get('cloudlab.io/restore') == 'postgres' and condition(p, 'Ready')]
    if len(pods) != 1:
        raise RuntimeError('Expected one ready physical PostgreSQL restore fixture')
    primary = pods[0]['metadata']['name']
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', 'exec', '-i', '-n', NAMESPACE,
                             primary, '-c', 'postgres', '--', *arguments], stdin=source,
                            input=data, capture_output=True, timeout=1800)
    if result.returncode:
        raise RuntimeError('Isolated PostgreSQL restore failed; private diagnostics withheld')
    return result.stdout


def sql(statement, database='postgres'):
    return postgres(['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-d', database], data=statement.encode()).decode().strip()


def authenticated_sql(manifest):
    from automation.data import verify as checks
    from automation.data.rotation import cleanup_sql
    values = control.settings()
    if manifest['database'] != values['database'] or manifest['roles'] != [values[key] for key in ('applicationRole', 'migrationRole', 'backupRole')]:
        raise RuntimeError('Restored identities require a reviewed credential mapping')
    if get('namespace', checks.NAMESPACE):
        raise RuntimeError('Previous SQL fixture must be cleaned before restore authentication')
    for role, name in zip(manifest['roles'], ('notes-application', 'notes-migration', 'database-backup')):
        credential = control.secret(name)
        if credential['username'] != role:
            raise RuntimeError('Restore credential identity differs')
        password = credential['password'].replace("'", "''")
        sql('ALTER ROLE ' + control.identity(role) + " LOGIN PASSWORD '" + password + "';")
    try:
        checks.sql_client(values, database_namespace=NAMESPACE, cluster='data-restore')
        wait(lambda: (result := checks.pod_query([], 'SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid();')).returncode == 0
             and result.stdout.strip() == 't',
             'restored password and verified SQL TLS')
        if 'notes_probe' in manifest:
            result = checks.pod_query([], "SELECT coalesce(json_agg(t ORDER BY id),'[]'::json) FROM public.cloudlab_recovery_probe t")
            if result.returncode or json.loads(result.stdout) != manifest['notes_probe']:
                raise RuntimeError('Authenticated restored application queries differ')
        for arguments, statement in [(['env', 'PGDATABASE=postgres'], 'SELECT 1;'),
                                     (['env', 'PGSSLMODE=disable'], 'SELECT 1;'),
                                     ([], 'CREATE TABLE cloudlab_restore_forbidden(id int);')]:
            if checks.pod_query(arguments, statement).returncode == 0:
                raise RuntimeError('Restored SQL permits plaintext, another database or unauthorized DDL')
    finally:
        cleanup_sql()


def cleanup():
    checkpoint = control.BASE / 'restore-cleanup.json'
    namespace = get('namespace', NAMESPACE)
    if not namespace and not checkpoint.exists():
        # Recover fixtures left by the pre-checkpoint cleanup implementation.
        targets = []
        names = {'data-restore-1', 'data-cloudlab-data-restore-data-restore-seaweedfs-master-0',
                 'data-filer-data-restore-seaweedfs-filer-0', 'data1-data-restore-seaweedfs-volume-0'}
        for volume in get('pv')['items']:
            ref = volume['spec'].get('claimRef', {})
            if ref.get('namespace') != NAMESPACE:
                continue
            if (ref.get('name') not in names or volume['status']['phase'] != 'Released'
                    or volume['spec'].get('storageClassName') not in {'cloudlab-data', *[physical.storage_class(c) for c in physical.CLAIMS]}
                    or volume['metadata']['name'] != 'pvc-' + ref.get('uid', '')):
                raise RuntimeError('Orphan restore volume has an unexpected identity')
            targets.append([volume['metadata']['name'], volume['metadata']['uid'], ref['uid']])
        if not targets:
            physical.cleanup_classes()
            return
        control.atomic(checkpoint, targets)
    if namespace and namespace['metadata'].get('labels', {}).get('cloudlab.io/fixture') != LABEL['cloudlab.io/fixture']:
        raise RuntimeError('Restore namespace is not owned by this fixture')
    # Retain-class PVs outlive PVC deletion. Record only this fixture's exact UIDs.
    claims = get('pvc', namespace=NAMESPACE)['items'] if namespace else []
    targets = json.loads(checkpoint.read_text()) if checkpoint.exists() else []
    for claim in claims:
        name = claim['spec'].get('volumeName')
        if not name:
            continue
        volume = get('pv', name)
        ref = volume['spec'].get('claimRef', {})
        if ref.get('namespace') != NAMESPACE or ref.get('uid') != claim['metadata']['uid']:
            raise RuntimeError('Restore PVC binding changed before cleanup')
        target = [name, volume['metadata']['uid'], ref['uid']]
        if target not in targets:
            targets.append(target)
    control.atomic(checkpoint, targets)
    if namespace:
        kube('delete', 'namespace', NAMESPACE, '--wait=true', '--timeout=300s', timeout=330)
    for name, uid, claim_uid in targets:
        wait(lambda: not get('pv', name) or get('pv', name)['status']['phase'] == 'Released', 'fixture volume release', timeout=120)
        volume = get('pv', name)
        if not volume:
            continue
        if (volume['metadata']['uid'] != uid or volume['spec']['claimRef']['uid'] != claim_uid
                or volume['spec']['claimRef']['namespace'] != NAMESPACE or volume['status']['phase'] != 'Released'):
            raise RuntimeError('Disposable restore volume is not safely released')
        kube('patch', 'pv', name, '--type=merge', '-p', '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}')
        kube('delete', 'pv', name, '--ignore-not-found=true', '--wait=true', '--timeout=300s', timeout=330)
    checkpoint.unlink()
    physical.cleanup_classes()


def run(manifest, offsite=False):
    verify(manifest)
    if get('namespace', NAMESPACE):
        raise RuntimeError('Previous isolated restore remains; inspect and run fixture cleanup before retrying')
    started = time.monotonic()
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Namespace',
        'metadata': {'name': NAMESPACE, 'labels': {**LABEL, 'istio-injection': 'disabled',
            'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.36'}}})
    try:
        physical.provision(manifest, offsite)
        physical.postgres(manifest)
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
        node = get('node', socket.gethostname())
        peers = [row for row in get('nodes')['items'] if row['metadata']['name'] != node['metadata']['name']]
        if len(peers) != 1:
            raise RuntimeError('Restore proof requires the declared two-node topology')
        result = subprocess.run(['helm', 'template', 'data-restore', str(chart), '--namespace', NAMESPACE,
                                 '--kube-version', '1.36.5'],
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
            if obj['kind'] == 'Deployment' and obj['metadata'].get('labels', {}).get('app.kubernetes.io/component') == 's3':
                obj['spec']['template']['spec']['nodeSelector'] = {'kubernetes.io/hostname': peers[0]['metadata']['labels']['kubernetes.io/hostname']}
            if obj['kind'] == 'StatefulSet':
                component = obj['metadata']['labels']['app.kubernetes.io/component']
                for claim in obj['spec']['volumeClaimTemplates']:
                    claim['spec']['storageClassName'] = physical.storage_class(component)
                    claim['spec']['resources']['requests']['storage'] = manifest['volumes'][component]['size']
            kube('apply', '-f', '-', document=obj)
        for name in ('master', 'volume', 'filer'):
            kube('rollout', 'status', 'statefulset/data-restore-seaweedfs-' + name, '-n', NAMESPACE, '--timeout=600s', timeout=630)
        kube('rollout', 'status', 'deployment/data-restore-seaweedfs-s3', '-n', NAMESPACE, '--timeout=600s', timeout=630)
        service = get('service', 'data-restore-seaweedfs-s3', NAMESPACE)
        values = control.settings()
        source = control.s3()
        endpoint = 'https://' + values['s3Host'] + ':8334'
        source_address = next(row['address'] for row in node['status']['addresses'] if row['type'] == 'InternalIP')
        # Bind to WireGuard: host access must also work when the S3 pod is remote.
        client = S3(endpoint, source.access, source.secret, address=service['spec']['clusterIP'], source_address=source_address)
        kube('apply', '-f', '-', document={'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
             'metadata': {'name': 'restore-client', 'namespace': NAMESPACE, 'labels': LABEL},
             'spec': {'podSelector': {'matchLabels': {'app.kubernetes.io/component': 's3'}},
                      'policyTypes': ['Ingress'], 'ingress': [{'from': [{'ipBlock': {'cidr': cidr}}
                                                                     for cidr in restore_source_cidrs(node, source_address)],
                                                             'ports': [{'protocol': 'TCP', 'port': 8334}]}]}})
        wait(lambda: s3_ready(client, manifest['bucket']), 'isolated S3 native TLS readiness')
        for row in manifest['objects']:
            with open('/dev/null', 'wb') as target:
                response = client.request('GET', manifest['bucket'], row['key'], target=target,
                                          limit=16 * 1024**3)
            record = row
            if response['sha256'] != record['sha256'] or response['bytes'] != record['bytes']:
                raise RuntimeError('Restored object checksum differs')
            headers = {key.lower(): value for key, value in response['headers'].items()}
            if any(headers.get(key) != value for key, value in row['headers'].items()):
                raise RuntimeError('Restored object metadata differs')
            expected_tags = object_tags(row['tags'])
            actual_tags = object_tags(client.request('GET', manifest['bucket'], row['key'], query={'tagging': ''})['data'])
            if actual_tags != expected_tags:
                raise RuntimeError('Restored object tags differ')
        app_source = control.s3(False)
        app = S3(endpoint, app_source.access, app_source.secret, address=service['spec']['clusterIP'], source_address=source_address)
        if {r['key'] for r in app.objects(manifest['bucket'])} != {r['key'] for r in manifest['objects']}:
            raise RuntimeError('Restored application cannot list its complete bucket')
        try:
            S3(endpoint, 'unrelated-restore-fixture', 'invalid-secret', address=service['spec']['clusterIP'], source_address=source_address).request('GET', manifest['bucket'])
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
        kube('rollout', 'status', 'deployment/restore-postgres', '-n', NAMESPACE, '--timeout=600s', timeout=630)
        for name in ('master', 'volume', 'filer'):
            kube('rollout', 'status', 'statefulset/data-restore-seaweedfs-' + name, '-n', NAMESPACE, '--timeout=600s', timeout=630)
        kube('rollout', 'status', 'deployment/data-restore-seaweedfs-s3', '-n', NAMESPACE, '--timeout=600s', timeout=630)
        wait(lambda: s3_ready(app, manifest['bucket']), 'restarted S3 native TLS readiness')
        s3_pods = [row for row in get('pods', namespace=NAMESPACE)['items']
                   if row['metadata'].get('labels', {}).get('app.kubernetes.io/component') == 's3']
        if len(s3_pods) != 1 or s3_pods[0]['spec']['nodeName'] != peers[0]['metadata']['name']:
            raise RuntimeError('Restored S3 did not exercise the cross-node private path')
        for row in manifest['objects']:
            record = row
            with open('/dev/null', 'wb') as target:
                recovered = app.request('GET', manifest['bucket'], row['key'], target=target, limit=16 * 1024**3)
            if recovered['sha256'] != record['sha256']:
                raise RuntimeError('Restart lost restored committed object data')
        if 'notes_probe' in manifest:
            recovered = json.loads(sql('SET ROLE ' + role + "; SELECT coalesce(json_agg(t ORDER BY id),'[]'::json) FROM public.cloudlab_recovery_probe t", manifest['database']).splitlines()[-1])
            if recovered != manifest['notes_probe']:
                raise RuntimeError('Restart lost restored notes or attachment references')
        authenticated_sql(manifest)
        return {'restored': True, 'objects': len(manifest['objects']), 'roles': len(manifest['roles']),
                'extensions': len(actual_extensions), 'seconds': round(time.monotonic() - started, 3),
                'same_existing_hosts': True, 'physical_restore': True, 'offsite_reads': offsite, 'fixture_restarts': True,
                'notes_object_generation_verified': 'notes_probe' in manifest,
                'current_vault_sql_login_and_tls': True, 'cross_node_restore_s3': True}
    finally:
        cleanup()
