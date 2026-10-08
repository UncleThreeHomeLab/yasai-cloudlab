"""Behavioral data gates using scoped clients and disposable restore services."""
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from automation.data import backup, control
from automation.data.s3 import S3, S3Error, NoRedirect
from automation.mesh.kube import application_ready, condition, get, kube, wait

NAMESPACE = 'cloudlab-data-proof'
OWNER = 'cloudlab-data-proof'


def pod_query(arguments, statement='SELECT 1;'):
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', 'exec', '-i', '-n', NAMESPACE,
                             'sql-client', '--', *arguments, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At'],
                            input=statement, capture_output=True, text=True, timeout=120)
    return result


def sql_client(values):
    if get('namespace', NAMESPACE):
        raise RuntimeError('Previous SQL fixture remains; review its owner before cleanup')
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NAMESPACE,
         'labels': {'cloudlab.io/fixture': OWNER, 'istio-injection': 'disabled',
                    'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.36'}}})
    credentials = control.secret('notes-application')
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Secret',
         'metadata': {'name': 'application', 'namespace': NAMESPACE}, 'stringData': credentials})
    certificate = get('secret', 'cloudlab-postgres-ca', control.NAMESPACE)
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'ConfigMap',
         'metadata': {'name': 'database-ca', 'namespace': NAMESPACE},
         'data': {'ca.crt': base64.b64decode(certificate['data']['ca.crt']).decode()}})
    pin = json.loads((control.ROOT / 'platform/data/cnpg/artifact.lock.json').read_text())['postgres_image']
    env = [{'name': name, 'value': value} for name, value in {
        'PGHOST': 'cloudlab-postgres-rw.cloudlab-data.svc', 'PGDATABASE': values['database'],
        'PGUSER': credentials['username'], 'PGSSLMODE': 'verify-full', 'PGSSLROOTCERT': '/tls/ca.crt',
        'PGCONNECT_TIMEOUT': '10'}.items()]
    env.append({'name': 'PGPASSWORD', 'valueFrom': {'secretKeyRef': {'name': 'application', 'key': 'password'}}})
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Pod',
        'metadata': {'name': 'sql-client', 'namespace': NAMESPACE},
        'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 26, 'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': 'client', 'image': pin, 'command': ['sleep', '3600'], 'env': env,
                'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'}, 'limits': {'cpu': '1', 'memory': '256Mi'}},
                'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                'volumeMounts': [{'name': 'ca', 'mountPath': '/tls', 'readOnly': True}]}],
            'volumes': [{'name': 'ca', 'configMap': {'name': 'database-ca'}}]}})
    wait(lambda: condition(get('pod', 'sql-client', NAMESPACE), 'Ready'), 'SQL fixture ready')


def storage():
    if any('application-logical-only' in job['spec'].get('groups', []) for job in get('recurringjobs.longhorn.io', namespace='longhorn-system')['items']):
        raise RuntimeError('Logical-only storage group must have no volume backup jobs')
    claims = get('pvc', namespace=control.NAMESPACE)['items']
    if len(claims) != 4:
        raise RuntimeError('Expected one database and three SeaweedFS PVCs')
    replica_count = 0
    for claim in claims:
        if claim['spec']['storageClassName'] != 'cloudlab-data' or claim['status']['phase'] != 'Bound':
            raise RuntimeError('Data PVC does not use explicit bound replicated storage')
        pv = get('pv', claim['spec']['volumeName'])
        volume = get('volumes.longhorn.io', pv['spec']['csi']['volumeHandle'], 'longhorn-system')
        if volume['spec']['numberOfReplicas'] != 2 or volume['status']['robustness'] != 'healthy':
            raise RuntimeError('Data Longhorn volume is not healthy with two replicas')
        labels = volume['metadata'].get('labels', {})
        active = {key for key, value in labels.items() if value == 'enabled' and key.startswith(('recurring-job.longhorn.io/', 'recurring-job-group.longhorn.io/'))}
        if active != {'recurring-job-group.longhorn.io/application-logical-only'}:
            raise RuntimeError('Data volume unexpectedly participates in a duplicate recurring backup path')
        replicas = [row for row in get('replicas.longhorn.io', namespace='longhorn-system')['items']
                    if row['spec'].get('volumeName') == volume['metadata']['name'] and not row['spec'].get('failedAt')]
        if len(replicas) != 2 or len({row['spec']['nodeID'] for row in replicas}) != 2 or any(row['status'].get('currentState') != 'running' for row in replicas):
            raise RuntimeError('Longhorn data replicas are not running on distinct nodes')
        replica_count += 2
    defaults = [row['metadata']['name'] for row in get('storageclasses')['items']
                if row['metadata'].get('annotations', {}).get('storageclass.kubernetes.io/is-default-class') == 'true']
    if defaults != ['local-path']:
        raise RuntimeError('Global default StorageClass changed')
    return {'claims': len(claims), 'replicas': replica_count, 'distinct_nodes_per_volume': 2}


def run():
    values = control.settings()
    revision = json.loads((control.BASE / 'ownership.json').read_text())['revision']
    for name in ('cloudlab-cnpg', 'cloudlab-data-configuration', 'cloudlab-seaweedfs'):
        if not application_ready(name, revision):
            raise RuntimeError('Data GitOps application is not converged at the tested revision')
    result = {'storage': storage(), 'b2_reads': 0}
    with control.locked():
        control.reconcile()
        admin, client = control.s3(), control.s3(False)
        data = b'cloudlab committed attachment\n'
        digest = hashlib.sha256(data).hexdigest()
        key = 'cloudlab-proof/committed'
        migration = control.identity(values['migrationRole'])
        control.sql(f'''SET ROLE {migration};
CREATE TABLE IF NOT EXISTS public.cloudlab_recovery_probe (id integer PRIMARY KEY, object_key text NOT NULL, sha256 text NOT NULL, note text NOT NULL);
CREATE EXTENSION IF NOT EXISTS pgcrypto;
''', values['database'])
        control.grants(values)
        client.request('PUT', values['bucket'], key, data=data, headers={'content-type': 'text/plain', 'x-amz-meta-fixture': 'cloudlab'})
        client.request('PUT', values['bucket'], key, query={'tagging': ''}, data=b'<Tagging><TagSet><Tag><Key>fixture</Key><Value>cloudlab</Value></Tag></TagSet></Tagging>')
        sql_client(values)
        try:
            statement = f"INSERT INTO public.cloudlab_recovery_probe VALUES (1, '{key}', '{digest}', 'committed') ON CONFLICT (id) DO UPDATE SET object_key=EXCLUDED.object_key, sha256=EXCLUDED.sha256; SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid();"
            allowed = pod_query([], statement)
            if allowed.returncode or allowed.stdout.splitlines()[-1] != 't':
                raise RuntimeError('Allowed application SQL over verified native TLS failed')
            for overrides in (['env', 'PGSSLMODE=disable'], ['env', 'PGDATABASE=postgres'], ['env', 'PGUSER=unrelated'], ['env', 'PGPASSWORD=deliberately-invalid-fixture-password']):
                if pod_query(overrides).returncode == 0:
                    raise RuntimeError('Unrelated, plaintext or wrong-database SQL unexpectedly succeeded')
            if pod_query([], 'CREATE TABLE forbidden_by_scope(id int);').returncode == 0:
                raise RuntimeError('DML application role can create schema objects')
            statements = '\\timing on\n' + '\n'.join("UPDATE public.cloudlab_recovery_probe SET note='committed' WHERE id=1;" for _ in range(20))
            measured = pod_query([], statements)
            milliseconds = [float(number) for number in re.findall(r'Time: ([0-9.]+) ms', measured.stdout)]
            if measured.returncode or len(milliseconds) != 20:
                raise RuntimeError('Database latency measurement failed')
            result['sql_transaction_ms'] = {'samples': 20, 'median': statistics.median(milliseconds), 'maximum': max(milliseconds)}
            if max(milliseconds) > 1000:
                raise RuntimeError('Database committed fixture transactions exceed the one-second admission bound')
        finally:
            namespace = get('namespace', NAMESPACE)
            if namespace and namespace['metadata']['labels'].get('cloudlab.io/fixture') == OWNER:
                kube('delete', 'namespace', NAMESPACE, '--wait=true', '--timeout=120s')
        if client.request('GET', values['bucket'], key)['data'] != data or key not in {row['key'] for row in client.objects(values['bucket'])}:
            raise RuntimeError('Allowed S3 read/list failed')
        unrelated_bucket = 'cloudlab-data-denied-fixture'
        created = admin.ensure_bucket(unrelated_bucket)
        if not created:
            raise RuntimeError('Denial fixture bucket already exists; refuse to adopt it')
        try:
            try:
                client.request('GET', unrelated_bucket, query={'list-type': '2'})
                raise RuntimeError('Application S3 key can list another bucket')
            except S3Error as error:
                if error.status != 403:
                    raise
            invalid = S3(client.endpoint, 'unrelated-fixture-key', secrets.token_urlsafe(32))
            try:
                invalid.request('GET', values['bucket'], key)
                raise RuntimeError('Unrelated S3 key was accepted')
            except S3Error as error:
                if error.status not in (401, 403):
                    raise
            opener = urllib.request.build_opener(NoRedirect())
            try:
                opener.open(client.endpoint + client.path(values['bucket'], key), timeout=30)
                raise RuntimeError('Anonymous S3 caller was accepted')
            except urllib.error.HTTPError as error:
                if error.code not in (401, 403):
                    raise RuntimeError('Anonymous S3 denial returned an unexpected response') from None
            disposable_key = 'cloudlab-proof/multipart'
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'payload'
                path.write_bytes(b'x' * (9 * 1024**2))
                client.upload(values['bucket'], disposable_key, path, headers={'content-type': 'application/octet-stream'})
                response = client.request('GET', values['bucket'], disposable_key)
                if response['sha256'] != hashlib.sha256(path.read_bytes()).hexdigest():
                    raise RuntimeError('Multipart checksum differs')
            client.request('DELETE', values['bucket'], disposable_key)
            url = client.presign('PUT', values['bucket'], disposable_key)
            with opener.open(urllib.request.Request(url, data=data, method='PUT'), timeout=30) as response:
                response.read()
            with opener.open(client.presign('GET', values['bucket'], disposable_key), timeout=30) as response:
                if response.read() != data:
                    raise RuntimeError('Presigned GET/PUT roundtrip differs')
            client.request('DELETE', values['bucket'], disposable_key)
            timings = []
            for _ in range(10):
                start = time.monotonic()
                client.request('GET', values['bucket'], key)
                timings.append((time.monotonic() - start) * 1000)
            result['s3_get_ms'] = {'samples': 10, 'median': round(statistics.median(timings), 3), 'maximum': round(max(timings), 3)}
            result['local_s3_network'] = client.counters()
        finally:
            admin.request('DELETE', unrelated_bucket)
    result['local_capture'] = backup.run('local')
    result['local_restore'] = backup.run('restore-local')
    result['routine_cloud_reads'] = 0
    # Shared stability checker covers rollouts/restarts after all fixtures finish.
    check = subprocess.run(['python3', '/opt/cloudlab/gitops/controller_stability.py', 'cnpg-system', 'cloudlab-data'],
                           capture_output=True, text=True, timeout=180)
    if check.returncode:
        raise RuntimeError('Data controllers did not remain stable after restore')
    result['controller_stability'] = json.loads(check.stdout)
    return result


if __name__ == '__main__':
    try:
        print(json.dumps(run(), sort_keys=True))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Data behavioral verification failed; private diagnostics withheld') from None
