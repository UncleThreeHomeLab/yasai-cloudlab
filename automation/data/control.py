"""Single application-data writer: runtime Applications, ACLs and maintenance."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.mesh.kube import application_ready, condition, contains, get, kube, wait
from automation.data.s3 import S3, S3Error

BASE = Path('/var/lib/cloudlab/application-data')
NAMESPACE = 'cloudlab-data'
APP = 'cloudlab-data-configuration'
OWNER = 'cloudlab-data-bootstrap'


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)


def locked():
    os.umask(0o077)
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BASE.resolve() != BASE:
        raise RuntimeError('Data state path must not contain symlinks')
    stream = (BASE / 'owner.lock').open('w')
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        stream.close()
        raise RuntimeError('Another application-data operation holds the owner lock') from None
    return stream


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,62}', value) or value.startswith('pg_') or value in ('postgres', 'template0', 'template1'):
        raise ValueError('Invalid or reserved application database identifier')
    return '"' + value + '"'


def secret(name):
    obj = get('secret', name, NAMESPACE)
    external = get('externalsecret.external-secrets.io', name, NAMESPACE)
    if not obj or not condition(external, 'Ready') or not any(
            ref.get('uid') == external['metadata']['uid'] and ref.get('kind') == 'ExternalSecret'
            for ref in obj['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Application data credential is not owned by ready ESO')
    return {key: base64.b64decode(value, validate=True).decode() for key, value in obj['data'].items()}


def primary():
    cluster = get('cluster.postgresql.cnpg.io', 'cloudlab-postgres', NAMESPACE)
    if not condition(cluster, 'Ready') or cluster['spec']['instances'] != 1:
        raise RuntimeError('Single-instance PostgreSQL is not ready')
    return cluster['status']['currentPrimary']


def postgres(arguments, *, input=None, target=None, database='postgres', timeout=300):
    command = ['/usr/local/bin/k3s', 'kubectl', 'exec', '-i', '-n', NAMESPACE, primary(), '-c', 'postgres', '--', *arguments]
    result = subprocess.run(command, input=input, stdout=target or subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError('PostgreSQL data operation failed; private diagnostics withheld')
    return result.stdout


def sql(statement, database='postgres'):
    return postgres(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-d', database],
                    input=statement.encode()).decode().strip()


def settings():
    values = get('application.argoproj.io', APP, 'argocd')['spec']['source']['helm']['valuesObject']
    for key in ('database', 'applicationRole', 'migrationRole', 'backupRole'):
        identity(values[key])
    if len({values[key] for key in ('applicationRole', 'migrationRole', 'backupRole')}) != 3:
        raise ValueError('Application roles must remain separate')
    return values


def s3(admin=True):
    values = settings()
    config = json.loads(secret('cloudlab-s3-config')['seaweedfs_s3_config'])
    selected = next((row for row in config['identities'] if row['name'] == ('data-admin' if admin else 'notes')), None)
    if not selected:
        raise RuntimeError('Requested S3 identity is disabled for maintenance')
    credentials = selected['credentials'][0]
    return S3('https://' + values['s3Host'], credentials['accessKey'], credentials['secretKey'])


def grants(values):
    app, migration, backup, database = [identity(values[key]) for key in
                                      ('applicationRole', 'migrationRole', 'backupRole', 'database')]
    desired = f'''REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
REVOKE ALL ON DATABASE {database} FROM PUBLIC;
GRANT CONNECT ON DATABASE {database} TO {app}, {migration}, {backup};
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO {app}, {backup};
GRANT USAGE, CREATE ON SCHEMA public TO {migration};
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {app};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {app};
GRANT SELECT ON ALL TABLES IN SCHEMA public TO {backup};
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO {backup};
ALTER DEFAULT PRIVILEGES FOR ROLE {migration} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app};
ALTER DEFAULT PRIVILEGES FOR ROLE {migration} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {app};
ALTER DEFAULT PRIVILEGES FOR ROLE {migration} IN SCHEMA public GRANT SELECT ON TABLES TO {backup};
ALTER DEFAULT PRIVILEGES FOR ROLE {migration} IN SCHEMA public GRANT SELECT ON SEQUENCES TO {backup};
'''
    # GRANT/REVOKE are idempotent; catalog comparisons detect actual changes.
    query = "SELECT json_agg(t ORDER BY t.name)::text FROM (SELECT 'db:'||datname name, datacl::text acl FROM pg_database UNION ALL SELECT 'schema:'||nspname, nspacl::text FROM pg_namespace UNION ALL SELECT 'relation:'||oid::text, relacl::text FROM pg_class UNION ALL SELECT 'default:'||oid::text, defaclacl::text FROM pg_default_acl) t;"
    before = sql(query, values['database'])
    sql(desired, values['database'])
    return before != sql(query, values['database'])


def reload_s3():
    raw = secret('cloudlab-s3-config')['seaweedfs_s3_config']
    digest = hashlib.sha256(raw.encode()).hexdigest()
    receipt = BASE / 's3-loaded.json'
    old = json.loads(receipt.read_text()) if receipt.exists() else {}
    if old.get('sha256') == digest:
        return False
    pods = get('pods', namespace=NAMESPACE)['items']
    selected = [p for p in pods if p['metadata'].get('labels', {}).get('app.kubernetes.io/component') == 's3']
    for pod in selected:
        # Restart the child, never compete with Argo over the Deployment template.
        kube('delete', 'pod', pod['metadata']['name'], '-n', NAMESPACE, '--wait=true', '--timeout=120s')
    kube('rollout', 'status', 'deployment/cloudlab-seaweedfs-s3', '-n', NAMESPACE, '--timeout=300s', timeout=330)
    # A successful request with the current admin key confirms the mounted config.
    s3().ensure_bucket(settings()['bucket'])
    atomic(receipt, {'sha256': digest, 'loaded_at': time.time()})
    return True


def maintenance(enabled):
    previous_client = s3(False) if enabled else None
    obj = get('application.argoproj.io', APP, 'argocd')
    if obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
        raise RuntimeError('Data Application has a conflicting runtime owner')
    if obj['spec']['source']['helm']['valuesObject']['maintenance'] != enabled:
        kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=merge',
             '--field-manager=' + OWNER, '-p', json.dumps({'spec': {'source': {'helm': {'valuesObject': {'maintenance': enabled}}}}}))
    values = settings()
    revision = json.loads((BASE / 'ownership.json').read_text())['revision']
    wait(lambda: application_ready(APP, revision), 'data maintenance convergence')
    expected_names = {'data-admin'} if enabled else {'data-admin', 'notes'}
    wait(lambda: {row['name'] for row in json.loads(secret('cloudlab-s3-config')['seaweedfs_s3_config'])['identities']} == expected_names,
         'maintenance credential synchronization', timeout=420)
    reload_s3()
    if previous_client:
        try:
            previous_client.request('HEAD', values['bucket'])
            raise RuntimeError('Application S3 key remains active during maintenance')
        except S3Error as error:
            if error.status != 403:
                raise
    role_list = ','.join("'" + values[key] + "'" for key in ('applicationRole', 'migrationRole'))
    wait(lambda: sql(f'SELECT count(*) FROM pg_roles WHERE rolname IN ({role_list}) AND rolcanlogin IS {"false" if enabled else "true"}') == '2',
         'database maintenance role convergence')
    if enabled:
        sql(f'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename IN ({role_list}) AND pid <> pg_backend_pid();')
        if sql(f'SELECT count(*) FROM pg_stat_activity WHERE usename IN ({role_list})') != '0':
            raise RuntimeError('Application sessions remain during coordinated capture')
    return values


def reconcile():
    values = settings()
    if values['maintenance']:
        raise RuntimeError('Interrupted data maintenance requires recovery before ordinary reconciliation')
    changed = grants(values)
    changed = reload_s3() or changed
    changed = s3().ensure_bucket(values['bucket']) or changed
    return changed


def application(payload, component, values=None):
    name = 'cloudlab-' + component
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
            'metadata': {'name': name, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
            'spec': {'project': name, 'source': {'repoURL': payload['repository'],
                'targetRevision': payload['branch'], 'path': 'platform/data/' + ('configuration' if component == 'data-configuration' else component),
                'helm': {'releaseName': name, 'valuesObject': values or {}}},
                'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
                'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                    'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                    'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}}}


def configure(payload):
    with locked():
        for name, path in [('Longhorn', '/var/lib/cloudlab/longhorn/ownership.json'),
                           ('ESO', '/var/lib/cloudlab/external-secrets/ownership.json'),
                           ('backup', '/var/lib/cloudlab/longhorn/backup-ownership.json')]:
            if json.loads(Path(path).read_text()).get('phase') != 'accepted':
                raise RuntimeError(name + ' ownership must be accepted before data services')
        wait(lambda: application_ready('cloudlab-cnpg', payload['revision']), 'CNPG operator convergence')
        private_cert = get('certificate.cert-manager.io', 'cloudlab-gateway', 'cloudlab-gateway-private')
        private_zone = payload['values']['s3Host'].split('.', 1)[1]
        if not condition(private_cert, 'Ready') or private_cert['spec']['dnsNames'] != ['*.' + private_zone, 'login.' + private_zone.removeprefix('internal.')]:
            raise RuntimeError('Data endpoint must belong to the existing ready private certificate zone')
        receipt = BASE / 'ownership.json'
        state = json.loads(receipt.read_text()) if receipt.exists() else {'applications': {}}
        existing = get('application.argoproj.io', APP, 'argocd')
        if existing and (existing['spec']['source']['helm']['valuesObject'].get('maintenance')
                         or (BASE / 'cold-maintenance.json').exists()):
            raise RuntimeError('Data capture was interrupted; run data-resume before apply')
        changed = False
        for component in ('data-configuration', 'seaweedfs'):
            desired = application(payload, component, payload['values'] if component == 'data-configuration' else None)
            name = desired['metadata']['name']
            current = get('application.argoproj.io', name, 'argocd')
            uid = state['applications'].get(name)
            if (uid and (not current or current['metadata']['uid'] != uid)) or (current and (
                    current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                    or current['metadata'].get('finalizers') or current['metadata'].get('ownerReferences'))):
                raise RuntimeError('Data Application identity or ownership changed')
            if not current or not contains(current, desired):
                kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
                changed = True
            state['applications'][name] = get('application.argoproj.io', name, 'argocd')['metadata']['uid']
            state['revision'] = payload['revision']
            atomic(receipt, state)
        # Routes depend on the service, while SeaweedFS depends on config Secrets.
        # Declare both owners before waiting for either health graph to converge.
        for component in ('data-configuration', 'seaweedfs'):
            name = 'cloudlab-' + component
            wait(lambda: application_ready(name, payload['revision']), 'data Application convergence', timeout=900)
        for name in ('notes-application', 'notes-migration', 'database-backup', 'cloudlab-s3-config', 'data-offsite'):
            wait(lambda: condition(get('externalsecret.external-secrets.io', name, NAMESPACE), 'Ready'), 'data credential readiness')
        primary()
        from automation.data.volumes import inventory
        inventory()
        atomic(BASE / 'desired.json', payload['values'])
        # DNS is configured after this role. Reconciliation uses the real private
        # endpoint only after both host resolvers have applied it.
        return changed


if __name__ == '__main__':
    try:
        action = sys.argv[1]
        if action == 'configure':
            result = configure(json.load(sys.stdin))
        else:
            with locked():
                if action == 'resume':
                    from automation.data.volumes import resume
                    resume()
                    result = True
                elif action == 'reconcile':
                    result = reconcile()
                else:
                    raise ValueError('Unknown application data control action')
        print(json.dumps({'changed': result}))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Application data control failed; private diagnostics withheld') from None
