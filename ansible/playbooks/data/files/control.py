"""Continuous scoped SQL/S3 repair and shared capture/restore exclusion."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
if not (ROOT / 'platform').is_dir():
    ROOT = ROOT.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from playbooks.istio.files.kube import application_ready, condition, get, kube, wait
from playbooks.data.files.s3 import S3, S3Error

BASE = Path('/var/lib/cloudlab/application-data')
CONTRACT = json.loads((ROOT / 'platform/data/contract.json').read_text())
NAMESPACE = CONTRACT['namespace']
APP = CONTRACT['bootstrap_application']
OWNER = CONTRACT['bootstrap_owner']


def atomic(path, value):
    document = json.dumps(value, sort_keys=True)
    if (not path.is_symlink() and path.exists() and path.read_text() == document
            and (path.stat().st_mode & 0o777) == 0o600):
        return False
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        stream.write(document)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    return True


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
    cluster = get('cluster.postgresql.cnpg.io', CONTRACT['cluster'], NAMESPACE)
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
    requested_buckets = {row['service'] for row in values.get('serviceRequests', []) if 'bucket' in row}
    expected_names = {'data-admin'} if enabled else {'data-admin', 'notes'} | requested_buckets
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
    roles = [values[key] for key in ('applicationRole', 'migrationRole')]
    roles += [row['database'][key] for row in values.get('serviceRequests', []) if 'database' in row
              for key in ('applicationRole', 'migrationRole')]
    for role in roles: identity(role)
    role_list = ','.join("'" + role + "'" for role in roles)
    wait(lambda: sql(f'SELECT count(*) FROM pg_roles WHERE rolname IN ({role_list}) AND rolcanlogin IS {"false" if enabled else "true"}') == str(len(roles)),
         'database maintenance role convergence')
    if enabled:
        sql(f'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename IN ({role_list}) AND pid <> pg_backend_pid();')
        if sql(f'SELECT count(*) FROM pg_stat_activity WHERE usename IN ({role_list})') != '0':
            raise RuntimeError('Application sessions remain during coordinated capture')
    return values


def native_repair(owner, component):
    """Dispatch a fixed native stage while its child retains the caller's lock FD."""
    stages = {'sql': 'native-sql.yml', 'ca': 'native-ca.yml'}
    if component not in stages:
        raise ValueError('Unknown native data repair stage')
    if owner.closed or Path(owner.name) != BASE / 'owner.lock':
        raise RuntimeError('Native data repair requires the existing data owner lock')
    play = (ROOT / 'playbooks/data/ca/current' / stages[component]).resolve(strict=True)
    collections = Path('/usr/local/lib/cloudlab-ansible/current').resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='cloudlab-data-ca-') as temporary:
        result = subprocess.run(
            ['/usr/bin/ansible-playbook', '-i', 'localhost,', str(play)],
            env=dict(os.environ, ANSIBLE_CONFIG='/usr/local/lib/cloudlab-ansible/ansible.cfg',
                     ANSIBLE_COLLECTIONS_PATH=str(collections), ANSIBLE_NOCOLOR='1',
                     ANSIBLE_LOCAL_TEMP=temporary + '/controller',
                     ANSIBLE_REMOTE_TEMP=temporary + '/modules'),
            pass_fds=(owner.fileno(),), capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError('Native data repair failed; private diagnostics withheld')
    return re.search(r'changed=[1-9][0-9]*', result.stdout) is not None


def reconcile(owner):
    values = settings()
    if values['maintenance']:
        raise RuntimeError('Interrupted data maintenance requires recovery before ordinary reconciliation')
    changed = native_repair(owner, 'sql')
    changed = reload_s3() or changed
    changed = s3().ensure_bucket(values['bucket']) or changed
    from playbooks.data.files.requests import reconcile as service_requests
    changed = service_requests(values, s3()) or changed
    changed = native_repair(owner, 'ca') or changed
    return changed


if __name__ == '__main__':
    try:
        action = sys.argv[1]
        with locked() as owner:
            if action == 'resume':
                from playbooks.data.files.volumes import resume
                resume()
                result = True
            elif action == 'reconcile':
                result = reconcile(owner)
            else:
                raise ValueError('Unknown application data control action')
        print(json.dumps({'changed': result}))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Application data control failed; private diagnostics withheld') from None
