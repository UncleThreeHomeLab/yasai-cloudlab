"""Explicit, resumable rotation of the notes SQL password and S3 key pair."""
import copy
import fcntl
import json
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

FIELDS = {'cnpg-notes-production': ('password',),
          's3-notes-production': ('ACCESS_KEY_ID', 'SECRET_ACCESS_KEY')}


def values(document):
    result = {}
    for field in document['fields']:
        if field.get('label') in result:
            raise RuntimeError('Ambiguous rotation item fields')
        result[field.get('label')] = field.get('value')
    return result


def replacement(document, names):
    updated = copy.deepcopy(document)
    current = values(document)
    if any(not current.get(name) for name in names):
        raise RuntimeError('Rotation item is missing its required fields')
    for field in updated['fields']:
        if field.get('label') in names:
            field['value'] = secrets.token_hex(16) if field['label'] == 'ACCESS_KEY_ID' else secrets.token_urlsafe(48)
    return updated


def local():
    from dotenv import dotenv_values
    from automation.credentials.provision import command
    from automation.connectivity.preflight import ssh
    from automation.data.control import atomic
    os.umask(0o077)
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    token = environment.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    if not token:
        raise RuntimeError('Rotation needs the separate CloudLab writer token')
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        os.environ[key] = environment[key]
    os.environ['VM_PORT'] = environment.get('VM_PORT') or '22'
    path = Path('/state/data-rotation-pending.json')
    with Path('/state/data-vault-provision.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not path.exists():
            documents = {}
            inventory = command(['item', 'list', '--vault', 'CloudLab'], token)
            for title, names in FIELDS.items():
                matches = [row for row in inventory if row['title'] == title]
                if len(matches) != 1:
                    raise RuntimeError('Rotation requires exactly one item: ' + title)
                old = command(['item', 'get', matches[0]['id'], '--vault', 'CloudLab'], token)
                documents[title] = {'old': old, 'new': replacement(old, names)}
            atomic(path, documents)
        documents = json.loads(path.read_text())
        if set(documents) != set(FIELDS):
            raise RuntimeError('Rotation checkpoint has an unexpected scope')
        for title, pair in documents.items():
            old, new = pair['old'], pair['new']
            current = command(['item', 'get', old['id'], '--vault', 'CloudLab'], token)
            if current['title'] != title:
                raise RuntimeError('Rotation item identity changed')
            actual, before, after = values(current), values(old), values(new)
            if all(actual[name] == after[name] for name in FIELDS[title]):
                continue
            if any(actual[name] != before[name] for name in FIELDS[title]):
                raise RuntimeError('Rotation conflicts with an external credential change')
            # Preserve unrelated fields and metadata from the latest document.
            for field in current['fields']:
                if field.get('label') in FIELDS[title]:
                    field['value'] = after[field['label']]
            command(['item', 'edit', current['id'], '--vault', 'CloudLab'], token, current)
        payload = {title: {version: values(document) for version, document in pair.items()}
                   for title, pair in documents.items()}
        result = json.loads(ssh('VM', os.environ['VM_HOST'],
            'python3 /opt/cloudlab/automation/data/rotation.py verify',
            input=json.dumps(payload), timeout=1200))
        if not result.get('rotated_and_verified'):
            raise RuntimeError('Rotation gate did not pass; retain the pending checkpoint')
        path.unlink()
        return result


def remote(payload):
    from automation.data import control, verify
    from automation.data.s3 import S3, S3Error
    from automation.mesh.kube import get, kube, wait
    with control.locked():
        desired = control.settings()
        if desired['maintenance']:
            raise RuntimeError('Resume interrupted data maintenance before credential rotation')
        if get('namespace', verify.NAMESPACE):
            raise RuntimeError('A previous SQL fixture remains; inspect before rotation')
        sql = payload['cnpg-notes-production']
        object_key = payload['s3-notes-production']
        for name in ('notes-application', 'cloudlab-s3-config'):
            kube('annotate', 'externalsecret', name, '-n', control.NAMESPACE,
                 'force-sync=' + str(time.time_ns()), '--overwrite')
        wait(lambda: control.secret('notes-application')['password'] == sql['new']['password'], 'rotated SQL Secret')
        wait(lambda: control.s3(False).access == object_key['new']['ACCESS_KEY_ID'] and
             control.s3(False).secret == object_key['new']['SECRET_ACCESS_KEY'], 'rotated S3 Secret')
        control.reconcile()
        client = control.s3(False)
        client.request('HEAD', desired['bucket'])
        old = S3(client.endpoint, object_key['old']['ACCESS_KEY_ID'], object_key['old']['SECRET_ACCESS_KEY'])
        try:
            old.request('HEAD', desired['bucket'])
            raise RuntimeError('Old S3 key remains active after rotation')
        except S3Error as error:
            if error.status not in (401, 403):
                raise
        try:
            verify.sql_client(desired, sql['old'])
            wait(lambda: verify.pod_query([]).returncode != 0, 'old SQL password revoked')
        finally:
            cleanup_sql()
        try:
            verify.sql_client(desired)
            wait(lambda: verify.pod_query([]).returncode == 0, 'new SQL password accepted')
        finally:
            cleanup_sql()
        evidence = {'rotated_and_verified': True, 'old_sql_password_denied': True,
                    'old_s3_key_denied': True, 'new_credentials_accepted': True,
                    'verified_at': time.time(), 'b2_requests': 0}
        control.atomic(control.BASE / 'rotation-receipt.json', evidence)
        return evidence


def cleanup_sql():
    from automation.data import verify
    from automation.mesh.kube import get, kube
    namespace = get('namespace', verify.NAMESPACE)
    if namespace and namespace['metadata'].get('labels', {}).get('cloudlab.io/fixture') == verify.OWNER:
        kube('delete', 'namespace', verify.NAMESPACE, '--wait=true', '--timeout=120s')


if __name__ == '__main__':
    try:
        print(json.dumps(remote(json.load(sys.stdin)) if sys.argv[1:] == ['verify'] else local()))
    except Exception:
        raise SystemExit('Application credential rotation incomplete; rerun data-rotate to resume. Private diagnostics withheld.') from None
