"""Portable credential delivery and independent read-only recovery retrieval."""
import json
import os
from pathlib import Path
import shutil
import sys
import time
import base64
import urllib.request
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'credentials'))
from vault import fields
from repository import Repository

POLICY = json.loads(Path(__file__).with_name('policy.json').read_text())


def shared_b2():
    # The operator selected reuse of Longhorn's existing key and bucket. Consume
    # its public policy owner; do not duplicate or overwrite the vault item.
    longhorn = json.loads((Path(__file__).resolve().parents[2] / 'platform/storage/longhorn-backup/policy.json').read_text())
    values = fields(longhorn['item'], ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_ENDPOINTS', 'BUCKET', 'REGION'))
    values['AWS_ENDPOINT'] = values.pop('AWS_ENDPOINTS')
    values['PREFIX'] = POLICY['prefix']
    return values


def shared_credentials():
    values = shared_b2()
    values.update(fields(POLICY['password_item'], ('RESTIC_PASSWORD',)))
    Repository(values)
    return values


def preflight():
    """One explicit read-only capability check, never part of routine proof."""
    values = shared_b2()
    basic = base64.b64encode((values['AWS_ACCESS_KEY_ID'] + ':' + values['AWS_SECRET_ACCESS_KEY']).encode()).decode()
    request = urllib.request.Request('https://api.backblazeb2.com/b2api/v4/b2_authorize_account',
                                    headers={'Authorization': 'Basic ' + basic})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.load(response)
    except urllib.error.URLError:
        raise RuntimeError('Shared B2 key capability check failed') from None
    storage = document['apiInfo']['storageApi']
    allowed = storage['allowed']
    prefix_ok = POLICY['prefix'].startswith(allowed.get('namePrefix') or '')
    buckets = allowed.get('buckets')
    bucket_ok = buckets is None or any(b.get('name') == values['BUCKET'] for b in buckets)
    capabilities_ok = {'listFiles', 'readFiles', 'writeFiles', 'deleteFiles'}.issubset(allowed['capabilities'])
    endpoint_ok = storage['s3ApiUrl'].rstrip('/') == values['AWS_ENDPOINT'].rstrip('/')
    expiry = document.get('applicationKeyExpirationTimestamp')
    expiry_ok = not expiry or expiry / 1000 > time.time()
    result = {'prefix_allowed': prefix_ok, 'bucket_allowed': bucket_ok,
              'required_capabilities': capabilities_ok, 'endpoint_matches': endpoint_ok, 'unexpired': expiry_ok}
    print(json.dumps(result))
    if not all(result.values()):
        raise RuntimeError('Shared B2 key cannot satisfy this repository; no permissions were changed')


def credentials():
    # Ansible consumes stdout only with no_log; never use this action interactively.
    print(json.dumps(shared_credentials()))


def retrieve():
    os.umask(0o077)
    repository = Repository(shared_credentials())
    snapshots = [s for s in repository.snapshots() if POLICY['tag'] in s.get('tags', []) and 'verified' in s.get('tags', [])]
    if not snapshots:
        raise RuntimeError('No verified K3s recovery snapshot is available')
    snapshot = max(snapshots, key=lambda s: s['time'])
    target = Path('/recovery') / ('retrieved-' + str(time.time_ns()))
    usage = shutil.disk_usage(target.parent)
    if usage.free < POLICY['staging_ceiling_bytes']:
        raise RuntimeError('Independent retrieval needs 80 GiB of available temporary storage')
    try:
        manifest, seconds = repository.retrieve(snapshot['id'], target, POLICY)
        print(json.dumps({'retrieved': True, 'seconds': seconds,
                          'data_age_hours': round((time.time() - manifest['captured_at']) / 3600, 1),
                          'disposable_output': True, 'cluster_restore_tested': False}))
    finally:
        if target.exists():
            shutil.rmtree(target)


if __name__ == '__main__':
    try:
        {'credentials': credentials, 'retrieve': retrieve, 'preflight': preflight}[sys.argv[1]]()
    except (RuntimeError, ValueError, KeyError) as error:
        raise SystemExit(str(error)) from None
