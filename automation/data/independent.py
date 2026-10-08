"""Explicit off-site retrieval using only a checkout and the local vault reader."""
import json
import os
from pathlib import Path
import sys
import time
import shutil

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.credentials.vault import fields
from automation.data.remote import Repository, POLICY


def retrieve():
    os.umask(0o077)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = dotenv_values(ROOT / '.env', interpolate=False).get('OP_SERVICE_ACCOUNT_TOKEN', '')
    policy = json.loads((ROOT / 'platform/storage/longhorn-backup/policy.json').read_text())
    values = fields(policy['item'], ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_ENDPOINTS', 'BUCKET', 'REGION'))
    values['AWS_ENDPOINT'] = values.pop('AWS_ENDPOINTS')
    values.update(fields('monthly-application-data-b2', ('RESTIC_PASSWORD',)))
    repository = Repository(values, acceptance=True)
    snapshots = [row for row in repository.snapshots() if 'verified' in row.get('tags', [])]
    if not snapshots:
        raise RuntimeError('No verified application generation is available')
    snapshot = max(snapshots, key=lambda row: row['time'])
    if shutil.disk_usage('/recovery').free < POLICY['max_generation_bytes']:
        raise RuntimeError('Independent application retrieval requires 16 GiB free space')
    directory = Path('/recovery') / ('application-data-' + str(time.time_ns()))
    directory.mkdir(mode=0o700)
    manifest = repository.retrieve(snapshot['id'], directory)
    evidence = {'retrieved': True, 'explicit_restore_exception': True, 'cluster_used': False,
                'captured_at': manifest['captured_at'], 'retrieved_at': time.time(),
                'objects': len(manifest['objects']), 'output_directory': str(directory)}
    # This evidence is local, outside the public checkout, and contains no secrets.
    Path('/state/application-data-retrieval.json').write_text(json.dumps(evidence))
    return evidence


if __name__ == '__main__':
    try:
        print(json.dumps(retrieve()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Independent data retrieval failed; private diagnostics withheld') from None
