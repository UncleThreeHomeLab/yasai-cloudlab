"""Explicit off-site retrieval using only a checkout and the local vault reader."""
import json
import os
from pathlib import Path
import sys
import time
import shutil
import re

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.credentials.vault import fields
from automation.data.remote import Repository


def retrieve():
    os.umask(0o077)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = dotenv_values(ROOT / '.env', interpolate=False).get('OP_SERVICE_ACCOUNT_TOKEN', '')
    policy = json.loads((ROOT / 'platform/storage/longhorn-backup/policy.json').read_text())
    values = fields(policy['item'], ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_ENDPOINTS', 'BUCKET', 'REGION'))
    values['AWS_ENDPOINT'] = values.pop('AWS_ENDPOINTS')
    repository = Repository(values, acceptance=True)
    manifest = repository.latest()
    blocks = repository.read_blocks(manifest)
    removed = 0
    for directory in Path('/recovery').glob('application-data-*'):
        if (directory.is_symlink() or directory.resolve().parent != Path('/recovery').resolve()
                or not re.fullmatch(r'application-data-[0-9]+', directory.name)
                or any(p.is_symlink() for p in directory.rglob('*'))):
            raise RuntimeError('Legacy retrieval path ownership changed; refusing removal')
        old = directory / 'manifest.json'
        if not old.is_file() or json.loads(old.read_text()).get('format') != 1:
            raise RuntimeError('Legacy retrieval metadata missing; refusing removal')
        shutil.rmtree(directory)
        removed += 1
    evidence = {'retrieved': True, 'explicit_restore_exception': True, 'cluster_used': False,
                'captured_at': manifest['captured_at'], 'retrieved_at': time.time(),
                'objects': len(manifest['objects']), **blocks,
                'removed_legacy_local_retrievals': removed,
                'network': repository.client.counters()}
    # This evidence is local, outside the public checkout, and contains no secrets.
    Path('/state/application-data-retrieval.json').write_text(json.dumps(evidence))
    return evidence


if __name__ == '__main__':
    try:
        print(json.dumps(retrieve()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Independent data retrieval failed; private diagnostics withheld') from None
