"""One monthly cold-volume generation; no retained local application backups."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from automation.data import control, restore, volumes
from automation.data.capture import POLICY, capture, verify
from automation.data.remote import Repository, require_window

RECEIPT = 'longhorn-monthly-receipt.json'
ATTEMPT = 'longhorn-monthly-attempt.json'


def freshness(now=None):
    now = time.time() if now is None else now
    path, attempt = control.BASE / RECEIPT, control.BASE / ATTEMPT
    if not path.exists():
        raise RuntimeError('No accepted monthly Longhorn application backup exists')
    receipt = json.loads(path.read_text())
    age = now - receipt['captured_at']
    if (age < 0 or age > POLICY['remote_max_age_seconds'] or not receipt['retention_complete']
            or (attempt.exists() and not json.loads(attempt.read_text())['success'])):
        raise RuntimeError('Monthly application backup is stale or its last attempt failed')
    return {'monthly_age_hours': round(age / 3600, 2), 'local_backups': 0, 'b2_reads': 0}


def retire_local():
    # Only legacy application generations beneath their exact former owner.
    base = control.BASE / 'generations'
    removed = 0
    if not base.exists():
        return removed
    if base.is_symlink() or base.resolve().parent != control.BASE.resolve():
        raise RuntimeError('Legacy generation directory escaped its owner')
    for path in base.iterdir():
        if (path.is_symlink() or not path.is_dir() or path.resolve().parent != base.resolve()
                or not re.fullmatch(r'(generation|candidate)-[0-9]+', path.name)):
            raise RuntimeError('Unexpected legacy backup path; refusing removal')
        if any(p.is_symlink() for p in path.rglob('*')):
            raise RuntimeError('Legacy application backup contains a link')
        manifest = path / 'manifest.json'
        if not manifest.exists() or json.loads(manifest.read_text()).get('format') != 1:
            raise RuntimeError('Legacy application backup ownership cannot be verified')
        shutil.rmtree(path)
        removed += 1
    base.rmdir()
    return removed


def run(action):
    if action == 'freshness':
        return freshness()
    if action not in ('monthly', 'acceptance-export', 'restore-offsite', 'check-local', 'cleanup-fixtures'):
        raise ValueError('Unknown application backup action')
    monthly = action in ('monthly', 'acceptance-export')
    acceptance = action == 'acceptance-export'
    if monthly:
        require_window(acceptance, reserve=4 * 3600)
    with control.locked():
        if action == 'cleanup-fixtures':
            from automation.data.rotation import cleanup_sql
            restore.cleanup()
            cleanup_sql()
            return {'disposable_fixtures_removed': True, 'production_data_removed': False, 'b2_reads': 0}
        if control.settings()['maintenance'] or (control.BASE / 'cold-maintenance.json').exists():
            raise RuntimeError('Interrupted maintenance must be resumed before another backup')
        if action == 'restore-offsite':
            repository = Repository(control.secret('data-offsite'), True)
            manifest = repository.latest()
            blocks = repository.read_blocks(manifest)
            proof = restore.run(manifest, offsite=True)
            return {**proof, **blocks, 'explicit_restore_exception': True,
                    'network': repository.client.counters()}
        pending = control.BASE / 'pending-volume.json'
        if action == 'check-local' and pending.exists():
            raise RuntimeError('Pending monthly candidate must finish before local restore proof')
        receipt = control.BASE / RECEIPT
        if monthly and receipt.exists() and not pending.exists():
            existing = json.loads(receipt.read_text())
            if acceptance and existing.get('explicit_acceptance_exception'):
                raise RuntimeError('Initial Longhorn export exception already consumed; use the monthly schedule')
            if (not acceptance and existing['retention_complete']
                    and datetime.fromtimestamp(existing['captured_at'], timezone.utc).strftime('%Y-%m')
                    == datetime.now(timezone.utc).strftime('%Y-%m')):
                return {'already_verified_this_month': True, 'b2_reads': 0}
        if monthly:
            control.atomic(control.BASE / ATTEMPT, {'success': False, 'started_at': time.time()})
        if pending.exists():
            manifest = json.loads(pending.read_text())
            if not manifest.get('captured'):
                volumes.cleanup_snapshots(manifest)
                pending.unlink()
        manifest = verify(json.loads(pending.read_text())) if pending.exists() else capture()
        if not monthly:
            try:
                proof = restore.run(manifest)
                return {'capture_seconds': manifest['capture_seconds'], 'restore': proof,
                        'retained_local_generations': 0, 'b2_reads': 0}
            finally:
                volumes.cleanup_snapshots(manifest)
                pending.unlink()
        repository = Repository(control.secret('data-offsite'), acceptance)
        repository.upload(manifest)
        blocks = repository.read_blocks(manifest)
        proof = restore.run(manifest, offsite=True)
        result = repository.accept(manifest, proof)
        result.update(blocks)
        volumes.cleanup_snapshots(manifest)
        result['removed_legacy_local_generations'] = retire_local()
        control.atomic(receipt, result)
        control.atomic(control.BASE / ATTEMPT, {'success': True, 'finished_at': time.time()})
        pending.unlink()
        return result


if __name__ == '__main__':
    try:
        print(json.dumps(run(sys.argv[1]), sort_keys=True))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Application backup failed; private diagnostics withheld') from None
