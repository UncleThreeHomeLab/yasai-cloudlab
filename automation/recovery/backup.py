"""Host monthly job and cloud-independent freshness/integrity verification."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

from capture import capture, verify_archive, require_active_sqlite
from repository import Repository, require_window
from write_window import authorize_initial, authorize_replacement, REPLACEMENT_TAG

BASE = Path('/var/lib/cloudlab/recovery')
POLICY = json.loads(Path(__file__).with_name('policy.json').read_text())


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True))
    temporary.chmod(0o600)
    temporary.replace(path)


def freshness(base=BASE, now=None):
    attempt = base / 'last-attempt.json'
    if attempt.exists() and not json.loads(attempt.read_text())['success']:
        raise RuntimeError('Last monthly recovery attempt failed; inspect the host service')
    receipt = base / 'receipt.json'
    if not receipt.exists():
        raise RuntimeError('No verified monthly recovery point; migration remains blocked')
    state = json.loads(receipt.read_text())
    age = (now or time.time()) - state['captured_at']
    if age < 0 or age > POLICY['max_age_seconds'] or not state['retention_complete']:
        raise RuntimeError('Monthly recovery point is stale or retention is incomplete')
    print(json.dumps({'fresh': True, 'age_hours': round(age / 3600, 1),
                      'archive_bytes': state['archive_bytes'], 'retrieval_seconds': state['retrieval_seconds']}))


def run(action):
    os.umask(0o077)
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    if action == 'freshness':
        with (BASE / 'job.lock').open('w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                stage = BASE / 'staging'
                if stage.exists() and not stage.is_symlink() and time.time() - stage.stat().st_mtime > 86400:
                    shutil.rmtree(stage)
            except BlockingIOError:
                pass
        freshness()
        return
    replacement = action == 'replacement-test'
    if replacement:
        authorize_replacement()
        action = 'monthly'
    initial = action == 'initial'
    if initial:
        authorize_initial()
        action = 'monthly'
    if action not in ('monthly', 'local-check'):
        raise RuntimeError('Expected monthly, local-check or freshness')
    if action == 'monthly':
        require_window(reserve=3600)
    with (BASE / 'job.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'monthly' and (BASE / 'receipt.json').exists():
            receipt = json.loads((BASE / 'receipt.json').read_text())
            if replacement and receipt.get('retention_proof') == REPLACEMENT_TAG:
                freshness()
                print('Replacement proof already recorded; no cloud operation needed.')
                return
            if initial:
                freshness()
                print('Initial recovery point already recorded; no cloud operation needed.')
                return
            month = datetime.now(timezone.utc).strftime('%Y-%m')
            if (not replacement and datetime.fromtimestamp(receipt['captured_at'], timezone.utc).strftime('%Y-%m') == month
                    and receipt['retention_complete']):
                freshness()
                print('This monthly generation is already verified; no cloud operation needed.')
                return
        stage = BASE / 'staging'
        # Only this module's locked, bounded temporary candidate is replaceable.
        if stage.is_symlink():
            raise RuntimeError('Unexpected staging symlink')
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(mode=0o700)
        started = time.monotonic()
        try:
            version = subprocess.check_output(['/usr/local/bin/k3s', '--version'], text=True).splitlines()[0]
            require_active_sqlite()
            manifest = capture(Path('/'), stage, POLICY, version)
            verify_archive(stage / 'recovery.tar.gz', stage / 'local-validation', POLICY)
            shutil.rmtree(stage / 'local-validation')
            if action == 'monthly':
                credentials = json.loads(Path('/etc/cloudlab/recovery/credentials.json').read_text())
                repository = Repository(credentials)
                receipt = repository.export(stage, POLICY, repository)
                receipt['job_seconds'] = round(time.monotonic() - started, 2)
                atomic(BASE / 'receipt.json', receipt)
                atomic(BASE / 'last-attempt.json', {'success': True, 'finished_at': time.time()})
                print(json.dumps({key: receipt[key] for key in (
                    'previous_verified', 'previous_preserved_until_verified',
                    'retained_generations', 'retrieval_seconds', 'retention_complete')}))
            print(json.dumps({'action': action, 'passed': True, 'seconds': round(time.monotonic() - started, 2),
                              'archive_bytes': (stage / 'recovery.tar.gz').stat().st_size,
                              'source_bytes': manifest['source_bytes']}))
        except Exception:
            if action == 'monthly':
                atomic(BASE / 'last-attempt.json', {'success': False, 'finished_at': time.time()})
            raise
        finally:
            # Staging is disposable, never the last successful off-site generation.
            shutil.rmtree(stage)


if __name__ == '__main__':
    try:
        run(sys.argv[1])
    except Exception as error:
        # Paths and backend output can contain secrets or deployment metadata.
        print('Recovery action failed: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1) from None
