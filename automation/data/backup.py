"""Daily local capture and batched monthly export; routine freshness is local only."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from automation.data import control, restore
from automation.data.capture import POLICY, capture, retain_local, verify, discard_candidate
from automation.data.remote import Repository, require_window


def freshness(now=None):
    now = now or time.time()
    results = {}
    for kind, maximum in [('local', POLICY['local_max_age_seconds']), ('monthly', POLICY['remote_max_age_seconds'])]:
        path = control.BASE / (kind + '-receipt.json')
        attempt = control.BASE / (kind + '-attempt.json')
        if not path.exists():
            raise RuntimeError('No accepted ' + kind + ' application backup exists')
        receipt = json.loads(path.read_text())
        age = now - receipt['captured_at']
        if age < 0 or age > maximum or (attempt.exists() and not json.loads(attempt.read_text())['success']):
            raise RuntimeError(kind + ' application backup is stale or its last attempt failed')
        results[kind + '_age_hours'] = round(age / 3600, 2)
    results['b2_reads'] = 0
    return results


def run(action):
    if action == 'freshness':
        return freshness()
    if action not in ('local', 'monthly', 'acceptance-export', 'restore-local'):
        raise ValueError('Unknown application backup action')
    monthly = action in ('monthly', 'acceptance-export')
    acceptance = action == 'acceptance-export'
    if monthly:
        require_window(acceptance)
    with control.locked():
        if monthly and (control.BASE / 'monthly-receipt.json').exists():
            existing = json.loads((control.BASE / 'monthly-receipt.json').read_text())
            if acceptance and existing.get('explicit_acceptance_exception'):
                raise RuntimeError('Initial application export exception already consumed; use the monthly schedule')
            if not acceptance and datetime.fromtimestamp(existing['captured_at'], timezone.utc).strftime('%Y-%m') == datetime.now(timezone.utc).strftime('%Y-%m') and existing['retention_complete']:
                return {'already_verified_this_month': True, 'b2_reads': 0}
        if action == 'restore-local':
            receipt = json.loads((control.BASE / 'local-receipt.json').read_text())
            return restore.run(control.BASE / 'generations' / receipt['generation'])
        kind = 'monthly' if monthly else 'local'
        base = control.BASE / 'generations'
        base.mkdir(mode=0o700, exist_ok=True)
        if control.settings()['maintenance']:
            raise RuntimeError('Interrupted maintenance must be resumed before another backup')
        for candidate in base.glob('candidate-*'):
            discard_candidate(candidate, base)
        directory = base / ('candidate-' + str(time.time_ns()))
        try:
            manifest = capture(directory)
            # Name becomes eligible for retention only after integrity validation.
            completed = directory.with_name('generation-' + str(time.time_ns()))
            directory.rename(completed)
            control.atomic(control.BASE / 'local-receipt.json', {'captured_at': manifest['captured_at'], 'generation': completed.name})
            control.atomic(control.BASE / 'local-attempt.json', {'success': True, 'finished_at': time.time()})
            retain_local(base, completed)
            if monthly:
                receipt = Repository(control.secret('data-offsite'), acceptance).export(completed, restore.run)
                control.atomic(control.BASE / 'monthly-receipt.json', receipt)
                control.atomic(control.BASE / 'monthly-attempt.json', {'success': True, 'finished_at': time.time()})
                return receipt
            return {'local_capture': True, 'capture_seconds': manifest['capture_seconds'], 'objects': len(manifest['objects']), 'b2_reads': 0}
        except Exception:
            control.atomic(control.BASE / (kind + '-attempt.json'), {'success': False, 'finished_at': time.time()})
            raise


if __name__ == '__main__':
    try:
        print(json.dumps(run(sys.argv[1]), sort_keys=True))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Application backup failed; private diagnostics withheld') from None
