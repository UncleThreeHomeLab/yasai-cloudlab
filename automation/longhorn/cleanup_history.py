"""Explicit monthly cleanup of hidden versions; preserve current object semantics."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from b2_native.api import NativeAPI
from credentials.vault import fields
from monthly_window import require_window
from backup_policy import load_policy

POLICY = load_policy()


def one_time_window(reserve=0, now=None):
    now = now or datetime.now(timezone.utc)
    start = datetime(2026, 10, 4, tzinfo=timezone.utc)
    end = datetime(2026, 10, 5, tzinfo=timezone.utc)
    remaining = (end - now).total_seconds() if start <= now < end else 0
    if remaining <= reserve:
        raise RuntimeError('The authorized Longhorn cleanup exception expired')
    return remaining


def plan(rows, prefix):
    if not prefix or prefix != POLICY['prefix']:
        raise RuntimeError('Cleanup requires the declared Longhorn prefix')
    current, historical = {}, []
    for row in rows:
        name = row['fileName']
        if not name.startswith(prefix):
            raise RuntimeError('Cleanup listing escaped the Longhorn prefix')
        if row['action'] not in ('upload', 'hide'):
            raise RuntimeError('Unexpected version action; refusing cleanup')
        if name not in current:
            current[name] = row
        elif row['action'] == 'upload':
            historical.append(row)
    return current, historical


def run(api, apply=False, guard=require_window):
    prefix = POLICY['prefix']
    current, hidden = plan(api.versions(prefix), prefix)
    result = {'candidate_versions': len(hidden), 'candidate_bytes': sum(r['contentLength'] for r in hidden),
              'current_uploads': sum(r['action'] == 'upload' for r in current.values()),
              'delete_markers_preserved': True, 'applied': apply}
    if not apply:
        return result
    guard(reserve=300)
    started = time.monotonic()
    # The one-time request covers only history already present when authorized.
    # It cannot become an off-window cleanup loop for newly generated history.
    if guard is one_time_window:
        cutoff = datetime(2026, 10, 4, 10, 40, tzinfo=timezone.utc).timestamp() * 1000
        if any(current[r['fileName']]['uploadTimestamp'] >= cutoff for r in hidden):
            raise RuntimeError('New history is outside the reviewed one-time cleanup; wait for monthly window')
    for row in hidden:
        api.delete_version(row, prefix, guard)
    after, remaining = plan(api.versions(prefix), prefix)
    before_visible = {name: row['fileId'] for name, row in current.items() if row['action'] == 'upload'}
    after_visible = {name: row['fileId'] for name, row in after.items() if row['action'] == 'upload'}
    if before_visible != after_visible:
        raise RuntimeError('Current Longhorn object inventory changed during cleanup; inspect concurrent writers')
    if remaining:
        raise RuntimeError('Historical versions remain; cleanup is incomplete')
    result.update(deleted_versions=len(hidden), remaining_historical_versions=0,
                  current_uploads_unchanged=True, seconds=round(time.monotonic() - started, 2))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true', help='Delete noncurrent versions on day 1 UTC')
    mode.add_argument('--authorized-once', action='store_true', help='Dated operator exception for existing history only')
    args = parser.parse_args()
    guard = one_time_window if args.authorized_once else require_window
    if args.apply or args.authorized_once:
        guard(reserve=300)
    from dotenv import dotenv_values
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = dotenv_values('/workspace/.env', interpolate=False).get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    values = fields(POLICY['item'], ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'BUCKET'))
    print(json.dumps(run(NativeAPI(values), args.apply or args.authorized_once, guard)))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, KeyError, ValueError) as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'Cleanup response could not be validated') from None
