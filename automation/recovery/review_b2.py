"""Explicit, read-only bucket review; no polling, writes, or billing changes."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

from dotenv import dotenv_values
from runner import shared_b2, POLICY


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from b2_native.api import NativeAPI


def lifecycle(rules, prefix):
    matching = [r for r in rules if prefix.startswith(r['fileNamePrefix']) or r['fileNamePrefix'].startswith(prefix)]
    # Nested rules may cover only a subset. A dangerous rule anywhere is enough
    # to fail current-object safety; never treat a prefix rule as an exclusion.
    return {'overlapping_rules': len(matching),
            'current_objects_expire': any(r.get('daysFromUploadingToHiding') is not None for r in matching),
            'hidden_version_delete_days': sorted({r['daysFromHidingToDeleting'] for r in matching if r.get('daysFromHidingToDeleting') is not None}),
            'unfinished_cancel_days': sorted({r['daysFromStartingToCancelingUnfinishedLargeFiles'] for r in matching if r.get('daysFromStartingToCancelingUnfinishedLargeFiles') is not None})}


def inventory(files, prefixes):
    groups = {name: {'stored_bytes': 0, 'upload_versions': 0, 'noncurrent_bytes': 0, 'hide_markers': 0} for name in [*prefixes, 'other']}
    seen = set()
    for row in files:
        name = row['fileName']
        group = next((label for label, prefix in prefixes.items() if name.startswith(prefix)), 'other')
        if row['action'] == 'upload':
            size = row['contentLength']
            groups[group]['stored_bytes'] += size
            groups[group]['upload_versions'] += 1
            if name in seen:
                groups[group]['noncurrent_bytes'] += size
        elif row['action'] == 'hide':
            groups[group]['hide_markers'] += 1
        seen.add(name)
    return groups


def review():
    values = shared_b2()
    api = NativeAPI(values)
    bucket = api.bucket
    longhorn = json.loads((Path(__file__).resolve().parents[2] / 'platform/storage/longhorn-backup/policy.json').read_text())
    prefixes = {'k3s': POLICY['prefix'], 'longhorn': longhorn['prefix']}
    result = {'checked_at': datetime.now(timezone.utc).isoformat(),
              'private_bucket': bucket['bucketType'] == 'allPrivate',
              'lifecycle': {label: lifecycle(bucket.get('lifecycleRules', []), prefix) for label, prefix in prefixes.items()},
              'object_lock': bucket.get('fileLockConfiguration'),
              'account_caps_and_billing': 'not exposed by this review; inspect account console'}
    files = api.versions('')
    result['inventory'] = inventory(files, prefixes)
    result['listing_scope'] = 'key-prefix-limited' if api.storage['allowed'].get('namePrefix') else 'configured bucket'
    unfinished = api.read('b2_list_unfinished_large_files', {'bucketId': bucket['bucketId'], 'maxFileCount': 100})
    result['unfinished_uploads'] = {'count': len(unfinished['files']), 'complete': not bool(unfinished.get('nextFileId')),
                                     'part_storage_excluded_from_bytes': True}
    total = sum(g['stored_bytes'] for g in result['inventory'].values())
    result['storage_only_usd_per_month_at_published_rate_before_free_allowance'] = round(total / 1e12 * 6.95, 6)
    result['estimate_excludes'] = ['unfinished parts', 'other buckets', 'egress', 'tax', 'other services', 'future growth']
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = dotenv_values('/workspace/.env', interpolate=False).get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    try:
        review()
    except (RuntimeError, KeyError, ValueError) as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'B2 review response could not be validated') from None
