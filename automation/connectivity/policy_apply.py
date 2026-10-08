"""Reconcile only access service grants; independent host SSH policy is retained."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'automation/tailscale'))
from control import API
from automation.connectivity.tailnet import candidate


def run():
    api = API('tailscale-policy')
    current, etag = api.request('GET', 'tailnet/-/acl')
    devices, _ = api.request('GET', 'tailnet/-/devices')
    owners = {d['user'] for d in devices.get('devices', []) if d.get('user')}
    desired = candidate(current, os.environ.get('TAILSCALE_ADMIN_LOGIN', ''), owners)
    if api.request('POST', 'tailnet/-/acl/validate', desired)[0]:
        raise RuntimeError('Access policy validation failed; existing policy retained')
    if desired != current:
        if not etag:
            raise RuntimeError('Policy API supplied no ETag; refusing unguarded write')
        api.request('POST', 'tailnet/-/acl', desired, etag)
    if api.request('GET', 'tailnet/-/acl')[0] != desired:
        raise RuntimeError('Access policy did not converge')
    print(json.dumps({'changed': desired != current, 'access_policy_ready': True}))


if __name__ == '__main__':
    try:
        run()
    except (RuntimeError, ValueError, OSError):
        raise SystemExit('Access policy reconciliation failed; host management retained.') from None
