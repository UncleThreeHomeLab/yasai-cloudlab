"""Prepare only operator tag ownership before external OAuth credential creation."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'automation/tailscale'))

from control import API
from automation.connectivity.tailnet import tag_owners


def run():
    api = API('tailscale-policy')
    current, etag = api.request('GET', 'tailnet/-/acl')
    desired = tag_owners(current, os.environ.get('TAILSCALE_ADMIN_LOGIN', ''))
    if api.request('POST', 'tailnet/-/acl/validate', desired)[0]:
        raise RuntimeError('Tag ownership policy validation failed')
    if desired != current:
        if not etag:
            raise RuntimeError('Policy API supplied no ETag; refusing unguarded write')
        api.request('POST', 'tailnet/-/acl', desired, etag)
    actual, _ = api.request('GET', 'tailnet/-/acl')
    if actual != desired:
        raise RuntimeError('Tag ownership did not converge')
    print(json.dumps({'changed': desired != current, 'tags_ready': True, 'access_grants_changed': False}))


if __name__ == '__main__':
    try:
        run()
    except (RuntimeError, ValueError, OSError):
        raise SystemExit('Operator tag preparation failed; existing management path retained.') from None
