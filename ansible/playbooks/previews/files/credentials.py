"""Local App key use; deliver only bounded read tokens through guarded SSH stdin."""
import base64
import json
import os
import sys
import time
from pathlib import Path

from dotenv import dotenv_values
from playbooks.argocd.files.repository_tokens import issue, revoke
from playbooks.argocd.files.github_setup import repository
from playbooks.previews.files.contract import catalog, discovery_lease, LEASE_MARGIN
from playbooks.previews.files.credentials_remote import owned

ROOT = Path(__file__).resolve().parents[4]


def remote(request):
    from playbooks.access.files.preflight import ssh
    return json.loads(ssh('VM', os.environ['VM_HOST'],
        'python3 /opt/cloudlab/playbooks/previews/files/credentials_remote.py', input=json.dumps(request), timeout=90))


def decode(value):
    owned(value)
    lease = json.loads(base64.b64decode(value['data']['lease.json'], validate=True))
    lease['token'] = base64.b64decode(value['data']['TOKEN'], validate=True).decode()
    return discovery_lease(lease)


def identity(value):
    return {key: value['metadata'][key] for key in ('uid', 'resourceVersion')} if value else None


def ensure(settings, values, *, now=None):
    catalog(settings)
    if not settings['privateDiscovery']:
        return {'changed': False, 'private_discovery': False}
    repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
    if any(row['repository'] != repo for row in settings['approvals']):
        raise ValueError('Private previews must use the designated configuration repository')
    now = int(time.time()) if now is None else now
    eligible = [row for row in settings['approvals'] if row['expiresAt'] > now]
    required = max((row['expiresAt'] + LEASE_MARGIN for row in eligible), default=now)
    current = remote({'action': 'inspect'})
    if current:
        lease = decode(current)
        if lease['repository'] != repo:
            raise ValueError('Existing discovery token belongs to another repository')
        if lease['expiresAt'] >= required and lease['expiresAt'] > now:
            return {'changed': False, 'private_discovery': True}
    if not eligible:
        return {'changed': False, 'private_discovery': True}
    lease = issue(values, 'private-config', {'contents': 'read', 'pull_requests': 'read'})
    try:
        if lease['expiresAt'] < required:
            raise ValueError('Private preview expiry exceeds the issued credential lease')
        remote({'action': 'deliver', 'expected': identity(current), 'lease': lease})
    except Exception:
        revoke(lease)
        raise
    # Superseded read-only tokens retain only their issuer-enforced one-hour lease.
    return {'changed': True, 'private_discovery': True}


def retire(values):
    current = remote({'action': 'retirement-inspect'})
    if current:
        lease = decode(current)
        if lease['repository'] != repository(values.get('PRIVATE_CONFIG_REPOSITORY')):
            raise ValueError('Discovery retirement cannot target another repository')
        revoke(lease)
    return remote({'action': 'remove', 'expected': identity(current)})


def main(action=None):
    values = dotenv_values(ROOT / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        os.environ[key] = values[key]
    os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    action = action or (sys.argv[1] if len(sys.argv) == 2 else None)
    if action == 'retire':
        result = retire(values)
    elif action == 'ensure':
        result = ensure(json.load(sys.stdin)['catalog'], values)
    else:
        raise ValueError('Unsupported local preview credential operation')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Preview discovery operation failed; credentials and private diagnostics withheld') from None
