"""Run the lab without putting credentials in command arguments or image layers."""

import json
import os
import socket
from pathlib import Path
import subprocess
import sys

from dotenv import dotenv_values

def playbook(name, *, syntax=False, unchanged=False):
    stats_path = Path('/tmp/lab-stats.json')
    stats_path.unlink(missing_ok=True)
    command = ['ansible-playbook', '-i', 'inventory.yml', name]
    if syntax:
        command.append('--syntax-check')
    result = subprocess.run(command, check=False)
    if result.returncode:
        raise SystemExit(result.returncode)
    if unchanged:
        stats = json.loads(stats_path.read_text())
        if set(stats) != {'cloudlab', 'cloudlab-worker'}:
            raise SystemExit('Repeat apply did not cover both expected VMs.')
        if any(host['changed'] for host in stats.values()):
            raise SystemExit('Repeat apply changed the VM; idempotency proof failed.')
        print('Repeat apply: zero changes.', flush=True)


def gitops_preflight():
    result = subprocess.run([sys.executable, '/workspace/ansible/playbooks/argocd/files/render.py', 'preflight'], check=False)
    if result.returncode:
        raise SystemExit('Public GitOps preflight failed before host mutation.')


def main():
    if '/workspace' not in sys.path:
        sys.path.insert(0, '/workspace')
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    if action == 'validate':
        subprocess.run([sys.executable, '/workspace/ansible/runner/validate.py'], check=True)
        return
    lifecycle = {'host-reauth-server': ('cloudlab', 'reauth'),
                 'host-reauth-worker': ('cloudlab-worker', 'reauth'),
                 'host-logout-server': ('cloudlab', 'logout'),
                 'host-logout-worker': ('cloudlab-worker', 'logout')}
    if action not in {'inspect', 'baseline', 'storage-check', 'setup', 'verify', 'prove', 'syntax', 'monthly-proof', 'tailnet-policy', 'host-access'} | lifecycle.keys():
        raise SystemExit('Unknown action; expected a supported runner action such as setup, validate, verify, or prove.')
    os.environ['LAB_MONTHLY_PROOF'] = '0'
    if action == 'monthly-proof':
        sys.path.insert(0, '/workspace/ansible/playbooks/longhorn/files')
        from monthly_window import require_window
        require_window(reserve=3600)
        if action == 'monthly-proof':
            os.environ['LAB_MONTHLY_PROOF'] = '1'
    if action == 'syntax':
        for path in sorted(Path('/workspace/ansible/playbooks').glob('**/*.yml')):
            if path.parent == Path('/workspace/ansible/playbooks') or path.parent.parent == Path('/workspace/ansible/playbooks'):
                if path.name not in {'vars.yml', 'argument_specs.yml', 'retired-tooling.yml'}:
                    playbook(str(path), syntax=True)
        return

    # No interpolation: passwords containing ${...} must remain literal.
    values = dotenv_values('/workspace/.env', interpolate=False)
    try:
        workload_sysctls = json.loads(values.get('K3S_ALLOWED_UNSAFE_SYSCTLS') or '[]')
    except (ValueError, TypeError):
        raise SystemExit('K3S_ALLOWED_UNSAFE_SYSCTLS must be a JSON list of supported workload sysctl names.') from None
    if workload_sysctls not in ([], ['net.ipv6.conf.all.disable_ipv6']):
        raise SystemExit('K3S_ALLOWED_UNSAFE_SYSCTLS permits only [] or ["net.ipv6.conf.all.disable_ipv6"].')
    os.environ['K3S_ALLOWED_UNSAFE_SYSCTLS'] = json.dumps(workload_sysctls)
    for name in ('TAILSCALE_HOSTS_ENABLED', 'TAILSCALE_ADMIN_LOGIN', 'K3S_BACKUP_ENABLED'):
        os.environ[name] = values.get(name) or ''
    for name in ('TAILSCALE_HOSTS_ENABLED', 'K3S_BACKUP_ENABLED'):
        if os.environ[name] not in ('', '0', '1'):
            raise SystemExit(name + ' must be 0 or 1.')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    for name in ('PRIVATE_ACCESS_HOSTS', 'CLOUDFLARE_HUMAN_EMAIL',
                 'CLOUDFLARE_IDP_ID', 'ACCESS_FREE_TIER_CONFIRMED'):
        os.environ[name] = values.get(name) or ''
    if action == 'tailnet-policy':
        for prefix in ('VM', 'VM2'):
            os.environ[prefix + '_PORT'] = values.get(prefix + '_PORT') or '22'
        playbook('playbooks/tailscale/policy.yml')
        return
    if action in {'setup', 'prove', 'verify'} and not os.environ['OP_SERVICE_ACCOUNT_TOKEN']:
        raise SystemExit('Missing .env inputs: OP_SERVICE_ACCOUNT_TOKEN')
    required = tuple(prefix + suffix for prefix in ('VM', 'VM2')
                     for suffix in ('_HOST', '_USER', '_PASSWORD'))
    missing = [name for name in required if not values.get(name)]
    if missing:
        raise SystemExit('Missing .env inputs: ' + ', '.join(missing))
    for name in required:
        os.environ[name] = values[name]
    for prefix in ('VM', 'VM2'):
        host = values[prefix + '_HOST']
        if host.startswith('-') or any(char.isspace() for char in host):
            raise SystemExit(prefix + '_HOST must be an IP address or DNS name.')
        try:
            port = int(values.get(prefix + '_PORT') or '22')
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            raise SystemExit(prefix + '_PORT must be between 1 and 65535.') from None
        os.environ[prefix + '_PORT'] = str(port)
        os.environ[prefix + '_BECOME_PASSWORD'] = (
            values.get(prefix + '_BECOME_PASSWORD') or values[prefix + '_PASSWORD'])
        try:
            os.environ[prefix + '_PUBLIC_IP'] = socket.gethostbyname(host)
        except OSError:
            raise SystemExit('Cannot resolve ' + prefix + '_HOST to IPv4.') from None
    if values['VM_HOST'] == values['VM2_HOST']:
        raise SystemExit('VM_HOST and VM2_HOST must identify different VMs.')
    if os.environ['VM_PUBLIC_IP'] == os.environ['VM2_PUBLIC_IP']:
        raise SystemExit('Both VM hosts resolve to the same IPv4 address.')

    if action in lifecycle:
        os.environ['LAB_TAILSCALE_TARGET'], os.environ['LAB_TAILSCALE_ACTION'] = lifecycle[action]
        playbook('playbooks/tailscale/lifecycle.yml')
    elif action == 'host-access':
        playbook('playbooks/tailscale/access.yml')
    elif action in {'inspect', 'verify'}:
        playbook('playbooks/' + action + '.yml')
    elif action in {'baseline', 'storage-check'}:
        playbook({'baseline': 'playbooks/baseline.yml', 'storage-check': 'playbooks/longhorn/check-host.yml'}[action])
    else:
        gitops_preflight()
        playbook('playbooks/setup.yml')
        if action == 'prove':
            playbook('playbooks/setup.yml', unchanged=True)
        playbook('playbooks/verify.yml')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
