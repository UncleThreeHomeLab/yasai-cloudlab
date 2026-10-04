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
    result = subprocess.run([sys.executable, '/workspace/automation/gitops/render.py', 'preflight'], check=False)
    if result.returncode:
        raise SystemExit('Public GitOps preflight failed before host mutation.')


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    lifecycle = {'host-reauth-server': ('cloudlab', 'reauth'),
                 'host-reauth-worker': ('cloudlab-worker', 'reauth'),
                 'host-logout-server': ('cloudlab', 'logout'),
                 'host-logout-worker': ('cloudlab-worker', 'logout')}
    if action not in {'inspect', 'baseline', 'charts', 'storage-check', 'apply', 'verify', 'prove', 'syntax', 'monthly-proof', 'tailnet-policy', 'host-access', 'recovery-monthly', 'recovery-retrieve', 'recovery-preflight', 'recovery-initial', 'recovery-replacement-test', 'k3s-migrate', 'k3s-migrate-rollback', 'gitops-bootstrap', 'gitops-source-migrate', 'gitops-private-remove', 'gitops-interruption-test', 'gitops-verify', 'repository-setup', 'publish-platform', 'github-app-check', 'private-fixture-prepare', 'eso-recover', 'eso-interruption-test', 'eso-bootstrap'} | lifecycle.keys():
        raise SystemExit('Unknown action; expected a supported runner action such as apply, verify, or prove.')
    if action in {'repository-setup', 'publish-platform', 'github-app-check', 'private-fixture-prepare'}:
        module = {'repository-setup': 'github_setup.py', 'publish-platform': 'publish_snapshot.py',
                  'github-app-check': 'github_app.py', 'private-fixture-prepare': 'private_fixture.py'}[action]
        result = subprocess.run([sys.executable, '/workspace/automation/gitops/' + module], check=False)
        if result.returncode:
            raise SystemExit(result.returncode)
        return
    if action == 'charts':
        subprocess.run([sys.executable, '/workspace/verification/integration/chart_parity.py'], check=True)
        subprocess.run([sys.executable, '/workspace/automation/external_secrets/chart.py', 'check'], check=True)
        subprocess.run([sys.executable, '/workspace/automation/longhorn/chart.py', 'check'], check=True)
        subprocess.run([sys.executable, '/workspace/automation/gitops/render.py', 'check'], check=True)
        return
    os.environ['LAB_MONTHLY_PROOF'] = '0'
    os.environ['LAB_ESO_STOP_AFTER_SEED'] = '0'
    os.environ['LAB_GITOPS_STOP_AFTER_SEED'] = '0'
    os.environ['LAB_GITOPS_ACTION'] = {'gitops-verify': 'verify', 'gitops-source-migrate': 'source-migrate', 'gitops-private-remove': 'private-remove'}.get(action, 'bootstrap')
    os.environ['LAB_RECOVERY_ACTION'] = 'initial' if action == 'recovery-initial' else 'monthly'
    if action == 'recovery-replacement-test':
        os.environ['LAB_RECOVERY_ACTION'] = 'replacement-test'
        sys.path.insert(0, '/workspace/automation/recovery')
        from write_window import authorize_replacement
        authorize_replacement()
    if action == 'recovery-initial':
        sys.path.insert(0, '/workspace/automation/recovery')
        from write_window import authorize_initial
        authorize_initial()
    if action in {'monthly-proof', 'recovery-monthly'}:
        sys.path.insert(0, '/workspace/automation/longhorn')
        from monthly_window import require_window
        require_window(reserve=3600)
        if action == 'monthly-proof':
            os.environ['LAB_MONTHLY_PROOF'] = '1'
    if action == 'syntax':
        for name in ('inspect.yml', 'baseline.yml', 'storage-check.yml', 'apply.yml', 'verify.yml', 'recovery.yml', 'tailscale-lifecycle.yml', 'k3s-migration.yml', 'gitops.yml', 'eso-recovery.yml', 'eso.yml'):
            playbook(name, syntax=True)
        return

    # No interpolation: passwords containing ${...} must remain literal.
    values = dotenv_values('/workspace/.env', interpolate=False)
    for name in ('TAILSCALE_HOSTS_ENABLED', 'TAILSCALE_ADMIN_LOGIN', 'K3S_BACKUP_ENABLED'):
        os.environ[name] = values.get(name) or ''
    for name in ('TAILSCALE_HOSTS_ENABLED', 'K3S_BACKUP_ENABLED'):
        if os.environ[name] not in ('', '0', '1'):
            raise SystemExit(name + ' must be 0 or 1.')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    if action in {'recovery-retrieve', 'recovery-preflight'}:
        subprocess.run([sys.executable, '/workspace/automation/recovery/runner.py', action.removeprefix('recovery-')], check=True)
        return
    if action == 'tailnet-policy':
        for prefix in ('VM', 'VM2'):
            os.environ[prefix + '_PORT'] = values.get(prefix + '_PORT') or '22'
        subprocess.run([sys.executable, '/workspace/automation/tailscale/control.py', 'policy'], check=True)
        return
    if action in {'apply', 'prove', 'verify', 'k3s-migrate', 'gitops-bootstrap', 'gitops-source-migrate', 'gitops-private-remove', 'gitops-interruption-test', 'gitops-verify', 'eso-recover', 'eso-interruption-test', 'eso-bootstrap'} and not os.environ['OP_SERVICE_ACCOUNT_TOKEN']:
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

    if action == 'k3s-migrate':
        if os.environ['TAILSCALE_HOSTS_ENABLED'] != '1' or os.environ['K3S_BACKUP_ENABLED'] != '1':
            raise SystemExit('Migration requires enabled milestone 01 host access and recovery.')
        gitops_preflight()
        # Prove both management policy and independent recovery before mutation.
        subprocess.run([sys.executable, '/workspace/automation/tailscale/verify_access.py'], check=True)
        subprocess.run([sys.executable, '/workspace/automation/recovery/runner.py', 'retrieve'], check=True)
        os.environ['LAB_K3S_MIGRATION_ACTION'] = 'migrate'
        playbook('k3s-migration.yml')
        playbook('apply.yml')
        playbook('apply.yml', unchanged=True)
        playbook('verify.yml')
        os.environ['LAB_K3S_MIGRATION_ACTION'] = 'accept'
        playbook('k3s-migration.yml')
    elif action == 'k3s-migrate-rollback':
        os.environ['LAB_K3S_MIGRATION_ACTION'] = 'rollback'
        playbook('k3s-migration.yml')
        playbook('baseline.yml')
    elif action in lifecycle:
        os.environ['LAB_TAILSCALE_TARGET'], os.environ['LAB_TAILSCALE_ACTION'] = lifecycle[action]
        playbook('tailscale-lifecycle.yml')
    elif action == 'gitops-interruption-test':
        gitops_preflight()
        os.environ['LAB_GITOPS_STOP_AFTER_SEED'] = '1'
        playbook('gitops.yml')
        os.environ['LAB_GITOPS_STOP_AFTER_SEED'] = '0'
        playbook('gitops.yml')
        os.environ['LAB_GITOPS_ACTION'] = 'verify'
        playbook('gitops.yml')
    elif action in {'gitops-bootstrap', 'gitops-verify', 'gitops-source-migrate'}:
        gitops_preflight()
        playbook('gitops.yml')
        if action == 'gitops-bootstrap':
            os.environ['LAB_GITOPS_ACTION'] = 'verify'
            playbook('gitops.yml')
    elif action == 'eso-bootstrap':
        gitops_preflight()
        playbook('eso.yml')
    elif action == 'eso-interruption-test':
        gitops_preflight()
        os.environ['LAB_ESO_STOP_AFTER_SEED'] = '1'
        playbook('eso.yml')
        os.environ['LAB_ESO_STOP_AFTER_SEED'] = '0'
        playbook('eso.yml')
    elif action == 'eso-recover':
        gitops_preflight()
        playbook('eso-recovery.yml')
    elif action == 'host-access':
        subprocess.run([sys.executable, '/workspace/automation/tailscale/verify_access.py'], check=True)
    elif action in {'recovery-monthly', 'recovery-initial', 'recovery-replacement-test'}:
        playbook('recovery.yml')
    elif action in {'inspect', 'baseline', 'storage-check', 'verify'}:
        playbook(action + '.yml')
    else:
        gitops_preflight()
        playbook('apply.yml')
        if action == 'prove':
            playbook('apply.yml', unchanged=True)
        playbook('verify.yml')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
