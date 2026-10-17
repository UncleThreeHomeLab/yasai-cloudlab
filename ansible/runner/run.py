"""Run the lab without putting credentials in command arguments or image layers."""

import json
import os
import socket
from pathlib import Path
import subprocess
import sys

from dotenv import dotenv_values

FOUNDATION_ACTIONS = {
    'eso-bootstrap', 'eso-interruption-test', 'eso-recover',
    'longhorn-bootstrap', 'longhorn-interruption-test', 'longhorn-recover',
    'longhorn-backup-bootstrap', 'longhorn-backup-interruption-test', 'longhorn-backup-recover',
}

IDENTITY_COMMANDS = {
    'identity-owner-credentials': ('owner_enrollment', 'provision'),
    'identity-owner-stage': ('owner_enrollment', '--stage'),
    'identity-owner-publish': ('owner_enrollment', 'publish'),
    'identity-owner-enroll': ('owner_enrollment', 'local'),
    'identity-private-publish': ('operations', '--publish'),
    'identity-access-prepare': ('access_provider',),
    'identity-access-cutover': ('access_cutover',),
    'identity-access-canary': ('access_canary', 'prepare'),
    'identity-access-canary-proof': ('access_canary', 'proof'),
    'identity-access-canary-remove': ('access_canary', 'remove'),
    'identity-primary-credentials': ('credentials', '--primary'),
    'identity-primary-login-items': ('credentials', '--login-items'),
    'identity-login-guide': ('credentials', '--login-guide'),
    'identity-offboard': ('lifecycle', '--offboard'),
    'identity-proof-credentials': ('session_fixture', 'provision'),
    'identity-proof-stage': ('session_fixture', '--stage'),
    'identity-proof-enroll': ('session_fixture', 'local'),
    'identity-session-canary': ('session_access', 'prepare'),
    'identity-session-canary-remove': ('session_access', 'remove'),
    'identity-client-refresh': ('rotation', '--refresh'),
    'identity-retire-bootstrap': ('emergency',),
    'identity-credentials': ('credentials',),
    'identity-operation': ('operations',),
    'identity-client-credential': ('rotation',),
    'identity-client-remove': ('lifecycle',),
}


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


def gitops_preflight(*, require_catalog=True):
    if require_catalog:
        sys.path.insert(0, '/workspace')
        from automation.services.inputs import catalog
        import yaml
        settings = yaml.safe_load(Path('/workspace/gitops/roots/public/values.yaml').read_text())
        catalog(required=settings.get('services', {}).get('enabled', False))
    result = subprocess.run([sys.executable, '/workspace/ansible/playbooks/argocd/files/render.py', 'preflight'], check=False)
    if result.returncode:
        raise SystemExit('Public GitOps preflight failed before host mutation.')


def main():
    if '/workspace' not in sys.path:
        sys.path.insert(0, '/workspace')
    if sys.argv[1:] == ['gitops-controller-recover']:
        raise SystemExit(subprocess.run([sys.executable, '-m', 'playbooks.argocd.files.recover'],
                                       cwd='/workspace', check=False).returncode)
    if sys.argv[1:2] == ['observe']:
        raise SystemExit(subprocess.run([sys.executable, '-m', 'automation.observability.command', *sys.argv[2:]],
                                       cwd='/workspace', check=False).returncode)
    if sys.argv[1:2] == ['service']:
        raise SystemExit(subprocess.run([sys.executable, '-m', 'automation.services.command', *sys.argv[2:]],
                                       cwd='/workspace', check=False).returncode)
    if sys.argv[1:2] in (['infra'], ['infra-harbor']):
        import argparse
        harbor = sys.argv[1] == 'infra-harbor'
        if harbor:
            arguments = sys.argv[2:]
            root = 'harbor'
            action = arguments[0] if arguments else ''
            if action == 'check' and arguments != ['check']:
                raise SystemExit('Harbor check accepts no mutation options')
        else:
            parser = argparse.ArgumentParser(description='Native infrastructure operation')
            parser.add_argument('action', choices=('check', 'locks', 'plan', 'apply', 'verify', 'drift'))
            parser.add_argument('root', choices=('cloudflare', 'github'))
            parser.add_argument('--review')
            selected = parser.parse_args(sys.argv[2:])
            if (selected.action == 'apply') != (selected.review is not None):
                parser.error('Apply alone requires the exact reviewed plan hash')
            arguments, root, action = sys.argv[2:], selected.root, selected.action
        os.environ['LAB_INFRA_ROOT'] = root
        os.environ['LAB_INFRA_ARGUMENTS'] = json.dumps(arguments)
        status_path = Path('/tmp/lab-infrastructure-exit.json')
        status_path.unlink(missing_ok=True)
        playbook('playbooks/infrastructure/' + ('check' if action == 'check' else 'harbor' if harbor else action) + '.yml')
        if not harbor and action not in ('check', 'locks'):
            raise SystemExit(json.loads(status_path.read_text()))
        return
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    action = {'apply': 'setup', 'backup': 'recovery-monthly'}.get(action, action)
    if action in {'maintenance', 'upgrade', 'nuke', 'recovery'}:
        if action == 'recovery':
            raise SystemExit('Select an explicit recovery-* operation and its required inputs.')
        playbook('playbooks/' + action + '.yml')
        return
    if action == 'validate':
        subprocess.run([sys.executable, '/workspace/ansible/runner/validate.py'], check=True)
        return
    identity_phase = {'identity-server': 'server', 'identity-bootstrap': 'bootstrap', 'identity-primary': 'primary', 'identity-scoped': 'scoped', 'identity-health': 'health', 'identity-argo': 'argo', 'identity-recover-startup': 'recover-startup'}.get(action)
    if identity_phase:
        os.environ['LAB_IDENTITY_PHASE'] = identity_phase
        action = 'inspect'
    if action == 'test':
        subprocess.run([sys.executable, '/workspace/ansible/runner/test.py'], check=True)
        return
    if action == 'service-check':
        subprocess.run([sys.executable, '-m', 'automation.services.check'], cwd='/workspace', check=True)
        return
    if action == 'identity-check':
        subprocess.run([sys.executable, '/workspace/automation/identity/chart.py'], check=True)
        subprocess.run([sys.executable, '-m', 'unittest', 'automation.identity.tests.test_identity'],
                       cwd='/workspace', check=True)
        return
    command = IDENTITY_COMMANDS.get(action)
    if command:
        subprocess.run([sys.executable, '-m', 'automation.identity.' + command[0], *command[1:]],
                       cwd='/workspace', check=True)
        return
    data_actions = {'data-monthly': 'monthly',
                    'data-acceptance-export': 'acceptance-export',
                    'data-restore': 'restore-offsite', 'data-freshness': 'freshness', 'data-resume': 'resume',
                    'data-cleanup-fixtures': 'cleanup-fixtures', 'data-bootstrap': 'bootstrap', 'data-check': 'check'}
    if action in ('data-credentials', 'data-retrieve', 'data-rotate'):
        module = {'data-credentials': 'credentials.py', 'data-retrieve': 'independent.py', 'data-rotate': 'rotation.py'}[action]
        subprocess.run([sys.executable, '/workspace/automation/data/' + module], check=True)
        return
    if action in data_actions:
        os.environ['LAB_DATA_ACTION'] = data_actions[action]
        # Common input validation and VM setup still run below.
        selected_data_action = action
        action = 'inspect'
    else:
        selected_data_action = None
    lifecycle = {'host-reauth-server': ('cloudlab', 'reauth'),
                 'host-reauth-worker': ('cloudlab-worker', 'reauth'),
                 'host-logout-server': ('cloudlab', 'logout'),
                 'host-logout-worker': ('cloudlab-worker', 'logout')}
    if action not in {'inspect', 'baseline', 'charts', 'storage-check', 'setup', 'verify', 'prove', 'syntax', 'monthly-proof', 'tailnet-policy', 'host-access', 'recovery-monthly', 'recovery-retrieve', 'recovery-preflight', 'recovery-initial', 'recovery-replacement-test', 'k3s-migrate', 'k3s-migrate-rollback', 'gitops-bootstrap', 'gitops-source-migrate', 'gitops-private-remove', 'gitops-interruption-test', 'gitops-verify', 'publish-platform', 'github-app-check', 'private-fixture-prepare', 'eso-recover', 'eso-interruption-test', 'eso-bootstrap', 'longhorn-bootstrap', 'longhorn-interruption-test', 'longhorn-recover', 'longhorn-backup-bootstrap', 'longhorn-backup-recover', 'longhorn-backup-interruption-test', 'mesh-check', 'access-preflight', 'access-external', 'access-prepare-tags', 'access-bootstrap', 'access-check', 'access-human-proof', 'access-cutover'} | lifecycle.keys():
        raise SystemExit('Unknown action; expected a supported runner action such as setup, validate, test, verify, or prove.')
    if action in {'publish-platform', 'github-app-check', 'private-fixture-prepare'}:
        module = {'publish-platform': 'publish_snapshot.py',
                  'github-app-check': 'github_app.py', 'private-fixture-prepare': 'private_fixture.py'}[action]
        result = subprocess.run([sys.executable, '/workspace/ansible/playbooks/argocd/files/' + module], check=False)
        if result.returncode:
            raise SystemExit(result.returncode)
        return
    if action == 'charts':
        subprocess.run([sys.executable, '/workspace/verification/integration/chart_parity.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/secrets/files/chart.py', 'check'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/longhorn/files/chart.py', 'check'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/longhorn/files/backup_parity.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/argocd/files/render.py', 'check'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/certificates/files/chart.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/istio/files/chart.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/access/files/chart.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/access/files/dns_check.py'], check=True)
        subprocess.run([sys.executable, '/workspace/automation/data/chart.py'], check=True)
        subprocess.run([sys.executable, '/workspace/automation/identity/chart.py'], check=True)
        subprocess.run([sys.executable, '-m', 'automation.services.check'], cwd='/workspace', check=True)
        return
    os.environ['LAB_MONTHLY_PROOF'] = '0'
    os.environ['LAB_LONGHORN_STOP_AFTER_SEED'] = '0'
    os.environ['LAB_BACKUP_STOP_AFTER_SEED'] = '0'
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
        sys.path.insert(0, '/workspace/ansible/playbooks/longhorn/files')
        from monthly_window import require_window
        require_window(reserve=3600)
        if action == 'monthly-proof':
            os.environ['LAB_MONTHLY_PROOF'] = '1'
    if action == 'syntax':
        for name in ('inspect.yml', 'baseline.yml', 'storage-check.yml', 'apply.yml', 'verify.yml', 'recovery.yml', 'playbooks/tailscale/lifecycle.yml', 'playbooks/tailscale/policy.yml', 'playbooks/tailscale/access.yml', 'playbooks/k3s/migrate.yml', 'gitops.yml', 'eso-recovery.yml', 'eso.yml', 'longhorn.yml', 'longhorn-recovery.yml', 'longhorn-backup.yml', 'longhorn-backup-recovery.yml', 'playbooks/istio/verify.yml', 'playbooks/access/setup.yml', 'playbooks/access/cutover.yml'):
            playbook(name, syntax=True)
        for path in sorted(Path('/workspace/ansible/playbooks').glob('*.yml')):
            playbook(str(path), syntax=True)
        playbook('data.yml', syntax=True)
        playbook('identity.yml', syntax=True)
        return

    # No interpolation: passwords containing ${...} must remain literal.
    values = dotenv_values('/workspace/.env', interpolate=False)
    for name in ('TAILSCALE_HOSTS_ENABLED', 'TAILSCALE_ADMIN_LOGIN', 'K3S_BACKUP_ENABLED'):
        os.environ[name] = values.get(name) or ''
    for name in ('TAILSCALE_HOSTS_ENABLED', 'K3S_BACKUP_ENABLED'):
        if os.environ[name] not in ('', '0', '1'):
            raise SystemExit(name + ' must be 0 or 1.')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    for name in ('CLOUDFLARE_ACCESS_HOSTS', 'PRIVATE_ACCESS_HOSTS', 'CLOUDFLARE_HUMAN_EMAIL',
                 'CLOUDFLARE_IDP_ID', 'ACCESS_FREE_TIER_CONFIRMED'):
        os.environ[name] = values.get(name) or ''
    if action not in FOUNDATION_ACTIONS:
        from automation.services.inputs import private_dns_names
        service_names = private_dns_names()
        if service_names:
            os.environ['PRIVATE_ACCESS_HOSTS'] = json.dumps(sorted(set(
                json.loads(os.environ['PRIVATE_ACCESS_HOSTS'] or '[]') + service_names)))
        import yaml
        public_settings = yaml.safe_load(Path('/workspace/gitops/roots/public/values.yaml').read_text())
        sys.path.insert(0, '/workspace')
        from automation.identity.access_inputs import runtime
        runtime(os.environ, public_settings)
    if action in {'recovery-retrieve', 'recovery-preflight'}:
        subprocess.run([sys.executable, '/workspace/automation/recovery/runner.py', action.removeprefix('recovery-')], check=True)
        return
    if action == 'tailnet-policy':
        for prefix in ('VM', 'VM2'):
            os.environ[prefix + '_PORT'] = values.get(prefix + '_PORT') or '22'
        playbook('playbooks/tailscale/policy.yml')
        return
    if action in {'setup', 'prove', 'verify', 'k3s-migrate', 'gitops-bootstrap', 'gitops-source-migrate', 'gitops-private-remove', 'gitops-interruption-test', 'gitops-verify', 'eso-recover', 'eso-interruption-test', 'eso-bootstrap', 'longhorn-bootstrap', 'longhorn-interruption-test', 'longhorn-recover', 'longhorn-backup-bootstrap', 'longhorn-backup-recover', 'longhorn-backup-interruption-test'} and not os.environ['OP_SERVICE_ACCOUNT_TOKEN']:
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

    if identity_phase:
        gitops_preflight()
        playbook('identity.yml')
    elif selected_data_action:
        if selected_data_action in ('data-bootstrap', 'data-check'):
            gitops_preflight()
        playbook('data.yml')
    elif action in {'access-preflight', 'access-external', 'access-prepare-tags'}:
        module = {'access-preflight': 'preflight.py', 'access-external': 'external.py',
                  'access-prepare-tags': 'prepare_tags.py'}[action]
        result = subprocess.run([sys.executable, '/workspace/ansible/playbooks/access/files/' + module], check=False)
        if result.returncode:
            raise SystemExit(result.returncode)
    elif action == 'k3s-migrate':
        if os.environ['TAILSCALE_HOSTS_ENABLED'] != '1' or os.environ['K3S_BACKUP_ENABLED'] != '1':
            raise SystemExit('Migration requires enabled milestone 01 host access and recovery.')
        gitops_preflight()
        # Prove both management policy and independent recovery before mutation.
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/tailscale/files/verify_access.py'], check=True)
        subprocess.run([sys.executable, '/workspace/automation/recovery/runner.py', 'retrieve'], check=True)
        os.environ['LAB_K3S_MIGRATION_ACTION'] = 'migrate'
        playbook('playbooks/k3s/migrate.yml')
        playbook('playbooks/setup.yml')
        playbook('playbooks/setup.yml', unchanged=True)
        playbook('playbooks/verify.yml')
        os.environ['LAB_K3S_MIGRATION_ACTION'] = 'accept'
        playbook('playbooks/k3s/migrate.yml')
    elif action == 'k3s-migrate-rollback':
        os.environ['LAB_K3S_MIGRATION_ACTION'] = 'rollback'
        playbook('playbooks/k3s/migrate.yml')
        playbook('baseline.yml')
    elif action in lifecycle:
        os.environ['LAB_TAILSCALE_TARGET'], os.environ['LAB_TAILSCALE_ACTION'] = lifecycle[action]
        playbook('playbooks/tailscale/lifecycle.yml')
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
        gitops_preflight(require_catalog=False)
        playbook('eso.yml')
    elif action == 'eso-interruption-test':
        gitops_preflight(require_catalog=False)
        os.environ['LAB_ESO_STOP_AFTER_SEED'] = '1'
        playbook('eso.yml')
        os.environ['LAB_ESO_STOP_AFTER_SEED'] = '0'
        playbook('eso.yml')
    elif action == 'eso-recover':
        gitops_preflight(require_catalog=False)
        playbook('eso-recovery.yml')
    elif action in {'longhorn-bootstrap', 'longhorn-interruption-test', 'longhorn-recover'}:
        gitops_preflight(require_catalog=False)
        if action == 'longhorn-recover':
            playbook('longhorn-recovery.yml')
        else:
            if action == 'longhorn-interruption-test':
                os.environ['LAB_LONGHORN_STOP_AFTER_SEED'] = '1'
                playbook('longhorn.yml')
                os.environ['LAB_LONGHORN_STOP_AFTER_SEED'] = '0'
            playbook('longhorn.yml')
    elif action in {'longhorn-backup-bootstrap', 'longhorn-backup-recover', 'longhorn-backup-interruption-test'}:
        gitops_preflight(require_catalog=False)
        if action == 'longhorn-backup-interruption-test':
            os.environ['LAB_BACKUP_STOP_AFTER_SEED'] = '1'
            playbook('longhorn-backup.yml')
            os.environ['LAB_BACKUP_STOP_AFTER_SEED'] = '0'
        playbook('longhorn-backup-recovery.yml' if action.endswith('recover') else 'longhorn-backup.yml')
    elif action == 'access-human-proof':
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/access/files/human.py'], check=True)
    elif action == 'access-check':
        gitops_preflight()
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/access/files/verify.py'], check=True)
    elif action == 'access-cutover':
        gitops_preflight()
        playbook('playbooks/access/cutover.yml')
    elif action == 'access-bootstrap':
        gitops_preflight()
        playbook('playbooks/access/setup.yml')
    elif action == 'mesh-check':
        gitops_preflight()
        playbook('playbooks/istio/verify.yml')
    elif action == 'host-access':
        playbook('playbooks/tailscale/access.yml')
    elif action in {'recovery-monthly', 'recovery-initial', 'recovery-replacement-test'}:
        playbook('recovery.yml')
    elif action in {'inspect', 'verify'}:
        playbook('playbooks/' + action + '.yml')
    elif action in {'baseline', 'storage-check'}:
        playbook(action + '.yml')
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
