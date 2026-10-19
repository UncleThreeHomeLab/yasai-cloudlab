"""Run the lab without putting credentials in command arguments or image layers."""

import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile

from dotenv import dotenv_values

FOUNDATION_ACTIONS = {
    'eso-bootstrap', 'eso-interruption-test', 'eso-recover',
    'longhorn-bootstrap', 'longhorn-interruption-test', 'longhorn-recover',
    'longhorn-backup-bootstrap', 'longhorn-backup-interruption-test', 'longhorn-backup-recover',
}

IDENTITY_COMMANDS = {'identity-owner-credentials': 'owner-credentials.yml',
 'identity-owner-stage': 'owner-stage.yml',
 'identity-owner-publish': 'owner-publish.yml',
 'identity-owner-enroll': 'owner-enroll.yml',
 'identity-private-publish': 'private-publish.yml',
 'identity-access-prepare': 'access-prepare.yml',
 'identity-access-cutover': 'access-cutover.yml',
 'identity-access-canary': 'access-canary.yml',
 'identity-access-canary-proof': 'access-canary-proof.yml',
 'identity-access-canary-remove': 'access-canary-remove.yml',
 'identity-primary-credentials': 'primary-credentials.yml',
 'identity-primary-login-items': 'primary-login-items.yml',
 'identity-login-guide': 'login-guide.yml',
 'identity-offboard': 'offboard.yml',
 'identity-proof-credentials': 'proof-credentials.yml',
 'identity-proof-stage': 'proof-stage.yml',
 'identity-proof-enroll': 'proof-enroll.yml',
 'identity-session-canary': 'session-canary.yml',
 'identity-session-canary-remove': 'session-canary-remove.yml',
 'identity-client-refresh': 'client-refresh.yml',
 'identity-retire-bootstrap': 'retire-bootstrap.yml',
 'identity-credentials': 'credentials.yml',
 'identity-operation': 'operation.yml',
 'identity-client-credential': 'client-credential.yml',
 'identity-client-remove': 'client-remove.yml'}
IDENTITY_REQUEST_COMMANDS = {'identity-access-canary-proof',
 'identity-client-credential',
 'identity-client-refresh',
 'identity-client-remove',
 'identity-offboard',
 'identity-operation',
 'identity-private-publish',
 'identity-proof-credentials',
 'identity-proof-enroll',
 'identity-proof-stage',
 'identity-retire-bootstrap',
 'identity-session-canary',
 'identity-session-canary-remove'}


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
        from playbooks.services.files.inputs import catalog
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
    if sys.argv[1:2] == ['observe'] and sys.argv[2:] in (['baseline-prepare'], ['baseline-cleanup']):
        action = {'baseline-prepare': 'prepare', 'baseline-cleanup': 'cleanup'}[sys.argv[2]]
        raise SystemExit(subprocess.run([sys.executable, '-m', 'playbooks.observability.tests.baseline', action],
                                       cwd='/workspace', check=False).returncode)
    if sys.argv[1:2] == ['observe']:
        raise SystemExit(subprocess.run([sys.executable, '-m', 'playbooks.observability.files.command', *sys.argv[2:]],
                                       cwd='/workspace', check=False).returncode)
    if sys.argv[1:2] == ['service']:
        raise SystemExit(subprocess.run([sys.executable, '-m', 'playbooks.services.files.command', *sys.argv[2:]],
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
        native_status = not harbor and action not in ('check', 'locks')
        with tempfile.TemporaryDirectory(prefix='infra-invocation-') as temporary:
            status_path = Path(temporary) / 'native-exit.json'
            invocation = Path(temporary).name
            os.environ['LAB_INFRA_STATUS_PATH'] = str(status_path)
            os.environ['LAB_INFRA_INVOCATION'] = invocation

            def native_exit():
                try:
                    document = json.loads(status_path.read_text())
                    if (not isinstance(document, dict) or set(document) != {'invocation', 'exit'} or
                            document['invocation'] != invocation or type(document['exit']) is not int or
                            not 0 <= document['exit'] <= 255):
                        return 1
                    return document['exit']
                except (OSError, ValueError):
                    return 1

            try:
                playbook('playbooks/infrastructure/' + ('check' if action == 'check' else 'harbor' if harbor else action) + '.yml')
            except SystemExit:
                if not native_status:
                    raise
                raise SystemExit(native_exit() or 1) from None
            if native_status:
                raise SystemExit(native_exit())
        return
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    if action in {'maintenance', 'upgrade', 'nuke', 'recovery'}:
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
        subprocess.run([sys.executable, '-m', 'playbooks.services.files.check'], cwd='/workspace', check=True)
        return
    if action == 'identity-check':
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/keycloak/files/chart.py'], check=True)
        subprocess.run([sys.executable, '-m', 'unittest', 'playbooks.keycloak.tests.test_identity'],
                       cwd='/workspace', check=True)
        return
    command = IDENTITY_COMMANDS.get(action)
    if command:
        if action in IDENTITY_REQUEST_COMMANDS:
            # Keep secrets out of arguments, Ansible output and persistent state.
            with tempfile.TemporaryDirectory(prefix='identity-request-') as directory:
                request = Path(directory) / 'request.json'
                with request.open('x') as stream:
                    request.chmod(0o600)
                    stream.write(sys.stdin.read())
                os.environ['LAB_IDENTITY_REQUEST'] = str(request)
                try:
                    playbook('playbooks/keycloak/' + command)
                finally:
                    os.environ.pop('LAB_IDENTITY_REQUEST', None)
        else:
            playbook('playbooks/keycloak/' + command)
        return
    data_actions = {'data-monthly': 'monthly',
                    'data-acceptance-export': 'acceptance-export',
                    'data-restore': 'restore-offsite', 'data-freshness': 'freshness', 'data-resume': 'resume',
                    'data-cleanup-fixtures': 'cleanup-fixtures', 'data-bootstrap': 'bootstrap', 'data-check': 'check'}
    if action in ('data-credentials', 'data-retrieve', 'data-rotate'):
        module = {'data-credentials': 'credentials.py', 'data-retrieve': 'independent.py', 'data-rotate': 'rotation.py'}[action]
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/data/files/' + module], check=True)
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
    if action not in {'inspect', 'baseline', 'charts', 'storage-check', 'setup', 'verify', 'prove', 'syntax', 'backup', 'monthly-proof', 'tailnet-policy', 'host-access', 'recovery-monthly', 'recovery-retrieve', 'recovery-preflight', 'recovery-initial', 'recovery-replacement-test', 'k3s-migrate', 'k3s-migrate-rollback', 'gitops-bootstrap', 'gitops-source-migrate', 'gitops-private-remove', 'gitops-interruption-test', 'gitops-verify', 'publish-platform', 'github-app-check', 'private-fixture-prepare', 'eso-recover', 'eso-interruption-test', 'eso-bootstrap', 'longhorn-bootstrap', 'longhorn-interruption-test', 'longhorn-recover', 'longhorn-backup-bootstrap', 'longhorn-backup-recover', 'longhorn-backup-interruption-test', 'mesh-check', 'access-preflight', 'access-external', 'access-prepare-tags', 'access-bootstrap', 'access-check', 'access-human-proof', 'access-cutover'} | lifecycle.keys():
        raise SystemExit('Unknown action; expected a supported runner action such as setup, validate, test, verify, or prove.')
    if action in {'publish-platform', 'github-app-check', 'private-fixture-prepare'}:
        module = {'publish-platform': 'publish_snapshot.py',
                  'github-app-check': 'github_app.py', 'private-fixture-prepare': 'private_fixture.py'}[action]
        result = subprocess.run([sys.executable, '/workspace/ansible/playbooks/argocd/files/' + module], check=False)
        if result.returncode:
            raise SystemExit(result.returncode)
        return
    if action == 'charts':
        subprocess.run([sys.executable, '-m', 'playbooks.admission.files.chart'], cwd='/workspace', check=True)
        subprocess.run([sys.executable, '/workspace/verification/integration/chart_parity.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/secrets/files/chart.py', 'check'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/longhorn/files/chart.py', 'check'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/longhorn/files/backup_parity.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/argocd/files/render.py', 'check'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/certificates/files/chart.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/istio/files/chart.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/access/files/chart.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/access/files/dns_check.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/data/files/chart.py'], check=True)
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/keycloak/files/chart.py'], check=True)
        subprocess.run([sys.executable, '-m', 'playbooks.services.files.check'], cwd='/workspace', check=True)
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
        sys.path.insert(0, '/workspace/ansible/playbooks/backup/files')
        from write_window import authorize_replacement
        authorize_replacement()
    if action == 'recovery-initial':
        sys.path.insert(0, '/workspace/ansible/playbooks/backup/files')
        from write_window import authorize_initial
        authorize_initial()
    if action in {'monthly-proof', 'recovery-monthly', 'backup'}:
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
    for name in ('TAILSCALE_HOSTS_ENABLED', 'TAILSCALE_ADMIN_LOGIN', 'K3S_BACKUP_ENABLED'):
        os.environ[name] = values.get(name) or ''
    for name in ('TAILSCALE_HOSTS_ENABLED', 'K3S_BACKUP_ENABLED'):
        if os.environ[name] not in ('', '0', '1'):
            raise SystemExit(name + ' must be 0 or 1.')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    for name in ('CLOUDFLARE_ACCESS_HOSTS', 'PRIVATE_ACCESS_HOSTS', 'CLOUDFLARE_HUMAN_EMAIL',
                 'CLOUDFLARE_IDP_ID', 'ACCESS_FREE_TIER_CONFIRMED'):
        os.environ[name] = values.get(name) or ''
    if action not in FOUNDATION_ACTIONS | {'inspect', 'baseline', 'storage-check'}:
        from playbooks.services.files.inputs import private_dns_names
        service_names = private_dns_names()
        if service_names:
            os.environ['PRIVATE_ACCESS_HOSTS'] = json.dumps(sorted(set(
                json.loads(os.environ['PRIVATE_ACCESS_HOSTS'] or '[]') + service_names)))
        import yaml
        public_settings = yaml.safe_load(Path('/workspace/gitops/roots/public/values.yaml').read_text())
        sys.path.insert(0, '/workspace')
        from playbooks.keycloak.files.access_inputs import runtime
        runtime(os.environ, public_settings)
    if action in {'recovery-retrieve', 'recovery-preflight'}:
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/backup/files/runner.py', action.removeprefix('recovery-')], check=True)
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
        playbook('playbooks/keycloak/' + {'server': '010-server.yml', 'bootstrap': '020-bootstrap.yml', 'primary': '030-primary.yml', 'scoped': '040-scoped.yml', 'health': 'verify.yml', 'argo': 'argo-login.yml', 'recover-startup': 'repair-startup.yml'}[identity_phase])
    elif selected_data_action:
        if selected_data_action in ('data-bootstrap', 'data-check'):
            gitops_preflight()
        playbook('playbooks/data/operate.yml')
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
        subprocess.run([sys.executable, '/workspace/ansible/playbooks/backup/files/runner.py', 'retrieve'], check=True)
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
        playbook('playbooks/baseline.yml')
    elif action in lifecycle:
        os.environ['LAB_TAILSCALE_TARGET'], os.environ['LAB_TAILSCALE_ACTION'] = lifecycle[action]
        playbook('playbooks/tailscale/lifecycle.yml')
    elif action == 'gitops-interruption-test':
        gitops_preflight()
        os.environ['LAB_GITOPS_STOP_AFTER_SEED'] = '1'
        playbook('playbooks/gitops.yml')
        os.environ['LAB_GITOPS_STOP_AFTER_SEED'] = '0'
        playbook('playbooks/gitops.yml')
        os.environ['LAB_GITOPS_ACTION'] = 'verify'
        playbook('playbooks/gitops.yml')
    elif action in {'gitops-bootstrap', 'gitops-verify', 'gitops-source-migrate'}:
        gitops_preflight()
        playbook('playbooks/gitops.yml')
        if action == 'gitops-bootstrap':
            os.environ['LAB_GITOPS_ACTION'] = 'verify'
            playbook('playbooks/gitops.yml')
    elif action == 'eso-bootstrap':
        gitops_preflight(require_catalog=False)
        playbook('playbooks/secrets/010-bootstrap.yml')
    elif action == 'eso-interruption-test':
        gitops_preflight(require_catalog=False)
        os.environ['LAB_ESO_STOP_AFTER_SEED'] = '1'
        playbook('playbooks/secrets/010-bootstrap.yml')
        os.environ['LAB_ESO_STOP_AFTER_SEED'] = '0'
        playbook('playbooks/secrets/010-bootstrap.yml')
    elif action == 'eso-recover':
        gitops_preflight(require_catalog=False)
        playbook('playbooks/secrets/recover.yml')
    elif action in {'longhorn-bootstrap', 'longhorn-interruption-test', 'longhorn-recover'}:
        gitops_preflight(require_catalog=False)
        if action == 'longhorn-recover':
            playbook('playbooks/longhorn/recover.yml')
        else:
            if action == 'longhorn-interruption-test':
                os.environ['LAB_LONGHORN_STOP_AFTER_SEED'] = '1'
                playbook('playbooks/longhorn/bootstrap.yml')
                os.environ['LAB_LONGHORN_STOP_AFTER_SEED'] = '0'
            playbook('playbooks/longhorn/bootstrap.yml')
    elif action in {'longhorn-backup-bootstrap', 'longhorn-backup-recover', 'longhorn-backup-interruption-test'}:
        gitops_preflight(require_catalog=False)
        if action == 'longhorn-backup-interruption-test':
            os.environ['LAB_BACKUP_STOP_AFTER_SEED'] = '1'
            playbook('playbooks/longhorn/030-backup-configuration.yml')
            os.environ['LAB_BACKUP_STOP_AFTER_SEED'] = '0'
        playbook('playbooks/longhorn/recover-backup.yml' if action.endswith('recover') else 'playbooks/longhorn/030-backup-configuration.yml')
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
        playbook('playbooks/backup/monthly.yml')
    elif action == 'backup':
        playbook('playbooks/backup.yml')
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
