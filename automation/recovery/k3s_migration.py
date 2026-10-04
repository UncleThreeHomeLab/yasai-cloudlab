"""Explicit, data-free K3s recreation. Retain old state; never downgrade a DB.

Ansible stages this module and supplies the authoritative target release. All
diagnostics are allowlisted; host paths, API documents and credentials stay local.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import time
from contextlib import ExitStack
from k3s_network import cleanup as cleanup_network

BASE = Path('/var/lib/cloudlab/k3s-migration')
STATE_PATHS = ('var/lib/rancher/k3s', 'var/lib/kubelet', 'var/lib/cni',
               'etc/rancher/k3s', 'etc/rancher/node')
FILES = ('usr/local/bin/k3s', 'usr/local/bin/k3s-killall.sh',
         'etc/systemd/system/k3s.service', 'etc/systemd/system/k3s.service.env',
         'etc/systemd/system/k3s-agent.service', 'etc/systemd/system/k3s-agent.service.env')
TIMERS = ('cloudlab-recovery.timer', 'cloudlab-recovery-freshness.timer')


def command(args, *, check=True, input=None):
    result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=300)
    if check and result.returncode:
        if Path(args[0]).name == 'k3s-killall.sh':
            error_path = BASE / 'last-stop-error.txt'
            error_path.write_text(result.stderr)
            error_path.chmod(0o600)
        raise RuntimeError('Migration command failed: ' + Path(args[0]).name +
                           ' exit ' + str(result.returncode) + '; private output withheld')
    return result


def stop_script(source):
    # Debian's iptables-nft cannot round-trip native nft expressions. The caller
    # removes only Kubernetes-owned chains through a checked nft transaction.
    patches = {
        "iptables-save | grep -v KUBE- | grep -v CNI- | grep -iv flannel | iptables-restore": ': # Kubernetes reconciles its existing IPv4 rules on startup',
        "ip6tables-save | grep -v KUBE- | grep -v CNI- | grep -iv flannel | ip6tables-restore": ': # Kubernetes reconciles its existing IPv6 rules on startup',
        '        tailscale set --advertise-routes=': '        : # Host Tailscale policy belongs to the host module',
    }
    for old, new in patches.items():
        if source.count(old) != 1:
            raise RuntimeError('Reviewed stop-script patch no longer matches')
        source = source.replace(old, new)
    return source


def stop_cluster(role, policy):
    source = BASE / 'files/usr/local/bin/k3s-killall.sh'
    if digest(source) != policy['killall_sha256']:
        raise RuntimeError('Retained stop-script checksum mismatch')
    command(['/bin/sh'], input=stop_script(source.read_text()))
    service = 'k3s' if role == 'server' else 'k3s-agent'
    if command(['systemctl', 'is-active', service], check=False).stdout.strip() != 'inactive':
        raise RuntimeError('K3s service did not stop')
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    if any(line.split()[4].startswith(('/run/k3s/', '/var/lib/kubelet/')) for line in mounts):
        raise RuntimeError('Kubernetes mounts remain; refusing state move')
    for proc in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            cmd = proc.read_bytes()
        except FileNotFoundError:
            continue
        if b'/var/lib/rancher/k3s/' in cmd and b'containerd-shim' in cmd:
            raise RuntimeError('Kubernetes container runtime remains; refusing state move')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def safe_path(root, relative):
    path = root / relative
    # Parent symlinks could redirect a rename outside the declared state tree.
    if path.resolve() != path.absolute():
        raise RuntimeError('Unexpected symlink in migration path')
    return path


def park_paths(root, destination, paths=STATE_PATHS):
    """A successful rename is the resume marker for that individual path."""
    for relative in paths:
        source = safe_path(root, relative)
        target = safe_path(destination, relative)
        if target.exists():
            if source.exists():
                raise RuntimeError('Both original and parked state exist; refusing overwrite')
            continue
        if source.exists():
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source.rename(target)


def restore_paths(root, backup, failed, paths=STATE_PATHS):
    for relative in paths:
        current = safe_path(root, relative)
        old = safe_path(backup, relative)
        parked = safe_path(failed, relative)
        if not old.exists():
            # This path was already restored, or never existed in the old tree.
            continue
        if current.exists():
            if parked.exists():
                raise RuntimeError('Rollback state conflict; refusing overwrite')
            parked.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            current.rename(parked)
        current.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        old.rename(current)


def empty_cluster():
    def get(kind):
        return json.loads(command(['/usr/local/bin/k3s', 'kubectl', 'get', kind,
                                   '-A', '-o', 'json']).stdout)['items']
    for kind in ('pv', 'pvc', 'volumes.longhorn.io', 'replicas.longhorn.io', 'ingresses'):
        if get(kind):
            raise RuntimeError('Migration requires zero application storage and ingress')
    allowed = {'default', 'kube-system', 'kube-public', 'kube-node-lease',
               'external-secrets', 'longhorn-system'}
    if any(x['metadata']['name'] not in allowed for x in get('namespaces')):
        raise RuntimeError('Unknown namespace blocks platform recreation')
    for x in get('pods,deployments,statefulsets,daemonsets,jobs,cronjobs'):
        if x['metadata']['namespace'] not in allowed - {'default'}:
            raise RuntimeError('Application workload blocks platform recreation')


def validate_source(policy):
    version = command(['/usr/local/bin/k3s', '--version']).stdout
    if not version.startswith('k3s version ' + policy['source'] + ' '):
        raise RuntimeError('Unexpected source K3s release')
    if digest(Path('/usr/local/bin/k3s')) != policy['source_binary_sha256'][platform.machine()]:
        raise RuntimeError('Source binary checksum mismatch')
    if digest(Path('/usr/local/bin/k3s-killall.sh')) != policy['killall_sha256']:
        raise RuntimeError('Stop script differs from the reviewed upstream artifact')


def run(action, role, target):
    if role not in ('server', 'agent'):
        raise RuntimeError('Invalid node role')
    policy = json.loads(Path(__file__).with_name('k3s_migration.json').read_text())
    if target['version'] != policy['target']:
        raise RuntimeError('Active target differs from reviewed migration')
    os.umask(0o077)
    safe_path(Path('/'), str(BASE).lstrip('/'))
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    BASE.chmod(0o700)
    with ExitStack() as resources:
        lock = resources.enter_context((BASE / 'lock').open('w'))
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state_file = BASE / 'state.json'
        state = json.loads(state_file.read_text()) if state_file.exists() else {'phase': 'new'}
        phase = state['phase']
        if state.get('id', policy['id']) != policy['id']:
            raise RuntimeError('Foreign migration checkpoint')
        if state.get('role', role) != role or state.get('target', policy['target']) != policy['target']:
            raise RuntimeError('Checkpoint role or target mismatch')
        stopping = ((action == 'park' and phase in ('prepared', 'parking')) or
                    (action == 'repair-network' and phase == 'active' and not state.get('network_cleanup_complete')) or
                    (action == 'rollback' and phase not in ('accepted', 'rolled-back')))
        if stopping and role == 'server':
            # Share the recovery job's actual lock; an is-active check alone races.
            recovery_lock = safe_path(Path('/'), 'var/lib/cloudlab/recovery/job.lock')
            recovery = resources.enter_context(recovery_lock.open('a'))
            try:
                fcntl.flock(recovery, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('Recovery capture is running; retry after it finishes') from None
        if action == 'inspect':
            if phase == 'new':
                validate_source(policy)
                if role == 'server':
                    empty_cluster()
                    command(['python3', '/opt/cloudlab/recovery/backup.py', 'freshness'])
            print(json.dumps({'phase': phase, 'changed': False}))
            return
        if action == 'prepare':
            if phase != 'new':
                print(json.dumps({'phase': phase, 'changed': False}))
                return
            validate_source(policy)
            if role == 'server':
                empty_cluster()
            if shutil.disk_usage(BASE).free < 20 * 1024**3:
                raise RuntimeError('Migration needs 20 GiB free for rollback headroom')
            # All downloads finish on both hosts before either host is stopped.
            if digest(BASE / 'target-k3s') != target['sha256']:
                raise RuntimeError('Staged target checksum mismatch')
            old = BASE / 'files'
            hashes = {}
            for relative in FILES:
                source = safe_path(Path('/'), relative)
                if source.is_file():
                    destination = old / relative
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    shutil.copy2(source, destination)
                    hashes[relative] = digest(destination)
            state = {'id': policy['id'], 'phase': 'prepared', 'files': hashes,
                     'source': policy['source'], 'target': policy['target'],
                     'role': role, 'started_at': time.time(),
                     'active_timers': [timer for timer in TIMERS if command(
                         ['systemctl', 'is-active', timer], check=False).returncode == 0]}
            atomic(state_file, state)
        elif action == 'park':
            if phase in ('parked', 'active', 'accepted'):
                print(json.dumps({'phase': phase, 'changed': False}))
                return
            if phase not in ('prepared', 'parking'):
                raise RuntimeError('Migration must be prepared before stopping nodes')
            if phase == 'prepared':
                validate_source(policy)
                if role == 'server':
                    empty_cluster()
                    if command(['systemctl', 'is-active', 'cloudlab-recovery.service'], check=False).returncode == 0:
                        raise RuntimeError('Monthly backup is running; retry after it finishes')
                state['phase'] = 'parking'
                atomic(state_file, state)
            for timer in TIMERS:
                command(['systemctl', 'stop', timer], check=False)
            if role == 'server' and command(['systemctl', 'is-active', 'cloudlab-recovery.service'], check=False).returncode == 0:
                raise RuntimeError('Monthly backup is running; retry after it finishes')
            # A reboot during parking must not start the old binary on empty state.
            command(['systemctl', 'disable', 'k3s' if role == 'server' else 'k3s-agent'])
            stop_cluster(role, policy)
            cleanup_network(command)
            state['network_cleanup_complete'] = True
            park_paths(Path('/'), BASE / 'old')
            if role == 'server':
                database = BASE / 'old/var/lib/rancher/k3s/server/db/state.db'
                with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                    if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                        raise RuntimeError('Parked datastore failed integrity check')
            state['phase'] = 'parked'
            atomic(state_file, state)
        elif action == 'repair-network':
            if phase != 'active' or state.get('network_cleanup_complete'):
                print(json.dumps({'phase': phase, 'changed': False}))
                return
            # Resume checkpoints written before scoped nft cleanup was introduced.
            # Keep the fresh datastore; stop runtime writers before removing rules.
            command(['systemctl', 'disable', 'k3s' if role == 'server' else 'k3s-agent'])
            stop_cluster(role, policy)
            cleanup_network(command)
            state['network_cleanup_complete'] = True
            atomic(state_file, state)
            print(json.dumps({'phase': phase, 'changed': True}))
            return
        elif action == 'activate':
            if phase in ('active', 'accepted'):
                print(json.dumps({'phase': phase, 'changed': False}))
                return
            if phase != 'parked':
                raise RuntimeError('Both nodes must be parked before activation')
            if digest(BASE / 'target-k3s') != target['sha256']:
                raise RuntimeError('Target artifact changed')
            destination = Path('/usr/local/bin/k3s')
            temporary = destination.with_suffix('.migration')
            shutil.copyfile(BASE / 'target-k3s', temporary)
            temporary.chmod(0o755)
            temporary.replace(destination)
            # Services and their independent host-network dependencies stay in place.
            state['phase'] = 'active'
            atomic(state_file, state)
        elif action == 'accept':
            if phase not in ('active', 'accepted'):
                raise RuntimeError('Only an active migration can be accepted')
            if digest(Path('/usr/local/bin/k3s')) != target['sha256']:
                raise RuntimeError('Acceptance binary checksum mismatch')
            state['phase'] = 'accepted'
            atomic(state_file, state)
        elif action == 'rollback':
            if phase == 'rolled-back':
                print(json.dumps({'phase': phase, 'changed': False}))
                return
            if phase not in ('prepared', 'parking', 'parked', 'active', 'rolling-back'):
                raise RuntimeError('Rollback is allowed only before acceptance')
            for relative, expected in state['files'].items():
                if digest(BASE / 'files' / relative) != expected:
                    raise RuntimeError('Rollback artifact checksum mismatch')
            for timer in TIMERS:
                command(['systemctl', 'stop', timer], check=False)
            command(['systemctl', 'disable', 'k3s' if role == 'server' else 'k3s-agent'])
            state['phase'] = 'rolling-back'
            atomic(state_file, state)
            stop_cluster(role, policy)
            cleanup_network(command)
            restore_paths(Path('/'), BASE / 'old', BASE / 'failed')
            for relative in state['files']:
                shutil.copy2(BASE / 'files' / relative, Path('/') / relative)
            command(['systemctl', 'daemon-reload'])
            state['phase'] = 'rolled-back'
            atomic(state_file, state)
        elif action == 'restore-timers':
            if phase != 'rolled-back':
                raise RuntimeError('Timer restoration requires completed rollback')
            timers = state.get('active_timers')
            if timers is None:
                timers = [timer for timer in TIMERS if command(
                    ['systemctl', 'is-enabled', timer], check=False).returncode == 0]
            for timer in timers:
                command(['systemctl', 'start', timer])
        else:
            raise RuntimeError('Unknown migration action')
        print(json.dumps({'phase': state['phase'], 'changed': phase != state['phase']}))


if __name__ == '__main__':
    try:
        run(sys.argv[1], sys.argv[2], json.load(sys.stdin))
    except Exception as error:
        # No subprocess stderr or paths: API and kubeconfig failures can disclose
        # private metadata. State stays available for the explicit resume action.
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        if isinstance(error, OSError):
            message += ' errno ' + str(error.errno)
        raise SystemExit('K3s migration failed; retained checkpoint: ' + message) from None
