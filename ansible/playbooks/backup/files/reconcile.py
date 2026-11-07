"""Control-machine backup protection reconciler: profiles plus bindings to owners.

Reads the reviewed public profiles from this checkout and the private
protection bindings plus service catalog from the administrator's
private-config checkout (reviewed main, clean tree). Compiles the exact host
recovery policy/timer bytes, plans them against live host state over SSH, and
applies only with a merged private approval binding {binding, plan}. Longhorn
coverage is verified by parity with its accepted chart policy, never rewritten
here. Invalid or unreachable sources retain last-valid state and report
blocked; they never restore, delete, export, or start a recovery job.

Approval ceremony: merge the binding change; read the pending binding and plan
digests from this reconciler's status; merge a second PR carrying
platform/recovery/approval.yaml {binding, plan} for the current bytes; the
standing loop applies it and reports convergence. Merging the approval PR
keeps the binding bytes identical, so the approval stays satisfiable; any
profile or binding change voids it until rebound.

Host delivery writes only the managed recovery policy, the two managed timer
units, and the scoped recovery credentials. Setup still owns the initial
installation; this reconciler owns post-bootstrap convergence and refuses
hosts setup never installed. Timer lifecycle stays at its setup-time state:
delivery never enables, disables, starts, or restarts units.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, '/workspace/ansible')
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / 'ansible/playbooks/tailscale/files'))

from dotenv import dotenv_values

import protection
import runner
from verify_access import ssh
from playbooks.secrets.files import provision

ROOT = Path(__file__).resolve().parents[4]
WORK = Path('/infra-work/protection')
PROFILES_PATH = ROOT / 'platform/recovery/profiles.yaml'
APPROVAL_PATH = 'platform/recovery/approval.yaml'
MAX_FILE_BYTES = 65536
# Same bound as the services root catalog-path gate.
CATALOG_PATH_PATTERN = re.compile(r'^services/catalog(-[a-z0-9]+(-[a-z0-9]+)*)?[.](json|yaml)$')
REVISION_PATTERN = re.compile(r'[a-f0-9]{40}')
POLICY_MODE = '0600'
TIMER_MODE = '0644'


def configuration():
    values = dotenv_values(str(ROOT / '.env'), interpolate=False)
    config = {'private_dir': os.environ.get('PRIVATE_CONFIG_DIR') or '/private-config',
              'catalog_path': os.environ.get('CLOUDLAB_CATALOG_PATH') or 'services/catalog.json',
              'token': values.get('OP_SERVICE_ACCOUNT_TOKEN') or '',
              'enabled': values.get('K3S_BACKUP_ENABLED') == '1',
              'interval': os.environ.get('PROTECTION_INTERVAL') or values.get('PROTECTION_INTERVAL') or '600'}
    try:
        config['interval'] = int(config['interval'])
    except ValueError:
        raise RuntimeError('PROTECTION_INTERVAL must be seconds') from None
    if not 60 <= config['interval'] <= 86400:
        raise RuntimeError('PROTECTION_INTERVAL must be between 60 and 86400 seconds')
    # Recovery timers run on the K3s server only; the worker takes no delivery.
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'VM_PORT', 'OP_SERVICE_ACCOUNT_TOKEN'):
        if values.get(key):
            os.environ.setdefault(key, values[key])
    os.environ.setdefault('VM_PORT', '22')
    return config


def run_git(directory, *arguments, timeout=120):
    try:
        result = subprocess.run(['git', '-C', str(directory), *arguments],
                                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Protection git command did not complete') from None
    if result.returncode:
        raise RuntimeError('Protection checkout is not a git repository at a reviewed commit')
    return result.stdout


def read_bounded(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise RuntimeError('Protection declaration exceeds its bound: ' + Path(path).name)
    return raw


def load_inputs(config):
    """Validate profiles, bindings, catalog, destinations, and chart parity."""
    profiles_bytes = read_bounded(PROFILES_PATH)
    profiles = protection.load_profiles(PROFILES_PATH)
    try:
        public_revision = run_git(ROOT, 'rev-parse', 'HEAD').strip()
        public_dirty = bool(run_git(ROOT, 'status', '--porcelain').strip())
    except RuntimeError:
        raise RuntimeError('Public checkout must be a git repository') from None
    if not REVISION_PATTERN.fullmatch(public_revision):
        raise RuntimeError('Public checkout is not at a reviewed commit')
    private = Path(config['private_dir'])
    if not CATALOG_PATH_PATTERN.fullmatch(config['catalog_path']):
        raise ValueError('Service catalog path must be a bounded catalog file directly under services')
    try:
        revision = run_git(private, 'rev-parse', 'HEAD').strip()
        dirty = run_git(private, 'status', '--porcelain').strip()
    except RuntimeError:
        raise ValueError('Private checkout must be a git repository at a reviewed commit') from None
    if dirty or not REVISION_PATTERN.fullmatch(revision):
        raise ValueError('Private checkout must be clean at a reviewed commit')
    catalog = protection.load_document(private / config['catalog_path'])
    if not isinstance(catalog, dict):
        raise ValueError('Service catalog requires its entry list')
    requests = protection.catalog_requests(catalog)
    bindings, files = {}, {}
    for path in sorted(private.glob('services/*/protection.yaml')) + \
            sorted(private.glob('services/*/protection.yml')):
        raw = read_bounded(path)
        if path.parent.name in bindings:
            raise ValueError('Duplicate protection binding: ' + path.parent.name)
        bindings[path.parent.name] = protection.validate_binding(
            protection.load_document(path), path.parent.name, requests)
        files[path.parent.name] = raw
    if not config['token']:
        raise RuntimeError('Missing .env input: OP_SERVICE_ACCOUNT_TOKEN')
    titles = {item.get('title') for item in provision.inventory_items(config['token'])}
    for service, binding in bindings.items():
        if binding['destination'] not in titles:
            raise RuntimeError('Protection destination is not provisioned: ' + service)
    compiled = protection.compile_host_policy(profiles)
    longhorn = protection.compile_longhorn(profiles)
    protection.check_longhorn_parity(longhorn)
    coverage = []
    for service in sorted(bindings):
        coverage.extend({**row, 'service': service}
                        for row in protection.coverage(bindings[service], profiles))
    return {'profiles': profiles, 'compiled': compiled, 'longhorn': longhorn,
            'coverage': coverage, 'revision': revision, 'public_revision': public_revision,
            'public_dirty': public_dirty,
            'binding': protection.binding_digest(profiles_bytes, files)}


def parse_hashes(output, paths):
    hashes = {}
    for line in output.splitlines():
        digest, _, name = line.partition('  ')
        if re.fullmatch(r'[a-f0-9]{64}', digest):
            hashes[name.strip()] = digest
    return {path: hashes.get(path) for path in paths}


def observe_host():
    """Read-only live host state; secret values never enter the report."""
    host = os.environ['VM_HOST']
    timers = sorted(ssh('VM', host, protection.list_timers_command()).split())
    wanted = sorted(name + '.timer' for name in protection.HOST_TIMERS)
    if timers != wanted:
        if set(wanted) - set(timers):
            raise RuntimeError('Host recovery was never installed by setup; refusing delivery')
        raise RuntimeError('Unknown recovery timers present; duplicate export risk, refusing delivery')
    paths = [protection.HOST_POLICY_PATH] + [
        protection.TIMER_DIR + '/' + name for name in timers]
    hashes = parse_hashes(
        ssh('VM', host, 'sha256sum ' + ' '.join(paths) + ' 2>/dev/null || true'), paths)
    if any(value is None for value in hashes.values()):
        raise RuntimeError('Host recovery installation is incomplete; refusing delivery')
    states = {}
    for unit in timers:
        states[unit[:-len('.timer')]] = protection.parse_timer_state(
            ssh('VM', host, protection.timer_state_command(unit[:-len('.timer')])))
    try:
        freshness_output = ssh('VM', host, protection.freshness_command())
        freshness = {'checked': True, 'report': json.loads(freshness_output)}
    except RuntimeError:
        freshness = {'checked': False}
    except ValueError:
        raise RuntimeError('Host freshness report is unreadable; refusing delivery') from None
    return {'hashes': hashes, 'timers': states, 'freshness': freshness}


def desired_files(compiled):
    files = {protection.HOST_POLICY_PATH: protection.policy_bytes(compiled['policy'])}
    for name, calendar in compiled['timers'].items():
        files[protection.TIMER_DIR + '/' + name + '.timer'] = protection.render_timer(
            name, calendar)
    return files


def observe_credentials():
    """Semantic credential comparison; values stay out of every report."""
    try:
        remote = json.loads(ssh('VM', os.environ['VM_HOST'],
                                protection.read_command(protection.HOST_CREDENTIALS_PATH)) or 'null')
    except ValueError:
        raise RuntimeError('Host recovery credentials are unreadable; refusing delivery') from None
    local = runner.shared_credentials()
    return local, remote != local


def plan_cycle(inputs, observed, credentials_changed):
    compiled = inputs['compiled']
    wanted = desired_files(compiled)
    actions = []
    if observed['hashes'][protection.HOST_POLICY_PATH] != hashlib.sha256(
            wanted[protection.HOST_POLICY_PATH]).hexdigest():
        actions.append('write-policy')
    for name in sorted(compiled['timers']):
        path = protection.TIMER_DIR + '/' + name + '.timer'
        if observed['hashes'][path] != hashlib.sha256(wanted[path]).hexdigest():
            actions.append('write-timer')
            break
    if 'write-timer' in actions:
        actions.append('daemon-reload')
    if credentials_changed:
        actions.append('refresh-credentials')
    plan = {'profile': protection.PROFILE, 'policy': compiled['policy'],
            'timers': compiled['timers'], 'longhorn': inputs['longhorn'],
            'data': inputs['profiles'][protection.PROFILE]['data'],
            'harbor': inputs['profiles'][protection.PROFILE]['harbor'],
            'actions': actions, 'credentialsChanged': credentials_changed}
    protection.plan_guard(plan)
    return plan, protection.plan_digest(plan)


def deliver(host, path, data, mode):
    expected = hashlib.sha256(data).hexdigest()
    ssh('VM', host, protection.stage_command(path, mode), input=data.decode())
    staged = parse_hashes(ssh('VM', host, protection.verify_staged_command(path)),
                          [path + '.protection-new'])[path + '.protection-new']
    if staged != expected:
        raise RuntimeError('Protection delivery upload changed during transfer; retained')
    ssh('VM', host, protection.finalize_command(path))
    final = parse_hashes(ssh('VM', host, protection.verify_command(path)), [path])[path]
    if final != expected:
        raise RuntimeError('Protection delivery did not converge; inspect before retrying')


def apply_plan(inputs, plan):
    """Apply the approved plan; any failure retains last-valid host state."""
    host = os.environ['VM_HOST']
    try:
        ssh('VM', host, protection.job_free_command())
    except RuntimeError:
        raise RuntimeError('Monthly recovery holds the host lock; retry next cycle') from None
    wanted = desired_files(inputs['compiled'])
    if 'write-policy' in plan['actions']:
        deliver(host, protection.HOST_POLICY_PATH, wanted[protection.HOST_POLICY_PATH], POLICY_MODE)
    if 'write-timer' in plan['actions']:
        for name in sorted(inputs['compiled']['timers']):
            path = protection.TIMER_DIR + '/' + name + '.timer'
            current = parse_hashes(ssh('VM', host, protection.verify_command(path)), [path])[path]
            if current != hashlib.sha256(wanted[path]).hexdigest():
                deliver(host, path, wanted[path], TIMER_MODE)
        ssh('VM', host, protection.daemon_reload_command())
        timers = sorted(ssh('VM', host, protection.list_timers_command()).split())
        if timers != sorted(name + '.timer' for name in protection.HOST_TIMERS):
            raise RuntimeError('Recovery timers changed during delivery; inspect before retrying')
    if 'refresh-credentials' in plan['actions']:
        local, _ = observe_credentials()
        deliver(host, protection.HOST_CREDENTIALS_PATH,
                json.dumps(local).encode(), POLICY_MODE)
    observed = observe_host()
    for path, data in wanted.items():
        if observed['hashes'][path] != hashlib.sha256(data).hexdigest():
            raise RuntimeError('Protection delivery did not converge; inspect before retrying')
    return observed


def once(config):
    """Plan every cycle; apply only the merged approval's exact plan."""
    if not config['enabled']:
        status = {'ok': True, 'enabled': False, 'skipped': True,
                  'reason': 'K3S_BACKUP_ENABLED=0 retains setup-time recovery without delivery'}
        report(status)
        return status
    try:
        inputs = load_inputs(config)
        observed = observe_host()
        _, credentials_changed = observe_credentials()
        plan, digest = plan_cycle(inputs, observed, credentials_changed)
        base = {'revision': inputs['revision'], 'publicRevision': inputs['public_revision'],
                'publicDirty': inputs['public_dirty'], 'binding': inputs['binding'],
                'plan': digest, 'coverage': inputs['coverage'],
                'freshness': observed['freshness'], 'timers': observed['timers']}
        if not plan['actions']:
            status = {'ok': True, 'protection': {
                **base, 'ready': True, 'changed': False, 'drifted': False}}
            report(status)
            return status
        approval_path = Path(config['private_dir']) / APPROVAL_PATH
        approved = False
        if approval_path.is_file():
            current, approved_plan = protection.validate_approval(
                read_bounded(approval_path).decode(), inputs['binding'])
            approved = current and approved_plan == digest
        if not approved:
            status = {'ok': True, 'protection': {
                **base, 'ready': True, 'changed': False, 'drifted': True,
                'approved': False, 'pending_review': True, 'actions': plan['actions']}}
            report(status)
            return status
        observed = apply_plan(inputs, plan)
        status = {'ok': True, 'protection': {
            **base, 'ready': True, 'changed': True, 'drifted': False,
            'approved': True, 'actions': plan['actions'],
            'freshness': observed['freshness'], 'timers': observed['timers']}}
    except (RuntimeError, ValueError, OSError) as error:
        status = {'ok': False, 'protection': {'ready': False, 'error': str(error)}}
    report(status)
    return status


def verify(config):
    """Read-only proof that live state matches accepted Git intent; never mutates."""
    if not config['enabled']:
        proof = {'verified': False, 'reason': 'K3S_BACKUP_ENABLED=0 retains setup-time recovery'}
        report(proof)
        return proof
    try:
        inputs = load_inputs(config)
        observed = observe_host()
        _, credentials_changed = observe_credentials()
        plan, digest = plan_cycle(inputs, observed, credentials_changed)
        proof = {'verified': not plan['actions'], 'revision': inputs['revision'],
                 'publicRevision': inputs['public_revision'], 'binding': inputs['binding'],
                 'plan': digest, 'drifted': bool(plan['actions']), 'actions': plan['actions'],
                 'coverage': inputs['coverage'], 'freshness': observed['freshness'],
                 'timers': observed['timers']}
    except (RuntimeError, ValueError, OSError) as error:
        proof = {'verified': False, 'error': str(error)}
    report(proof)
    return proof


def report(status):
    WORK.mkdir(parents=True, exist_ok=True)
    path = WORK / 'status.json'
    path.write_text(json.dumps(status, sort_keys=True))
    os.chmod(path, 0o600)
    print(json.dumps(status, sort_keys=True), flush=True)


def main(argv):
    if argv[:1] not in (['once'], ['loop'], ['verify']):
        raise SystemExit('Protection reconciler requires once, loop, or verify')
    os.umask(0o077)
    WORK.mkdir(parents=True, exist_ok=True)
    import fcntl
    with (WORK / 'lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit('Another protection reconciliation holds the lock')
        config = configuration()
        for name in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
            if not os.environ.get(name):
                raise SystemExit('Missing lab connection input: ' + name)
        if argv[0] == 'once':
            status = once(config)
            raise SystemExit(0 if status['ok'] else 1)
        if argv[0] == 'verify':
            proof = verify(config)
            raise SystemExit(0 if proof['verified'] else 1)
        while True:
            try:
                once(config)
            except RuntimeError as error:
                report({'ok': False, 'error': str(error)})
            except Exception:
                report({'ok': False, 'error': 'Protection reconciliation failed; state retained'})
            time.sleep(config['interval'])


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
