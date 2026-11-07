"""Validate DNS generations before activation; retain original host resolver recovery."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

try:
    from .dns_render import configuration
    from .dns_wire import absent_answer, private_answer, query
except ImportError:
    from dns_render import configuration
    from dns_wire import absent_answer, private_answer, query

BASE = Path('/etc/cloudlab-dns')
STATE = Path('/var/lib/cloudlab/private-dns')
SERVICE = 'cloudlab-private-dns'
RESOLVER = Path('/etc/resolv.conf')
# Initial authority before the first Git convergence; the reconciler replaces it.
INITIAL_ZONE = 'internal.example.invalid'


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Private DNS service operation failed')
    return result.stdout


def atomic(path, content, mode=0o600):
    temporary = path.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, mode)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def validate_answers(payload, port=53):
    for tcp in (False, True):
        for address, expected, source in [('127.0.0.1', payload.get('cluster_gateway'), None),
                                         (payload['tailnet_address'], payload.get('tailnet_gateway'), payload['tailnet_address'])]:
            if payload['names'] and expected:
                private_answer(address, payload['names'][0] + '.' + payload['zone'], expected,
                               port=port, source=source, tcp=tcp)
            if payload.get('identity_host') and expected:
                private_answer(address, payload['identity_host'], expected,
                               port=port, source=source, tcp=tcp)
            absent_answer(address, 'nonexistent-cloudlab-proof.' + payload['zone'],
                          port=port, source=source, tcp=tcp)
    if not query('127.0.0.1', 'github.com', port=port)['addresses']:
        raise RuntimeError('Retained public DNS forwarding failed')


def digest_for(payload):
    """Generation identity over served content only, never host bind addresses.

    Both resolvers must report the same digest when serving the same names;
    hashing the rendered files (which embed per-host binds) made cross-host
    generation proofs unsatisfiable.
    """
    content = {'names': sorted(payload['names']), 'zone': payload['zone'],
               'identity_host': payload.get('identity_host'),
               'cluster_gateway': payload.get('cluster_gateway'),
               'tailnet_gateway': payload.get('tailnet_gateway'),
               'artifact': payload['artifact']}
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def adopt(payload):
    """Bootstrap adoption: unset fields inherit the live generation, else initial.

    Omitted fields (None) keep existing live values so setup converges
    finished servers instead of wiping them; fresh servers get the initial
    authority. The reconciler always sends complete payloads, so Git intent -
    including an explicit empty publication - still converges exactly.
    """
    try:
        existing = json.loads((STATE / 'inputs.json').read_text())
    except (OSError, ValueError):
        existing = {}
    merged = dict(payload)
    if merged.get('zone') is None:
        merged['zone'] = existing.get('zone') or INITIAL_ZONE
    if merged.get('names') is None:
        merged['names'] = existing.get('names') or []
    if merged.get('identity_host') is None:
        merged['identity_host'] = existing.get('identity_host')
    for gateway in ('cluster_gateway', 'tailnet_gateway'):
        if merged.get(gateway) is None:
            merged[gateway] = existing.get(gateway)
    if merged.get('cluster_gateway') is None or merged.get('tailnet_gateway') is None:
        merged['cluster_gateway'] = merged['tailnet_gateway'] = None
        if merged['names']:
            raise ValueError('Published private names require both gateway addresses')
    return merged


def configure(payload):
    payload = adopt(payload)
    original = STATE / 'resolv.conf.original'
    resolver = RESOLVER
    if not original.exists():
        if resolver.is_symlink():
            raise RuntimeError('Resolver has a separate active owner; explicit integration required')
        content = resolver.read_text()
    else:
        content = original.read_text()
    payload['upstreams'] = [line.split()[1] for line in content.splitlines() if line.startswith('nameserver ')]
    files = configuration(payload)
    if not original.exists():
        atomic(original, content)
    digest = digest_for(payload)
    generation = BASE / digest
    generation.mkdir(mode=0o755, exist_ok=True)
    repaired = False
    for name, value in files.items():
        path = generation / name
        if not path.exists() or path.read_text() != value:
            atomic(path, value, 0o644)
            repaired = True
    current = BASE / 'current'
    previous = current.resolve() if current.is_symlink() else None
    receipt = STATE / 'generation'
    changed = (previous != generation or repaired or payload.get('service_changed', False)
               or not receipt.exists() or receipt.read_text() != digest)
    active = subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE]).returncode == 0
    if changed or not active:
        # Candidate uses separate ports and the actual private bind addresses.
        with tempfile.TemporaryDirectory(prefix='validate-', dir=BASE) as folder:
            candidate = Path(folder)
            for name, value in files.items():
                if name == 'Corefile':
                    value = value.replace(':53 {', ':1053 {').replace(':18053', ':18054')
                (candidate / name).write_text(value)
            process = subprocess.Popen(['/usr/local/bin/cloudlab-coredns', '-conf', 'Corefile'], cwd=candidate,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for attempt in range(15):
                    if process.poll() is not None:
                        raise RuntimeError('Candidate DNS process failed before activation')
                    try:
                        validate_answers(payload, 1053)
                        break
                    except (OSError, ValueError, RuntimeError):
                        if attempt == 14:
                            raise
                        time.sleep(1)
            finally:
                process.terminate()
                process.wait(timeout=10)
        temporary = BASE / 'current.tmp'
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(generation)
        temporary.replace(current)
        try:
            command('systemctl', 'restart', SERVICE)
            for attempt in range(15):
                try:
                    validate_answers(payload)
                    break
                except (OSError, ValueError, RuntimeError):
                    if attempt == 14:
                        raise
                    time.sleep(1)
        except Exception:
            if previous:
                temporary.symlink_to(previous)
                temporary.replace(current)
                command('systemctl', 'restart', SERVICE)
            raise
    else:
        # An unchanged generation still needs live proof. Bound transient packet
        # loss without restarting a healthy resolver or declaring a change.
        for attempt in range(5):
            try:
                validate_answers(payload)
                break
            except (OSError, ValueError, RuntimeError):
                if attempt == 4:
                    raise
                time.sleep(1)
    atomic(STATE / 'inputs.json', json.dumps(payload, sort_keys=True))
    atomic(receipt, digest)
    return {'changed': changed or not active, 'dns_ready': True, 'digest': digest,
            'host_resolver_changed': False}


def activate():
    payload = json.loads((STATE / 'inputs.json').read_text())
    for address in ('10.44.0.1', '10.44.0.2'):
        for tcp in (False, True):
            if payload['names'] and payload.get('cluster_gateway'):
                private_answer(address, payload['names'][0] + '.' + payload['zone'],
                               payload['cluster_gateway'], tcp=tcp)
            if payload.get('identity_host') and payload.get('cluster_gateway'):
                private_answer(address, payload['identity_host'],
                               payload['cluster_gateway'], tcp=tcp)
            absent_answer(address, 'nonexistent-cloudlab-proof.' + payload['zone'], tcp=tcp)
            if not query(address, 'github.com', tcp=tcp)['addresses']:
                raise RuntimeError('Independent resolver forwarding is unavailable')
    desired = ('# Managed by cloudlab; original retained in /var/lib/cloudlab/private-dns.\n'
               'nameserver 10.44.0.1\nnameserver 10.44.0.2\noptions timeout:2 attempts:2\n')
    path = RESOLVER
    if path.is_symlink():
        raise RuntimeError('Host resolver ownership changed')
    original = (STATE / 'resolv.conf.original').read_text()
    if path.read_text() not in (original, desired):
        raise RuntimeError('Host resolver has conflicting changes; retained original remains available')
    changed = path.read_text() != desired
    if changed:
        atomic(path, desired, 0o644)
    return {'changed': changed, 'both_resolvers_verified': True}


def check():
    """Read-only drift check of the active generation; never writes or restarts."""
    try:
        payload = json.loads((STATE / 'inputs.json').read_text())
    except (OSError, ValueError):
        raise RuntimeError('No active private DNS generation') from None
    receipt = STATE / 'generation'
    current = BASE / 'current'
    if not current.is_symlink() or not receipt.exists():
        raise RuntimeError('No active private DNS generation')
    if receipt.read_text() != current.resolve().name:
        raise RuntimeError('Active private DNS generation differs from its receipt')
    validate_answers(payload)
    return {'dns_ready': True, 'digest': receipt.read_text(), 'names': len(payload['names'])}


def absent(names):
    """Prove retired names answer absent on both views; never writes."""
    try:
        payload = json.loads((STATE / 'inputs.json').read_text())
    except (OSError, ValueError):
        raise RuntimeError('No active private DNS generation') from None
    zone, tailnet = payload.get('zone'), payload.get('tailnet_address')
    if not zone or not tailnet:
        raise RuntimeError('No active private DNS generation')
    confirmed = []
    for name in names:
        if (not isinstance(name, str) or not name.endswith('.' + zone) or name == zone
                or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                           for label in name.split('.'))):
            raise RuntimeError('Retirement proof requires exact zone names')
        for tcp in (False, True):
            absent_answer('127.0.0.1', name, tcp=tcp)
            absent_answer(tailnet, name, source=tailnet, tcp=tcp)
        confirmed.append(name)
    return {'absent': confirmed}


if __name__ == '__main__':
    try:
        with (STATE / 'lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if sys.argv[1:] == ['activate']:
                print(json.dumps(activate()))
            elif sys.argv[1:] == ['check']:
                print(json.dumps(check()))
            elif len(sys.argv) > 2 and sys.argv[1] == 'absent':
                print(json.dumps(absent(sys.argv[2:])))
            elif not sys.argv[1:]:
                print(json.dumps(configure(json.load(sys.stdin))))
            else:
                raise ValueError('Unknown private DNS action')
    except Exception:
        raise SystemExit('Private DNS operation failed; original resolver and last generation retained.') from None
