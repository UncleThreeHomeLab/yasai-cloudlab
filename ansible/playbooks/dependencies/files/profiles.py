"""Accept reviewed hand-derived BuildKit profiles without widening their permissions."""
import json
from pathlib import Path
import re
import urllib.request

from .inputs import baseline
from .security import digest, download, owned_path
from .tools import write_json

BASE = 'ansible/playbooks/buildkit/files/'
BLOCKED = {'keyctl', 'add_key', 'request_key', 'bpf', 'kexec_load', 'reboot', 'perf_event_open',
           'init_module', 'delete_module'}
NAMESPACE = {'chroot', 'clone', 'mount', 'pivot_root', 'sethostname', 'setns', 'umount2', 'unshare'}


def official(version):
    request = urllib.request.Request('https://api.github.com/repos/containerd/containerd/commits/v' + version,
                                     headers={'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Containerd tag metadata exceeds its bound')
    document = json.loads(raw)
    commit = document.get('sha', '')
    if (not re.fullmatch(r'[a-f0-9]{40}', commit) or
            document.get('html_url') != 'https://github.com/containerd/containerd/commit/' + commit):
        raise ValueError('Containerd tag does not resolve to an official immutable commit')
    return commit


def seccomp(old, new):
    before, after = json.loads(old), json.loads(new)
    if (set(after) != set(before) or after.get('defaultAction') != 'SCMP_ACT_ERRNO' or
            after.get('architectures') != ['SCMP_ARCH_X86_64']):
        raise ValueError('BuildKit requires its existing default-deny architecture')
    allowed = {name for row in before['syscalls'] if row['action'] == 'SCMP_ACT_ALLOW' for name in row['names']}
    active = set()
    for row in after['syscalls']:
        if (set(row) - {'names', 'action', 'errnoRet', 'args', 'comment'} or not row.get('names') or
                any(not re.fullmatch(r'[a-z0-9_]+', name) for name in row['names']) or
                row.get('action') not in {'SCMP_ACT_ALLOW', 'SCMP_ACT_ERRNO'}):
            raise ValueError('Unsupported reviewed seccomp rule')
        if 'errnoRet' in row and (type(row['errnoRet']) is not int or not 0 <= row['errnoRet'] <= 4095):
            raise ValueError('Reviewed seccomp errno is invalid')
        if row['action'] == 'SCMP_ACT_ALLOW':
            if set(row['names']) - allowed or set(row['names']) & BLOCKED:
                raise ValueError('Reviewed profile cannot add syscall authority')
            # Existing argument restrictions must survive every retained allow rule.
            for name in row['names']:
                previous = [value for value in before['syscalls'] if name in value['names'] and value['action'] == 'SCMP_ACT_ALLOW']
                if not any(value.get('args') == row.get('args') for value in previous):
                    raise ValueError('Reviewed profile cannot remove syscall argument restrictions')
            active.update(row['names'])
    if not NAMESPACE <= active or not any(row['names'] == ['keyctl'] and row['action'] == 'SCMP_ACT_ERRNO' and
                                         row.get('errnoRet') == 38 for row in after['syscalls']):
        raise ValueError('BuildKit namespace or keyctl denial guard differs')


def apparmor(old, new):
    # This hand-derived policy has no automatic permission expansion interface.
    normalize = lambda raw: '\n'.join(line.strip() for line in raw.decode().splitlines()
                                      if line.strip() and not line.lstrip().startswith(('# ', '#\t')) and line.strip() != '#')
    if normalize(old) != normalize(new):
        raise ValueError('AppArmor permission changes require a separate owner review')


def update(root, request, *, fetch=download):
    if (set(request) != {'version', 'commit', 'seccompSha256', 'apparmorSha256'} or
            not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', request['version']) or
            not re.fullmatch(r'[a-f0-9]{40}', request['commit']) or
            any(not re.fullmatch(r'[a-f0-9]{64}', request[name]) for name in ('seccompSha256', 'apparmorSha256'))):
        raise ValueError('Profile maintenance requires exact reviewed inputs and an immutable upstream ref')
    if official(request['version']) != request['commit']:
        raise ValueError('Reviewed containerd version differs from its exact official tag commit')
    pin_path = owned_path(root, BASE + 'profiles.lock.json')
    lock = json.loads(pin_path.read_bytes())
    sources = {}
    for name, upstream, validate in (('seccomp', 'seccomp/seccomp_default.go', seccomp),
                                      ('apparmor', 'apparmor/template.go', apparmor)):
        path = owned_path(root, BASE + lock[name]['file'])
        raw = path.read_bytes()
        if digest(raw) != request[name + 'Sha256']:
            raise ValueError('Reviewed profile input checksum differs')
        validate(baseline(root, BASE + lock[name]['file']), raw)
        url = 'https://raw.githubusercontent.com/containerd/containerd/' + request['commit'] + '/contrib/' + upstream
        source = fetch(url, prefix='https://raw.githubusercontent.com/containerd/containerd/')
        sources[name] = {'url': url, 'sha256': digest(source)}
    for name in ('seccomp', 'apparmor'):
        lock[name]['sha256'] = request[name + 'Sha256']
    lock.update(upstream='https://github.com/containerd/containerd/tree/v' + request['version'] + '/contrib',
                reviewed_sources=sources)
    write_json(pin_path, lock)
    return {'owner': 'buildkit-profile', 'status': 'pending-verification', 'derivation': 'reviewed hand-derived profiles',
            'permissionExpansion': False}
