"""Read-only qualification of the pinned native K3s launcher and local API."""
import base64
import ctypes
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import shlex
import ssl
import stat
import subprocess
import tarfile
import time
import urllib.request

import yaml


def refused():
    raise ValueError('Native K3s custody unavailable')


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0: refused()
    return value


def run(arguments, deadline):
    result = subprocess.run(arguments, capture_output=True, timeout=min(10, remaining(deadline)),
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode or len(result.stdout) + len(result.stderr) > 262144: refused()
    return result.stdout.decode()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def opened(path, limit, *, executable=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    stream = os.fdopen(descriptor, 'rb')
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or
            not 0 <= info.st_size <= limit or executable and (not info.st_size or not info.st_mode & 0o111)):
        stream.close(); refused()
    return stream


def unchanged(stream, path, before):
    if identity(os.fstat(stream.fileno())) != before or identity(os.stat(path, follow_symlinks=False)) != before:
        refused()


def digest(stream, deadline):
    stream.seek(0); result = hashlib.sha256()
    while raw := stream.read(1024 * 1024):
        remaining(deadline); result.update(raw)
    return result.hexdigest()


def loaded_library(raw, expected):
    paths = {line.split(None, 5)[-1] for line in raw.decode().splitlines() if 'libzstd.so' in line}
    if paths != {expected}: refused()


def preload_state():
    path = Path('/etc/ld.so.preload')
    if not os.path.lexists(path): return False
    with opened(path, 262144) as stream:
        if stream.read().strip(): refused()
    return True


def environment_policy(raw):
    if len(raw) > 262144: refused()
    pairs = [entry.split(b'=', 1) for entry in raw.split(b'\0') if entry]
    if any(len(pair) != 2 for pair in pairs) or len(dict(pairs)) != len(pairs): refused()
    for key, item in pairs:
        if item and (key.upper().endswith(b'_PROXY') or key.startswith(b'K3S_') and key != b'K3S_TOKEN' or
                     key in (b'LD_PRELOAD', b'LD_LIBRARY_PATH', b'LD_AUDIT')): refused()


def trusted_library(deadline):
    if any(os.environ.get(key) for key in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT')): refused()
    preload_state()
    directory = {'x86_64': 'x86_64-linux-gnu', 'aarch64': 'aarch64-linux-gnu'}.get(platform.machine())
    if directory is None: refused()
    alias = Path('/usr/lib') / directory / 'libzstd.so.1'
    if alias.lstat().st_uid != 0: refused()
    resolved = alias.resolve(strict=True)
    if resolved.parent != alias.parent or not re.fullmatch(r'libzstd\.so\.1\.5\.[0-9]+', resolved.name): refused()
    for path in (alias.parent, resolved):
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022: refused()
    owner = run(['dpkg-query', '--search', str(resolved)], deadline).strip()
    if owner not in ('libzstd1:amd64: '+str(resolved), 'libzstd1:arm64: '+str(resolved), 'libzstd1: '+str(resolved)):
        refused()
    if run(['dpkg', '--verify', 'libzstd1'], deadline).strip(): refused()
    before = identity(resolved.stat())
    library = ctypes.CDLL(str(resolved))
    if identity(resolved.stat()) != before: refused()
    with Path('/proc/self/maps').open('rb') as stream: maps = stream.read(1048577)
    if len(maps) > 1048576: refused()
    loaded_library(maps, str(resolved))
    library.ZSTD_versionNumber.restype = ctypes.c_uint
    if not 10504 <= library.ZSTD_versionNumber() < 10600: refused()
    library._custody_path = str(resolved)
    library._custody_identity = before
    return library


class Buffer(ctypes.Structure):
    _fields_ = [('src', ctypes.c_void_p), ('size', ctypes.c_size_t), ('pos', ctypes.c_size_t)]


class Archive(io.RawIOBase):
    """Bounded streaming zstd reader; no extracted file or executable is created."""
    def __init__(self, library, frame, deadline):
        self.library, self.frame, self.deadline = library, frame, deadline
        self.offset = self.total = 0; self.pending = b''; self.done = False
        library.ZSTD_createDStream.restype = ctypes.c_void_p
        library.ZSTD_freeDStream.argtypes = [ctypes.c_void_p]
        library.ZSTD_initDStream.argtypes = [ctypes.c_void_p]; library.ZSTD_initDStream.restype = ctypes.c_size_t
        library.ZSTD_DCtx_setMaxWindowSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        library.ZSTD_DCtx_setMaxWindowSize.restype = ctypes.c_size_t
        library.ZSTD_decompressStream.argtypes = [ctypes.c_void_p, ctypes.POINTER(Buffer), ctypes.POINTER(Buffer)]
        library.ZSTD_decompressStream.restype = ctypes.c_size_t
        library.ZSTD_isError.argtypes = [ctypes.c_size_t]; library.ZSTD_isError.restype = ctypes.c_uint
        self.context = library.ZSTD_createDStream()
        if not self.context: refused()
        self.check(library.ZSTD_initDStream(self.context))
        self.check(library.ZSTD_DCtx_setMaxWindowSize(self.context, 1 << 25))

    def check(self, result):
        if self.library.ZSTD_isError(result): refused()
        return result

    def readable(self): return True

    def readinto(self, output):
        remaining(self.deadline)
        if not self.pending and not self.done:
            raw = self.frame[self.offset:self.offset + 131072]
            if not raw: refused()
            source = ctypes.create_string_buffer(raw); target = ctypes.create_string_buffer(131072)
            incoming = Buffer(ctypes.addressof(source), len(raw), 0)
            outgoing = Buffer(ctypes.addressof(target), len(target), 0)
            result = self.check(self.library.ZSTD_decompressStream(self.context, ctypes.byref(outgoing), ctypes.byref(incoming)))
            if incoming.pos == outgoing.pos == 0: refused()
            self.offset += incoming.pos; self.total += outgoing.pos
            if self.total > 512 * 1024 * 1024: refused()
            self.pending = target.raw[:outgoing.pos]
            self.done = result == 0
            if self.done and self.offset != len(self.frame): refused()
            if not self.pending and not self.done: return self.readinto(output)
        count = min(len(output), len(self.pending)); output[:count] = self.pending[:count]
        self.pending = self.pending[count:]; return count

    def close(self):
        if getattr(self, 'context', None):
            self.library.ZSTD_freeDStream(self.context); self.context = None
        super().close()


def derive(stream, expected, library, deadline):
    """Authenticate the complete outer file before parsing its embedded data."""
    before = identity(os.fstat(stream.fileno()))
    if not 0 < before[2] <= 256 * 1024 * 1024 or not re.fullmatch('[a-f0-9]{64}', expected): refused()
    stream.seek(0); data = stream.read(256 * 1024 * 1024 + 1)
    if len(data) != before[2] or hashlib.sha256(data).hexdigest() != expected: refused()
    if identity(os.fstat(stream.fileno())) != before: refused()
    remaining(deadline)
    assets = set(re.findall(rb'([0-9a-f]{64})\.tar\.zst', data))
    if len(assets) != 1: refused()
    asset = next(iter(assets)).decode()
    library.ZSTD_findFrameCompressedSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    library.ZSTD_findFrameCompressedSize.restype = ctypes.c_size_t
    library.ZSTD_isError.argtypes = [ctypes.c_size_t]; library.ZSTD_isError.restype = ctypes.c_uint
    matches = []; offset = candidates = 0
    while (offset := data.find(b'\x28\xb5\x2f\xfd', offset)) >= 0:
        remaining(deadline); candidates += 1
        if candidates > 32: refused()
        raw = data[offset:]; source = ctypes.create_string_buffer(raw)
        length = library.ZSTD_findFrameCompressedSize(source, len(raw))
        if not library.ZSTD_isError(length) and 0 < length <= 128 * 1024 * 1024:
            frame = raw[:length]
            if hashlib.sha256(frame).hexdigest() == asset: matches.append(frame)
        offset += 4
    if len(matches) != 1: refused()
    core = None; links = {}; seen = set()
    with Archive(library, matches[0], deadline) as raw, io.BufferedReader(raw) as decoded:
        with tarfile.open(fileobj=decoded, mode='r|') as archive:
            for item in archive:
                remaining(deadline)
                name = item.name.removeprefix('./')
                if (len(seen) >= 512 or name in seen or len(name) > 256 or
                        not name or name.startswith('/') or '..' in name.split('/') or
                        name.split('/')[0] not in ('bin', 'etc') or item.pax_headers or
                        not (item.isdir() or item.isfile() or item.issym()) or not 0 <= item.size <= 384 * 1024 * 1024): refused()
                seen.add(name)
                if item.issym():
                    destination = posixpath.normpath(posixpath.join(posixpath.dirname(name), item.linkname))
                    if (item.linkname.startswith('/') or not item.linkname or
                            destination.split('/')[0] not in ('bin', 'etc')): refused()
                    links[name] = item.linkname
                if name == 'bin/k3s':
                    if not item.isfile() or core is not None: refused()
                    member = archive.extractfile(item); result = hashlib.sha256()
                    while chunk := member.read(1024 * 1024):
                        remaining(deadline); result.update(chunk)
                    core = result.hexdigest()
        # Tar terminators do not permit an incomplete zstd frame or hidden suffix.
        while chunk := decoded.read(131072):
            if chunk.strip(b'\0'): refused()
    if not core or links.get('bin/kubectl') != 'k3s' or links.get('bin/k3s-server') != 'k3s': refused()
    if identity(os.fstat(stream.fileno())) != before: refused()
    return {'asset': asset, 'core': core, 'links': {name: links[name] for name in ('bin/kubectl', 'bin/k3s-server')}}


def unique(pairs):
    value = dict(pairs)
    if len(value) != len(pairs): refused()
    return value


def flag_policy(raw):
    value = json.loads(raw, object_pairs_hook=unique)
    if (not isinstance(value, dict) or set(value) != {'apiVersion', 'kind', 'metadata', 'flags'} or
            value['apiVersion'] != 'config.k8s.io/v1beta1' or value['kind'] != 'Flagz' or
            value['metadata'] != {'name': 'apiserver'} or not isinstance(value['flags'], dict) or
            any(type(key) is not str or type(item) is not str or item == 'CLASSIFIED'
                for key, item in value['flags'].items())): refused()
    required = {'audit-log-path': '', 'audit-webhook-config-file': '', 'audit-policy-file': '',
                'v': '0', 'vmodule': '', 'profiling': 'false', 'debug-socket-path': ''}
    if any(value['flags'].get(key) != item for key, item in required.items()): refused()
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): refused()


def unit_policy(raw):
    lines = raw.replace('\\\n', ' ').splitlines(); section = None; values = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'): continue
        if line in ('[Unit]', '[Install]', '[Service]'): section = line; continue
        if not section or '=' not in line: refused()
        key, value = line.split('=', 1)
        values.setdefault((section, key), []).append(value.strip())
    expected = {'[Unit]': {'Description': ['Lightweight Kubernetes'], 'Documentation': ['https://k3s.io'],
                          'Wants': ['network-online.target'], 'After': ['network-online.target']},
        '[Install]': {'WantedBy': ['multi-user.target']},
        '[Service]': {'Type': ['notify'], 'EnvironmentFile': ['-/etc/default/%N', '-/etc/sysconfig/%N',
            '-/etc/systemd/system/k3s.service.env'], 'KillMode': ['process'], 'Delegate': ['yes'], 'User': ['root'],
            'LimitNOFILE': ['1048576'], 'LimitNPROC': ['infinity'], 'LimitCORE': ['infinity'], 'TasksMax': ['infinity'],
            'TimeoutStartSec': ['0'], 'Restart': ['always'], 'RestartSec': ['5s'],
            'ExecStartPre': ['-/sbin/modprobe br_netfilter', '-/sbin/modprobe overlay']}}
    command = values.pop(('[Service]', 'ExecStart'), [])
    if len(command) != 1 or shlex.split(command[0]) != ['/usr/local/bin/k3s', 'server']: refused()
    if values != {(section, key): value for section, fields in expected.items() for key, value in fields.items()}: refused()


def network_unit(raw):
    match = re.fullmatch(r'\[Unit\]\nRequires=wg-quick@([A-Za-z0-9_.-]{1,15})\.service cloudlab-firewall\.service\n'
                         r'After=wg-quick@\1\.service cloudlab-firewall\.service\n', raw)
    if not match: refused()


class Session:
    """One session retains authenticated descriptors, never a persisted custody cache."""
    def __init__(self, deadline):
        self.deadline = deadline; self.stack = ExitStack(); self.files = {}

    def __enter__(self):
        try:
            pins = yaml.safe_load(self.read(Path(__file__).parents[1] / 'vars.yml'))
            architecture = platform.machine()
            if architecture not in pins['k3s_binaries']: refused()
            self.outer = self.hold('/usr/local/bin/k3s', 256 * 1024 * 1024, executable=True)
            library = trusted_library(self.deadline)
            self.hold(library._custody_path, 4 * 1024 * 1024)
            if identity(os.fstat(self.files[library._custody_path][0].fileno())) != library._custody_identity: refused()
            self.package = derive(self.outer, pins['k3s_binaries'][architecture]['sha256'],
                                  library, self.deadline)
            self.base = '/var/lib/rancher/k3s/data/' + self.package['asset']
            self.core = self.hold(self.base + '/bin/k3s', 384 * 1024 * 1024, executable=True)
            if digest(self.core, self.deadline) != self.package['core']: refused()
            self.initial = self.observe()
            return self
        except BaseException:
            self.stack.close(); raise

    def __exit__(self, *args): self.stack.close()

    def hold(self, path, limit=262144, **kwargs):
        path = str(path)
        # Native maintenance may change directories; it cannot redirect trusted files.
        for directory in Path(path).parents:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: refused()
        if path not in self.files:
            stream = self.stack.enter_context(opened(path, limit, **kwargs))
            self.files[path] = (stream, identity(os.fstat(stream.fileno())))
        stream, before = self.files[path]; unchanged(stream, path, before)
        return stream

    def read(self, path):
        stream = self.hold(path); stream.seek(0); return stream.read(262145)

    def dispatch(self):
        values = {}
        directory = Path('/var/lib/rancher/k3s/data/cni')
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: refused()
        values['directory'] = (info.st_dev, info.st_ino)
        for name in ('kubectl', 'k3s-server'):
            shadow = Path('/var/lib/rancher/k3s/data/cni') / name
            if os.path.lexists(shadow): refused()
            link = Path(self.base) / 'bin' / name
            info = link.lstat()
            if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or os.readlink(link) != 'k3s': refused()
            values[name] = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
        return values

    def effective_flags(self, kubeconfig):
        directory = '/var/lib/rancher/k3s/server/tls/'
        ca = self.read(directory + 'server-ca.crt')
        certificate = self.read(directory + 'client-admin.crt')
        key = self.read(directory + 'client-admin.key')
        if any(os.fstat(self.hold(path).fileno()).st_mode & 0o077 for path in (
                directory + 'client-admin.key', '/etc/rancher/k3s/k3s.yaml')): refused()
        if (kubeconfig['clusters'][0]['cluster'] != {'server': 'https://127.0.0.1:6443',
                'certificate-authority-data': base64.b64encode(ca).decode()} or
                kubeconfig['users'][0]['user'] != {'client-certificate-data': base64.b64encode(certificate).decode(),
                                                   'client-key-data': base64.b64encode(key).decode()}): refused()
        context = ssl.create_default_context(cadata=ca.decode())
        context.load_cert_chain('/proc/self/fd/' + str(self.hold(directory + 'client-admin.crt').fileno()),
                                '/proc/self/fd/' + str(self.hold(directory + 'client-admin.key').fileno()))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                              urllib.request.HTTPSHandler(context=context))
        request = urllib.request.Request('https://127.0.0.1:6443/flagz',
            headers={'Accept': 'application/json;v=v1beta1;g=config.k8s.io;as=Flagz'})
        with opener.open(request, timeout=min(5, remaining(self.deadline))) as response:
            if response.status != 200 or response.geturl() != request.full_url: refused()
            raw = response.read(262145)
            if len(raw) > 262144: refused()
        return flag_policy(raw)

    def observe(self):
        remaining(self.deadline)
        if any(os.environ.get(key) for key in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT')): refused()
        preload = preload_state()
        command = ['systemctl', 'show', 'k3s', '--property=ExecStart,MainPID,FragmentPath,DropInPaths,Environment,EnvironmentFiles,NeedDaemonReload',
                   '--no-pager']
        properties = run(command, self.deadline)
        values = dict(line.split('=', 1) for line in properties.splitlines() if '=' in line)
        if (set(values) != {'ExecStart', 'MainPID', 'FragmentPath', 'DropInPaths', 'Environment', 'EnvironmentFiles', 'NeedDaemonReload'} or
                values['NeedDaemonReload'] != 'no' or
                values['DropInPaths'] != '/etc/systemd/system/k3s.service.d/10-cloudlab-network.conf' or
                values['Environment'] or values['FragmentPath'] != '/etc/systemd/system/k3s.service' or
                not re.search(r'path=/usr/local/bin/k3s\s*; argv\[\]=/usr/local/bin/k3s server\s*;', values['ExecStart']) or
                values['ExecStart'].count('path=') != 1 or not values['MainPID'].isdecimal() or int(values['MainPID']) <= 1): refused()
        unit = self.read(values['FragmentPath']).decode()
        unit_policy(unit)
        dropin = self.read(values['DropInPaths']).decode(); network_unit(dropin)
        environment_files = ('/etc/default/k3s', '/etc/sysconfig/k3s', '/etc/systemd/system/k3s.service.env')
        listed = re.findall(r'(/[^ ]+) \(ignore_errors=yes\)', values['EnvironmentFiles'])
        if values['EnvironmentFiles'] != ' '.join(path + ' (ignore_errors=yes)' for path in listed) or tuple(listed) != environment_files: refused()
        optional = {}
        for path in environment_files:
            exists = os.path.lexists(path); optional[path] = exists
            if exists:
                raw = self.read(path)
                if any(line.strip() and not line.lstrip().startswith(b'#') and not line.startswith(b'K3S_TOKEN=')
                       for line in raw.splitlines()): refused()
        pid = values['MainPID']; proc = Path('/proc') / pid
        start = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        executable = str((proc / 'exe').resolve(strict=True))
        if executable != self.base + '/bin/k3s': refused()
        with (proc / 'exe').open('rb') as stream:
            if identity(os.fstat(stream.fileno())) != identity(os.fstat(self.core.fileno())): refused()
        with (proc / 'cmdline').open('rb') as stream: argv = stream.read(65537)
        if len(argv) > 65536 or argv.rstrip(b'\0').strip() not in (b'k3s server', b'/usr/local/bin/k3s server'): refused()
        with (proc / 'environ').open('rb') as stream: environment = stream.read(262145)
        environment_policy(environment)
        configuration = yaml.safe_load(self.read('/etc/rancher/k3s/config.yaml'))
        allowed = {'node-name', 'node-ip', 'flannel-iface', 'write-kubeconfig-mode', 'advertise-address', 'tls-san',
                   'cluster-cidr', 'service-cidr', 'flannel-backend', 'disable'}
        if not isinstance(configuration, dict) or set(configuration) - allowed: refused()
        supplements = Path('/etc/rancher/k3s/config.yaml.d')
        if supplements.exists() and (supplements.is_symlink() or any(supplements.iterdir())): refused()
        kubeconfig = yaml.safe_load(self.read('/etc/rancher/k3s/k3s.yaml'))
        if (not isinstance(kubeconfig, dict) or len(kubeconfig.get('clusters', [])) != 1 or
                len(kubeconfig.get('users', [])) != 1 or len(kubeconfig.get('contexts', [])) != 1): refused()
        cluster, user, context = kubeconfig['clusters'][0], kubeconfig['users'][0], kubeconfig['contexts'][0]
        if (set(cluster) != {'name', 'cluster'} or set(user) != {'name', 'user'} or set(context) != {'name', 'context'} or
                context['context'] != {'cluster': cluster['name'], 'user': user['name']} or
                kubeconfig.get('current-context') != context['name']): refused()
        snapshot = {'unit': unit, 'dropin': dropin, 'process': [pid, start, executable], 'title': argv.hex(),
                    'environment': hashlib.sha256(environment).hexdigest(), 'config': configuration,
                    'dispatch': self.dispatch(), 'optional': optional, 'preload': preload, 'flags': self.effective_flags(kubeconfig)}
        for path in self.files: self.hold(path)
        if (run(command, self.deadline) != properties or
                (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19] != start): refused()
        if hasattr(self, 'initial') and snapshot != self.initial: refused()
        return snapshot
