"""Online SQLite capture and bounded, self-verifying recovery archive."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import time
from contextlib import closing

SERVER = Path('var/lib/rancher/k3s/server')
DATABASE = SERVER / 'db/state.db'
REQUIRED = [SERVER / 'token', SERVER / 'tls', SERVER / 'cred', Path('etc/rancher/k3s/config.yaml')]
OPTIONAL = [SERVER / 'agent-token', SERVER / 'manifests', Path('etc/rancher/node/password'),
            Path('etc/rancher/k3s/config.yaml.d'),
            Path('etc/systemd/system/k3s.service'), Path('etc/systemd/system/k3s.service.env'),
            Path('etc/systemd/system/k3s.service.d')]


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require_active_sqlite():
    pid = subprocess.check_output(['systemctl', 'show', 'k3s', '--property=MainPID', '--value'], text=True).strip()
    if not pid.isdigit() or pid == '0':
        raise RuntimeError('K3s server is not running; actual datastore cannot be verified')
    expected = (Path('/') / DATABASE).resolve()
    descriptors = Path('/proc') / pid / 'fd'
    if not any(path.resolve() == expected for path in descriptors.iterdir()):
        raise RuntimeError('Running K3s does not have the declared SQLite datastore open')


def inventory(root):
    paths = []
    for relative in REQUIRED + OPTIONAL:
        path = root / relative
        if not path.exists():
            if relative in REQUIRED:
                raise RuntimeError('Required K3s recovery state is missing')
            continue
        entries = sorted(path.rglob('*')) if path.is_dir() else [path]
        for entry in entries:
            if entry.is_file():
                # K3s token aliases may be symlinks. Archive their contents only.
                if not entry.resolve().is_relative_to(root.resolve()):
                    raise RuntimeError('Recovery input symlink escapes the source root')
                paths.append(entry.relative_to(root))
    return {str(p): digest(root / p) for p in paths}


def sqlite_copy(source, target, limit, timeout=600):
    deadline = time.monotonic() + timeout
    with closing(sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True)) as live:
        page_size = live.execute('PRAGMA page_size').fetchone()[0]
        def progress(status, remaining, total):
            if time.monotonic() > deadline or total * page_size > limit:
                raise RuntimeError('SQLite online backup exceeds time or staging bound')
        with closing(sqlite3.connect(target)) as backup:
            live.backup(backup, pages=256, progress=progress, sleep=0.05)
            if backup.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise RuntimeError('SQLite backup integrity check failed')


class BoundedFile:
    def __init__(self, path, limit):
        self.file = open(path, 'wb')
        self.limit = limit
        self.count = 0
    def write(self, data):
        self.count += len(data)
        if self.count > self.limit:
            raise RuntimeError('Compressed recovery archive exceeds admission limit')
        return self.file.write(data)
    def flush(self):
        self.file.flush()


def capture(root, staging, policy, version):
    """Caller owns a locked disposable staging directory. Never stop K3s."""
    if (root / SERVER / 'db/etcd').exists():
        raise RuntimeError('Embedded etcd detected; this procedure requires SQLite')
    if not (root / DATABASE).is_file():
        raise RuntimeError('SQLite datastore missing; refusing an assumed datastore')
    before = inventory(root)
    source_bytes = sum((root / p).stat().st_size for p in before) + (root / DATABASE).stat().st_size
    if source_bytes > policy['max_source_bytes']:
        raise RuntimeError('Recovery source exceeds staging admission limit')
    usage = shutil.disk_usage(staging)
    # Source, archive, restored archive and validation copy must all fit.
    reserve = policy['staging_ceiling_bytes']
    if usage.free - reserve < usage.total * policy['minimum_free_fraction']:
        raise RuntimeError('Recovery staging would breach the filesystem free-space floor')
    tree = staging / 'generation'
    tree.mkdir(mode=0o700)
    target_db = tree / DATABASE
    target_db.parent.mkdir(parents=True, mode=0o700)
    sqlite_copy(root / DATABASE, target_db, policy['max_source_bytes'] - sum(
        (root / p).stat().st_size for p in before))
    copied = target_db.stat().st_size
    for relative in before:
        source = root / relative
        copied += source.stat().st_size
        if copied > policy['max_source_bytes']:
            raise RuntimeError('Recovery state grew beyond staging admission limit')
        target = tree / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with source.open('rb') as src, target.open('wb') as dst:
            remaining = policy['max_source_bytes'] - (copied - source.stat().st_size)
            while chunk := src.read(min(1024 * 1024, remaining + 1)):
                remaining -= len(chunk)
                if remaining < 0:
                    raise RuntimeError('Recovery file grew beyond admission limit')
                dst.write(chunk)
        target.chmod(0o600)
    if inventory(root) != before or any(digest(tree / p) != h for p, h in before.items()):
        raise RuntimeError('K3s token/CA/configuration changed during capture; retry in the window')
    hashes = dict(before, **{str(DATABASE): digest(target_db)})
    manifest = {'format': 1, 'datastore': 'sqlite-online-backup', 'k3s_version': version,
                'captured_at': time.time(), 'files': hashes, 'source_bytes': copied}
    (tree / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True))
    archive = staging / 'recovery.tar.gz'
    writer = BoundedFile(archive, policy['max_archive_bytes'])
    try:
        with tarfile.open(fileobj=writer, mode='w|gz', dereference=True) as tar:
            for path in sorted(tree.rglob('*')):
                if path.is_file():
                    tar.add(path, arcname=str(path.relative_to(tree)), recursive=False)
    finally:
        writer.file.close()
    shutil.rmtree(tree)
    return manifest


def verify_archive(archive, destination, policy):
    """Extract only regular, bounded files; check every byte and SQLite offline."""
    destination.mkdir(mode=0o700)
    total = 0
    names = set()
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar:
            path = Path(member.name)
            if not member.isfile() or path.is_absolute() or '..' in path.parts or member.name in names:
                raise RuntimeError('Unsafe or duplicate recovery archive member')
            names.add(member.name)
            total += member.size
            if total > policy['max_source_bytes'] + 1024 * 1024:
                raise RuntimeError('Recovery archive exceeds extraction bound')
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tar.extractfile(member) as src, target.open('wb') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            target.chmod(0o600)
    manifest = json.loads((destination / 'manifest.json').read_text())
    if manifest['format'] != 1 or manifest['datastore'] != 'sqlite-online-backup':
        raise RuntimeError('Unsupported recovery manifest')
    if names != set(manifest['files']) | {'manifest.json'}:
        raise RuntimeError('Recovery manifest does not cover the complete archive')
    required = {str(DATABASE), str(SERVER / 'token'), 'etc/rancher/k3s/config.yaml'}
    if not required.issubset(names) or not any('/tls/' in p for p in names) or not any('/cred/' in p for p in names):
        raise RuntimeError('Recovery archive lacks required datastore/token/CA/state')
    for relative, expected in manifest['files'].items():
        if digest(destination / relative) != expected:
            raise RuntimeError('Recovery file checksum mismatch')
    with closing(sqlite3.connect((destination / DATABASE).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
        if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise RuntimeError('Retrieved SQLite integrity check failed')
    return manifest
