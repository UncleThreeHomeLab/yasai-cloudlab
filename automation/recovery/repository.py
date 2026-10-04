"""Encrypted restic repository operations with a strict cloud-write window."""
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import time
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'longhorn'))
from write_window import require_window, initial_active, replacement_active, REPLACEMENT_TAG
from capture import digest, verify_archive

FIELDS = ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_ENDPOINT', 'BUCKET',
          'REGION', 'PREFIX', 'RESTIC_PASSWORD')


def environment(values):
    if any(not values.get(key) for key in FIELDS):
        raise RuntimeError('Incomplete recovery credentials')
    endpoint = urllib.parse.urlsplit(values['AWS_ENDPOINT'])
    if (endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.query
            or endpoint.path not in ('', '/') or not endpoint.hostname.endswith('.backblazeb2.com')):
        raise RuntimeError('Recovery requires an HTTPS B2 S3 endpoint')
    prefix = json.loads(Path(__file__).with_name('policy.json').read_text())['prefix']
    if values['PREFIX'] != prefix or '/' in values['BUCKET']:
        raise RuntimeError('Recovery requires its separate k3s-restic/ repository prefix')
    env = dict(os.environ)
    # Never inherit a repository/password/backend override from the caller.
    for key in list(env):
        if key.startswith(('RESTIC_', 'AWS_', 'B2_')):
            del env[key]
    env.update(AWS_ACCESS_KEY_ID=values['AWS_ACCESS_KEY_ID'],
               AWS_SECRET_ACCESS_KEY=values['AWS_SECRET_ACCESS_KEY'],
               AWS_DEFAULT_REGION=values['REGION'], RESTIC_PASSWORD=values['RESTIC_PASSWORD'],
               RESTIC_REPOSITORY='s3:' + values['AWS_ENDPOINT'].rstrip('/') + '/' + values['BUCKET'] + '/' + values['PREFIX'])
    return env


class Repository:
    def __init__(self, values):
        self.values = values
        self.env = environment(values)

    def run(self, *args, write=False, cwd=None, missing_ok=False):
        timeout = max(1, require_window(reserve=60) - 30) if write else 7200
        command = ['restic', '--no-cache'] + ([] if write else ['--no-lock']) + list(args)
        try:
            result = subprocess.run(command, env=self.env, cwd=cwd, capture_output=True,
                                    text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Restic operation timed out; no off-window cleanup attempted') from None
        if missing_ok and result.returncode == 10:
            return None
        if result.returncode:
            raise RuntimeError('Restic operation failed: ' + args[0] + ' (private diagnostics suppressed)')
        return result.stdout

    def snapshots(self):
        return json.loads(self.run('snapshots', '--json'))

    def initialize(self):
        if self.run('cat', 'config', missing_ok=True) is None:
            self.run('init', '--repository-version', '2', write=True)

    def retrieve(self, snapshot, target, policy, expected=None):
        started = time.monotonic()
        listing = [json.loads(line) for line in self.run('ls', snapshot, '--json').splitlines()]
        files = [row for row in listing if row.get('type') == 'file']
        if (len(files) != 1 or files[0].get('path') != '/recovery.tar.gz'
                or files[0].get('size', policy['max_archive_bytes'] + 1) > policy['max_archive_bytes']):
            raise RuntimeError('Repository snapshot exceeds the declared retrieval scope')
        self.run('restore', snapshot, '--target', str(target), '--verify')
        archive = target / 'recovery.tar.gz'
        if archive.stat().st_size > policy['max_archive_bytes']:
            raise RuntimeError('Retrieved archive exceeds admission limit')
        if expected and digest(archive) != expected:
            raise RuntimeError('Retrieved archive checksum differs from captured generation')
        manifest = verify_archive(archive, target / 'validated', policy)
        return manifest, round(time.monotonic() - started, 2)

    def export(self, staging, policy, reader):
        require_window(reserve=3600)
        from b2 import S3
        writer_s3 = S3(self.values)
        self.initialize()
        snapshots = self.snapshots()
        if initial_active() and any('verified' in s.get('tags', []) for s in snapshots):
            raise RuntimeError('Initial exception already consumed by a verified snapshot; use monthly recovery')
        if any(policy['tag'] not in s.get('tags', []) for s in snapshots):
            raise RuntimeError('Repository contains unrelated snapshots; refusing retention')
        # Resume an interrupted replacement without accumulating a third generation.
        verified = [s for s in snapshots if 'verified' in s.get('tags', [])]
        keep_previous = max(verified, key=lambda s: s['time']) if verified else None
        replacement_test = replacement_active()
        if replacement_test and (not keep_previous or any(REPLACEMENT_TAG in s.get('tags', []) and 'verified' in s.get('tags', []) for s in snapshots)):
            raise RuntimeError('Replacement test requires a previous generation and an unused exception')
        if keep_previous:
            reader.retrieve(keep_previous['id'], staging / 'previous-verified', policy)
            shutil.rmtree(staging / 'previous-verified')
        abandoned = [s['id'] for s in snapshots if not keep_previous or s['id'] != keep_previous['id']]
        if abandoned:
            if keep_previous:
                reader.retrieve(keep_previous['id'], staging / 'resumed', policy)
                shutil.rmtree(staging / 'resumed')
            self.run('forget', *abandoned, write=True)
            self.run('prune', write=True)
        existing_bytes = writer_s3.cleanup()
        if existing_bytes > policy['max_archive_bytes'] * 1.1:
            raise RuntimeError('Recovery repository exceeds the retained budget; review before another export')
        archive = staging / 'recovery.tar.gz'
        generation = 'generation-' + digest(archive)
        output = self.run('backup', 'recovery.tar.gz', '--host', 'cloudlab-control-plane',
                          '--tag', policy['tag'], '--tag', generation, '--json', write=True, cwd=staging)
        summaries = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
        snapshot = next(row['snapshot_id'] for row in summaries if row.get('message_type') == 'summary')
        if keep_previous and keep_previous['id'] not in {s['id'] for s in self.snapshots()}:
            raise RuntimeError('Previous verified generation disappeared during upload')
        self.run('check', '--read-data', write=True)
        # Read-only commands must decrypt and retrieve before retention. The
        # operator-selected shared credential still has write/delete capability.
        manifest, seconds = reader.retrieve(snapshot, staging / 'retrieved', policy, digest(archive))
        if keep_previous and keep_previous['id'] not in {s['id'] for s in self.snapshots()}:
            raise RuntimeError('Previous verified generation disappeared before replacement verification')
        tags = 'verified,' + REPLACEMENT_TAG if replacement_test else 'verified'
        self.run('tag', '--add', tags, snapshot, write=True)
        snapshots = self.snapshots()
        retained = [s for s in snapshots if generation in s.get('tags', []) and 'verified' in s.get('tags', [])]
        if len(retained) != 1:
            raise RuntimeError('Cannot identify the verified replacement snapshot')
        keep = retained[0]['id']
        old = [s['id'] for s in snapshots if s['id'] != keep]
        if old:
            self.run('forget', *old, write=True)
        self.run('prune', write=True)
        self.run('check', '--read-data', write=True)
        retained_bytes = writer_s3.cleanup()
        if retained_bytes > policy['max_archive_bytes'] * 1.1:
            raise RuntimeError('Recovery repository exceeds its payload and metadata budget')
        final = self.snapshots()
        if len(final) != 1 or final[0]['id'] != keep:
            raise RuntimeError('Retention did not leave exactly one verified replacement')
        return {'retention_proof': REPLACEMENT_TAG if replacement_test else None,
                'previous_verified': bool(keep_previous),
                'previous_preserved_until_verified': bool(keep_previous),
                'retained_generations': len(final), 'snapshot': keep, 'captured_at': manifest['captured_at'], 'verified_at': time.time(),
                'retrieval_seconds': seconds, 'archive_bytes': archive.stat().st_size,
                'repository_bytes': retained_bytes,
                'sha256': digest(archive), 'retention_complete': True}
