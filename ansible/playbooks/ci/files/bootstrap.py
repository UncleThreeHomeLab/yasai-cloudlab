"""Publish locally built, scanned tool archives without ARC or a Docker socket."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess

from playbooks.harbor.files.recovery import atomic
from playbooks.harbor.files.registry import Registry
from playbooks.infrastructure.files import harbor as api

ROOT = Path(__file__).resolve().parents[4]
KINDS = ('controller', 'runner', 'builder')
PROJECT = 'cloudlab-public'
SCAN = json.loads((ROOT / 'platform/delivery/ci/scan.lock.json').read_text())


def prepare(archives, directory):
    """Scan every archive before loading registry or backend credentials."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    tools = Registry('harbor.internal.example.invalid', environment, directory / 'diagnostics.txt')
    cache = directory / ('trivy-' + SCAN['database'].rsplit(':', 1)[1])
    images = {}
    for kind in KINDS:
        archive = archives / (kind + '.tar')
        if archive.is_symlink() or not archive.is_file():
            raise ValueError('All three original local image archives are required')
        digest = tools.command('digest', '--tarball', str(archive)).decode().strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise ValueError('Bootstrap archive has an invalid native image digest')
        report = directory / (kind + '-scan.json')
        result = subprocess.run(['trivy', 'image', '--quiet', '--no-progress', '--config', '/dev/null',
            '--ignorefile', '/dev/null', '--ignore-unfixed=false', '--input', str(archive),
            '--timeout', '15m', '--parallel', '2',
            '--cache-dir', str(cache), '--db-repository', SCAN['database'], '--offline-scan',
            '--skip-java-db-update', '--scanners', 'vuln', '--severity', ','.join(SCAN['severities']),
            '--exit-code', '1', '--format', 'json', '--output', str(report)], env=environment,
            capture_output=True, timeout=1800)
        if result.returncode:
            with (directory / 'diagnostics.txt').open('ab') as output:
                output.write(result.stdout + result.stderr)
            raise RuntimeError('Tool image scan failed; no registry publication')
        document = json.loads(report.read_text())
        if (document.get('SchemaVersion') != 2 or document.get('ArtifactType') != 'container_image' or
                not document.get('Results') or any(row.get('Vulnerabilities') for row in document['Results'])):
            raise ValueError('Tool image requires a complete scan without HIGH or CRITICAL findings')
        if tools.command('digest', '--tarball', str(archive)).decode().strip() != digest:
            raise ValueError('Bootstrap archive changed while it was scanned')
        images[kind] = digest
    return images


def publish(client, archives, images):
    """Preserve immutable publications and the original interruption receipt."""
    if set(images) != set(KINDS) or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', value) for value in images.values()):
        raise ValueError('Publication requires exactly three scanned tool digests')
    if client.plan(verify=True)['changes']:
        raise ValueError('Resolve native Harbor API drift before publishing bootstrap images')
    directory = client.path / 'ci' / client.revision
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt = directory / 'receipt.json'
    record = {'revision': client.revision, 'database': SCAN['database'], 'images': images}
    if receipt.exists():
        if json.loads(receipt.read_text()) != record:
            raise ValueError('Preserve original bootstrap archives; publication inputs changed')
    else:
        atomic(receipt, record)
    registry = Registry(client.private['host'], client.env, directory / 'diagnostics.txt')
    references = {}
    for kind in KINDS:
        digest = images[kind]
        options = {'repository': 'ci-' + kind, 'tag': 'release-' + digest.replace(':', '-')}
        tag = registry.reference(PROJECT, **options)
        reference = registry.reference(PROJECT, digest, **options)
        with registry.identity(client.private['robots'][PROJECT + '-push']):
            existing = registry.digest(tag, missing=True)
            if existing is not None and existing != digest:
                raise ValueError('Existing immutable bootstrap tag differs; preserve original artifact')
            if existing is None:
                archive = archives / (kind + '.tar')
                if registry.command('digest', '--tarball', str(archive)).decode().strip() != digest:
                    raise ValueError('Publication requires its original scanned archive')
                registry.command('push', str(archive), tag)
            if registry.digest(tag) != digest:
                raise RuntimeError('Published tool image differs from its scanned digest')
        with registry.identity(client.private['robots'][PROJECT + '-pull']):
            if registry.digest(reference) != digest:
                raise RuntimeError('Public project pull robot cannot obtain the published tool')
        references[kind] = reference
    atomic(client.path / 'ci/images.json', {'revision': client.revision, 'images': references})
    return {'published_tools': len(references), 'scanned_severities': SCAN['severities'],
            'arc_used': False, 'docker_socket_used': False, 'robot_mutations': 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archives', type=Path, default=ROOT / '.infra-private/ci')
    parser.add_argument('--scan-only', action='store_true')
    arguments = parser.parse_args()
    os.umask(0o077)
    api.WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        images = prepare(arguments.archives, api.WORK / 'ci/scans')
        if arguments.scan_only:
            print(json.dumps({'scanned_tools': len(images), 'service_credentials_used': False}))
            return
        client = api.Client()
        with client.connected():
            print(json.dumps(publish(client, arguments.archives, images), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('CI bootstrap incomplete; original archives, receipts and protected diagnostics retained') from None
