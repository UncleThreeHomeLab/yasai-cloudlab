"""Publish locally built, scanned tool archives without ARC or a Docker socket."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

import yaml

from playbooks.harbor.files.recovery import atomic
from playbooks.harbor.files.registry import Registry
from playbooks.infrastructure.files import harbor as api

ROOT = Path(__file__).resolve().parents[4]
KINDS = ('controller', 'runner', 'builder')
PROJECT = 'cloudlab-public'
SCAN = json.loads((ROOT / 'platform/delivery/ci/scan.lock.json').read_text())
SHA = r'[a-f0-9]{40}'
DIGEST = r'sha256:[a-f0-9]{64}'


def scan_archive(archive, directory, name):
    """Scan with the fixed policy before any registry or backend credentials."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    tools = Registry('harbor.internal.example.invalid', environment, directory / 'diagnostics.txt')
    cache = directory / ('trivy-' + SCAN['database'].rsplit(':', 1)[1])
    if archive.is_symlink() or not archive.is_file():
        raise ValueError('Original local image archive is required')
    digest = tools.command('digest', '--tarball', str(archive)).decode().strip()
    if not re.fullmatch(DIGEST, digest):
        raise ValueError('Bootstrap archive has an invalid native image digest')
    report = directory / (name + '-scan.json')
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
    return digest


def prepare(archives, directory):
    """Scan every archive before loading registry or backend credentials."""
    images = {}
    for kind in KINDS:
        archive = archives / (kind + '.tar')
        if archive.is_symlink() or not archive.is_file():
            raise ValueError('All three original local image archives are required')
        images[kind] = scan_archive(archive, directory, kind)
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


def local_path(path):
    path = Path(path)
    if '..' in path.parts:
        raise ValueError('Environment paths cannot contain parent traversal')
    path = path.absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError('Environment inputs and outputs cannot follow symlinks')
    return path.resolve()


def environment_application(path):
    from playbooks.argocd.files.github_setup import repository
    path = local_path(path)
    if not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('Environment publication requires a bounded application input')
    value = json.loads(path.read_text(encoding='utf-8'))
    required = {'name', 'repository', 'visibility'}
    if (not isinstance(value, dict) or not required <= set(value) or
            set(value) - required - {'testing', 'components', 'primaryComponent', 'releaseRepository', 'releaseMode'} or
            not isinstance(value.get('name'), str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,34}', value['name']) or
            not isinstance(value.get('repository'), str) or
            not re.fullmatch(r'https://github[.]com/[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*[.]git',
                             value.get('repository', '')) or value.get('visibility') != 'public' or
            ('testing' in value and not isinstance(value['testing'], dict))):
        raise ValueError('Environment producer requires an approved public application identity')
    if value.get('releaseMode', 'automatic') not in ('automatic', 'manual') or (
            value.get('releaseMode') == 'manual' and 'releaseRepository' not in value):
        raise ValueError('Manual promotion requires an explicit private release target')
    if 'components' in value or 'primaryComponent' in value:
        from playbooks.ci.files.publisher import component_configuration
        component_configuration(value.get('components'), value.get('primaryComponent'))
    if 'releaseRepository' in value and (not isinstance(value['releaseRepository'], str) or
            not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', value['releaseRepository']) or
            value['releaseRepository'].split('/')[0].lower() != repository(value['repository']).split('/')[0].lower()):
        raise ValueError('Environment application requires a same-organization release repository')
    return value


def environment_metadata(archive, application):
    """Read Docker save metadata without extracting archive members."""
    archive = local_path(archive)
    if not archive.is_file() or not 0 < archive.stat().st_size <= 16 * 1024 ** 3:
        raise ValueError('Environment publication requires a bounded Docker save archive')
    with tarfile.open(archive, 'r:') as bundle:
        members = []
        for member in bundle:
            if len(members) >= 4096:
                raise ValueError('Environment archive contains too many metadata members')
            members.append(member)
        def read(name):
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or any(ord(char) < 32 for char in name):
                raise ValueError('Environment archive has an unsafe metadata path')
            matches = [member for member in members if member.name == name]
            if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= 1024 * 1024:
                raise ValueError('Environment archive metadata is missing, duplicated or oversized')
            return bundle.extractfile(matches[0]).read()
        manifest = json.loads(read('manifest.json'))
        if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
            raise ValueError('Environment archive must contain exactly one image')
        config_name = manifest[0].get('Config')
        if not isinstance(config_name, str):
            raise ValueError('Environment archive lacks its image configuration')
        config = read(config_name)
        config_digest = PurePosixPath(config_name).name.removesuffix('.json')
        if (not re.fullmatch(r'[a-f0-9]{64}', config_digest) or
                hashlib.sha256(config).hexdigest() != config_digest):
            raise ValueError('Environment archive configuration digest differs')
        value = json.loads(config)
    if not isinstance(value, dict) or not isinstance(value.get('config'), dict):
        raise ValueError('Environment archive has an invalid image configuration')
    labels = value['config'].get('Labels') or {}
    if not isinstance(labels, dict):
        raise ValueError('Environment archive has invalid source labels')
    revision = labels.get('org.opencontainers.image.revision', '')
    if (value.get('os') != 'linux' or value.get('architecture') != 'amd64' or
            labels.get('org.opencontainers.image.source') != application['repository'].removesuffix('.git') or
            not isinstance(revision, str) or not re.fullmatch(SHA, revision)):
        raise ValueError('Environment archive platform or source labels differ from the application')
    return {'source_revision': revision, 'source_repository': application['repository']}


def environment_source(checkout, application, metadata, github):
    """Bind trusted local archive labels to the current protected source main."""
    checkout = local_path(checkout)
    if not checkout.is_dir() or not (checkout / '.git').is_dir() or (checkout / '.git').is_symlink():
        raise ValueError('Environment source requires a normal Git checkout')
    environment = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    def git(*arguments):
        result = subprocess.run(['git', '-c', 'safe.directory=' + str(checkout), '-c', 'core.fsmonitor=false',
                                 *arguments], cwd=checkout, env=environment, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('Environment source Git inspection failed')
        return result.stdout.decode('utf-8').strip()
    if (git('branch', '--show-current') != 'main' or git('status', '--porcelain', '--untracked-files=all') or
            git('rev-parse', 'HEAD') != metadata['source_revision'] or
            git('config', '--get', 'remote.origin.url') != application['repository']):
        raise ValueError('Environment source must be the clean declared main checkout')
    from playbooks.argocd.files.github_setup import repository
    name = repository(application['repository'])
    owner = repository(yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']).split('/')[0]
    if name.split('/')[0].lower() != owner.lower():
        raise ValueError('Environment application must belong to the platform organization')
    current = github.request('GET', 'repos/' + name)
    branch = github.request('GET', 'repos/' + name + '/branches/main')
    if (not isinstance(current, dict) or not isinstance(branch, dict) or
            current.get('full_name') != name or current.get('visibility') != 'public' or current.get('private') is not False or
            current.get('fork') or current.get('archived') or current.get('disabled') or
            current.get('default_branch') != 'main' or branch.get('protected') is not True or
            branch.get('commit', {}).get('sha') != metadata['source_revision']):
        raise ValueError('Environment source is not the current protected public main')


def environment_output(path):
    path = local_path(path)
    local_path(path.with_suffix('.tmp'))
    if not any(path.is_relative_to(root.resolve()) for root in (api.WORK, ROOT / '.infra-private')):
        raise ValueError('Environment reference output must remain in ignored or protected storage')
    if path.exists() and not path.is_file():
        raise ValueError('Environment reference output must be a regular file')
    return path


def environment_record(path, value, *, write=False):
    for candidate in (local_path(path), local_path(path.with_suffix('.tmp'))):
        if candidate.exists() and (not candidate.is_file() or json.loads(candidate.read_text()) != value):
            raise ValueError('Preserve original environment publication record')
    if write and not path.exists():
        atomic(path, value)


def publish_environment(client, archive, application, metadata, digest, output=None):
    if (not isinstance(digest, str) or not re.fullmatch(DIGEST, digest) or
            not isinstance(application.get('name'), str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,34}', application['name']) or
            application.get('visibility') != 'public' or set(metadata) != {'source_revision', 'source_repository'} or
            not isinstance(metadata['source_revision'], str) or not re.fullmatch(SHA, metadata['source_revision']) or
            metadata['source_repository'] != application.get('repository')):
        raise ValueError('Environment publication requires its scanned image digest')
    if client.plan(verify=True)['changes']:
        raise ValueError('Resolve native Harbor API drift before publishing an environment')
    directory = client.path / 'ci/environments' / application['name'] / metadata['source_revision']
    directory = local_path(directory)
    output = environment_output(output or directory / 'reference.json')
    registry = Registry(client.private['host'], client.env, directory / 'diagnostics.txt')
    options = {'repository': application['name'] + '-test-environment', 'tag': 'release-' + digest.replace(':', '-')}
    tag = registry.reference(PROJECT, **options)
    reference = registry.reference(PROJECT, digest, **options)
    value = {'image': reference}
    environment_record(output, value)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt = directory / 'receipt.json'
    record = dict(metadata, application=application['name'], database=SCAN['database'], digest=digest)
    environment_record(receipt, record, write=True)
    if registry.command('digest', '--tarball', str(archive)).decode().strip() != digest:
        raise ValueError('Environment archive changed after scanning')
    with registry.identity(client.private['robots'][PROJECT + '-push']):
        existing = registry.digest(tag, missing=True)
        if existing is not None and existing != digest:
            raise ValueError('Existing immutable environment tag differs')
        if existing is None:
            registry.command('push', str(archive), tag)
        if registry.digest(tag) != digest:
            raise RuntimeError('Published environment differs from its scanned digest')
    with registry.identity(client.private['robots'][PROJECT + '-pull']):
        if registry.digest(reference) != digest:
            raise RuntimeError('Public project pull robot cannot obtain the environment')
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment_record(output, value, write=True)
    return {'published_environments': 1, 'scanned_severities': SCAN['severities'],
            'arc_used': False, 'docker_socket_used': False, 'robot_mutations': 0}


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--archives', type=Path, default=ROOT / '.infra-private/ci')
    mode.add_argument('--test-environment-archive', type=Path)
    parser.add_argument('--application-file', type=Path)
    parser.add_argument('--source-checkout', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--scan-only', action='store_true')
    arguments = parser.parse_args()
    if arguments.test_environment_archive:
        if not arguments.application_file or (not arguments.scan_only and not arguments.source_checkout):
            parser.error('Environment publication requires an application and its main source checkout')
    elif arguments.application_file or arguments.source_checkout or arguments.output:
        parser.error('Environment inputs require --test-environment-archive')
    if arguments.output:
        arguments.output = environment_output(arguments.output)
    os.umask(0o077)
    api.WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if arguments.test_environment_archive:
            application = environment_application(arguments.application_file)
            archive = local_path(arguments.test_environment_archive)
            metadata = environment_metadata(archive, application)
            digest = scan_archive(archive, api.WORK / 'ci/environment-scans', application['name'])
            if arguments.scan_only:
                print(json.dumps({'scanned_environments': 1, 'service_credentials_used': False}))
                return
            from playbooks.argocd.files.github_setup import inputs
            _, github = inputs()
            environment_source(arguments.source_checkout, application, metadata, github)
            client = api.Client()
            with client.connected():
                print(json.dumps(publish_environment(client, archive, application, metadata, digest,
                                                      arguments.output), sort_keys=True))
            return
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
