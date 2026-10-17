"""Independent OCI bootstrap proof; preserve interrupted uploads and immutable digests."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import time
import traceback

from playbooks.infrastructure.files import harbor as api
from automation.harbor import api_policy
from automation.harbor.recovery import atomic
from automation.harbor.registry import Registry
from automation.harbor.node_pull import verify_nodes
from automation.harbor.restore import PYTHON
from playbooks.infrastructure.files.retention import ciphertext
from playbooks.access.files.preflight import ssh

LARGE_LAYER = 256 * 1024**2
PAYLOAD = 'cloudlab-proof/payload.bin'
ROLLBACK_TAGS = tuple('rollback-proof-' + str(number) for number in range(1, 6))


def payload(directory, size, project='cloudlab-public'):
    path = directory / 'payload.bin'
    digest = hashlib.sha256()
    with path.open('wb') as stream:
        remaining = size
        chunk = 0
        while remaining:
            seed = ('cloudlab-harbor-bootstrap-v1:' + project + ':' + str(chunk)).encode()
            data = hashlib.shake_256(seed).digest(min(remaining, 1024**2))
            stream.write(data)
            digest.update(data)
            remaining -= len(data)
            chunk += 1
    layer = directory / 'layer.tar'
    with tarfile.open(layer, 'w') as archive:
        member = tarfile.TarInfo(PAYLOAD)
        member.size, member.mode = size, 0o444
        with path.open('rb') as stream:
            archive.addfile(member, stream)
    return layer, digest.hexdigest()


def verify_payload(archive_path, expected):
    with tarfile.open(archive_path) as archive:
        member = archive.getmember(PAYLOAD)
        if not member.isfile() or member.size != expected['payload_bytes']:
            raise RuntimeError('Pulled OCI payload has another type or size')
        digest = hashlib.sha256()
        with archive.extractfile(member) as stream:
            for data in iter(lambda: stream.read(1024**2), b''):
                digest.update(data)
        if digest.hexdigest() != expected['payload_sha256']:
            raise RuntimeError('Pulled OCI payload differs from the committed upload')


def receipt(path):
    value = json.loads(path.read_text()) if path.exists() else {'recipe': 1, 'base': PYTHON, 'projects': {}}
    if (value.get('recipe') != 1 or value.get('base') != PYTHON or not isinstance(value.get('projects'), dict) or
            set(value['projects']) - set(api_policy.POLICY['projects'])):
        raise ValueError('Preserve the original bootstrap source and artifact receipt')
    for project, entry in value['projects'].items():
        size = LARGE_LAYER if project == 'cloudlab-public' else 1024**2
        if (entry.get('payload_bytes') != size or
                not re.fullmatch(r'sha256:[a-f0-9]{64}', entry.get('digest') or '') or
                not re.fullmatch(r'[a-f0-9]{64}', entry.get('payload_sha256') or '')):
            raise ValueError('Invalid bootstrap artifact receipt; never overwrite remote tags')
        rollback = entry.get('rollback', {})
        if not isinstance(rollback, dict) or set(rollback) - set(ROLLBACK_TAGS):
            raise ValueError('Invalid rollback artifact scope')
        for row in rollback.values():
            if (row.get('payload_bytes') != 4096 or
                    not re.fullmatch(r'sha256:[a-f0-9]{64}', row.get('digest') or '') or
                    not re.fullmatch(r'[a-f0-9]{64}', row.get('payload_sha256') or '')):
                raise ValueError('Invalid rollback artifact receipt; preserve original archives')
        if len({row['digest'] for row in rollback.values()}) != len(rollback):
            raise ValueError('Rollback revisions require distinct digests')
    return value


def rollback_artifacts(registry, credentials, directory, recorded, record, project):
    """Retain five distinct revisions; journal each digest before publishing its immutable tag."""
    rows = record['projects'][project].setdefault('rollback', {})
    repository = registry.reference(project).removesuffix(':deploy-bootstrap')
    for tag in ROLLBACK_TAGS:
        image = directory / (project + '-' + tag + '.tar')
        reference = repository + ':' + tag
        if tag not in rows:
            with tempfile.TemporaryDirectory(dir=directory, prefix='prepare-rollback-') as temporary, registry.identity():
                layer, content = payload(Path(temporary), 4096, project + ':' + tag)
                registry.command('append', '--base', PYTHON, '--new_layer', str(layer), '--new_tag', reference,
                                 '--output', str(image))
                rows[tag] = {'digest': registry.command('digest', '--tarball', str(image)).decode().strip(),
                             'payload_bytes': 4096, 'payload_sha256': content}
                record.pop('verified_at', None)
                atomic(recorded, record)
                receipt(recorded)
        entry = rows[tag]
        with registry.identity(credentials[project + '-push']):
            existing = registry.digest(reference, missing=True)
            if existing is not None and existing != entry['digest']:
                raise RuntimeError('Existing rollback tag changed; preserve its original receipt')
            if existing is None:
                if not image.is_file() or registry.command('digest', '--tarball', str(image)).decode().strip() != entry['digest']:
                    raise RuntimeError('Interrupted rollback upload requires its original archive')
                registry.command('push', str(image), reference)
            if registry.digest(reference) != entry['digest']:
                raise RuntimeError('Published rollback revision differs from its receipt')
        with registry.identity(credentials[project + '-pull']), \
                tempfile.TemporaryDirectory(dir=directory, prefix='pull-rollback-') as temporary:
            exported = Path(temporary) / 'filesystem.tar'
            registry.command('export', registry.reference(project, entry['digest']), str(exported))
            verify_payload(exported, entry)
        image.unlink(missing_ok=True)
    with registry.identity(credentials[project + '-push']):
        probe = repository + ':rollback-immutability-probe'
        existing = registry.digest(probe, missing=True)
        first, second = [rows[tag]['digest'] for tag in ROLLBACK_TAGS[:2]]
        if existing is None:
            registry.command('tag', registry.reference(project, first), 'rollback-immutability-probe')
        elif existing != first:
            raise RuntimeError('Immutability probe changed; preserve recorded deployment and rollback tags')
        registry.command('tag', registry.reference(project, second), 'rollback-immutability-probe', immutable=True)
        if registry.digest(probe) != first:
            raise RuntimeError('Immutable probe digest changed')
        if registry.digest(registry.reference(project)) != record['projects'][project]['digest']:
            raise RuntimeError('Deployment artifact changed during rollback proof')


def run(client):
    client.initialize()
    ciphertext(client.env)
    if api_policy.inventory(json.loads(client.native('show', '-json').stdout)) != client.accepted():
        raise ValueError('Registry artifacts require accepted native resource identities')
    directory = client.path / 'artifacts'
    directory.mkdir(mode=0o700, exist_ok=True)
    recorded = directory / 'receipt.json'
    record = receipt(recorded)
    registry = Registry(client.private['host'], client.env, directory / 'diagnostics.txt')
    for project in api_policy.POLICY['projects']:
        image = directory / (project + '.tar')
        tag = registry.reference(project)
        if project not in record['projects']:
            with tempfile.TemporaryDirectory(dir=directory, prefix='prepare-') as temporary, registry.identity():
                size = LARGE_LAYER if project == 'cloudlab-public' else 1024**2
                layer, content = payload(Path(temporary), size, project)
                registry.command('append', '--base', PYTHON, '--new_layer', str(layer), '--new_tag', tag,
                                 '--output', str(image))
                digest = registry.command('digest', '--tarball', str(image)).decode().strip()
                record['projects'][project] = {'digest': digest, 'payload_bytes': size, 'payload_sha256': content}
                atomic(recorded, record)
                receipt(recorded)
        entry = record['projects'][project]
        with registry.identity(client.private['robots'][project + '-push']):
            existing = registry.digest(tag, missing=True)
            if existing is not None and existing != entry['digest']:
                raise RuntimeError('Existing immutable bootstrap tag has another digest; preserve it')
            if existing is None:
                if not image.is_file() or registry.command('digest', '--tarball', str(image)).decode().strip() != entry['digest']:
                    raise RuntimeError('Interrupted upload requires its original generated OCI archive')
                registry.command('push', str(image), tag)
            if registry.digest(tag) != entry['digest']:
                raise RuntimeError('Pushed OCI digest differs from its preserved local receipt')
        reference = registry.reference(project, entry['digest'])
        with registry.identity(client.private['robots'][project + '-pull']), \
                tempfile.TemporaryDirectory(dir=directory, prefix='pull-') as temporary:
            exported = Path(temporary) / 'filesystem.tar'
            registry.command('export', reference, str(exported))
            verify_payload(exported, entry)
            registry.command('tag', reference, 'denied-push-probe', denied=True)
        other = next(name for name in api_policy.POLICY['projects'] if name != project)
        with registry.identity(client.private['robots'][other + '-push']):
            registry.command('manifest', reference, denied=True)
        with registry.identity(client.private['robots'][project + '-push']):
            registry.command('copy', reference, registry.host + '/' + other + '/bootstrap:denied-cross-project-probe',
                             denied=True)
        with registry.identity():
            registry.command('manifest', reference, denied=True)
        rollback_artifacts(registry, client.private['robots'], directory, recorded, record, project)
    node_pulls = verify_nodes(client, record)
    record['verified_at'] = time.time()
    atomic(recorded, record)
    for project in api_policy.POLICY['projects']:
        (directory / (project + '.tar')).unlink(missing_ok=True)
    return {'independent_bootstrap': True, 'large_layer_bytes': LARGE_LAYER, 'project_push_pull': 2,
            'pull_robot_push_denied': True, 'cross_project_denied': True, 'cross_project_write_denied': True,
            'anonymous_denied': True,
            'node_digest_pulls': node_pulls, 'rollback_digests_verified': 2 * len(ROLLBACK_TAGS),
            'immutable_overwrite_denied': True, 'interactive_login_used': False, 'arc_used': False}


def deployment_proof(client, action):
    if client.plan(verify=True)['changes'] != 0:
        raise ValueError('Accept the unchanged Harbor root before Deployment preservation checks')
    record = receipt(client.path / 'artifacts/receipt.json')
    if not record.get('verified_at') or any(set(row.get('rollback', {})) != set(ROLLBACK_TAGS)
            for row in record['projects'].values()) or set(record['projects']) != set(api_policy.POLICY['projects']):
        raise ValueError('Complete all independent digest artifacts before native Deployment rollback')
    document = {project: [{key: entry[key] for key in ('digest', 'payload_bytes', 'payload_sha256')}
                         for entry in (row, *[row['rollback'][tag] for tag in ROLLBACK_TAGS])]
                for project, row in record['projects'].items()}
    if action not in ('prepare', 'cleanup'):
        raise ValueError('Unknown Deployment fixture operation')
    result = json.loads(ssh('VM', client.values['VM_HOST'],
        'python3 /opt/cloudlab/automation/harbor/deployments.py ' + action,
        input=json.dumps(document) if action == 'prepare' else '', timeout=9000))
    if action == 'prepare' and (result.get('active') is not True or result.get('rollback_replicasets') != 10):
        raise RuntimeError('Native Harbor Deployment history proof is incomplete')
    return result


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--deployments', action='store_true')
    group.add_argument('--cleanup-deployments', action='store_true')
    arguments = parser.parse_args()
    os.umask(0o077)
    api.WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        client = api.Client()
        with client.connected():
            result = (deployment_proof(client, 'cleanup' if arguments.cleanup_deployments else 'prepare')
                      if arguments.deployments or arguments.cleanup_deployments else run(client))
            print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        diagnostics = api.WORK / 'artifacts/diagnostics.txt'
        try:
            if diagnostics.parent.is_dir():
                with diagnostics.open('ab') as stream:
                    stream.write((json.dumps({'exception': type(error).__name__, 'frames': [
                        {'file': Path(frame.filename).name, 'line': frame.lineno}
                        for frame in traceback.extract_tb(error.__traceback__)]}) + '\n').encode())
        except OSError:
            pass
        raise SystemExit('OCI bootstrap proof incomplete; original artifact receipts and private diagnostics retained') from None
