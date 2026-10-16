"""Independent OCI bootstrap proof; preserve interrupted uploads and immutable digests."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import time

from automation.harbor import api, api_policy
from automation.harbor.recovery import atomic
from automation.harbor.registry import Registry
from automation.harbor.node_pull import verify_nodes
from automation.harbor.restore import PYTHON
from automation.infra.retention import ciphertext

LARGE_LAYER = 256 * 1024**2
PAYLOAD = 'cloudlab-proof/payload.bin'


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
    return value


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
        with registry.identity():
            registry.command('manifest', reference, denied=True)
    node_pulls = verify_nodes(client, record)
    record['verified_at'] = time.time()
    atomic(recorded, record)
    for project in api_policy.POLICY['projects']:
        (directory / (project + '.tar')).unlink(missing_ok=True)
    return {'independent_bootstrap': True, 'large_layer_bytes': LARGE_LAYER, 'project_push_pull': 2,
            'pull_robot_push_denied': True, 'cross_project_denied': True, 'anonymous_denied': True,
            'node_digest_pulls': node_pulls, 'interactive_login_used': False, 'arc_used': False}


def main():
    os.umask(0o077)
    api.WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        client = api.Client()
        with client.connected():
            print(json.dumps(run(client), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('OCI bootstrap proof incomplete; original artifact receipts and private diagnostics retained') from None
