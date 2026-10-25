"""Bind original local archives to current builds and reuse the existing scan gate."""
import hashlib
import json
from pathlib import Path
import re
import tarfile
import tempfile
import subprocess
import os

from .security import digest, relative
from .toolchain import embedded
from .workspace import tree

METADATA = {'usr/share/doc/cloudlab-ci/Dockerfile': 'platform/delivery/ci/Dockerfile',
            'usr/share/doc/cloudlab-ci/tools.lock.json': 'platform/delivery/ci/tools/source.lock.json',
            'usr/share/doc/cloudlab-ci/runner.lock.json': 'platform/delivery/ci/runner/source.lock.json'}


def archive_metadata(path):
    if path.is_symlink() or path.stat().st_size > 8 * 1024 ** 3:
        raise ValueError('CI scan requires a bounded original local image archive')
    found, removed = {}, set()
    with tarfile.open(path, mode='r:*') as outer:
        manifest = outer.getmember('manifest.json')
        if not manifest.isfile() or manifest.size > 65536:
            raise ValueError('CI archive manifest is invalid')
        rows = json.load(outer.extractfile(manifest))
        if len(rows) != 1:
            raise ValueError('CI scan requires exactly one image per archive')
        config = relative(rows[0]['Config']).as_posix()
        member = outer.getmember(config)
        if not member.isfile() or member.size > 1024 * 1024:
            raise ValueError('CI archive configuration is invalid')
        image_id = 'sha256:' + digest(outer.extractfile(member).read())
        for layer in reversed(rows[0]['Layers']):
            item = outer.getmember(relative(layer).as_posix())
            if not item.isfile():
                raise ValueError('CI image layer is not a regular archive')
            with tarfile.open(fileobj=outer.extractfile(item), mode='r:*') as source:
                for value in source:
                    name = value.name.removeprefix('./').lstrip('/')
                    if name.rsplit('/', 1)[-1].startswith('.wh.'):
                        parent, _, basename = name.rpartition('/')
                        if basename == '.wh..wh..opq':
                            removed.update(key for key in METADATA if key.startswith(parent + '/'))
                        else:
                            removed.add(parent + '/' + basename.removeprefix('.wh.'))
                    if name not in METADATA or name in found or name in removed:
                        continue
                    if not value.isfile() or value.size > 128 * 1024:
                        raise ValueError('CI image proof metadata is invalid')
                    found[name] = source.extractfile(value).read()
            if set(found) == set(METADATA):
                break
    if set(found) != set(METADATA):
        raise ValueError('CI archive lacks current embedded build metadata')
    return image_id, found


def scan(root=Path('/candidate'), archives=Path('/archives'), records=Path('/image-records'),
         output=Path('/proof-results/ci-scans.json')):
    from .inventory import ROOT
    embedded(ROOT)
    expected_tree = tree(root)
    plan = json.loads(Path('/plan.json').read_bytes())
    ids, original_hashes = {}, {}
    for role in ('controller', 'runner', 'builder'):
        record = json.loads((records / ('ci-' + role + '.json')).read_bytes())
        archive = archives / (role + '.tar')
        validation = subprocess.run(['crane', 'validate', '--tarball', str(archive)],
                                    env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home'},
                                    capture_output=True, timeout=600)
        if validation.returncode:
            raise ValueError('Original CI archive failed native layer/configuration integrity validation')
        image_id, metadata = archive_metadata(archive)
        if record != {'operation': plan['operation'], 'candidateTree': expected_tree,
                      'role': 'ci-' + role, 'imageId': image_id}:
            raise ValueError('Original CI archive differs from its recorded immutable build')
        for name, relative_path in METADATA.items():
            if metadata[name] != (root / relative_path).read_bytes():
                raise ValueError('Original CI archive is stale or differs from the maintained source')
        ids[role] = image_id
        original_hashes[role] = file_hash(archive)
    policy = json.loads((root / 'platform/delivery/ci/scan.lock.json').read_bytes())
    if (set(policy) != {'database', 'severities'} or policy['severities'] != ['HIGH', 'CRITICAL'] or
            not re.fullmatch(r'ghcr[.]io/aquasecurity/trivy-db(?::2)?@sha256:[a-f0-9]{64}', policy['database'])):
        raise ValueError('CI maintenance must preserve the existing vulnerability scan policy')
    from playbooks.ci.files import bootstrap
    bootstrap.SCAN = policy
    if not re.fullmatch(r'[a-f0-9]{32}', plan['operation']):
        raise ValueError('CI scan operation identity differs')
    reports = Path('/reports/ci') / plan['operation']
    digests = bootstrap.prepare(archives, reports)
    if any(file_hash(archives / (role + '.tar')) != sha256 for role, sha256 in original_hashes.items()):
        raise ValueError('Original CI archive changed after its vulnerability scan')
    document = {'candidateTree': expected_tree, 'images': digests, 'imageIds': ids,
                'archiveSha256': original_hashes, 'scanPolicy': policy,
                'requiredChecks': 'existing bootstrap.prepare', 'passed': True}
    output.write_text(json.dumps(document, sort_keys=True) + '\n')
    return {'scannedImages': 3, 'severities': policy['severities'], 'passed': True, 'serviceCredentialsUsed': False}


def file_hash(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


if __name__ == '__main__':
    try:
        print(json.dumps(scan()))
    except Exception:
        raise SystemExit('Mandatory CI image scan failed; private reports remain isolated and candidate stays draft') from None
