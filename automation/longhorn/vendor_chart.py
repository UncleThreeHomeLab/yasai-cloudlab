"""Reproduce the narrowly patched, pinned Longhorn dependency without extraction.

Only the two Helm lifecycle hooks and CRD retention annotations differ upstream.
The archive is deterministic; all other members retain their original bytes.
"""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2] / 'platform/storage/longhorn'
HOOKS = {'longhorn/templates/postupgrade-job.yaml', 'longhorn/templates/uninstall-job.yaml'}
CRDS = 'longhorn/templates/crds.yaml'
MARKER = b'kind: CustomResourceDefinition\nmetadata:\n  annotations:\n'
ANNOTATION = b'    argocd.argoproj.io/sync-options: ServerSideApply=true,Prune=false,Delete=false\n'


def package(source):
    output = io.BytesIO()
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(source), mode='r:gz') as upstream:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as target:
                for member in upstream:
                    if not member.isfile() or member.name.startswith('/') or '..' in Path(member.name).parts:
                        raise ValueError('Unexpected chart member type or path')
                    if member.name in seen:
                        raise ValueError('Duplicate upstream chart member')
                    seen.add(member.name)
                    if member.name in HOOKS:
                        continue
                    data = upstream.extractfile(member).read()
                    if member.name == CRDS:
                        if data.count(MARKER) != 28 or ANNOTATION in data:
                            raise ValueError('Longhorn CRD template differs from the reviewed baseline')
                        data = data.replace(MARKER, MARKER + ANNOTATION)
                    entry = tarfile.TarInfo(member.name)
                    entry.size, entry.mode = len(data), 0o644
                    target.addfile(entry, io.BytesIO(data))
    if not HOOKS | {CRDS} <= seen:
        raise ValueError('Longhorn lifecycle hook inventory differs from the reviewed baseline')
    return output.getvalue()


def verify():
    lock = json.loads((ROOT / 'artifact.lock.json').read_text())
    archive = (ROOT / lock['archive']).resolve()
    if not archive.is_relative_to(ROOT.resolve()):
        raise ValueError('Longhorn chart archive escapes its module')
    source = (ROOT / 'upstream.tgz').read_bytes()
    if hashlib.sha256(source).hexdigest() != lock['upstream_sha256']:
        raise ValueError('Longhorn upstream checksum mismatch')
    patched = package(source)
    if (hashlib.sha256(patched).hexdigest() != lock['sha256']
            or patched != archive.read_bytes()):
        raise ValueError('Longhorn vendored patch does not reproduce its locked archive')
    return patched


if __name__ == '__main__':
    verify()
    print('Longhorn vendor patch and both archive checksums verified.')
