"""Narrow cert-manager CRD retention patch; all other upstream bytes stay intact."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2] / 'platform/certificates/cert-manager'


def patched(raw):
    output = io.BytesIO()
    count = 0
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        with gzip.GzipFile(fileobj=output, mode='wb', mtime=0, filename='') as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as target:
                for original in source:
                    if (not original.isfile() or original.name.startswith('/')
                            or '..' in Path(original.name).parts or original.name in seen):
                        raise ValueError('Unexpected cert-manager chart member')
                    seen.add(original.name)
                    data = source.extractfile(original).read()
                    if original.name.startswith('cert-manager/templates/crd-'):
                        marker = b'    helm.sh/resource-policy: keep\n'
                        if data.count(marker) != 1:
                            raise ValueError('Unexpected cert-manager CRD retention template')
                        data = data.replace(marker, marker +
                            b'    argocd.argoproj.io/sync-options: ServerSideApply=true,Prune=false,Delete=false\n')
                        count += 1
                    member = tarfile.TarInfo(original.name)
                    member.mode, member.size = 0o644, len(data)
                    target.addfile(member, io.BytesIO(data))
    if count != 6:
        raise ValueError('Unexpected cert-manager CRD inventory')
    return output.getvalue()


def verify():
    lock = json.loads((ROOT / 'artifact.lock.json').read_text())
    original = (ROOT / 'upstream.tgz').read_bytes()
    archive = (ROOT / lock['archive']).resolve()
    if not archive.is_relative_to(ROOT.resolve()):
        raise ValueError('cert-manager archive escapes its module')
    vendored = archive.read_bytes()
    if hashlib.sha256(original).hexdigest() != lock['upstream_sha256']:
        raise ValueError('cert-manager upstream checksum mismatch')
    if hashlib.sha256(vendored).hexdigest() != lock['sha256'] or patched(original) != vendored:
        raise ValueError('cert-manager vendor patch or checksum mismatch')
    return lock
