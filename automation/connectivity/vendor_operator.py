"""Reproducible CRD retention patch, with all other upstream member bytes intact."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2] / 'platform/connectivity/tailscale-operator'


def patched(raw):
    output = io.BytesIO()
    count, seen = 0, set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        with gzip.GzipFile(fileobj=output, mode='wb', mtime=0, filename='') as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as target:
                for original in source:
                    if not original.isfile() or original.name.startswith('/') or '..' in Path(original.name).parts or original.name in seen:
                        raise ValueError('Unexpected Tailscale chart member')
                    seen.add(original.name)
                    data = source.extractfile(original).read()
                    if b'kind: CustomResourceDefinition' in data:
                        marker = b'kind: CustomResourceDefinition\nmetadata:\n  annotations:\n'
                        if data.count(marker) != 1 or b'argocd.argoproj.io/sync-options' in data:
                            raise ValueError('Unexpected Tailscale CRD retention template')
                        data = data.replace(marker, marker + b'    argocd.argoproj.io/sync-options: ServerSideApply=true,Prune=false,Delete=false\n')
                        count += 1
                    member = tarfile.TarInfo(original.name)
                    member.mode, member.size = 0o644, len(data)
                    target.addfile(member, io.BytesIO(data))
    if count != 8:
        raise ValueError('Unexpected Tailscale CRD inventory')
    return output.getvalue()


def verify():
    lock = json.loads((ROOT / 'artifact.lock.json').read_text())
    original = (ROOT / 'upstream.tgz').read_bytes()
    archive = ROOT / 'charts/tailscale-operator-1.102.4.tgz'
    vendored = archive.read_bytes()
    if hashlib.sha256(original).hexdigest() != lock['upstream_sha256']:
        raise ValueError('Tailscale upstream checksum mismatch')
    if hashlib.sha256(vendored).hexdigest() != lock['sha256'] or patched(original) != vendored:
        raise ValueError('Tailscale retention patch or checksum mismatch')
    return lock
