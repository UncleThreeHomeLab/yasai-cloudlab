"""Retain CNPG CRDs under Argo; preserve every other upstream chart byte."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2] / 'platform/data/cnpg'
UPSTREAM_SHA256 = 'b53d3991fe84bcf38767e7702cae78666265427a127a26fff168ab4207d2b1df'


def patched(raw):
    if hashlib.sha256(raw).hexdigest() != UPSTREAM_SHA256:
        raise ValueError('CNPG upstream checksum mismatch')
    output = io.BytesIO()
    changed = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as target:
                for original in source:
                    if not original.isfile() or original.name.startswith('/') or '..' in Path(original.name).parts:
                        raise ValueError('Unexpected CNPG chart member')
                    data = source.extractfile(original).read()
                    if original.name == 'cloudnative-pg/templates/crds/crds.yaml':
                        marker = b'    helm.sh/resource-policy: keep\n'
                        count = data.count(b'kind: CustomResourceDefinition\n')
                        if not count or data.count(marker) != count:
                            raise ValueError('CNPG CRD retention contract changed')
                        data = data.replace(marker, marker + b'    argocd.argoproj.io/sync-options: ServerSideApply=true,Prune=false,Delete=false\n')
                        changed += 1
                    member = tarfile.TarInfo(original.name)
                    member.mode, member.size = 0o644, len(data)
                    target.addfile(member, io.BytesIO(data))
    if changed != 1:
        raise ValueError('CNPG CRD template missing')
    return output.getvalue()


if __name__ == '__main__':
    data = patched((ROOT / 'upstream.tgz').read_bytes())
    target = ROOT / 'charts/cloudnative-pg-0.29.1.tgz'
    if sys.argv[1:] == ['--write']:
        target.write_bytes(data)
    elif target.read_bytes() != data:
        raise SystemExit('CNPG vendored patch differs from its source')
    print(json.dumps({'sha256': hashlib.sha256(data).hexdigest()}))
