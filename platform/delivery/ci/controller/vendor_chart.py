"""Repackage the locked ARC controller chart without its CI fixtures."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile


ROOT = Path(__file__).resolve().parent
CHART = 'gha-runner-scale-set-controller'
FIXTURES = {f'{CHART}/{name}' for name in (
    'ci/ci-values.yaml', 'tests/metrics_test.go', 'tests/template_test.go',
)}


def package(raw, upstream_sha256):
    if hashlib.sha256(raw).hexdigest() != upstream_sha256:
        raise ValueError('ARC upstream checksum mismatch')

    output = io.BytesIO()
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as upstream:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as target:
                for member in upstream:
                    name = member.name
                    if (member.type != tarfile.REGTYPE or not name.startswith(f'{CHART}/')
                            or '\\' in name or {'', '.', '..'}.intersection(name.split('/')) or name in seen):
                        raise ValueError('Unexpected ARC chart member')
                    seen.add(name)
                    if name in FIXTURES:
                        continue
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mode = member.size, 0o644
                    with upstream.extractfile(member) as content:
                        target.addfile(entry, content)
    if not FIXTURES <= seen:
        raise ValueError('ARC fixture inventory differs from the reviewed source')
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('upstream', type=Path, help='archive pulled from the locked OCI chart URL and version')
    parser.add_argument('--output', type=Path, help='write a new archive instead of verifying the committed one')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'artifact.lock.json').read_text())
    data = package(args.upstream.read_bytes(), lock['upstream_sha256'])
    digest = hashlib.sha256(data).hexdigest()
    if args.output is None:
        if digest != lock['sha256'] or data != (ROOT / lock['archive']).read_bytes():
            raise ValueError('ARC vendor package does not reproduce its locked archive')
    else:
        with args.output.open('xb') as target:
            target.write(data)
    print(digest)


if __name__ == '__main__':
    main()
