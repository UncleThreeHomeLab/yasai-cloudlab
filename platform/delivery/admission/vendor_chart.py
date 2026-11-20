"""Repackage the locked Kyverno chart without its bundled test templates."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile


ROOT = Path(__file__).resolve().parent
CHART = 'kyverno'
FIXTURES = {f'{CHART}/templates/tests/{name}' for name in (
    '_helpers.tpl', 'admission-controller-liveness.yaml', 'admission-controller-metrics.yaml',
    'admission-controller-readiness.yaml', 'cleanup-controller-liveness.yaml',
    'cleanup-controller-metrics.yaml', 'cleanup-controller-readiness.yaml',
    'helper-functions-test.yaml', 'reports-controller-metrics.yaml',
)}


def package(raw, upstream_sha256):
    if hashlib.sha256(raw).hexdigest() != upstream_sha256:
        raise ValueError('Kyverno upstream checksum mismatch')

    output = io.BytesIO()
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as upstream:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as target:
                for member in upstream:
                    name = member.name
                    if (member.type != tarfile.REGTYPE or not name.startswith(f'{CHART}/')
                            or '\\' in name or {'', '.', '..'}.intersection(name.split('/')) or name in seen):
                        raise ValueError('Unexpected Kyverno chart member')
                    seen.add(name)
                    if name in FIXTURES:
                        continue
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mode = member.size, 0o644
                    with upstream.extractfile(member) as content:
                        target.addfile(entry, content)
    if not FIXTURES <= seen:
        raise ValueError('Kyverno fixture inventory differs from the reviewed source')
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('upstream', type=Path, help='archive matching the locked upstream checksum')
    parser.add_argument('--output', type=Path, help='write a new archive instead of verifying the committed one')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'artifact.lock.json').read_text())
    data = package(args.upstream.read_bytes(), lock['upstream_sha256'])
    digest = hashlib.sha256(data).hexdigest()
    if args.output is None:
        if digest != lock['sha256'] or data != (ROOT / lock['archive']).read_bytes():
            raise ValueError('Kyverno vendor package does not reproduce its locked archive')
    else:
        with args.output.open('xb') as target:
            target.write(data)
    print(digest)


if __name__ == '__main__':
    main()
