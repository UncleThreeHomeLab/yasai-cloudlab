"""Record public native Renovate qualification without executing candidate helpers."""
import json
from pathlib import Path

from .workspace import tree


def write(root=Path('/candidate')):
    record = json.loads(Path('/toolchain.json').read_bytes())
    pin = json.loads((root / 'platform/delivery/dependencies/image.lock.json').read_bytes())
    result = json.loads(Path('/results/renovate.json').read_bytes())
    if result != {'operation': record['operation'], 'candidateTree': tree(root), 'image': pin['image'], 'passed': True}:
        raise ValueError('Native Renovate qualification is missing or stale')
    Path('/proof-results/renovate.json').write_text(json.dumps(result, sort_keys=True) + '\n')
    return {'nativeRenovateVerified': True}


if __name__ == '__main__':
    try:
        print(json.dumps(write()))
    except Exception:
        raise SystemExit('Renovate qualification receipt refused; candidate remains draft') from None
