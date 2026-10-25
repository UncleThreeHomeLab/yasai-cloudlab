"""Read build metadata in a trusted container with no candidate execution."""
import json
from pathlib import Path

from .security import digest
from .workspace import tree


def check(root=Path('/candidate'), built=Path('/proof'), output=Path('/proof-results/ci-images.json')):
    expected = {'Dockerfile': root / 'platform/delivery/ci/Dockerfile',
                'tools.lock.json': root / 'platform/delivery/ci/tools/source.lock.json',
                'runner.lock.json': root / 'platform/delivery/ci/runner/source.lock.json'}
    hashes = {name: digest(path.read_bytes()) for name, path in expected.items()}
    for stage in ('controller', 'builder', 'runner'):
        for name, sha256 in hashes.items():
            if digest((built / stage / name).read_bytes()) != sha256:
                raise ValueError('CI build metadata differs from the maintained candidate')
    result = {'candidateTree': tree(root), 'inputs': hashes, 'stages': ['controller', 'builder', 'runner']}
    output.write_text(json.dumps(result, sort_keys=True) + '\n')
    return {'ciBuildsVerified': 3, 'lockedRunnerTestsRequired': True}


if __name__ == '__main__':
    try:
        print(json.dumps(check()))
    except Exception:
        raise SystemExit('CI image proof failed; candidate remains draft') from None
