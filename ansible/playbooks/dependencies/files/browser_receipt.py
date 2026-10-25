"""Record native browser evidence after its immutable-image Compose check succeeds."""
import json
from pathlib import Path

from .workspace import tree


def write(root=Path('/candidate')):
    plan = json.loads(Path('/plan.json').read_bytes())
    record = json.loads(Path('/browser-toolchain.json').read_bytes())
    lock = json.loads((root / 'ansible/playbooks/keycloak/tests/browser/package.json').read_bytes())
    result = json.loads(Path('/results/browser.json').read_bytes())
    if (record['operation'] != plan['operation'] or record['candidateTree'] != tree(root) or
            record['role'] != 'identity-browser' or
            result != {**record, 'version': lock['dependencies']['playwright'], 'passed': True}):
        raise ValueError('Native browser result differs from the current candidate')
    Path('/proof-results/browser.json').write_text(json.dumps(result, sort_keys=True) + '\n')
    return {'browserBuildVerified': True, 'nativeBrowserChecked': True}


if __name__ == '__main__':
    try:
        print(json.dumps(write()))
    except Exception:
        raise SystemExit('Browser proof receipt refused; candidate remains draft') from None
