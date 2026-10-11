"""Run component and integration tests in separate Python processes."""
import os
from pathlib import Path
import subprocess
import sys


def run(root):
    directories = sorted((root / 'automation').glob('*/tests'))
    directories.append(root / 'verification/integration')
    failed = []
    for directory in directories:
        if not list(directory.glob('test_*.py')):
            raise RuntimeError('No tests found in ' + str(directory.relative_to(root)))
        print('\n' + str(directory.relative_to(root)), flush=True)
        # Standalone VM modules use local imports; isolate owners with overlapping names.
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join(map(str, (
            directory.parent, root, root / 'automation/longhorn', root / 'verification/integration'))))
        result = subprocess.run(
            [sys.executable, '-m', 'unittest', 'discover', '-s', str(directory)],
            cwd=root, env=environment, check=False)
        if result.returncode:
            failed.append(str(directory.relative_to(root)))
    if failed:
        raise RuntimeError('Tests failed: ' + ', '.join(failed))


if __name__ == '__main__':
    try:
        run(Path(__file__).resolve().parents[2])
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
