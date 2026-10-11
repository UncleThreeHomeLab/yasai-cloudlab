"""Explicit lock maintenance; copy the result into a dependency-review change."""
from pathlib import Path
import shutil
import subprocess


def main():
    destination = Path('/tmp/infra-lock-review')
    shutil.copytree('/workspace/infra', destination, ignore=shutil.ignore_patterns('.terraform'))
    for name in ('cloudflare', 'github'):
        root = destination / name
        (root / '.terraform.lock.hcl').unlink(missing_ok=True)
        for arguments in (('fmt', '-recursive'), ('providers', 'lock', '-platform=linux_amd64'),
                          ('init', '-backend=false', '-input=false', '-lockfile=readonly'),
                          ('validate', '-no-color')):
            subprocess.run(['tofu', *arguments], cwd=root, check=True)


if __name__ == '__main__':
    main()
