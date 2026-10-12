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
        mirror = ('-fs-mirror=/opt/providers',) if name == 'cloudflare' else ()
        for arguments in (('fmt', '-recursive'), ('providers', 'lock', *mirror, '-platform=linux_amd64'),
                          ('init', '-backend=false', '-input=false', '-lockfile=readonly'),
                          ('validate', '-no-color')):
            from automation.infra.backend import environment
            subprocess.run(['tofu', *arguments], cwd=root,
                           env=environment({'USERNAME': 'synthetic', 'TOKEN': 'synthetic'},
                                           'https://example.invalid', 'synthetic-lock-review-passphrase'), check=True)


if __name__ == '__main__':
    main()
