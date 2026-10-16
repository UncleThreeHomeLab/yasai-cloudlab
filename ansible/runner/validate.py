"""Credential-free input, playbook, lint and chart validation."""
from pathlib import Path
import subprocess
import sys

from dotenv import dotenv_values

ROOT = Path('/workspace')


def main():
    inputs = dotenv_values(ROOT / '.env.example', interpolate=False)
    required = {prefix + suffix for prefix in ('VM', 'VM2')
                for suffix in ('_HOST', '_USER', '_PASSWORD')}
    if not required <= inputs.keys():
        raise SystemExit('Missing documented VM bootstrap input names.')
    subprocess.run([sys.executable, '/opt/runner/run.py', 'syntax'], check=True)
    # Legacy owners are checked by syntax and behavior until their replacement.
    # Lint all component playbooks as they arrive; never suppress a lint rule.
    exclusions = [ROOT / 'ansible/roles', *sorted((ROOT / 'ansible').glob('*.yml'))]
    command = ['ansible-lint', '--offline', '--project-dir', str(ROOT / 'ansible')]
    for path in exclusions:
        command += ['--exclude', str(path)]
    command.append('--')
    command += [str(path) for path in sorted((ROOT / 'ansible/playbooks').rglob('*.yml'))]
    subprocess.run(command, cwd=ROOT / 'ansible', check=True)
    subprocess.run([sys.executable, '/opt/runner/run.py', 'charts'], check=True)


if __name__ == '__main__':
    main()
