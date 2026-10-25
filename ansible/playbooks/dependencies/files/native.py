"""Maintain native registry locks in existing isolated OpenTofu roots."""
import os
from pathlib import Path
import re
import subprocess
import shutil
import tempfile

from .inputs import baseline

ROOTS = {
    'github': 'infra/github',
    'keycloak': 'ansible/playbooks/keycloak/tests/provider-fixture',
    'postgresql': 'ansible/playbooks/data/tests/provider-fixture',
    's3': 'ansible/playbooks/data/tests/s3-provider-fixture',
    'grafana': 'ansible/playbooks/observability/tests/provider-fixture',
    'tailscale': 'ansible/playbooks/tailscale/provider-fixture',
}
SOURCES = {'github': 'integrations/github', 'keycloak': 'keycloak/keycloak',
           'postgresql': 'cyrilgdn/postgresql', 's3': 'hashicorp/aws',
           'grafana': 'grafana/grafana', 'tailscale': 'tailscale/tailscale'}


def environment():
    values = {'PATH': os.environ['PATH'], 'HOME': '/tmp/home',
              'TF_IN_AUTOMATION': '1', 'TF_INPUT': '0', 'CHECKPOINT_DISABLE': '1',
              'AWS_EC2_METADATA_DISABLED': 'true', 'AWS_SHARED_CREDENTIALS_FILE': '/dev/null',
              'AWS_CONFIG_FILE': '/dev/null'}
    if Path('/opt/runner/providers.tfrc').is_file():
        values['TF_CLI_CONFIG_FILE'] = '/opt/runner/providers.tfrc'
    return values


def command(arguments, *, cwd):
    result = subprocess.run(arguments, cwd=cwd, env=environment(), capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError('Native maintenance check failed; provider diagnostics withheld')
    return result.stdout


def registry(root, name, version):
    if name not in ROOTS or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Unsupported native provider owner or version')
    directory = Path(root) / ROOTS[name]
    path = directory / 'versions.tf'
    text = path.read_text()
    # The version line follows its native provider source in every accepted root.
    pattern = r'(source\s*=\s*"' + re.escape(SOURCES[name]) + r'"\s+version\s*=\s*"=\s*)[0-9]+\.[0-9]+\.[0-9]+(")'
    original = baseline(root, ROOTS[name] + '/versions.tf').decode()
    current = re.search(pattern, original)
    if not current:
        raise ValueError('Native provider baseline is missing its exact source constraint')
    old_version = re.search(r'[0-9]+\.[0-9]+\.[0-9]+$', current[0].rstrip('"'))[0]
    if version.split('.')[:2] != old_version.split('.')[:2]:
        raise ValueError('Native provider minor changes require separate compatibility review')
    updated, count = re.subn(pattern, r'\g<1>' + version + r'\2', text)
    if count != 1:
        raise ValueError('Native provider declaration is missing or ambiguous')
    path.write_text(updated, newline='\n')
    lock_and_check(directory)
    return {'provider': name, 'version': version, 'lockUpdated': True, 'nativeChecks': 'PASS'}


def lock_and_check(directory, *, mirror=None, update=True):
    directory = Path(directory)
    with tempfile.TemporaryDirectory(prefix='maintenance-native-') as temporary:
        work = Path(temporary)
        shutil.copytree(directory, work, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('.terraform', '.env', '*.tfstate', '*.tfstate.backup'))
        if update:
            # providers lock keeps the previous selection even after a constraint
            # changes. Re-resolve only inside this isolated, backend-free copy.
            (work / '.terraform.lock.hcl').unlink(missing_ok=True)
            arguments = ['tofu', 'providers', 'lock']
            if mirror is not None:
                arguments.append('-fs-mirror=' + str(mirror))
            command([*arguments, '-platform=linux_amd64'], cwd=work)
        for arguments in (['fmt', '-check', '-recursive', '-no-color'],
                          ['init', '-backend=false', '-lockfile=readonly', '-input=false', '-no-color'],
                          ['validate', '-no-color'], ['test', '-no-color']):
            command(['tofu', *arguments], cwd=work)
        if update:
            (directory / '.terraform.lock.hcl').write_bytes((work / '.terraform.lock.hcl').read_bytes())
