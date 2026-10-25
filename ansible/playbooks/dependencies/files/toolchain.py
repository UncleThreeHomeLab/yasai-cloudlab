"""Bind native Docker inspection to the actual immutable verification image."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def embedded(root):
    root = Path(root)
    required = {'/opt/runner/Dockerfile': 'ansible/runner/Dockerfile',
                '/opt/runner/tools.lock.json': 'ansible/runner/tools.lock.json',
                '/opt/runner/helm.lock.json': 'ansible/runner/helm.lock.json',
                '/opt/runner/requirements.txt': 'ansible/runner/requirements.txt',
                '/opt/runner/ci-tools.lock.json': 'platform/delivery/ci/tools/source.lock.json',
                '/opt/runner/install_tools.py': 'ansible/runner/install_tools.py',
                '/opt/runner/install_helm.py': 'ansible/runner/install_helm.py',
                '/etc/apt/sources.list.d/debian.sources': 'ansible/runner/debian.sources',
                '/opt/runner/providers.tfrc': 'ansible/runner/providers.tfrc'}
    for installed, source in required.items():
        if Path(installed).read_bytes() != (root / source).read_bytes():
            raise ValueError('Verification image differs from its locked recipe or inputs')
    for name in ('cloudflare', 'harbor'):
        pin = json.loads((root / 'ansible/runner' / (name + '-provider.lock.json')).read_text())
        package = Path('/opt/providers/registry.opentofu.org/cloudlab') / name / (
            'terraform-provider-' + name + '_' + pin['version'] + '_linux_amd64.zip')
        if hashlib.sha256(package.read_bytes()).hexdigest() != pin['package_sha256']:
            raise ValueError('Verification provider package differs from its reviewed checksum')
    pins = json.loads((root / 'ansible/runner/tools.lock.json').read_text())
    environment = {'PATH': os.environ['PATH'], 'HOME': '/tmp/home'}
    commands = {'tofu': ['tofu', 'version', '-json'], 'op': ['op', '--version'], 'restic': ['restic', 'version']}
    for name, command in commands.items():
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError('Verification tool version check failed')
        version = pins[name]['version']
        if name == 'tofu':
            valid = json.loads(result.stdout)['terraform_version'] == version
        elif name == 'restic':
            valid = result.stdout.startswith('restic ' + version + ' ')
        else:
            valid = result.stdout.strip() == version
        if not valid:
            raise ValueError('Verification image executes a stale bootstrap tool')
    helm = subprocess.run(['helm', 'version', '--short'], env=environment, capture_output=True, text=True, timeout=30)
    expected = json.loads((root / 'ansible/runner/helm.lock.json').read_text())['version']
    if helm.returncode or not helm.stdout.strip().startswith(expected + '+'):
        raise ValueError('Verification image executes a stale Helm tool')


ROLES = {'candidate-runner', 'ci-controller', 'ci-builder', 'ci-runner', 'identity-browser'}


def record(image_id, role='candidate-runner'):
    from .control import CANDIDATE, CONTROL, load, save
    from .workspace import tree
    if role not in ROLES or not isinstance(image_id, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise ValueError('Toolchain recording requires the exact native Docker image ID')
    plan = load('operation.json')
    if not re.fullmatch(r'[a-f0-9]{32}', plan['operation']):
        raise ValueError('Invalid maintenance operation identity')
    candidate_tree = tree(CANDIDATE)
    if role in {'candidate-runner', 'identity-browser'}:
        from .check import source
        check_plan = load('check-plan.json')
        if check_plan['operation'] != plan['operation'] or source(CANDIDATE, check_plan) != candidate_tree:
            raise ValueError('Candidate source changed during trusted toolchain recording')
    value = {'operation': plan['operation'], 'candidateTree': candidate_tree, 'role': role, 'imageId': image_id}
    (CONTROL / 'images').mkdir(mode=0o700, exist_ok=True)
    save('images/' + role + '.json', value)
    if role == 'identity-browser':
        with (CONTROL / 'toolchain.env').open('a', encoding='utf-8', newline='\n') as stream:
            stream.write('DEPENDENCY_BROWSER_IMAGE_ID=' + image_id + '\n')
    if role != 'candidate-runner':
        return {'role': role, 'imageRecorded': True, 'operation': plan['operation']}
    save('toolchain.json', value)
    work = os.environ.get('DEPENDENCY_WORK_DIR', '../../../docs/local/dependency-work')
    if len(work) > 1024 or any(char in work for char in '\r\n\x00'):
        raise ValueError('Invalid maintenance work directory')
    (CONTROL / 'toolchain.env').write_text('DEPENDENCY_VERIFIED_IMAGE_ID=' + image_id + '\nDEPENDENCY_WORK_DIR=' +
                                           json.dumps(work) + '\nDEPENDENCY_OPERATION=' + plan['operation'] + '\n' +
                                           'DEPENDENCY_K3S_IMAGE=' + k3s_image(CANDIDATE) + '\n' +
                                           'DEPENDENCY_RENOVATE_IMAGE=' + renovate_image(CANDIDATE) + '\n', newline='\n')
    return {'role': 'candidate-runner', 'imageRecorded': True, 'operation': plan['operation']}


def k3s_image(root):
    import yaml
    proof = yaml.safe_load((root / 'ansible/playbooks/keycloak/tests/compose.identity-operator-proof.yaml').read_bytes())
    image = proof['services']['cluster']['image']
    if not re.fullmatch(r'rancher/k3s:v1[.]36[.][0-9]+-k3s[0-9]+@sha256:[a-f0-9]{64}', image):
        raise ValueError('Identity qualification requires its tested public K3s image')
    from .ci_tools import image_digest
    if (image_digest(image.split('@')[0]) != image and
            image_digest(image.split('@')[0], platform='linux/amd64') != image):
        raise ValueError('Privileged fixture image differs from its exact official release tag digest')
    return image


def renovate_image(root):
    relative = 'platform/delivery/dependencies/image.lock.json'
    pin = json.loads((root / relative).read_bytes())
    from .inventory import ROOT
    original = json.loads((ROOT / relative).read_bytes())
    if (not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+', pin['version']) or
            pin['version'].split('.')[:2] != original['version'].split('.')[:2] or
            not re.fullmatch(re.escape('ghcr.io/renovatebot/renovate:' + pin['version']) + r'@sha256:[a-f0-9]{64}', pin['image'])):
        raise ValueError('Renovate qualification requires its tested official image range')
    from .ci_tools import image_digest
    if image_digest(pin['image'].split('@')[0]) != pin['image']:
        raise ValueError('Renovate image differs from its exact official release tag digest')
    return pin['image']


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ROLES:
            raise ValueError('Unsupported toolchain role')
        raw = sys.stdin.read(129)
        if len(raw) > 128:
            raise ValueError('Toolchain image ID exceeds its size limit')
        print(json.dumps(record(json.loads(raw), sys.argv[1])))
    except Exception:
        raise SystemExit('Toolchain recording failed; use the fixed native Docker inspection command') from None
