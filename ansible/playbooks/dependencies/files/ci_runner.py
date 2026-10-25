"""Update the runner's source, SDK, runtime, security pins and build companions."""
import json
from pathlib import Path
import re

from .ci_tools import image_digest
from .security import archive_files, digest, download
from .tools import write_json
from .inputs import baseline


def update(root, request):
    required = {'version', 'sdk', 'runtime', 'securityPackages'}
    if (set(request) != required or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', request['version']) or
            not re.fullmatch(r'8[.]0[.][0-9]+-bookworm-slim', request['sdk']) or
            not re.fullmatch(r'8[.]0[.][0-9]+', request['runtime']) or
            set(request['securityPackages']) != {'System.Security.Cryptography.Pkcs', 'System.Formats.Asn1'} or
            any(not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version)
                for version in request['securityPackages'].values())):
        raise ValueError('CI runner update requires explicit compatible source, SDK, runtime and security pins')
    root = Path(root)
    base = root / 'platform/delivery/ci'
    path = base / 'runner/source.lock.json'
    lock = json.loads(path.read_text())
    previous = json.loads(baseline(root, 'platform/delivery/ci/runner/source.lock.json'))
    if request['version'].split('.')[0] != previous['runner_version'].split('.')[0] or any(
            version.split('.')[:2] != previous['security_packages'][name].split('.')[:2]
            for name, version in request['securityPackages'].items()):
        raise ValueError('CI runner or security package leaves its reviewed compatibility range')
    url = 'https://codeload.github.com/actions/runner/tar.gz/refs/tags/v' + request['version']
    raw = download(url, prefix='https://codeload.github.com/actions/runner/tar.gz/refs/tags/')
    archive_files(raw)
    lock['runner_version'] = request['version']
    lock['source'] = {'url': url, 'sha256': digest(raw)}
    lock['sdk'] = image_digest('mcr.microsoft.com/dotnet/sdk:' + request['sdk'])
    lock['runtime_version'] = request['runtime']
    lock['security_packages'] = dict(request['securityPackages'])
    lock['images']['base'] = image_digest('ghcr.io/actions/actions-runner:' + request['version'])
    dockerfile = base / 'Dockerfile'
    text = dockerfile.read_text()
    replacements = [(previous['source']['url'], lock['source']['url']),
                    (previous['source']['sha256'], lock['source']['sha256']),
                    (previous['sdk'], lock['sdk']), (previous['images']['base'], lock['images']['base']),
                    ('RunnerVersion=' + previous['runner_version'], 'RunnerVersion=' + lock['runner_version']),
                    ('Version=' + previous['runner_version'], 'Version=' + lock['runner_version']),
                    ("= '" + previous['runner_version'] + "'", "= '" + lock['runner_version'] + "'"),
                    ('"version": "' + previous['runtime_version'] + '"', '"version": "' + lock['runtime_version'] + '"')]
    for old, new in replacements:
        if old not in text and new not in text:
            raise ValueError('CI runner Dockerfile companion is missing')
        text = text.replace(old, new)
    patch_path = base / 'runner/runner.patch'
    patch = patch_path.read_text()
    for name, version in lock['security_packages'].items():
        pattern = r'(?m)^(\+[^\n]*<PackageReference Include="' + re.escape(name) + r'" Version=")[^"]+("[^\n]*)$'
        patch, count = re.subn(pattern, r'\g<1>' + version + r'\2', patch)
        if count != 1:
            raise ValueError('Reviewed runner security package patch differs')
    dockerfile.write_text(text, newline='\n')
    values_path = base / 'runner.values.yaml'
    values = values_path.read_text()
    before, after = previous['images']['base'], lock['images']['base']
    if before not in values and after not in values:
        raise ValueError('Native ARC runner image companion is missing')
    values_path.write_text(values.replace(before, after), newline='\n')
    patch_path.write_text(patch, newline='\n')
    write_json(path, lock)
    return {'owner': 'ci-runner', 'status': 'pending-build', 'pendingBuild': 'refresh-ci-runner',
            'next': 'docker compose -f ansible/playbooks/dependencies/compose.yaml run --build --rm refresh-ci-runner'}


def finalize(root):
    import base64
    base = Path(root) / 'platform/delivery/ci/runner'
    path = base / 'source.lock.json'
    lock = json.loads(path.read_text())
    expected = {'Sdk', 'Runner.Common', 'Runner.Sdk', 'Runner.Listener', 'Runner.Worker',
                'Runner.PluginHost', 'Runner.Plugins', 'Test'}
    projects = list((base / 'nuget').glob('*/packages.lock.json'))
    if {item.parent.name for item in projects} != expected:
        raise ValueError('Runner maintenance requires all eight NuGet project locks')
    seen = set()
    for item in projects:
        from .nuget import validate_lock
        relative = item.relative_to(Path(root)).as_posix()
        validate_lock(baseline(root, relative), item.read_bytes())
        for packages in json.loads(item.read_text())['dependencies'].values():
            for name, package in packages.items():
                if package['type'] == 'Project':
                    continue
                if len(base64.b64decode(package['contentHash'], validate=True)) != 64:
                    raise ValueError('Runner NuGet package content hash is invalid')
                if name in lock['security_packages']:
                    if package['resolved'] != lock['security_packages'][name]:
                        raise ValueError('Runner NuGet security package version differs')
                    seen.add(name)
    if seen != set(lock['security_packages']):
        raise ValueError('Runner security package lock coverage differs')
    lock['nuget'] = {item.parent.name: digest(item.read_bytes()) for item in sorted(projects)}
    lock['overlays'] = {relative: digest((base / relative).read_bytes()) for relative in lock['overlays']}
    write_json(path, lock)
    return {'owner': 'ci-runner', 'status': 'pending-build', 'pendingBuild': [
        'candidate-runner', 'candidate-ci-controller', 'candidate-ci-builder', 'candidate-ci-runner']}
