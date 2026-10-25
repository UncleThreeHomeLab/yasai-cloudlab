"""Maintain the existing Go source overlays and their Docker build companions."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .security import archive_files, digest, download, owned_path
from .tools import write_json
from .inputs import baseline

UPSTREAMS = {'buildkit': 'moby/buildkit', 'cosign': 'sigstore/cosign',
             'crane': 'google/go-containerregistry', 'runc': 'opencontainers/runc',
             'rootlesskit': 'rootless-containers/rootlesskit', 'arc': 'actions/actions-runner-controller'}


def compiler(root):
    pin = json.loads((Path(root) / 'ansible/runner/cloudflare-provider.lock.json').read_text())['go']
    raw = download(pin['url'], prefix='https://go.dev/dl/', sha256=pin['sha256'])
    directory = Path(tempfile.mkdtemp(prefix='maintenance-go-'))
    for name, content in archive_files(raw, max_unpacked=512 * 1024 * 1024).items():
        path = owned_path(directory, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    go = directory / 'go/bin/go'
    go.chmod(0o755)
    for name in ('compile', 'link', 'asm', 'cgo', 'cover', 'vet'):
        for binary in (directory / 'go/pkg/tool').glob('*/' + name):
            binary.chmod(0o755)
    return go


def image_digest(reference, *, platform=None):
    if not re.fullmatch(r'[a-zA-Z0-9./_-]+:[a-zA-Z0-9._-]+', reference):
        raise ValueError('CI image update requires an explicit public tag')
    if platform not in {None, 'linux/amd64', 'linux/arm64'}:
        raise ValueError('Unsupported public image platform')
    arguments = ['crane', 'digest', *(['--platform', platform] if platform else []), reference]
    result = subprocess.run(arguments, capture_output=True, text=True,
                            env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home'}, timeout=120)
    actual = result.stdout.strip()
    if result.returncode or not re.fullmatch(r'sha256:[a-f0-9]{64}', actual):
        raise RuntimeError('Public CI image digest lookup failed')
    return reference + '@' + actual


def block_update(path, stage, replacements):
    text = path.read_text()
    marker = 'FROM compiler AS ' + stage + '\n'
    if text.count(marker) != 1:
        raise ValueError('CI Dockerfile source stage differs')
    start = text.index(marker)
    end = text.find('\nFROM ', start + len(marker))
    if end < 0:
        end = len(text)
    block = text[start:end]
    for index, (old, new) in enumerate(replacements):
        if old not in block:
            if new in block:
                continue
            if index < 2:
                raise ValueError('CI Dockerfile lacks a required source companion')
            continue
        block = block.replace(old, new)
    path.write_text(text[:start] + block + text[end:], newline='\n')


def update(root, name, version):
    if name == 'compiler':
        return update_compiler(root, version)
    if name not in UPSTREAMS or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Unsupported CI tool or version')
    root = Path(root)
    base = root / 'platform/delivery/ci'
    lock_path = base / 'tools/source.lock.json'
    lock = json.loads(lock_path.read_text())
    rows = [row for row in lock['sources'] if row['name'] == name]
    if len(rows) != 1:
        raise ValueError('CI tool source is missing or duplicated')
    row = rows[0]
    previous = json.loads(baseline(root, 'platform/delivery/ci/tools/source.lock.json'))
    old = next(item for item in previous['sources'] if item['name'] == name)
    old_number = old['version'].removeprefix('gha-runner-scale-set-').removeprefix('v')
    if version.split('.')[:2] != old_number.split('.')[:2]:
        raise ValueError('CI source minor changes require separate compatibility review')
    tag = ('gha-runner-scale-set-' if name == 'arc' else 'v') + version
    prefix = 'https://codeload.github.com/' + UPSTREAMS[name] + '/tar.gz/refs/tags/'
    url = prefix + tag
    raw = download(url, prefix=prefix)
    contents = archive_files(raw)
    work = Path(tempfile.mkdtemp(prefix='maintenance-source-'))
    for relative, content in contents.items():
        if '/' not in relative:
            raise ValueError('CI source archive lacks its root directory')
        path = owned_path(work, relative.split('/', 1)[1])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    overlay = base / 'tools' / name
    for filename in ('go.mod', 'go.sum'):
        source = overlay / filename
        if digest(source.read_bytes()) != row['modules'][filename]:
            raise ValueError('CI source overlay checksum differs')
        (work / filename).write_bytes(source.read_bytes())
    expected = row.get('replacements', [])
    if re.findall(r'^replace .+$', (work / 'go.mod').read_text(), re.M) != expected:
        raise ValueError('CI source replacement differs from its reviewed declaration')
    go = compiler(root)
    environment = {'PATH': str(go.parent) + ':' + os.environ['PATH'], 'HOME': '/tmp/home',
                   'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '0', 'GOMAXPROCS': '2',
                   'GOPROXY': 'https://proxy.golang.org', 'GOSUMDB': 'sum.golang.org',
                   'GOPATH': '/cache/go', 'GOMODCACHE': '/cache/modules', 'GOCACHE': '/cache/build',
                   'GOMEMLIMIT': '1536MiB'}
    for arguments in (['mod', 'tidy'], ['mod', 'download'], ['mod', 'verify']):
        result = subprocess.run([str(go), *arguments], cwd=work, env=environment,
                                capture_output=True, timeout=600)
        if result.returncode:
            raise RuntimeError('CI Go overlay maintenance failed; public build diagnostics withheld')
    if re.findall(r'^replace .+$', (work / 'go.mod').read_text(), re.M) != expected:
        raise ValueError('CI Go maintenance changed a reviewed replacement')
    for filename in ('go.mod', 'go.sum'):
        (overlay / filename).write_bytes((work / filename).read_bytes())
        row['modules'][filename] = digest((overlay / filename).read_bytes())
    row.update(version=tag, source=url, sha256=digest(raw))
    old_version = old['version'].removeprefix('gha-runner-scale-set-') if name == 'arc' else old['version']
    replacements = [(old['source'], url), (old['sha256'], row['sha256']),
                    (old_version, version if name == 'arc' else tag)]
    block_update(base / 'Dockerfile', name, replacements)
    if name == 'crane':
        dockerfile = root / 'ansible/runner/Dockerfile'
        text = dockerfile.read_text()
        for before, after in replacements:
            if before not in text and after not in text:
                raise ValueError('Bootstrap crane source companion is missing')
            text = text.replace(before, after)
        dockerfile.write_text(text, newline='\n')
    if name == 'arc':
        import urllib.request
        with urllib.request.urlopen('https://api.github.com/repos/actions/actions-runner-controller/commits/' + tag,
                                    timeout=60) as response:
            commit = json.load(response)['sha']
        if not re.fullmatch(r'[a-f0-9]{40}', commit):
            raise ValueError('ARC source tag did not resolve to an immutable upstream commit')
        row['commit'] = commit
        old_image = lock['images']['controller']
        lock['images']['controller'] = image_digest('ghcr.io/actions/gha-runner-scale-set-controller:' + version)
        text = (base / 'Dockerfile').read_text().replace(old_image, lock['images']['controller'])
        text, count = re.subn(r'(-X github[.]com/actions/actions-runner-controller/build[.]CommitSHA=)[a-f0-9]{40}',
                              r'\g<1>' + commit, text)
        if count != 2:
            raise ValueError('ARC linker commit companions are missing')
        (base / 'Dockerfile').write_text(text, newline='\n')
    if name == 'buildkit':
        runner_path = base / 'runner/source.lock.json'
        runner = json.loads(runner_path.read_text())
        old_builder = runner['qualification_builder']
        new_builder = image_digest('docker.io/moby/buildkit:v' + version + '-rootless')
        for path in (base / 'Dockerfile', base / 'runner.values.yaml'):
            text = path.read_text()
            if old_builder not in text:
                raise ValueError('CI BuildKit image companion is missing')
            path.write_text(text.replace(old_builder, new_builder), newline='\n')
        runner['qualification_builder'] = new_builder
        write_json(runner_path, runner)
    write_json(lock_path, lock)
    if name == 'arc':
        from .charts import one
        for component in ('controller', 'pool'):
            one(root, 'delivery/ci/' + component, version)
    return {'owner': 'ci-tools', 'tool': name, 'pendingBuild': [
        'candidate-runner', 'candidate-ci-controller', 'candidate-ci-builder', 'candidate-ci-runner'],
        'requiredChecks': ['ansible/playbooks/ci/tests/test_runner_image.py']}


def update_compiler(root, version):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('CI compiler requires an exact stable version')
    path = Path(root) / 'platform/delivery/ci/tools/source.lock.json'
    lock = json.loads(path.read_bytes())
    original = json.loads(baseline(root, 'platform/delivery/ci/tools/source.lock.json'))['compiler']
    match = re.fullmatch(r'docker[.]io/library/golang:([0-9]+[.][0-9]+)[.][0-9]+-bookworm@sha256:[a-f0-9]{64}', original)
    if not match or '.'.join(version.split('.')[:2]) != match[1]:
        raise ValueError('CI Go compiler minor changes require separate compatibility review')
    updated = image_digest('docker.io/library/golang:' + version + '-bookworm')
    dockerfile = Path(root) / 'platform/delivery/ci/Dockerfile'
    text = dockerfile.read_text()
    marker = 'FROM ' + original + ' AS compiler'
    replacement = 'FROM ' + updated + ' AS compiler'
    if marker not in text and replacement not in text:
        raise ValueError('CI compiler Dockerfile companion differs')
    dockerfile.write_text(text.replace(marker, replacement), newline='\n')
    lock['compiler'] = updated
    write_json(path, lock)
    return {'owner': 'ci-tools', 'tool': 'compiler', 'status': 'pending-build',
            'pendingBuild': ['candidate-runner', 'candidate-ci-controller', 'candidate-ci-builder', 'candidate-ci-runner']}
