"""Synthetic official-registry responses for isolated maintenance checks."""
import base64
import hashlib
import io
import json
import tarfile


def gateway_artifact():
    import yaml
    rows = [{'kind': 'CustomResourceDefinition', 'metadata': {'name': 'fixture' + str(index)},
             'spec': {'group': 'gateway.networking.k8s.io'}} for index in range(10)]
    rows += [{'kind': kind, 'metadata': {'name': 'safe-upgrades.gateway.networking.k8s.io'}}
             for kind in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding')]
    return yaml.safe_dump_all(rows).encode()


def tailscale_release(version):
    import yaml
    contents = {'tailscale-operator/Chart.yaml': yaml.safe_dump({'apiVersion': 'v2', 'name': 'tailscale-operator',
                'version': version, 'appVersion': 'v' + version}).encode()}
    contents.update({'tailscale-operator/templates/crd-' + str(index) + '.yaml':
                     b'kind: CustomResourceDefinition\nmetadata:\n  annotations:\n    example: value\n'
                     for index in range(8)})
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, raw in contents.items():
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            archive.addfile(item, io.BytesIO(raw))
    return output.getvalue()


def browser_registry(locked, version):
    from playbooks.dependencies.files.browser import PACKAGES, REGISTRY, tarball
    responses = {}
    for name in PACKAGES:
        previous = locked['packages']['node_modules/' + name]
        manifest = {'name': name, 'version': version,
                    **{key: previous[key] for key in ('license', 'bin', 'engines')}}
        if name == 'playwright':
            manifest['dependencies'] = {'playwright-core': version}
        payload = json.dumps(manifest).encode()
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            member = tarfile.TarInfo('package/package.json')
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        raw = output.getvalue()
        metadata = dict(manifest, dist={'tarball': tarball(name, version),
            'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()})
        responses[REGISTRY + name + '/' + version] = json.dumps(metadata).encode()
        responses[tarball(name, version)] = raw
    return responses


def provider_candidate(source, candidate, control, name):
    """Stage only index-tracked public builder/root inputs for the native local proof."""
    from pathlib import Path
    import os
    import secrets
    import subprocess
    from playbooks.dependencies.files.inventory import selected
    from playbooks.dependencies.files.security import owned_path
    from playbooks.dependencies.files.workspace import files, supports_modes
    if name not in {'cloudflare', 'harbor'}:
        raise ValueError('Unsupported provider fixture')
    source, candidate, control = map(Path, (source, candidate, control))
    candidate.mkdir(parents=True, exist_ok=True)
    control.mkdir(parents=True, exist_ok=True)
    if any(candidate.iterdir()) or any(control.iterdir()):
        raise ValueError('Provider proof requires a new empty owned fixture directory')
    roots = ('ansible/runner', 'infra/cloudflare', 'infra/harbor', 'ansible/playbooks/harbor/tests/provider-fixture',
             'platform/delivery/ci/tools/source.lock.json', 'platform/delivery/ci/tools/crane')
    result = subprocess.run(['git', '-c', 'core.fsmonitor=false', 'ls-files', '--cached', '-z', '--', *roots],
                            cwd=source, capture_output=True, check=True, timeout=60,
                            env={'PATH': os.environ['PATH'], 'HOME': '/tmp/home', 'GIT_CONFIG_NOSYSTEM': '1',
                                 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'})
    for relative in result.stdout.decode().split('\0'):
        if not relative:
            continue
        if not any(relative == prefix or relative.startswith(prefix + '/') for prefix in roots):
            raise ValueError('Provider fixture escaped its exact public inputs')
        path = owned_path(candidate, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(owned_path(source, relative).read_bytes())
    manifest = files(candidate)
    owner = selected([name + '-provider'])[name + '-provider']
    operation = secrets.token_hex(16)
    base = {relative: {'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                       'mode': '100644'} for relative in manifest
            for raw in [owned_path(candidate, relative).read_bytes()]}
    check_plan = {'operation': operation, 'checks': owner['checks'], 'allowed': owner['writePaths'], 'baseTree': base,
                  'fileModes': supports_modes(candidate),
                  'baseFiles': {relative: base64.b64encode(owned_path(candidate, relative).read_bytes()).decode()
                                for relative in owner['writePaths'] if relative in manifest}}
    (control / 'check-plan.json').write_text(json.dumps(check_plan))
    (control / 'operation.json').write_text(json.dumps({'operation': operation, 'owners': [name + '-provider']}))
    return {'fixture': name + '-provider', 'trackedPublicFiles': len(manifest), 'credentials': False}


def browser_candidate(source, candidate, control, work):
    """Build the current public browser bundle through its actual protected native proof."""
    from pathlib import Path
    import secrets
    from playbooks.dependencies.files.browser import BASE
    from playbooks.dependencies.files.security import owned_path
    from playbooks.dependencies.files.workspace import files, supports_modes
    source, candidate, control = map(Path, (source, candidate, control))
    candidate.mkdir(parents=True, exist_ok=True)
    control.mkdir(parents=True, exist_ok=True)
    if any(candidate.iterdir()) or any(control.iterdir()) or any(char in work for char in '\r\n\0'):
        raise ValueError('Browser proof requires a new empty owned public fixture')
    names = ('Dockerfile', 'package.json', 'package-lock.json', 'proof.mjs', 'sessions.mjs', 'disposable.mjs')
    for name in names:
        target = owned_path(candidate, BASE + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(owned_path(source, BASE + name).read_bytes())
    operation = secrets.token_hex(16)
    manifest = files(candidate)
    base = {relative: {'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), 'mode': '100644'}
            for relative in manifest for raw in [owned_path(candidate, relative).read_bytes()]}
    plan = {'operation': operation, 'owners': ['identity-browser']}
    check = {'operation': operation, 'checks': [], 'allowed': [BASE + name for name in names[:3]], 'baseTree': base,
             'fileModes': supports_modes(candidate),
             'baseFiles': {relative: base64.b64encode(owned_path(candidate, relative).read_bytes()).decode() for relative in base}}
    (control / 'operation.json').write_text(json.dumps(plan))
    (control / 'check-plan.json').write_text(json.dumps(check))
    (control / 'toolchain.env').write_text('DEPENDENCY_WORK_DIR=' + json.dumps(work) + '\n')
    return {'fixture': 'identity-browser', 'publicFiles': len(manifest), 'credentials': False}


def actions_source(source, target):
    """Commit exact public task inputs only inside an owned disposable Linux Git fixture."""
    from pathlib import Path
    import os
    import subprocess
    from playbooks.dependencies.files.local import PUBLIC
    from playbooks.dependencies.files.security import owned_path
    source, target = Path(source), Path(target)
    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()):
        raise ValueError('Actions source proof requires a new empty owned fixture volume')
    environment = {'PATH': os.environ['PATH'], 'HOME': '/tmp/home', 'GIT_CONFIG_NOSYSTEM': '1',
                   'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0'}
    result = subprocess.run(['git', '-c', 'core.fsmonitor=false', 'ls-files', '--cached', '-z', '--', *PUBLIC],
                            cwd=source, env=environment, capture_output=True, check=True, timeout=60)
    names = {name for name in result.stdout.decode().split('\0') if name}
    # Only the two explicitly owned, not-yet-committed task directories are added.
    added = subprocess.run(['git', '-c', 'core.fsmonitor=false', 'ls-files', '--others', '--exclude-standard', '-z', '--',
                            'ansible/playbooks/dependencies', 'platform/delivery/dependencies'],
                           cwd=source, env=environment, capture_output=True, check=True, timeout=60)
    definition = json.loads((source / 'platform/delivery/dependencies/owners.json').read_bytes())['owners']['native-extraction-fixture']
    fixture_inputs = set(definition['sources'] + definition['companions'])
    for name in filter(None, added.stdout.decode().split('\0')):
        path = Path(name)
        public = (name in fixture_inputs or name == 'ansible/playbooks/dependencies/compose.yaml' or
                  (path.parent.as_posix() == 'ansible/playbooks/dependencies/files' and
                   (path.suffix in {'.py', '.cjs'} or path.name == '.dockerignore')) or
                  (path.parent.as_posix() == 'ansible/playbooks/dependencies/tests' and
                   (path.name == 'fixtures.py' or (path.name.startswith('test_') and path.suffix == '.py'))) or
                  (path.parent.as_posix() == 'platform/delivery/dependencies' and
                   (path.suffix == '.cjs' or path.name in {'owners.json', 'renovate.json', 'image.lock.json'})))
        if public:
            names.add(name)
    names.add('ansible/playbooks/dependencies/README.md')
    names = {name for name in names if not set(Path(name).parts) & {
        '.git', '.env', '.ssh', '.terraform', '__pycache__', 'node_modules'}}
    for relative in names:
        if not any(relative == prefix or relative.startswith(prefix + '/') for prefix in PUBLIC):
            raise ValueError('Actions fixture escaped its public inputs')
        path = owned_path(target, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(owned_path(source, relative).read_bytes())
    template = Path('/tmp/empty-git-template')
    template.mkdir(exist_ok=True)
    commands = (['init', '--template=' + str(template)], ['config', 'core.filemode', 'false'],
                ['--literal-pathspecs', 'add', '--force', '--', *sorted(names)],
                ['-c', 'user.name=CloudLab maintenance fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', 'commit', '-m', 'Public maintenance fixture'],
                ['checkout-index', '--all', '--force'])
    for arguments in commands:
        subprocess.run(['git', *arguments], cwd=target, env=environment, capture_output=True, check=True, timeout=120)
    committed = subprocess.check_output(['git', 'ls-files', '-z'], cwd=target, env=environment).decode().split('\0')
    if {name for name in committed if name} != names:
        raise ValueError('Committed source fixture differs from its exact public file inventory')
    return {'fixture': 'committed public Actions source', 'publicFiles': len(names), 'credentials': False}


def keycloak_candidate(source, candidate, control):
    """Reset only the owned qualification flag in an exact public committed fixture."""
    from pathlib import Path
    import os
    import secrets
    import subprocess
    from playbooks.dependencies.files.inventory import selected
    from playbooks.dependencies.files.keycloak import LOCK
    from playbooks.dependencies.files.local import PUBLIC
    from playbooks.dependencies.files.security import archive_files, owned_path
    from playbooks.dependencies.files.workspace import supports_modes
    source, candidate, control = map(Path, (source, candidate, control))
    candidate.mkdir(parents=True, exist_ok=True)
    control.mkdir(parents=True, exist_ok=True)
    if any(candidate.iterdir()) or any(control.iterdir()):
        raise ValueError('Identity proof requires a new empty owned fixture')
    environment = {'PATH': os.environ['PATH'], 'HOME': '/tmp/home', 'GIT_CONFIG_NOSYSTEM': '1',
                   'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'}
    result = subprocess.run(['git', 'archive', '--format=tar', 'HEAD', '--', *PUBLIC], cwd=source,
                            env=environment, capture_output=True, check=True, timeout=120)
    contents = archive_files(result.stdout)
    modes = subprocess.check_output(['git', 'ls-files', '--stage', '-z', '--', *PUBLIC], cwd=source, env=environment)
    indexed = {row.split('\t', 1)[1]: row.split()[0] for row in modes.decode().split('\0') if row}
    if set(contents) != set(indexed) or any(mode not in {'100644', '100755'} for mode in indexed.values()):
        raise ValueError('Identity fixture archive differs from its exact public index')
    base = {}
    for relative, raw in contents.items():
        path = owned_path(candidate, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o755 if indexed[relative] == '100755' else 0o644)
        base[relative] = {'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), 'mode': indexed[relative]}
    owner = selected(['chart:identity/keycloak'])['chart:identity/keycloak']
    operation = secrets.token_hex(16)
    plan = {'operation': operation, 'owners': ['chart:identity/keycloak']}
    check = {'operation': operation, 'checks': owner['checks'], 'allowed': owner['writePaths'], 'baseTree': base,
             'fileModes': supports_modes(candidate),
             'baseFiles': {relative: base64.b64encode(contents[relative]).decode() for relative in owner['writePaths']}}
    lock = json.loads((candidate / LOCK).read_bytes())
    lock['operator_install_verified'] = False
    (candidate / LOCK).write_text(json.dumps(lock, indent=2) + '\n')
    (control / 'operation.json').write_text(json.dumps(plan))
    (control / 'check-plan.json').write_text(json.dumps(check))
    return {'fixture': 'identity qualification', 'publicFiles': len(contents), 'qualificationReset': True, 'credentials': False}


def registry_proof(source):
    """Exercise a complete ordinary-provider update and real readonly checksum veto."""
    from pathlib import Path
    import shutil
    import tempfile
    from unittest.mock import patch
    from playbooks.dependencies.files import native
    with tempfile.TemporaryDirectory(prefix='maintenance-registry-proof-') as directory:
        root = Path(directory)
        relative = native.ROOTS['tailscale']
        target = root / relative
        shutil.copytree(Path(source) / relative, target,
                        ignore=shutil.ignore_patterns('.terraform', '*.tfstate*', '.env'))
        # The older fixture is owned local data; production constraints stay fixed.
        with patch.object(native, 'baseline', side_effect=lambda _, path: (root / path).read_bytes()):
            native.registry(root, 'tailscale', '0.29.1')
            result = native.registry(root, 'tailscale', '0.29.2')
        lock = target / '.terraform.lock.hcl'
        original = lock.read_text()
        import re
        altered, count = re.subn(r'h1:[A-Za-z0-9+/=]+', 'h1:' + 'A' * 43 + '=', original)
        if not count:
            raise AssertionError('Native lock lacks its actual h1 checksum')
        altered = re.sub(r'zh:[a-f0-9]{64}', 'zh:' + '0' * 64, altered)
        lock.write_text(altered)
        try:
            native.lock_and_check(target, update=False)
        except RuntimeError:
            return {'fixture': 'native tailscale 0.29.1 to 0.29.2', 'completeUpdate': result['nativeChecks'],
                    'staleChecksumsRejected': True, 'credentials': False}
        raise AssertionError('Actual readonly native init accepted stale package checksums')


def custom_checksum_proof(source, name):
    """Use the ordinary runner mirror to reject stale derivative lock checksums."""
    from pathlib import Path
    import re
    import shutil
    import tempfile
    from playbooks.dependencies.files.native import lock_and_check
    from playbooks.dependencies.files.providers import ROOTS
    if name not in ROOTS:
        raise ValueError('Unsupported custom checksum fixture')
    with tempfile.TemporaryDirectory(prefix='maintenance-fork-checksums-') as directory:
        target = Path(directory) / 'root'
        shutil.copytree(Path(source) / ROOTS[name][0], target,
                        ignore=shutil.ignore_patterns('.terraform', '*.tfstate*', '.env'))
        lock_and_check(target, update=False)
        lock = target / '.terraform.lock.hcl'
        raw, count = re.subn(r'h1:[A-Za-z0-9+/=]+', 'h1:' + 'A' * 43 + '=', lock.read_text())
        if count != 1:
            raise AssertionError('Derivative fixture requires one native h1 checksum')
        lock.write_text(re.sub(r'zh:[a-f0-9]{64}', 'zh:' + '0' * 64, raw))
        try:
            lock_and_check(target, update=False)
        except RuntimeError:
            return {'provider': name, 'ordinaryMirrorLockChecks': 'PASS', 'staleChecksumsRejected': True}
        raise AssertionError('Derivative readonly init accepted stale checksum evidence')


def postgres_image_proof(source):
    """Repair an older public PostgreSQL fixture and run its existing chart check."""
    from pathlib import Path
    import shutil
    import tempfile
    from unittest.mock import patch
    from playbooks.dependencies.files import images
    from playbooks.dependencies.files.inventory import selected
    from playbooks.data.files import chart
    with tempfile.TemporaryDirectory(prefix='maintenance-postgres-image-') as directory:
        root = Path(directory)
        shutil.copytree(source, root, dirs_exist_ok=True, ignore=shutil.ignore_patterns('.git'))
        owner = selected(['image:postgresql'])['image:postgresql']
        current = json.loads((root / owner['sources'][0]).read_bytes())['postgres_image']
        older = images.image_digest('ghcr.io/cloudnative-pg/postgresql:18.3-standard-trixie')
        images.apply(root, owner['writePaths'], {current: older})
        plan = {'baseFiles': {path: base64.b64encode((root / path).read_bytes()).decode()
                              for path in owner['writePaths']}}
        borrowed = current.split('@')[0] + '@' + older.rsplit('@', 1)[1]
        images.apply(root, owner['writePaths'], {older: borrowed})
        try:
            images.provenance(root, plan)
        except ValueError:
            pass
        else:
            raise AssertionError('A new PostgreSQL tag borrowed a historical image digest')
        result = images.update(root, 'postgresql', {'selector': 'postgres_image', 'version': '18.4-standard-trixie'})
        verified = images.provenance(root, plan)
        with patch.object(chart, 'ROOT', root):
            native = chart.check()
        if native['helm_hooks'] != 0 or result['images'] < 1:
            raise AssertionError('PostgreSQL image repair did not pass its existing owner')
        return {'fixture': 'PostgreSQL18.3 to18.4', 'completeImageUpdate': True, 'existingChartCheck': 'PASS',
                'changedTagsVerified': verified, 'borrowedDigestRejected': True, 'credentials': False}


def chart_provenance_proof(source):
    """Qualify the final archive boundary against real public Argo release bytes."""
    from pathlib import Path
    import copy
    import shutil
    import tempfile
    import yaml
    from playbooks.dependencies.files import charts, compatibility
    from playbooks.dependencies.files.security import archive_files, digest, download
    prefix = 'platform/delivery/argocd/'
    downloads = {}
    def fetch(url, **arguments):
        if url not in downloads:
            downloads[url] = download(url, **arguments)
        return downloads[url]
    with tempfile.TemporaryDirectory(prefix='maintenance-chart-provenance-') as temporary:
        root = Path(temporary)
        directory = root / prefix
        shutil.copytree(Path(source) / prefix, directory)
        lock = json.loads((directory / 'artifact.lock.json').read_bytes())
        before = copy.deepcopy(lock)
        pin = before['chart']
        version = pin['version']
        if version != '10.9.6':
            raise ValueError('This bounded qualification fixture requires its reviewed Argo patch')
        pin.update(version='10.9.5', archive='charts/argo-cd-10.9.5.tgz',
                   url=pin['url'].replace(version, '10.9.5'))
        old = fetch(pin['url'], prefix='https://github.com/argoproj/argo-helm/releases/download/')
        pin['sha256'] = digest(old)
        plan = {'baseFiles': {prefix + 'artifact.lock.json': base64.b64encode(json.dumps(before).encode()).decode()}}
        compatibility.verify(root, plan)
        charts.provenance(root, plan, fetch=fetch)
        archive = directory / lock['chart']['archive']
        contents = archive_files(archive.read_bytes())
        contents['argo-cd/templates/unowned-role.yaml'] = b'apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: injected}\nrules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]\n'
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as tar:
            for name, raw in contents.items():
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                tar.addfile(item, io.BytesIO(raw))
        archive.write_bytes(output.getvalue())
        lock['chart']['sha256'] = digest(output.getvalue())
        (directory / 'artifact.lock.json').write_text(json.dumps(lock))
        try:
            charts.provenance(root, plan, fetch=fetch)
        except ValueError:
            return {'fixture': 'Argo10.9.5 to10.9.6', 'officialArchiveProvenance': 'PASS',
                    'matchingChecksumInjectedRBACRejected': True, 'publicDownloads': len(downloads), 'credentials': False}
        raise AssertionError('A matching candidate checksum authorized an injected chart resource')


def tofu_update_proof(source):
    """Repair real public OpenTofu fixture pins and check every existing native root."""
    from pathlib import Path
    import shutil
    import tempfile
    from unittest.mock import patch
    from playbooks.dependencies.files import native, tools
    from playbooks.dependencies.files.providers import ROOTS as CUSTOM_ROOTS
    from playbooks.dependencies.files.toolchain import embedded
    with tempfile.TemporaryDirectory(prefix='maintenance-tofu-update-') as directory:
        root = Path(directory)
        shutil.copytree(source, root, dirs_exist_ok=True, ignore=shutil.ignore_patterns('.git'))
        embedded(root)
        with patch.object(tools, 'baseline', side_effect=lambda _, path: (root / path).read_bytes()):
            tools.update(root, 'tofu', '1.13.0')
            result = tools.update(root, 'tofu', '1.13.1')
        # The repaired current pin must match the real immutable runner inputs.
        embedded(root)
        roots = list(native.ROOTS.values()) + [path for rows in CUSTOM_ROOTS.values() for path in rows]
        for relative in roots:
            native.lock_and_check(root / relative, update=False)
        return {'fixture': 'OpenTofu1.13.0 to1.13.1', 'completeToolUpdate': True,
                'runnerInputsAndNativeVersions': 'PASS', 'nativeRoots': len(roots),
                'newTargetStillRequiresBuild': result['requiresBuild'], 'credentials': False}


def ci_tools_proof(source):
    """Repair a real older crane source fixture to the already qualified build inputs."""
    from pathlib import Path
    import shutil
    import tempfile
    from unittest.mock import patch
    from playbooks.dependencies.files import ci_tools
    from playbooks.dependencies.files.security import digest, download
    from playbooks.dependencies.files.tools import write_json
    relative = 'platform/delivery/ci/tools/source.lock.json'
    with tempfile.TemporaryDirectory(prefix='maintenance-ci-source-') as directory:
        root = Path(directory)
        shutil.copytree(source, root, dirs_exist_ok=True, ignore=shutil.ignore_patterns('.git'))
        path = root / relative
        original = json.loads(path.read_bytes())
        lock = json.loads(path.read_bytes())
        row = next(item for item in lock['sources'] if item['name'] == 'crane')
        current = dict(row)
        old_url = 'https://codeload.github.com/google/go-containerregistry/tar.gz/refs/tags/v0.22.0'
        row.update(version='v0.22.0', source=old_url,
                   sha256=digest(download(old_url, prefix='https://codeload.github.com/google/go-containerregistry/tar.gz/refs/tags/')))
        write_json(path, lock)
        for recipe in ('platform/delivery/ci/Dockerfile', 'ansible/runner/Dockerfile'):
            target = root / recipe
            text = target.read_text().replace(current['source'], row['source']).replace(current['sha256'], row['sha256'])
            target.write_text(text.replace(current['version'], row['version']), newline='\n')
        immutable = path.read_bytes()
        with patch.object(ci_tools, 'baseline', return_value=immutable):
            result = ci_tools.update(root, 'crane', '0.22.1')
        if json.loads(path.read_bytes()) != original:
            raise AssertionError('Repaired CI source differs from its qualified native build inputs')
        for recipe in ('platform/delivery/ci/Dockerfile', 'ansible/runner/Dockerfile'):
            if (root / recipe).read_text() != (Path(source) / recipe).read_text():
                raise AssertionError('Repaired CI recipe differs from its qualified native build')
        return {'fixture': 'crane0.22.0 to0.22.1', 'sourceUrlChecksumModulesAndRecipes': 'PASS',
                'sameQualifiedNativeBuildInputs': True, 'requiredBuildTargets': result['pendingBuild'], 'credentials': False}


class MaintenanceAPI:
    """Public synthetic Git object/PR API; never connects to a repository."""

    def __init__(self, base, head):
        from playbooks.dependencies.files.gate import branch_prefix
        self.blobs, self.trees, self.commits, self.calls = {}, {}, {}, []
        self.base, self.head = self.commit(base), self.commit(head)
        self.row = {'number': 7, 'node_id': 'PR_7', 'state': 'open', 'draft': True,
                    'user': {'login': 'release[bot]', 'type': 'Bot'},
                    'head': {'repo': {'id': 1}, 'ref': branch_prefix('main') + 'argocd', 'sha': self.head},
                    'base': {'repo': {'id': 1}, 'ref': 'main', 'sha': self.base}}

    @staticmethod
    def sha(raw):
        return hashlib.sha1(raw).hexdigest()

    def commit(self, contents):
        paths = {}
        for path, raw in contents.items():
            sha = self.sha(b'blob ' + str(len(raw)).encode() + b'\0' + raw)
            self.blobs[sha] = raw
            paths[path] = sha
        tree = self.sha(json.dumps(paths, sort_keys=True).encode())
        self.trees[tree] = paths
        commit = self.sha(('commit:' + tree).encode())
        self.commits[commit] = {'tree': {'sha': tree}}
        return commit

    def snapshot(self, repository, revision, *, expected=None, fetch=None):
        if repository != 'example/platform':
            raise ValueError('Synthetic repository identity differs')
        paths = self.trees[self.commits[revision]['tree']['sha']]
        if expected is not None and expected != {path: {'sha': sha, 'mode': '100644'} for path, sha in paths.items()}:
            raise ValueError('Synthetic snapshot differs from exact Git tree')
        return {path: self.blobs[sha] for path, sha in paths.items()}

    def request(self, method, path, body=None):
        import copy
        self.calls.append((method, path, body))
        if path == 'repos/example/platform':
            return {'id': 1, 'full_name': 'example/platform', 'private': False}
        if path.endswith('/pulls?state=open&per_page=100'):
            return [copy.deepcopy(self.row)]
        if path.endswith('/pulls/7'):
            return copy.deepcopy(self.row)
        if '/git/ref/heads/' in path:
            return {'object': {'sha': self.base}}
        if method == 'GET' and '/git/commits/' in path:
            return self.commits[path.rsplit('/', 1)[1]]
        if method == 'GET' and '/git/trees/' in path:
            paths = self.trees[path.split('/git/trees/')[1].split('?')[0]]
            return {'truncated': False, 'tree': [{'path': key, 'sha': value, 'mode': '100644', 'type': 'blob'}
                                                for key, value in paths.items()]}
        if path == 'graphql':
            self.row['draft'] = 'convertPullRequestToDraft' in body['query']
            return {}
        if method == 'POST' and path.endswith('/git/blobs'):
            raw = base64.b64decode(body['content'], validate=True)
            sha = self.sha(b'blob ' + str(len(raw)).encode() + b'\0' + raw)
            self.blobs[sha] = raw
            return {'sha': sha}
        if method == 'POST' and path.endswith('/git/trees'):
            paths = dict(self.trees[body['base_tree']])
            for row in body['tree']:
                if row['sha'] is None:
                    del paths[row['path']]
                else:
                    paths[row['path']] = row['sha']
            sha = self.sha(json.dumps(paths, sort_keys=True).encode())
            self.trees[sha] = paths
            return {'sha': sha}
        if method == 'POST' and path.endswith('/git/commits'):
            sha = self.sha(json.dumps(body, sort_keys=True).encode())
            self.commits[sha] = {'tree': {'sha': body['tree']}}
            return {'sha': sha}
        if method == 'PATCH' and '/git/refs/heads/' in path:
            if body['force'] is not False:
                raise ValueError('Synthetic publication must preserve non-force update')
            self.row['head']['sha'] = body['sha']
            return {}
        raise AssertionError('Unexpected synthetic Git operation')


class DependencyFixtureAPI(MaintenanceAPI):
    """Fixed public fixture refs and native Bot PR, with real expected-head races."""

    def __init__(self, source):
        super().__init__(source, source)
        self.refs = {'main': self.base}
        self.native = False
        self.lose = None
        self.reject_ref = False
        self.race_delete = False

    def native_pr(self, base, head):
        from playbooks.dependencies.files.gate import branch_prefix
        self.native = True
        self.row['base'].update(ref=base, sha=self.refs[base])
        self.row['head'].update(ref=branch_prefix(base)+'tofu', sha=head)
        self.refs[self.row['head']['ref']] = head

    def request(self, method, path, body=None, missing=False):
        import copy
        from playbooks.argocd.files.github_setup import GitHubHTTPError
        if path == 'repos/example/platform':
            self.calls.append((method, path, body))
            return {'id': 1, 'node_id': 'REPO_1', 'full_name': 'example/platform', 'private': False,
                    'fork': False, 'default_branch': 'main'}
        if '/git/ref/heads/' in path:
            self.calls.append((method, path, body))
            branch = path.split('/git/ref/heads/', 1)[1]
            if branch not in self.refs:
                if missing: return None
                raise GitHubHTTPError(404)
            return {'object': {'sha': self.refs[branch]}}
        if path.endswith('/pulls?state=open&per_page=100'):
            self.calls.append((method, path, body))
            return [copy.deepcopy(self.row)] if self.native and self.row['state'] == 'open' else []
        if method == 'POST' and path.endswith('/git/refs'):
            self.calls.append((method, path, body))
            branch = body['ref'].removeprefix('refs/heads/')
            if self.reject_ref or branch in self.refs: raise GitHubHTTPError(422)
            self.refs[branch] = body['sha']
            if self.lose == 'create-ref': self.lose = None; raise RuntimeError('synthetic response loss')
            return {'object': {'sha': body['sha']}}
        if method == 'PATCH' and path.endswith('/pulls/7'):
            self.calls.append((method, path, body)); self.row['state'] = body['state']
            if self.lose == 'close': self.lose = None; raise RuntimeError('synthetic response loss')
            return copy.deepcopy(self.row)
        if path == 'graphql' and 'updateRefs' in body['query']:
            self.calls.append((method, path, body))
            mutation = body['variables']['input']
            row = mutation['refUpdates'][0]; branch = row['name'].removeprefix('refs/heads/')
            if self.race_delete: self.refs[branch] = 'f'*40
            if self.refs.get(branch) != row['beforeOid'] or row['force'] is not False: raise GitHubHTTPError(422)
            if row['afterOid'] != '0'*40: raise AssertionError('Only exact deletion is supported')
            del self.refs[branch]
            if self.lose == 'delete': self.lose = None; raise RuntimeError('synthetic response loss')
            return {'data': {'updateRefs': {'clientMutationId': mutation['clientMutationId']}}}
        result = super().request(method, path, body)
        if method == 'POST' and path.endswith('/git/commits'):
            self.commits[result['sha']].update(message=body['message'], parents=[{'sha': value} for value in body['parents']])
        if method == 'PATCH' and '/git/refs/heads/' in path:
            self.refs[path.split('/git/refs/heads/', 1)[1]] = body['sha']
        return result
