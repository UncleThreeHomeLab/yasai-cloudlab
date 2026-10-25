"""Explicit dependency ownership and verification contracts."""
import json
import copy
import re
from functools import lru_cache
from pathlib import Path

from .security import digest, owned_path

ROOT = Path(__file__).resolve().parents[4]
INVENTORY = ROOT / 'platform/delivery/dependencies/owners.json'


def load(root=ROOT):
    document = json.loads(INVENTORY.read_text())
    if document.get('schema') != 1 or not isinstance(document.get('owners'), dict):
        raise ValueError('Unsupported maintenance inventory')
    for name, owner in document['owners'].items():
        for field in ('sources', 'companions', 'writePaths', 'checks'):
            if not isinstance(owner.get(field), list) or any(not isinstance(item, str) for item in owner[field]):
                raise ValueError('Dependency owner requires explicit lists: ' + name)
        if not owner['sources'] or not owner['checks'] or owner['updater'] not in {
                'tool', 'image', 'chart', 'provider', 'ci-tools', 'ci-runner',
                'actions', 'package', 'profile', 'requirements', 'native'}:
            raise ValueError('Incomplete dependency owner: ' + name)
        if owner['updater'] == 'chart':
            source = next(path for path in owner['sources'] if path.endswith('/artifact.lock.json'))
            lock = json.loads(owned_path(root, source).read_text())
            entry = lock['chart'] if isinstance(lock.get('chart'), dict) else lock
            if 'archive' in entry:
                policy = [path for path in owner['writePaths'] if '/charts/' in path and path.endswith('.tgz')]
                if len(policy) != 1:
                    raise ValueError('Chart owner requires one explicit archive family')
                version = re.search(r'v?[0-9]+\.[0-9]+\.[0-9]+(?=[.]tgz$)', policy[0])
                current = (Path(source).parent / entry['archive']).as_posix()
                if not version or not re.fullmatch(re.escape(policy[0][:version.start()]) +
                        r'v?[0-9]+\.[0-9]+\.[0-9]+' + re.escape(policy[0][version.end():]), current):
                    raise ValueError('Chart archive differs from its approved owner family')
                for field in ('companions', 'writePaths'):
                    owner[field] = [current if path == policy[0] else path for path in owner[field]]
        for path in owner['sources'] + owner['companions']:
            if not owned_path(root, path).is_file():
                raise ValueError('Missing dependency owner input: ' + path)
        if set(owner['writePaths']) - paths(owner):
            raise ValueError('Writable dependency paths must be registered owner inputs: ' + name)
        for path in owner['writePaths']:
            if not owned_path(root, path).is_file():
                raise ValueError('Writable dependency path does not exist: ' + path)
        for check in owner['checks']:
            if check.startswith(('module:', 'native:')):
                continue
            if not check.rsplit('/', 1)[-1].startswith('test_') or not owned_path(root, check).is_file():
                raise ValueError('Missing existing dependency check: ' + check)
    return document


def paths(owner):
    return set(owner['sources'] + owner['companions'])


def pin_files(root):
    found = set()
    for directory in ('ansible', 'platform', 'infra', 'apps', '.github'):
        for path in (Path(root) / directory).rglob('*'):
            if not path.is_file() or '.terraform' in path.parts or '__pycache__' in path.parts:
                continue
            name = path.name
            if (name.endswith(('lock.json', 'lock.hcl')) or name in {
                    'Chart.yaml', 'Chart.lock', 'Dockerfile', 'go.mod', 'go.sum',
                    'requirements.txt', 'telemetry-requirements.txt', 'versions.tf',
                    'debian.sources', 'release.json', 'package.json'} or name.endswith('.Dockerfile') or
                    (path.parent == Path(root) / 'apps/releases' and name.endswith('.json')) or
                    (name.startswith('compose.') and name.endswith(('.yaml', '.yml')))):
                found.add(path.relative_to(root).as_posix())
    found.add('compose.yaml')
    return found


def coverage(root=ROOT):
    document = load(root)
    registered = set().union(*(paths(owner) for owner in document['owners'].values()))
    missing = pin_files(root) - registered - set(document['historical'])
    if missing:
        raise ValueError('Active dependencies have no maintenance owner: ' + ', '.join(sorted(missing)))
    return document


def selected(names, root=ROOT):
    owners = (_trusted() if root == ROOT else coverage(root))['owners']
    if not names or any(name not in owners for name in names):
        raise ValueError('Unsupported dependency owner')
    names = [owners[name].get('aliasFor', name) for name in names]
    if any(name not in owners or owners[name].get('disposition') in {'existing-owner', 'historical', 'qualification-fixture'} for name in names):
        raise ValueError('This input retains its existing publication or historical owner; dependency writes are forbidden')
    expanded = set(names)
    if 'runner' in names:
        expanded.update(('tool:tofu', 'tool:restic', 'tool:helm', 'tool:op', 'tool:debian', 'image:python', 'image:cosign'))
    if any(name in {'ci-tools', 'chart:delivery/ci/controller', 'chart:delivery/ci/pool'} for name in names):
        expanded.update(('ci-tools', 'chart:delivery/ci/controller', 'chart:delivery/ci/pool'))
    if any(name.startswith('chart:connectivity/istio/') for name in names):
        expanded.update('chart:connectivity/istio/' + component for component in ('base', 'istiod', 'cni', 'ztunnel'))
        expanded.update(('image:istio', 'preview-package'))
    for name in names:
        companion = {'chart:harbor/server': 'image:harbor', 'chart:delivery/admission': 'image:admission',
                     'chart:connectivity/tailscale-operator': 'image:access'}.get(name)
        if name.startswith('chart:observability/'):
            companion = 'image:observability'
        if companion:
            expanded.add(companion)
    return {name: copy.deepcopy(owners[name]) for name in sorted(expanded)}


@lru_cache(maxsize=1)
def _trusted():
    # Each invocation uses one read-only trusted source; candidate state is separate.
    return coverage(ROOT)


def fingerprint(root, owners):
    files = set().union(*(paths(owner) for owner in owners.values()))
    for owner in owners.values():
        if owner['updater'] != 'chart':
            continue
        source = next(path for path in owner['sources'] if path.endswith('/artifact.lock.json'))
        lock = json.loads(owned_path(root, source).read_bytes())
        entry = lock.get('chart') if isinstance(lock.get('chart'), dict) else lock
        if 'archive' not in entry:
            continue
        archive = (Path(source).parent / entry['archive']).as_posix()
        owned_path(root, archive)
        files.add(archive)
        files = {path for path in files if not (path.startswith(str(Path(source).parent).replace('\\', '/') + '/charts/') and
                                                path.endswith('.tgz') and path != archive)}
    return digest(json.dumps({path: digest(owned_path(root, path).read_bytes())
                              for path in sorted(files)}, sort_keys=True).encode())
