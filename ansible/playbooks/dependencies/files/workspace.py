"""Materialize public candidate bytes without credentials, Git caches or private inputs."""
import json
import hashlib
import secrets
from pathlib import Path

from .security import archive_files, digest, download, owned_path, relative


def supports_modes(root):
    """Probe the actual owned filesystem before any candidate process executes."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = owned_path(root, '.maintenance-mode-probe-' + secrets.token_hex(16))
    with path.open('xb'):
        pass
    try:
        try:
            path.chmod(0o600)
            private = path.stat().st_mode & 0o777
            path.chmod(0o700)
            executable = path.stat().st_mode & 0o777
        except PermissionError:
            return False
        return private == 0o600 and executable == 0o700
    finally:
        path.unlink()


def files(root):
    root = Path(root)
    result = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Maintenance candidate contains a symlink')
        if not path.is_file():
            continue
        name = path.relative_to(root).as_posix()
        relative(name)
        if (any(part in {'.git', '.env', '.ssh', '.terraform', 'node_modules', '__pycache__'} for part in path.relative_to(root).parts) or
                name.endswith(('.tfstate', '.tfstate.backup'))):
            raise ValueError('Maintenance candidate contains forbidden private or runtime inputs')
        result[name] = digest(path.read_bytes())
    return result


def tree(root):
    return digest(json.dumps(files(root), sort_keys=True).encode())


def remote_tree(api, repository, revision):
    commit = api.request('GET', 'repos/' + repository + '/git/commits/' + revision)
    document = api.request('GET', 'repos/' + repository + '/git/trees/' + commit['tree']['sha'] + '?recursive=1')
    if document.get('truncated') or len(document.get('tree', [])) > 10000:
        raise ValueError('Maintenance tree inventory is incomplete or exceeds its limit')
    result = {}
    for entry in document['tree']:
        path = entry['path']
        relative(path)
        if entry.get('type') == 'tree':
            continue
        if entry.get('type') != 'blob' or entry.get('mode') not in ('100644', '100755') or path in result:
            raise ValueError('Maintenance tree contains an unsupported file mode or duplicate path')
        result[path] = {'sha': entry['sha'], 'mode': entry['mode']}
    return result


def owned_diff(base, head, allowed):
    if any(base[path]['mode'] != head[path]['mode'] for path in set(base) & set(head)):
        raise ValueError('Maintenance must preserve existing Git file modes')
    changed = {path for path in set(base) | set(head) if base.get(path) != head.get(path)}
    if not changed or changed - set(allowed):
        raise ValueError('Initial maintenance PR contains unowned paths or file modes')
    return changed


def snapshot(repository, head, *, expected=None, fetch=download):
    url = 'https://codeload.github.com/' + repository + '/tar.gz/' + head
    contents = archive_files(fetch(url, prefix='https://codeload.github.com/' + repository + '/tar.gz/'))
    output = {}
    for name, raw in contents.items():
        if '/' not in name:
            raise ValueError('Unexpected public repository archive layout')
        name = name.split('/', 1)[1]
        relative(name)
        if any(part in {'.env', '.git', '.ssh', '.terraform'} for part in name.split('/')):
            raise ValueError('Public candidate archive contains forbidden private inputs')
        if name in output:
            raise ValueError('Duplicate public candidate file')
        output[name] = raw
    if expected is not None:
        if set(output) != set(expected):
            raise ValueError('Public candidate archive differs from its exact Git tree')
        for name, raw in output.items():
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            if blob != expected[name]['sha']:
                raise ValueError('Public candidate content differs from its exact Git blob')
    return output


def export(root, repository, head, *, expected=None, fetch=download):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    output = snapshot(repository, head, expected=expected, fetch=fetch)
    if any(root.iterdir()):
        # After publication, reuse only the byte-identical final published tree.
        current = files(root)
        if current != {name: digest(raw) for name, raw in output.items()}:
            raise ValueError('Export requires an empty candidate or the exact published tree')
        if expected is not None and supports_modes(root):
            for name in current:
                executable = bool(owned_path(root, name).stat().st_mode & 0o111)
                if executable != (expected[name]['mode'] == '100755'):
                    raise ValueError('Published candidate file mode differs')
        return current
    for name, raw in output.items():
        target = owned_path(root, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        if expected is not None:
            target.chmod(0o755 if expected[name]['mode'] == '100755' else 0o644)
    return files(root)


def changes(root, baseline, allowed):
    current = files(root)
    added, removed = set(current) - set(baseline), set(baseline) - set(current)
    import re
    normalize = lambda path: re.sub(r'v?[0-9]+\.[0-9]+\.[0-9]+(?=[.]tgz$)', '<version>', path)
    if (any(not path.endswith('.tgz') or normalize(path) == path for path in added | removed) or
            sorted(map(normalize, added)) != sorted(map(normalize, removed))):
        raise ValueError('Maintenance permits only complete owned chart archive rename pairs')
    changed = added | removed | {path for path in set(current) & set(baseline) if current[path] != baseline[path]}
    if changed - set(allowed):
        raise ValueError('Maintenance modified an unowned candidate path')
    return {path: owned_path(root, path).read_bytes() if path in current else None for path in sorted(changed)}
